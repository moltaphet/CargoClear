"""Autonomous Studio Next deployment + live end-to-end proof for CargoClear.

    .venv/bin/python scripts/deploy_and_verify.py [--contract 0x...] [--feed-sha <40 hex>]

Everything runs unattended:

  1. loads the two fresh project wallets (cargoclear-importer / cargoclear-exporter),
     funds them from the Studio Next faucet and, if the faucet credits nothing,
     from any unlocked local CLI account that holds a balance;
  2. deploys contracts/cargo_clear.py with the Carrier Authority's Ed25519 public key;
  3. opens LC-1 (importer) and accepts it (exporter);
  4. submits a FORGED Bill of Lading signature and records the finalized rejection
     (ERR_INVALID_BOL_ATTESTATION) -- no HTTP fetch, no state change;
  5. submits the genuine Carrier Authority signature, then settles Stage 1 and
     Stage 2 through real 2-of-3 consensus over the three pinned CDN feeds;
  6. withdraws both parties' balances;
  7. records every finalized tx hash and the exact gen_call readbacks in
     deployments/studio-next.json plus the ABI in deployments/cargo_clear_abi.json.

Private keys live in .secrets/ (git-ignored) and never touch the repository.
"""

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import time
from decimal import Decimal
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from eth_account import Account
from genlayer_py import create_client
from genlayer_py.abi import calldata
from genlayer_py.chains import studio_devnet
from genlayer_py.contracts.actions import _estimate_transaction_fees_with_policy, get_current_fee_policy

ROOT = Path(__file__).resolve().parent.parent
SECRETS = ROOT / ".secrets"
RPC = "https://studio-next.genlayer.com/api"
EXPLORER = "https://explorer-studio-next.genlayer.com"
CHAIN_ID = 61997
OWNER, REPO = "moltaphet", "CargoClear"

# L/C terms. Shapes match deployments/mock_feeds (see scripts/make_fixtures.py).
PRINCIPAL = 50_000_000_000_000_003  # 0.05 GEN + 3 wei: not divisible by 5, so dust is exercised live
BOL_ID = "BOL-CC-20261009-0001"
CONTAINER = "MSKU4471290"
CARGO_SPEC = "Frozen Atlantic shrimp, grade A, 18 t, reefer -18.0C"
MAX_TEMP_TENTHS_C = -180
LATEST_ARRIVAL_TS = 1_792_886_400  # 2026-10-25T00:00:00Z

NEED_IMPORTER = 250 * 10**15  # principal + fee deposits with headroom
NEED_EXPORTER = 60 * 10**15


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def jsonable(v):
    if isinstance(v, (bytes, bytearray)):
        return "0x" + bytes(v).hex()
    if isinstance(v, dict):
        return {str(k): jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [jsonable(x) for x in v]
    if hasattr(v, "hex") and callable(v.hex) and not isinstance(v, (int, str)):
        try:
            return "0x" + v.hex()
        except Exception:  # noqa: BLE001
            pass
    return v


# ------------------------------------------------------------------- wallets
def load_account(name: str):
    path = SECRETS / f"{name}.key"
    if not path.exists():
        SECRETS.mkdir(mode=0o700, exist_ok=True)
        acct = Account.create()
        path.write_text(acct.key.hex())
        path.chmod(0o600)
    return Account.from_key(path.read_text().strip())


def carrier_key() -> Ed25519PrivateKey:
    path = SECRETS / "carrier_ed25519.seed"
    if not path.exists():
        path.write_text(os.urandom(32).hex())
        path.chmod(0o600)
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(path.read_text().strip()))


def client_for(account=None):
    return create_client(chain=studio_devnet, endpoint=RPC, account=account)


def retry(fn, attempts: int = 8, wait: float = 6.0):
    """Studio Next occasionally drops a connection; retry read-only calls."""
    for i in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            if i + 1 == attempts:
                raise
            log(f"transient RPC error ({str(exc)[:90]}); retry {i + 1}/{attempts - 1}")
            time.sleep(wait)


def balance(client, address) -> int:
    return int(retry(lambda: client.get_balance(address)))


def ensure_funds(client, address, label: str, need: int) -> dict:
    have = balance(client, address)
    info = {"label": label, "address": address, "before_wei": have, "method": "already funded"}
    if have >= need:
        info["after_wei"] = have
        return info
    try:
        client.fund_account(address, need - have)
        time.sleep(3)
    except Exception as exc:  # noqa: BLE001
        log(f"faucet error for {label}: {str(exc)[:160]}")
    have = balance(client, address)
    info["method"] = "studio faucet"
    if have < need:
        log(f"faucet credited {have - info['before_wei']} wei to {label}; falling back to a local CLI account")
        info["method"] = "local CLI account transfer"
        info["transfer"] = fallback_transfer(address, need - have)
        have = balance(client, address)
    info["after_wei"] = have
    return info


def fallback_transfer(to: str, amount_wei: int) -> dict:
    """Send GEN from any unlocked local CLI account that can cover it."""
    out = subprocess.run(["genlayer", "account", "list"], capture_output=True, text=True, timeout=120).stdout
    names = [
        line.split()[1] if line.startswith("*") else line.split()[0]
        for line in out.splitlines()
        if "(unlocked)" in line and "cargoclear" not in line
    ]
    for name in names:
        show = subprocess.run(
            ["genlayer", "account", "show", "--account", name], capture_output=True, text=True, timeout=120
        ).stdout
        for line in show.splitlines():
            if "balance:" in line:
                gen = Decimal(line.split("'")[1].split()[0]) if "'" in line else Decimal(0)
                if int(gen * 10**18) > amount_wei + 10**16:
                    amt = f"{Decimal(amount_wei) / Decimal(10**18):.6f}".rstrip("0")
                    subprocess.run(
                        ["genlayer", "account", "send", to, amt, "--account", name], check=True, timeout=300
                    )
                    return {"from_cli_account": name, "amount_gen": amt}
    raise SystemExit("no funded unlocked local account available to top up")


# ----------------------------------------------------------------- tx helpers
def fee_options(client) -> dict:
    est = retry(lambda: _estimate_transaction_fees_with_policy(client, None, get_current_fee_policy(client)))
    return {"distribution": est["distribution"], "feeValue": est.get("feeValue") or est.get("fee_value") or 0}


def leader_receipt(tx: dict) -> dict:
    cd = tx.get("consensus_data") or {}
    lr = cd.get("leader_receipt") or []
    return lr[0] if lr else {}


def decode_payload(res) -> str | None:
    """Text of a leader result. A leading 0x00 byte marks a successful return whose
    remainder is calldata; anything else is the revert message verbatim."""
    data = None
    if isinstance(res, dict):
        raw = res.get("raw")
        if isinstance(raw, str) and raw:
            try:
                data = base64.b64decode(raw)
            except Exception:  # noqa: BLE001
                data = None
        if data is None and isinstance(res.get("payload"), str):
            data = res["payload"].encode("utf-8")
    elif isinstance(res, str):
        data = res.encode("utf-8")
    if not data:
        return None
    if data[:1] == b"\x00":
        try:
            val = calldata.decode(data[1:])
            return val if isinstance(val, str) else json.dumps(jsonable(val), sort_keys=True)
        except Exception:  # noqa: BLE001
            pass
    return data.decode("utf-8", "replace").lstrip("\x00\x01")


def outcome_of(tx: dict) -> dict:
    lr = leader_receipt(tx)
    res = lr.get("result")
    gv = lr.get("genvm_result") or {}
    return {
        "execution": tx.get("txExecutionResultName"),
        "consensus": tx.get("result_name"),
        "lifecycle": tx.get("lifecycle"),
        "leader_result": jsonable(res),
        "result_text": decode_payload(res),
        "stderr": (gv.get("stderr") or "")[-1200:] if isinstance(gv, dict) else None,
        "stdout": (gv.get("stdout") or "")[-600:] if isinstance(gv, dict) else None,
        "block_timestamp": tx.get("created_timestamp"),
        "emitted_messages": jsonable(tx.get("messages")),
    }


def send(client, label, fn, steps, **kw):
    """Submit one transaction, wait for FINALIZATION, and record the outcome."""
    t0 = time.time()
    tx_hash = fn(fees=fee_options(client), **kw)
    h = tx_hash.hex() if hasattr(tx_hash, "hex") else str(tx_hash)
    h = h if h.startswith("0x") else "0x" + h
    log(f"{label}: submitted {h}")
    retry(lambda: client.wait_for_transaction_receipt(tx_hash, wait_until="finalized", interval=4, retries=240))
    tx = retry(lambda: client.get_transaction(tx_hash))
    out = outcome_of(tx)
    out.update(
        {
            "label": label,
            "tx_hash": h,
            "explorer": f"{EXPLORER}/tx/{h}",
            "sender": tx.get("sender") or tx.get("from_address"),
            "to": tx.get("to_address"),
            "value_wei": tx.get("value"),
            "seconds_to_finalize": round(time.time() - t0, 1),
        }
    )
    log(f"{label}: {out['execution']} / {out['consensus']} / {out['lifecycle']}  {str(out['result_text'])[:160]!r}")
    steps.append(out)
    return out, tx


def read(client, address, method, args=None):
    return retry(lambda: jsonable(client.read_contract(address, method, args=args or [])))


def git_feed_sha() -> str:
    return subprocess.check_output(
        ["git", "log", "-1", "--format=%H", "--", "deployments/mock_feeds"], cwd=ROOT, text=True
    ).strip()


def feed_urls(sha: str) -> list:
    name = "LC-1.json"
    return [
        f"https://raw.githubusercontent.com/{OWNER}/{REPO}/{sha}/deployments/mock_feeds/a/{name}",
        f"https://cdn.jsdelivr.net/gh/{OWNER}/{REPO}@{sha}/deployments/mock_feeds/b/{name}",
        f"https://raw.githack.com/{OWNER}/{REPO}/{sha}/deployments/mock_feeds/c/{name}",
    ]


# ------------------------------------------------------------------------ main
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--contract", help="reuse an already deployed address instead of deploying")
    ap.add_argument("--feed-sha", default=None)
    ap.add_argument("--out", default=str(ROOT / "deployments" / "studio-next.json"))
    ns = ap.parse_args()

    importer, exporter = load_account("importer"), load_account("exporter")
    carrier = carrier_key()
    carrier_pub = carrier.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    impostor = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"CargoClear forged carrier").digest())
    c_imp, c_exp = client_for(importer), client_for(exporter)
    c_ro = client_for(importer)  # reads need a connected account; nothing is signed with it

    chain_id = int(retry(lambda: c_ro.provider.make_request("eth_chainId", []))["result"], 16)
    assert chain_id == CHAIN_ID, f"expected chain {CHAIN_ID}, got {chain_id}"
    log(f"Studio Next chain {chain_id}; importer {importer.address}; exporter {exporter.address}")

    rec: dict = {
        "network": "studio-next",
        "chain_id": CHAIN_ID,
        "rpc_url": RPC,
        "explorer_url": EXPLORER,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "wallets": {
            "cargoclear-importer": importer.address,
            "cargoclear-exporter": exporter.address,
        },
        "carrier_authority_pubkey": carrier_pub,
        "steps": [],
    }
    steps = rec["steps"]

    rec["funding"] = [
        ensure_funds(c_ro, importer.address, "cargoclear-importer", NEED_IMPORTER),
        ensure_funds(c_ro, exporter.address, "cargoclear-exporter", NEED_EXPORTER),
    ]
    rec["balances_before_wei"] = {
        "importer": balance(c_ro, importer.address),
        "exporter": balance(c_ro, exporter.address),
    }

    feed_sha = ns.feed_sha or git_feed_sha()
    urls = feed_urls(feed_sha)
    rec["feed_commit_sha"] = feed_sha
    rec["feed_urls"] = urls

    source = (ROOT / "contracts" / "cargo_clear.py").read_text()
    source_sha = hashlib.sha256(source.encode()).hexdigest()
    rec["source"] = "contracts/cargo_clear.py"
    rec["source_sha256"] = source_sha
    rec["runner"] = source.splitlines()[1].split('"Depends": ')[1].strip(' "}')

    # ---- 1. deploy ---------------------------------------------------------
    if ns.contract:
        address = ns.contract
        log(f"reusing contract {address}")
    else:
        out, tx = send(c_imp, "deploy", c_imp.deploy_contract, steps, code=source, args=[carrier_pub])
        assert out["execution"] == "FINISHED_WITH_RETURN", out
        address = tx.get("recipient") or tx.get("to_address")
        out["contract_address"] = address
    rec["contract_address"] = address
    rec["contract_explorer_url"] = f"{EXPLORER}/address/{address}"
    log(f"contract {address}")

    # ---- 2. open + accept ----------------------------------------------------
    lc_id = read(c_ro, address, "get_protocol_summary")["lc_count"] + 1
    lc_id = f"LC-{lc_id}"
    open_out, _ = send(
        c_imp, "open_letter_of_credit", c_imp.write_contract, steps,
        address=address, function_name="open_letter_of_credit", value=PRINCIPAL,
        args=[
            exporter.address.lower(), CONTAINER, hashlib.sha256(CARGO_SPEC.encode()).hexdigest(),
            MAX_TEMP_TENTHS_C, LATEST_ARRIVAL_TS, *urls,
        ],
    )
    assert open_out["execution"] == "FINISHED_WITH_RETURN", open_out
    rec["lc_id"] = lc_id
    accept_out, _ = send(
        c_exp, "accept_lc_terms", c_exp.write_contract, steps,
        address=address, function_name="accept_lc_terms", args=[lc_id],
    )
    assert accept_out["execution"] == "FINISHED_WITH_RETURN", accept_out
    rec["readback_after_accept"] = read(c_ro, address, "get_lc_state", [lc_id])

    # ---- 3. Ed25519: forged rejection, then the genuine attestation -----------
    message = read(c_ro, address, "get_bol_message", [lc_id, BOL_ID])
    exporter_hex = exporter.address.lower()
    expected = "|".join(
        [BOL_ID, lc_id, CONTAINER, exporter_hex, hashlib.sha256(CARGO_SPEC.encode()).hexdigest(),
         str(MAX_TEMP_TENTHS_C), str(LATEST_ARRIVAL_TS)]
    )
    assert message == expected, (message, expected)
    rec["bol_canonical_message"] = message
    forged_sig = impostor.sign(message.encode()).hex()  # well-formed Ed25519 signature, WRONG authority
    genuine_sig = carrier.sign(message.encode()).hex()
    rec["readback_check_forged"] = read(c_ro, address, "check_bol_attestation", [lc_id, BOL_ID, forged_sig])
    rec["readback_check_genuine"] = read(c_ro, address, "check_bol_attestation", [lc_id, BOL_ID, genuine_sig])
    assert rec["readback_check_forged"] is False and rec["readback_check_genuine"] is True

    before = read(c_ro, address, "get_lc_state", [lc_id])
    forged_out, _ = send(
        c_imp, "verify_bill_of_lading[FORGED]", c_imp.write_contract, steps,
        address=address, function_name="verify_bill_of_lading", args=[lc_id, BOL_ID, forged_sig],
    )
    after = read(c_ro, address, "get_lc_state", [lc_id])
    forged_out["forged_signature"] = forged_sig
    forged_out["state_unchanged"] = before == after
    forged_out["bol_verified_after"] = after["bol_verified"]
    blob = json.dumps(forged_out)
    forged_out["rejected_with_ERR_INVALID_BOL_ATTESTATION"] = "ERR_INVALID_BOL_ATTESTATION" in blob
    rec["forged_bol_rejection"] = {
        k: forged_out.get(k)
        for k in ("tx_hash", "explorer", "execution", "consensus", "lifecycle", "result_text",
                  "state_unchanged", "bol_verified_after", "rejected_with_ERR_INVALID_BOL_ATTESTATION",
                  "forged_signature")
    }

    genuine_out, _ = send(
        c_imp, "verify_bill_of_lading[GENUINE]", c_imp.write_contract, steps,
        address=address, function_name="verify_bill_of_lading", args=[lc_id, BOL_ID, genuine_sig],
    )
    assert genuine_out["execution"] == "FINISHED_WITH_RETURN", genuine_out
    genuine_out["genuine_signature"] = genuine_sig

    # ---- 4. staged settlement over the three pinned CDN feeds ------------------
    for stage, name in ((1, "STAGE_1_DEPARTURE"), (2, "STAGE_2_CUSTOMS_CLEARED")):
        out = None
        for attempt in range(1, 4):  # QUORUM_FAILURE is retryable by design
            out, _ = send(
                c_imp, f"settle_shipment_stage[{name}]", c_imp.write_contract, steps,
                address=address, function_name="settle_shipment_stage", args=[lc_id, stage],
            )
            text = out.get("result_text") or ""
            if '"verdict": 1' in text or '"verdict":1' in text or '"verdict": 0' in text:
                break
            log(f"stage {stage} attempt {attempt}: not settled yet, retrying in 20s")
            time.sleep(20)
        out["stage"] = stage
        out["stage_name"] = name
        rec[f"readback_after_stage{stage}"] = read(c_ro, address, "get_lc_state", [lc_id])

    # ---- 5. authoritative readbacks (settled, before withdrawal) ---------------
    rec["readbacks"] = {
        "get_lc_state": read(c_ro, address, "get_lc_state", [lc_id]),
        "get_protocol_summary": read(c_ro, address, "get_protocol_summary"),
        "get_feed_sources": read(c_ro, address, "get_feed_sources", [lc_id]),
        "verify_solvency_invariant": read(c_ro, address, "verify_solvency_invariant"),
    }

    # ---- 6. pull-pattern withdrawals ---------------------------------------------
    send(c_exp, "claim_funds[exporter]", c_exp.write_contract, steps,
         address=address, function_name="claim_funds", args=[lc_id])
    rebate = rec["readbacks"]["get_lc_state"]["importer_rebate"]
    if rebate > 0:
        send(c_imp, "claim_funds[importer]", c_imp.write_contract, steps,
             address=address, function_name="claim_funds", args=[lc_id])
    time.sleep(8)
    rec["readbacks_after_claims"] = {
        "get_lc_state": read(c_ro, address, "get_lc_state", [lc_id]),
        "get_protocol_summary": read(c_ro, address, "get_protocol_summary"),
        "verify_solvency_invariant": read(c_ro, address, "verify_solvency_invariant"),
    }
    rec["balances_after_wei"] = {
        "importer": balance(c_ro, importer.address),
        "exporter": balance(c_ro, exporter.address),
        "contract": balance(c_ro, address),
    }

    # ---- 7. deployed bytes == repository bytes ------------------------------------
    try:
        res = subprocess.run(["genlayer", "code", address], capture_output=True, text=True, timeout=180).stdout
        body = res.split("Result:\n", 1)[1] if "Result:\n" in res else res
        deployed = body.strip()
        rec["deployed_code_sha256_stripped"] = hashlib.sha256(deployed.encode()).hexdigest()
        rec["deployed_code_matches_source"] = deployed == source.strip()
    except Exception as exc:  # noqa: BLE001
        rec["deployed_code_matches_source"] = f"unverified: {exc}"

    try:
        schema = c_ro.get_contract_schema(address)
        (ROOT / "deployments" / "cargo_clear_abi.json").write_text(json.dumps(jsonable(schema), indent=2, sort_keys=True) + "\n")
    except Exception as exc:  # noqa: BLE001
        log(f"ABI export failed: {exc}")

    Path(ns.out).write_text(json.dumps(jsonable(rec), indent=2) + "\n")
    log(f"wrote {ns.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
