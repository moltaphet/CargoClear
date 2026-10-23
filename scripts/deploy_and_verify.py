"""Autonomous Studio Next deployment + live validation for CargoClear (evidence v2).

    .venv/bin/python scripts/deploy_and_verify.py [--contract 0x...] [--witness-urls A B C]

Everything runs unattended and publishes nothing outside Studio Next:

  1. loads the two project wallets (cargoclear-importer / cargoclear-exporter) and the
     four demo Ed25519 keys (Carrier Authority + three witnesses, all in git-ignored
     .secrets/); funds the wallets from the Studio Next faucet;
  2. proves on-chain that a deployment reusing one key for two roles is refused, then
     deploys contracts/cargo_clear.py with the carrier key and the three witness keys;
  3. proves the open-time guards live: bad IMO check digit, git-mirror endpoint and
     duplicate endpoint hosts all revert;
  4. opens LC-1 and accepts it;
  5. forged Bill of Lading (rejected), genuine Bill of Lading (accepted, IMO signed in);
  6. `check_evidence` readbacks: authentic / tampered / wrong-slot / unregistered key /
     wrong-shipment records, judged by the deployed contract;
  7. settle_shipment_stage against witness endpoints that serve nothing: fail-closed
     QUORUM_FAILURE, no funds move, the call is retryable;
  8. records every tx hash and readback in deployments/studio-next.json plus the ABI in
     deployments/cargo_clear_abi.json.

By default the three endpoints are RESERVED-TLD placeholders (`.example`, RFC 2606: can
never resolve): this repository has no real maritime providers behind it, and nothing
here stands one up. Pass --witness-urls to point the contract at real endpoints whose
operators hold the registered witness keys. Private keys never touch the repository.
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
sys.path.insert(0, str(ROOT / "scripts"))
import cargoclear_witness as witness  # noqa: E402

SECRETS = ROOT / ".secrets"
RPC = "https://studio-next.genlayer.com/api"
EXPLORER = "https://explorer-studio-next.genlayer.com"
CHAIN_ID = 61997

# L/C terms. The shipment: one reefer container on one vessel under one Bill of Lading.
PRINCIPAL = 50_000_000_000_000_003  # 0.05 GEN + 3 wei: not divisible by 5, so dust is exercised live
BOL_ID = "BOL-CC-20261023-0001"
CONTAINER = "MSKU4471290"
VESSEL_IMO = "9074729"  # check-digit-valid demo IMO
CARGO_SPEC = "Frozen Atlantic shrimp, grade A, 18 t, reefer -18.0C"
MAX_TEMP_TENTHS_C = -180
LATEST_ARRIVAL_TS = 1_794_700_800  # 2026-11-15T00:00:00Z

# Scenario timeline for the sample witness records (all in the past of the chain clock).
DEPARTURE_TS = 1_791_532_800  # 2026-10-09T08:00:00Z
ARRIVAL_TS = 1_792_247_400  # 2026-10-17T14:30:00Z
EVENT_TS = 1_792_252_800  # 2026-10-17T16:00:00Z
PEAK_TENTHS_C = -160

# Placeholder endpoints: three distinct, never-resolving hosts (RFC 2606 `.example`).
PLACEHOLDER_URLS = [
    f"https://carrier-witness.unprovisioned.example/v1/evidence/{CONTAINER}",
    f"https://customs-witness.unprovisioned.example/v1/evidence/{CONTAINER}",
    f"https://ais-witness.unprovisioned.example/v1/evidence/{CONTAINER}",
]

NEED_IMPORTER = 150 * 10**15  # principal + fee deposits with headroom
NEED_EXPORTER = 40 * 10**15


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
    # A dropped connection while the SDK estimates gas happens before anything is signed
    # or sent, so retrying the submission is safe.
    tx_hash = retry(lambda: fn(fees=fee_options(client), **kw), attempts=4, wait=8.0)
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


def sample_record(name: str, signer=None, **over) -> dict:
    """A witness-signed record for the L/C's shipment (signed by `signer`, default the witness's own key)."""
    fields = dict(
        bol=BOL_ID, container=CONTAINER, imo=VESSEL_IMO, status="CUSTOMS_CLEARED",
        departure_ts=DEPARTURE_TS, arrival_ts=ARRIVAL_TS, event_ts=EVENT_TS, peak=PEAK_TENTHS_C,
    )
    fields.update(over)
    return witness.evidence(name, signer or witness.load_signer(name), **fields)


def reverted(out: dict, code: str) -> bool:
    return out["execution"] == "FINISHED_WITH_ERROR" and code in json.dumps(out)


# ------------------------------------------------------------------------ main
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--contract", help="reuse an already deployed address instead of deploying")
    ap.add_argument("--witness-urls", nargs=3, metavar=("MANIFEST", "CUSTOMS", "TELEMETRY"), default=None)
    ap.add_argument("--out", default=str(ROOT / "deployments" / "studio-next.json"))
    ns = ap.parse_args()
    urls = ns.witness_urls or PLACEHOLDER_URLS

    importer, exporter = load_account("importer"), load_account("exporter")
    carrier = carrier_key()
    carrier_pub = carrier.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    wit = {n: witness.load_signer(n) for n in ("manifest", "customs", "telemetry")}
    wit_pub = [witness.pubkey_hex(wit[n]) for n in ("manifest", "customs", "telemetry")]
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
        "witness_pubkeys": dict(zip(("manifest", "customs", "telemetry"), wit_pub)),
        "witness_endpoints": urls,
        "witness_endpoints_are_placeholders": ns.witness_urls is None,
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

    source = (ROOT / "contracts" / "cargo_clear.py").read_text()
    rec["source"] = "contracts/cargo_clear.py"
    rec["source_sha256"] = hashlib.sha256(source.encode()).hexdigest()
    rec["runner"] = source.splitlines()[1].split('"Depends": ')[1].strip(' "}')

    # ---- 1. deploy (after proving key reuse is refused) -----------------------
    if ns.contract:
        address = ns.contract
        log(f"reusing contract {address}")
    else:
        dup, _ = send(
            c_imp, "deploy[REFUSED: witness key == carrier key]", c_imp.deploy_contract, steps,
            code=source, args=[carrier_pub, carrier_pub, wit_pub[1], wit_pub[2]],
        )
        dup["refused_with_ERR_INVALID_WITNESS_PUBKEY"] = reverted(dup, "ERR_INVALID_WITNESS_PUBKEY")
        assert dup["refused_with_ERR_INVALID_WITNESS_PUBKEY"], dup
        out, tx = send(c_imp, "deploy", c_imp.deploy_contract, steps, code=source, args=[carrier_pub, *wit_pub])
        assert out["execution"] == "FINISHED_WITH_RETURN", out
        address = tx.get("recipient") or tx.get("to_address")
        out["contract_address"] = address
    rec["contract_address"] = address
    rec["contract_explorer_url"] = f"{EXPLORER}/address/{address}"
    log(f"contract {address}")
    rec["readback_constructor"] = read(c_ro, address, "get_protocol_summary")
    assert rec["readback_constructor"]["witness_pubkeys"] == wit_pub
    assert rec["readback_constructor"]["carrier_authority_pubkey"] == carrier_pub

    # ---- 2. open-time guards, live ------------------------------------------------
    cargo_hash = hashlib.sha256(CARGO_SPEC.encode()).hexdigest()
    exporter_hex = exporter.address.lower()

    def open_args(imo=VESSEL_IMO, endpoints=urls):
        return [exporter_hex, CONTAINER, imo, cargo_hash, MAX_TEMP_TENTHS_C, LATEST_ARRIVAL_TS, *endpoints]

    mirrors = [
        f"https://raw.githubusercontent.com/moltaphet/CargoClear/{'a' * 40}/deployments/x/{CONTAINER}.json",
        urls[1], urls[2],
    ]
    same_host = [urls[0], urls[0].replace("/v1/evidence/", "/v2/evidence/"), urls[2]]
    guards = [
        ("bad IMO check digit", open_args(imo="9074720"), "ERR_INVALID_VESSEL_IMO"),
        ("git-mirror endpoint", open_args(endpoints=mirrors), "ERR_INVALID_FEED_URL"),
        ("one host in two slots", open_args(endpoints=same_host), "ERR_INVALID_FEED_URL"),
    ]
    rec["open_guards"] = []
    for name, args, code in guards:
        out, _ = send(
            c_imp, f"open_letter_of_credit[REFUSED: {name}]", c_imp.write_contract, steps,
            address=address, function_name="open_letter_of_credit", value=PRINCIPAL, args=args,
        )
        ok_ = reverted(out, code)
        rec["open_guards"].append({"case": name, "expected": code, "refused": ok_, "tx_hash": out["tx_hash"]})
        assert ok_, out
    assert read(c_ro, address, "get_protocol_summary")["lc_count"] == 0

    # ---- 3. open + accept ----------------------------------------------------------
    lc_id = "LC-1"
    open_out, _ = send(
        c_imp, "open_letter_of_credit", c_imp.write_contract, steps,
        address=address, function_name="open_letter_of_credit", value=PRINCIPAL, args=open_args(),
    )
    assert open_out["execution"] == "FINISHED_WITH_RETURN", open_out
    rec["lc_id"] = lc_id
    accept_out, _ = send(
        c_exp, "accept_lc_terms", c_exp.write_contract, steps,
        address=address, function_name="accept_lc_terms", args=[lc_id],
    )
    assert accept_out["execution"] == "FINISHED_WITH_RETURN", accept_out
    rec["readback_after_accept"] = read(c_ro, address, "get_lc_state", [lc_id])

    # ---- 4. Ed25519 BoL: forged rejection, then the genuine attestation -------------
    message = read(c_ro, address, "get_bol_message", [lc_id, BOL_ID])
    expected = "|".join(
        [BOL_ID, lc_id, CONTAINER, VESSEL_IMO, exporter_hex, cargo_hash, str(MAX_TEMP_TENTHS_C), str(LATEST_ARRIVAL_TS)]
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
    forged_out["rejected_with_ERR_INVALID_BOL_ATTESTATION"] = reverted(forged_out, "ERR_INVALID_BOL_ATTESTATION")
    rec["forged_bol_rejection"] = {
        k: forged_out.get(k)
        for k in ("tx_hash", "explorer", "execution", "consensus", "lifecycle", "result_text",
                  "state_unchanged", "bol_verified_after", "rejected_with_ERR_INVALID_BOL_ATTESTATION",
                  "forged_signature")
    }
    assert forged_out["state_unchanged"] and forged_out["rejected_with_ERR_INVALID_BOL_ATTESTATION"]

    genuine_out, _ = send(
        c_imp, "verify_bill_of_lading[GENUINE]", c_imp.write_contract, steps,
        address=address, function_name="verify_bill_of_lading", args=[lc_id, BOL_ID, genuine_sig],
    )
    assert genuine_out["execution"] == "FINISHED_WITH_RETURN", genuine_out
    genuine_out["genuine_signature"] = genuine_sig

    # ---- 5. evidence authentication, judged by the deployed contract ----------------
    binding = read(c_ro, address, "get_evidence_binding", [BOL_ID, CONTAINER, VESSEL_IMO])
    assert binding == witness.binding(BOL_ID, CONTAINER, VESSEL_IMO)
    rec["evidence_binding"] = binding
    names = ("manifest", "customs", "telemetry")

    def check(slot, record_dict):
        return read(c_ro, address, "check_evidence", [lc_id, slot, witness.compact(record_dict)])

    checks = []
    for slot, n in enumerate(names):
        authentic = sample_record(n)
        res = check(slot, authentic)
        checks.append({"case": f"authentic record from the {n} witness, slot {slot}", "record": authentic,
                       "expect_authentic": True, "result": res})
        assert res["authentic"] is True, res
    manifest_rec = sample_record("manifest")
    negative = [
        ("tampered after signing (peak 1 tenth colder)", 0, {**manifest_rec, "peak_temp_tenths_c": PEAK_TENTHS_C - 1}),
        ("right record, wrong slot (manifest record offered as customs)", 1, manifest_rec),
        ("valid shape, signed by an unregistered key", 0, sample_record("manifest", signer=impostor)),
        ("carrier authority key signing evidence", 0, sample_record("manifest", signer=carrier)),
        ("another witness's key signing as the manifest witness", 0, sample_record("manifest", signer=wit["customs"])),
        ("registered witness, but a different shipment (other BoL)", 0, sample_record("manifest", bol=BOL_ID + "-X")),
        ("registered witness, but a different vessel IMO", 0, sample_record("manifest", imo="9321483")),
        ("unsigned record", 0, {k: v for k, v in manifest_rec.items() if k != "signature"}),
    ]
    for case, slot, r in negative:
        res = check(slot, r)
        checks.append({"case": case, "record": r, "expect_authentic": False, "result": res})
        assert res["authentic"] is False, (case, res)
    rec["check_evidence"] = checks

    # ---- 6. fail-closed settlement: endpoints that serve no authentic evidence ------
    before = read(c_ro, address, "get_lc_state", [lc_id])
    settle_out, _ = send(
        c_imp, "settle_shipment_stage[STAGE_1, no authentic evidence]", c_imp.write_contract, steps,
        address=address, function_name="settle_shipment_stage", args=[lc_id, 1],
    )
    after = read(c_ro, address, "get_lc_state", [lc_id])
    payload = json.loads(settle_out["result_text"]) if settle_out["execution"] == "FINISHED_WITH_RETURN" else {}
    settle_out["quorum_failure"] = payload.get("verdict") == 2 and payload.get("source_count") == 0
    movable = ("state", "unreleased_escrow", "exporter_claimable", "importer_rebate", "stage1_settled", "stage2_settled")
    settle_out["funds_and_state_unchanged"] = all(before[k] == after[k] for k in movable)
    settle_out["quorum_failures_counter"] = after["quorum_failures"]
    rec["fail_closed_settlement"] = {
        k: settle_out.get(k)
        for k in ("tx_hash", "explorer", "execution", "consensus", "lifecycle", "result_text", "quorum_failure",
                  "funds_and_state_unchanged", "quorum_failures_counter")
    }
    assert settle_out["quorum_failure"] and settle_out["funds_and_state_unchanged"], settle_out
    assert after["quorum_failures"] == before["quorum_failures"] + 1

    # ---- 7. authoritative readbacks -------------------------------------------------
    rec["readbacks"] = {
        "get_lc_state": read(c_ro, address, "get_lc_state", [lc_id]),
        "get_protocol_summary": read(c_ro, address, "get_protocol_summary"),
        "get_evidence_sources": read(c_ro, address, "get_evidence_sources", [lc_id]),
        "verify_solvency_invariant": read(c_ro, address, "verify_solvency_invariant"),
    }
    rec["balances_after_wei"] = {
        "importer": balance(c_ro, importer.address),
        "exporter": balance(c_ro, exporter.address),
        "contract": balance(c_ro, address),
    }

    # ---- 8. deployed bytes == repository bytes ---------------------------------------
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
