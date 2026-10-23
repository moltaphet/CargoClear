"""Witness-side reference for CargoClear evidence (`cargoclear.evidence.v2`).

A witness is any party that holds an Ed25519 key registered in the contract's
constructor and attests, with that key, what it observed about ONE shipment. This
module shows exactly what a provider has to sign; it shares no code with the
contract (the contract verifies with its own RFC 8032 implementation).

    python scripts/cargoclear_witness.py pubkeys
    python scripts/cargoclear_witness.py sign --witness customs --bol BOL-... \\
        --container MSKU... --imo 9074729 --status CUSTOMS_CLEARED \\
        --departure-ts 1791532800 --arrival-ts 1792247400 --event-ts 1792252800 --peak -160

Demo seeds live in .secrets/witness_<name>.seed (git-ignored). In a real
deployment the three witnesses are separate organisations, each holding its own
key; only the three PUBLIC keys are handed to the contract.
"""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SECRETS = Path(__file__).resolve().parent.parent / ".secrets"
SCHEMA = "cargoclear.evidence.v2"
# witness name -> (contract slot, role tag signed into every record)
WITNESSES = {
    "manifest": (0, "CARRIER_MANIFEST_WITNESS"),
    "customs": (1, "PORT_CUSTOMS_WITNESS"),
    "telemetry": (2, "COLD_CHAIN_AIS_WITNESS"),
}


def load_signer(name: str) -> Ed25519PrivateKey:
    """The demo seed for `name`, created on first use (0600, git-ignored)."""
    path = SECRETS / f"witness_{name}.seed"
    if not path.exists():
        SECRETS.mkdir(mode=0o700, exist_ok=True)
        path.write_text(os.urandom(32).hex())
        path.chmod(0o600)
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(path.read_text().strip()))


def pubkey_hex(signer: Ed25519PrivateKey) -> str:
    return signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def binding(bol_record_id: str, container_id: str, vessel_imo: str) -> str:
    """The shipment nonce: sha256 over BoL id, container and vessel IMO."""
    return hashlib.sha256(f"cargoclear.binding.v2|{bol_record_id}|{container_id}|{vessel_imo}".encode()).hexdigest()


def message(rec: dict) -> str:
    return "|".join(
        (
            SCHEMA,
            rec["role"],
            rec["binding"],
            rec["bol_record_id"],
            rec["container_id"],
            rec["vessel_imo"],
            rec["status"],
            str(rec["departure_ts"]),
            str(rec["arrival_ts"]),
            str(rec["event_ts"]),
            str(rec["peak_temp_tenths_c"]),
        )
    )


def evidence(
    witness: str,
    signer: Ed25519PrivateKey,
    *,
    bol: str,
    container: str,
    imo: str,
    status: str,
    departure_ts: int,
    arrival_ts: int,
    event_ts: int,
    peak: int,
) -> dict:
    rec = {
        "schema": SCHEMA,
        "role": WITNESSES[witness][1],
        "binding": binding(bol, container, imo),
        "bol_record_id": bol,
        "container_id": container,
        "vessel_imo": imo,
        "status": status,
        "departure_ts": departure_ts,
        "arrival_ts": arrival_ts,
        "event_ts": event_ts,
        "peak_temp_tenths_c": peak,
    }
    rec["signature"] = signer.sign(message(rec).encode()).hex()
    return rec


def compact(rec: dict) -> str:
    return json.dumps(rec, sort_keys=True, separators=(",", ":"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("pubkeys", help="print the three demo witness public keys")
    sg = sub.add_parser("sign", help="print one signed evidence record")
    sg.add_argument("--witness", choices=sorted(WITNESSES), required=True)
    sg.add_argument("--bol", required=True)
    sg.add_argument("--container", required=True)
    sg.add_argument("--imo", required=True)
    sg.add_argument("--status", required=True)
    sg.add_argument("--departure-ts", type=int, required=True)
    sg.add_argument("--arrival-ts", type=int, required=True)
    sg.add_argument("--event-ts", type=int, required=True)
    sg.add_argument("--peak", type=int, required=True, help="peak reefer temperature, integer tenths of a degC")
    ns = ap.parse_args()
    if ns.cmd == "pubkeys":
        for name in sorted(WITNESSES, key=lambda n: WITNESSES[n][0]):
            print(f"{WITNESSES[name][0]} {name:10s} {pubkey_hex(load_signer(name))}")
        return 0
    rec = evidence(
        ns.witness, load_signer(ns.witness), bol=ns.bol, container=ns.container, imo=ns.imo, status=ns.status,
        departure_ts=ns.departure_ts, arrival_ts=ns.arrival_ts, event_ts=ns.event_ts, peak=ns.peak,
    )
    print(compact(rec))
    return 0


if __name__ == "__main__":
    sys.exit(main())
