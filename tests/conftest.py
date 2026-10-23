"""Shared fixtures for the CargoClear direct-mode suite.

CARGOCLEAR_CONTRACT lets the mutation harness point the whole suite at a
deliberately broken copy of the contract.
"""

import hashlib
import json
import os
import re
import sys

# The contract pins py-genlayer:5jycge... (GenVM executor v0.3.0-rc7). The default
# newest bundle no longer ships that runner, so pin the bundle the contract targets.
os.environ.setdefault("GENVM_VERSION", "v0.6.0-rc7")
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = Path(os.environ.get("CARGOCLEAR_CONTRACT", ROOT / "contracts" / "cargo_clear.py"))
sys.path.insert(0, str(ROOT / "tests"))

ATTO = 10**18
PRINCIPAL = 1_000_000_000_000_000_003  # deliberately not divisible by 5 -> exercises dust
T0 = 1_792_000_000  # 2026-10-14T..Z, the "now" of every test
LATEST = T0 + 7 * 86400
MAX_TEMP = -180
CARGO_HASH = hashlib.sha256(b"frozen shrimp, grade A").hexdigest()
CONTAINER = "MSKU1234567"
BOL = "BOL-CC-0001"
IMO = "9074729"  # 9*7 + 0*6 + 7*5 + 4*4 + 7*3 + 2*2 = 139 -> check digit 9
WITNESS_ROLES = ("CARRIER_MANIFEST_WITNESS", "PORT_CUSTOMS_WITNESS", "COLD_CHAIN_AIS_WITNESS")


def iso(ts: int) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def feed_urls(container: str = CONTAINER):
    """Three witness endpoints on three distinct hosts (names only; the web is mocked)."""
    return (
        f"https://carrier-witness.example.net/v1/evidence/{container}",
        f"https://customs-witness.example.org/api/evidence/{container}",
        f"https://ais-witness.example.com/evidence/{container}",
    )


def binding_of(bol: str = BOL, container: str = CONTAINER, imo: str = IMO) -> str:
    """Independent re-statement of the shipment nonce (does not call the contract)."""
    return hashlib.sha256(f"cargoclear.binding.v2|{bol}|{container}|{imo}".encode()).hexdigest()


def evidence_message(rec: dict) -> str:
    """Independent re-statement of the string a witness signs."""
    return "|".join(
        (
            "cargoclear.evidence.v2",
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


def raw_of(a) -> bytes:
    return bytes(a.as_bytes) if hasattr(a, "as_bytes") else bytes(a)


def hex_of(a) -> str:
    v = getattr(a, "as_hex", None)
    if isinstance(v, str):
        return v.lower()
    return "0x" + bytes(a).hex()


def record(**over) -> dict:
    """An evidence record body WITHOUT role/signature. `ok()` keeps the dict so
    World.mock_feeds can have witness `slot` fill the role and sign it."""
    base = {
        "schema": "cargoclear.evidence.v2",
        "binding": binding_of(),
        "bol_record_id": BOL,
        "container_id": CONTAINER,
        "vessel_imo": IMO,
        "status": "CUSTOMS_CLEARED",
        "departure_ts": T0 - 6 * 86400,
        "arrival_ts": T0 - 86400,
        "peak_temp_tenths_c": -185,
        "event_ts": T0 - 3600,
    }
    base.update(over)
    return base


def ok(rec: dict, signer=None) -> dict:
    """A 200 response carrying `rec`. Unless the record already has a
    `signature`, the witness of whichever slot serves it signs it (or `signer`
    does, to model a validly-shaped record from a key nobody registered)."""
    return {"status": 200, "body": json.dumps(rec), "_rec": rec, "_signer": signer}


NOT_FOUND = {"status": 404, "body": "not found"}
OUTAGE = {"status": 503, "body": "unavailable"}


def revert_message(fn, *args, **kwargs):
    """Message of the UserError `fn` raises, or None when it does not revert."""
    try:
        fn(*args, **kwargs)
    except BaseException as exc:  # noqa: BLE001 - we want every kind of revert
        text = getattr(exc, "message", None) or str(exc)
        if text.startswith("UserError(") and text.endswith(")"):
            inner = text[len("UserError(") : -1]
            if len(inner) >= 2 and inner[0] in "'\"" and inner[-1] == inner[0]:
                inner = inner[1:-1]
            text = inner
        return text
    return None


def assert_reverts(code, fn, *args, **kwargs):
    msg = revert_message(fn, *args, **kwargs)
    assert msg is not None, f"expected {code}, but the call succeeded"
    assert msg.startswith(code), f"expected {code}, got {msg!r}"
    return msg


class Carrier:
    """Test double for an Ed25519 signer (the Carrier Authority, or a witness)."""

    def __init__(self, seed: bytes = b"carrier-authority-seed-000000001"):
        self.sk = Ed25519PrivateKey.from_private_bytes(seed)
        self.pub = self.sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.pub_hex = self.pub.hex()

    def sign(self, message: str) -> str:
        return self.sk.sign(message.encode()).hex()


def _witness_seed(i: int) -> bytes:
    return (b"witness-%d-seed-" % i).ljust(32, b"0")


WITNESSES = tuple(Carrier(_witness_seed(i)) for i in range(3))


def sign_for_slot(rec: dict, slot: int, signer=None) -> dict:
    """`rec` with the slot's role filled (unless set) and signed by the slot's
    witness (or `signer`)."""
    out = dict(rec)
    out.setdefault("role", WITNESS_ROLES[slot])
    who = signer or WITNESSES[slot]
    out["signature"] = who.sign(evidence_message(out))
    return out


@pytest.fixture(scope="session")
def carrier():
    return Carrier()


@pytest.fixture(scope="session")
def witnesses():
    return WITNESSES


@pytest.fixture(scope="session")
def cc():
    """The contract module (pure helpers: ed25519_verify, aggregate, ...)."""
    from gltest.direct.vm import VMContext
    from gltest.direct.loader import create_address, load_contract_class

    vm = VMContext()
    vm.sender = create_address("loader")
    with vm.activate():
        cls = load_contract_class(CONTRACT, vm)
    import types

    return types.SimpleNamespace(**cls.__init__.__globals__)


class World:
    def __init__(self, vm, deploy, carrier):
        from gltest.direct.loader import create_address

        self.vm = vm
        self.carrier = carrier
        self.importer = create_address("importer")
        self.exporter = create_address("exporter")
        self.stranger = create_address("stranger")
        self.now = T0
        self.vm.warp(iso(T0))
        self.vm.sender = self.importer
        self.contract = deploy(str(CONTRACT), carrier.pub_hex, *(w.pub_hex for w in WITNESSES))
        self.warp(T0)
        self.vm.deal(self.importer, 10 * ATTO)
        self.vm.deal(self.exporter, 0)
        self.vm.deal(self.vm._contract_address, 0)
        self.transfers = []
        self.vm._gl_call_hook = self._on_gl_call

    def _on_gl_call(self, vm, request):
        """Applies emit_transfer() to the simulated balances and records it."""
        msg = request.get("EmitInternalMessage") if isinstance(request, dict) else None
        if msg is None:
            return None
        value = int(msg.get("value", 0))
        dest = bytes(msg["address"].as_bytes)
        contract = bytes(vm._contract_address)
        assert vm._balances.get(contract, 0) >= value, "contract paid out more than it holds"
        vm._balances[contract] = vm._balances.get(contract, 0) - value
        vm._balances[dest] = vm._balances.get(dest, 0) + value
        self.transfers.append((dest, value))
        return {"ok": None}

    def balance_of(self, who) -> int:
        return self.vm._balances.get(raw_of(who), 0)

    def contract_balance(self) -> int:
        return self.vm._balances.get(bytes(self.vm._contract_address), 0)

    def warp(self, ts: int) -> None:
        """Move the chain clock. Direct mode only re-injects the transaction
        datetime at load time, so the SDK's message.raw is updated by hand."""
        import genlayer.message as sdk_message

        self.now = ts
        self.vm.warp(iso(ts))
        sdk_message.raw["datetime"] = iso(ts)

    def as_(self, who):
        self.vm.sender = who

    def open(self, principal=PRINCIPAL, **over):
        args = dict(
            exporter=hex_of(self.exporter),
            container_id=CONTAINER,
            vessel_imo=IMO,
            cargo_spec_hash=CARGO_HASH,
            max_temp_tenths_c=MAX_TEMP,
            latest_arrival_ts=LATEST,
            feed_a_url=feed_urls()[0],
            feed_b_url=feed_urls()[1],
            feed_c_url=feed_urls()[2],
        )
        args.update(over)
        self.as_(self.importer)
        self.vm.value = principal
        before = self.contract_balance()
        try:
            lc_id = self.contract.open_letter_of_credit(**args)
        finally:
            self.vm.value = 0
        # the VM credits msg.value to the contract on a successful payable call
        self.vm._balances[bytes(self.vm._contract_address)] = before + principal
        self.vm._balances[raw_of(self.importer)] -= principal
        return lc_id

    def accept(self, lc="LC-1"):
        self.as_(self.exporter)
        return self.contract.accept_lc_terms(lc)

    def bol_message(self, lc="LC-1", bol=BOL):
        return self.contract.get_bol_message(lc, bol)

    def sign_bol(self, lc="LC-1", bol=BOL):
        return self.carrier.sign(self.bol_message(lc, bol))

    def verify_bol(self, lc="LC-1", bol=BOL, who=None):
        self.as_(who or self.importer)
        return self.contract.verify_bill_of_lading(lc, bol, self.sign_bol(lc, bol))

    def ready(self, principal=PRINCIPAL):
        """LC-1 opened, accepted, BoL verified."""
        self.open(principal)
        self.accept()
        self.verify_bol()

    def mock_feeds(self, a=None, b=None, c=None):
        """Mock the three witness endpoints. Responses built with `ok(rec)` are
        signed by the witness serving that slot; anything else is served verbatim."""
        self.vm.clear_mocks()
        for slot, (url, resp) in enumerate(zip(feed_urls(), (a, b, c))):
            if resp is None:
                continue
            resp = dict(resp)
            rec = resp.pop("_rec", None)
            signer = resp.pop("_signer", None)
            if rec is not None:
                if "signature" not in rec:
                    rec = sign_for_slot(rec, slot, signer)
                elif "role" not in rec:
                    rec = dict(rec, role=WITNESS_ROLES[slot])
                resp["body"] = json.dumps(rec)
            self.vm.mock_web(re.escape(url), resp)

    def settle(self, stage, who=None):
        self.as_(who or self.importer)
        return json.loads(self.contract.settle_shipment_stage("LC-1", stage))

    def state(self, lc="LC-1"):
        return self.contract.get_lc_state(lc)


@pytest.fixture
def world(direct_vm, direct_deploy, carrier):
    direct_vm.strict_mocks = False if hasattr(direct_vm, "strict_mocks") else None
    return World(direct_vm, direct_deploy, carrier)
