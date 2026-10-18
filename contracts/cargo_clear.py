# v0.3.0
# { "Depends": "py-genlayer:5jycge4q8k23462jtb0b9fyey1s9qz928sz2nbrd9mg4sxqg2qng" }

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone

import genlayer as gl
from genlayer import Address, i256, u256
from genlayer.storage import TreeMap

# genvm-lint matches the bare decorator name `allow_storage`; bind it to the
# very same decorator object the runner exposes as gl.storage.allow.
allow_storage = gl.storage.allow

# --- Deterministic business errors -------------------------------------------
ERR_UNAUTHORIZED = "ERR_UNAUTHORIZED_PARTY"
ERR_STATE = "ERR_INVALID_STATE"
ERR_PARAMS = "ERR_INVALID_PARAMS"
ERR_UNKNOWN_LC = "ERR_UNKNOWN_LC"
ERR_INVALID_BOL = "ERR_INVALID_BOL_ATTESTATION"
ERR_BOL_NOT_VERIFIED = "ERR_BOL_NOT_VERIFIED"
ERR_BOL_REPLAY = "ERR_BOL_REPLAY"
ERR_BAD_FEED_URL = "ERR_INVALID_FEED_URL"
ERR_NO_FUNDS = "ERR_NO_CLAIMABLE_BALANCE"
ERR_EXPIRED = "ERR_ACCEPTANCE_WINDOW_CLOSED"
ERR_NOT_YET = "ERR_NOT_YET_AVAILABLE"
ERR_STAGE = "ERR_INVALID_STAGE"
ERR_TRANSFER = "ERR_TRANSFER_FAILED_RESTORED"
ERR_FUNDS = "ERR_PRINCIPAL_REQUIRED"
ERR_PUBKEY = "ERR_INVALID_CARRIER_PUBKEY"

# --- Settlement constants (integer basis points) -----------------------------
BPS = 10000
STAGE_1_DEPARTURE = 1
STAGE_2_CUSTOMS_CLEARED = 2
STAGE_1_BPS = 2000
STAGE_2_BPS = 8000

BUCKET_0_CLEAN_DELIVERY = 0
BUCKET_1_LATE_DEMURRAGE = 1
BUCKET_2_MINOR_THERMAL_DRIFT = 2
BUCKET_3_SPOILED_OR_REJECTED = 3
# (exporter_bps, importer_bps) of the WHOLE letter of credit, per bucket.
BUCKET_TABLE = ((8000, 0), (6000, 2000), (4000, 4000), (0, 8000))

THERMAL_TOLERANCE_TENTHS = 30  # 3.0 degC above the contractual maximum
GRACE_SECONDS = 7 * 24 * 3600  # late-arrival demurrage window
ACCEPTANCE_WINDOW = 48 * 3600  # exporter handshake
SETTLEMENT_WINDOW = 30 * 24 * 3600  # after latest_arrival + grace, importer may reclaim
FUTURE_SKEW = 3600  # feed timestamps beyond now + this are rejected
MIN_PRINCIPAL = 1000  # wei
MIN_TEMP_TENTHS = -700
MAX_TEMP_TENTHS = 500
MAX_FEED_BODY = 16384
MAX_ABS_INT = 2**63

# --- Verdicts ----------------------------------------------------------------
VERDICT_REJECTION = 0
VERDICT_VERIFIED = 1
VERDICT_QUORUM_FAILURE = 2

# --- Per-source outcomes -----------------------------------------------------
SRC_POSITIVE = "POS"  # valid record that supports the requested stage
SRC_REJECT = "REJ"  # explicit CUSTOMS_REJECTED / VOYAGE_ABORTED attestation
SRC_LAG = "LAG"  # 404, or the record has not reached the requested stage yet
SRC_OUTAGE = "OUT"  # 5xx, timeout, malformed, mismatched or future-dated

# --- L/C lifecycle -----------------------------------------------------------
ST_PENDING = "PENDING_EXPORTER_ACCEPTANCE"
ST_ACTIVE = "ACTIVE"
ST_STAGE_1 = "STAGE_1_SETTLED"
ST_COMPLETED = "COMPLETED"
ST_REJECTED = "REJECTED_BY_EXPORTER"
ST_CANCELLED = "CANCELLED"
ST_EXPIRED = "EXPIRED_REFUNDED"
ST_ABORTED = "ABORTED_REFUNDED"
OPEN_STATES = (ST_PENDING, ST_ACTIVE, ST_STAGE_1)

# --- Feed statuses -----------------------------------------------------------
FS_DEPARTED = "VESSEL_DEPARTED"
FS_CLEARED = "CUSTOMS_CLEARED"
FS_CUSTOMS_REJECTED = "CUSTOMS_REJECTED"
FS_ABORTED = "VOYAGE_ABORTED"
FEED_STATUSES = (FS_DEPARTED, FS_CLEARED, FS_CUSTOMS_REJECTED, FS_ABORTED)
FEED_SCHEMA = "cargoclear.feed.v1"
FEED_KEYS = (
    "arrival_ts",
    "bol_record_id",
    "container_id",
    "departure_ts",
    "event_ts",
    "lc_id",
    "manifest_hash",
    "peak_temp_tenths_c",
    "schema",
    "status",
)

# --- Pinned feed operators ----------------------------------------------------
REPO_OWNER = "moltaphet"
REPO_NAME = "CargoClear"
FEED_HOSTS = ("raw.githubusercontent.com", "cdn.jsdelivr.net", "raw.githack.com")
FEED_ROLES = ("CARRIER_MANIFEST_FEED", "PORT_CUSTOMS_FEED", "COLD_CHAIN_AIS_MIRROR")
FEED_DIRS = ("a", "b", "c")

_HEX = "0123456789abcdef"
_ID_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"
_FILE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"


# =============================================================================
# Ed25519 (RFC 8032, pure integer arithmetic -- no floats, no external crypto)
# =============================================================================
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555
_SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752
_BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960
_BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_BASE = (_BX, _BY, 1, _BX * _BY % _P)
_IDENTITY = (0, 1, 1, 0)


def _pt_add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _pt_neg(p):
    return ((-p[0]) % _P, p[1], p[2], (-p[3]) % _P)


def _pt_mul(s, p):
    q = _IDENTITY
    while s > 0:
        if s & 1:
            q = _pt_add(q, p)
        p = _pt_add(p, p)
        s >>= 1
    return q


def _pt_double_mul(s1, p1, s2, p2):
    """Shamir's trick: s1*p1 + s2*p2 in a single pass."""
    both = _pt_add(p1, p2)
    q = _IDENTITY
    for i in range(max(s1.bit_length(), s2.bit_length()) - 1, -1, -1):
        q = _pt_add(q, q)
        b1 = (s1 >> i) & 1
        b2 = (s2 >> i) & 1
        if b1 and b2:
            q = _pt_add(q, both)
        elif b1:
            q = _pt_add(q, p1)
        elif b2:
            q = _pt_add(q, p2)
    return q


def _pt_compress(p) -> bytes:
    zinv = pow(p[2], _P - 2, _P)
    x = p[0] * zinv % _P
    y = p[1] * zinv % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _pt_decompress(raw: bytes):
    """Strict decode: canonical y only, on-curve only. None when invalid."""
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if x == 0 and sign == 1:
        return None
    if (x & 1) != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


def _is_small_order(p) -> bool:
    q = _pt_mul(8, p)
    return q[0] % _P == 0


def _unhex(text: str, nbytes: int):
    """Strict lowercase-hex -> bytes of exact length, else None."""
    if not isinstance(text, str) or len(text) != 2 * nbytes:
        return None
    for ch in text:
        if ch not in _HEX:
            return None
    return bytes.fromhex(text)


def ed25519_verify(pubkey: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032 Ed25519 verification (cofactorless, canonical encodings only)."""
    if len(pubkey) != 32 or len(signature) != 64:
        return False
    a_pt = _pt_decompress(pubkey)
    if a_pt is None:
        return False
    r_raw = signature[:32]
    if _pt_decompress(r_raw) is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(r_raw + pubkey + message).digest(), "little") % _L
    # [S]B - [k]A must equal R
    lhs = _pt_double_mul(s, _BASE, k, _pt_neg(a_pt))
    return _pt_compress(lhs) == r_raw


# =============================================================================
# Pure helpers
# =============================================================================
def _err(code: str, detail: str = "") -> "gl.vm.UserError":
    return gl.vm.UserError(code if detail == "" else f"{code} {detail}")


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _valid_id(text, limit: int = 64) -> bool:
    if not isinstance(text, str) or len(text) == 0 or len(text) > limit:
        return False
    for ch in text:
        if ch not in _ID_CHARS:
            return False
    return True


def _hex_of(addr) -> str:
    return addr.as_hex.lower()


def _now_ts() -> int:
    raw = gl.message.raw["datetime"]
    dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def canonical_bol_message(
    bol_record_id: str,
    lc_id: str,
    container_id: str,
    exporter_address: str,
    cargo_spec_hash: str,
    max_temp_tenths_c: int,
    latest_arrival_ts: int,
) -> str:
    return "|".join(
        (
            bol_record_id,
            lc_id,
            container_id,
            exporter_address,
            cargo_spec_hash,
            str(max_temp_tenths_c),
            str(latest_arrival_ts),
        )
    )


def classify_bucket(max_temp: int, peak_temp: int, arrival_ts: int, latest_arrival_ts: int) -> int:
    """Settlement bucket for a CLEARED container. Customs rejection is handled
    separately (it is always BUCKET_3). Integer-only; boundaries are inclusive
    on the favourable side."""
    if peak_temp > max_temp + THERMAL_TOLERANCE_TENTHS:
        return BUCKET_3_SPOILED_OR_REJECTED
    if arrival_ts > latest_arrival_ts + GRACE_SECONDS:
        return BUCKET_3_SPOILED_OR_REJECTED
    bucket = BUCKET_0_CLEAN_DELIVERY
    if arrival_ts > latest_arrival_ts:
        bucket = BUCKET_1_LATE_DEMURRAGE
    if peak_temp > max_temp:
        bucket = BUCKET_2_MINOR_THERMAL_DRIFT
    return bucket


def stage1_amount(principal: int) -> int:
    return principal * STAGE_1_BPS // BPS


def stage2_split(principal: int, bucket: int):
    """(exporter_wei, importer_wei) of Stage 2. The whole Stage 2 pool
    (principal - stage1) is distributed: the rounding dust goes to the exporter
    on BUCKET_0 and to the importer on every haircut bucket."""
    pool = principal - stage1_amount(principal)
    exp_bps, imp_bps = BUCKET_TABLE[bucket]
    exporter = principal * exp_bps // BPS
    importer = principal * imp_bps // BPS
    dust = pool - exporter - importer
    if bucket == BUCKET_0_CLEAN_DELIVERY:
        exporter += dust
    else:
        importer += dust
    return exporter, importer


def _reject_float(_literal):
    raise ValueError("float literal rejected")


def _reject_pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key")
        out[k] = v
    return out


def parse_feed_json(text: str):
    """Strict feed JSON: objects only, no duplicate keys, and NO floats of any
    spelling (1.0, 1e2, -0.0, NaN, Infinity). Returns the dict or None."""
    try:
        data = json.loads(
            text,
            parse_float=_reject_float,
            parse_constant=_reject_float,
            object_pairs_hook=_reject_pairs,
        )
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return data


def _record_ok(rec) -> bool:
    """Exact key set + exact types + sane ranges."""
    if tuple(sorted(rec.keys())) != FEED_KEYS:
        return False
    if rec["schema"] != FEED_SCHEMA:
        return False
    if not _valid_id(rec["bol_record_id"]) or not _valid_id(rec["lc_id"]):
        return False
    if not _valid_id(rec["container_id"]):
        return False
    if rec["status"] not in FEED_STATUSES:
        return False
    if _unhex(rec["manifest_hash"], 32) is None:
        return False
    for key in ("departure_ts", "arrival_ts", "event_ts", "peak_temp_tenths_c"):
        v = rec[key]
        if not _is_int(v) or v < -MAX_ABS_INT or v > MAX_ABS_INT:
            return False
    for key in ("departure_ts", "arrival_ts", "event_ts"):
        if rec[key] < 0:
            return False
    return True


def evaluate_record(rec, terms: dict, stage: int, now: int) -> dict:
    """Judge ONE parsed feed record against the L/C terms for the requested
    stage. Never raises. Returns {kind, stage, bucket, manifest_hash, event_ts}."""
    bad = {"kind": SRC_OUTAGE, "stage": stage, "bucket": 0, "manifest_hash": "", "event_ts": 0}
    if rec is None or not _record_ok(rec):
        return bad
    if (
        rec["bol_record_id"] != terms["bol_record_id"]
        or rec["lc_id"] != terms["lc_id"]
        or rec["container_id"] != terms["container_id"]
    ):
        return bad
    horizon = now + FUTURE_SKEW
    if rec["event_ts"] > horizon or rec["departure_ts"] > horizon or rec["arrival_ts"] > horizon:
        return bad
    out = {
        "kind": SRC_OUTAGE,
        "stage": stage,
        "bucket": 0,
        "manifest_hash": rec["manifest_hash"],
        "event_ts": rec["event_ts"],
    }
    status = rec["status"]
    if status == FS_ABORTED:
        out["kind"] = SRC_REJECT
        out["bucket"] = BUCKET_3_SPOILED_OR_REJECTED
        return out
    latest = terms["latest_arrival_ts"]
    if stage == STAGE_1_DEPARTURE:
        if status == FS_DEPARTED or status == FS_CLEARED or status == FS_CUSTOMS_REJECTED:
            if rec["departure_ts"] > 0 and rec["departure_ts"] <= latest:
                out["kind"] = SRC_POSITIVE
                return out
        return bad
    # Stage 2
    if status == FS_DEPARTED:
        out["kind"] = SRC_LAG
        return out
    if status == FS_CUSTOMS_REJECTED:
        out["kind"] = SRC_REJECT
        out["bucket"] = BUCKET_3_SPOILED_OR_REJECTED
        return out
    if status == FS_CLEARED:
        if rec["arrival_ts"] <= 0 or rec["departure_ts"] <= 0:
            return bad
        if rec["arrival_ts"] < rec["departure_ts"]:
            return bad
        out["kind"] = SRC_POSITIVE
        out["bucket"] = classify_bucket(
            terms["max_temp_tenths_c"], rec["peak_temp_tenths_c"], rec["arrival_ts"], latest
        )
        return out
    return bad


def aggregate(outcomes, stage: int) -> dict:
    """The fault-tolerant 5-step quorum.

    1. Each source is already reduced to POS / REJ / LAG / OUT (404, lag and
       outages never vote).
    2. Group the explicit rejections by manifest_hash.
    3. >= 2 matching rejections            -> verdict 0 (CONFIRMED_CARGO_REJECTION).
    4. Group the positives by (stage, bucket, manifest_hash).
    5. >= 2 matching positives             -> verdict 1 (VERIFIED_SETTLEMENT);
       anything else (incl. 1 CONFIRMED + 2x404, 1 CONFIRMED + 404 + OUTAGE,
       fewer than 2 responders, or no two sources agreeing) -> verdict 2
       (QUORUM_FAILURE: retryable, mutates nothing).
    """
    groups_rej = {}
    groups_pos = {}
    responders = 0
    for o in outcomes:
        if o["kind"] == SRC_REJECT:
            responders += 1
            groups_rej.setdefault(o["manifest_hash"], []).append(o)
        elif o["kind"] == SRC_POSITIVE:
            responders += 1
            key = (o["stage"], o["bucket"], o["manifest_hash"])
            groups_pos.setdefault(key, []).append(o)
    for mhash in sorted(groups_rej.keys()):
        grp = groups_rej[mhash]
        if len(grp) >= 2:
            return {
                "verdict": VERDICT_REJECTION,
                "stage": stage,
                "bucket": BUCKET_3_SPOILED_OR_REJECTED,
                "source_count": len(grp),
                "manifest_hash": mhash,
                "event_ts": max(g["event_ts"] for g in grp),
            }
    for key in sorted(groups_pos.keys()):
        grp = groups_pos[key]
        if len(grp) >= 2:
            return {
                "verdict": VERDICT_VERIFIED,
                "stage": key[0],
                "bucket": key[1],
                "source_count": len(grp),
                "manifest_hash": key[2],
                "event_ts": max(g["event_ts"] for g in grp),
            }
    return {
        "verdict": VERDICT_QUORUM_FAILURE,
        "stage": stage,
        "bucket": 0,
        "source_count": responders,
        "manifest_hash": "",
        "event_ts": 0,
    }


PAYLOAD_KEYS = ("bucket", "event_ts", "manifest_hash", "source_count", "stage", "verdict")


def payload_well_formed(p) -> bool:
    """Exact key set and exact types of the 6-field consensus payload."""
    if not isinstance(p, dict) or tuple(sorted(p.keys())) != PAYLOAD_KEYS:
        return False
    for key in ("verdict", "stage", "bucket", "source_count", "event_ts"):
        if not _is_int(p[key]):
            return False
    if not isinstance(p["manifest_hash"], str):
        return False
    if p["verdict"] not in (0, 1, 2) or p["stage"] not in (1, 2):
        return False
    if p["bucket"] < 0 or p["bucket"] > 3 or p["source_count"] < 0 or p["source_count"] > 3:
        return False
    if p["verdict"] == VERDICT_QUORUM_FAILURE:
        return p["manifest_hash"] == "" and p["event_ts"] == 0 and p["bucket"] == 0
    return _unhex(p["manifest_hash"], 32) is not None and p["source_count"] >= 2


def run_validator(leader_payload, own_payload) -> bool:
    """Validator rule: the leader's payload must be well-formed AND equal to
    what this validator independently derived, field for field."""
    if not payload_well_formed(leader_payload) or not payload_well_formed(own_payload):
        return False
    for key in PAYLOAD_KEYS:
        if leader_payload[key] != own_payload[key]:
            return False
    return True


def fetch_source(url: str) -> tuple:
    """(kind, record_or_None). 404 -> LAG; every other failure -> OUT."""
    try:
        res = gl.nondet.web.get(url)
    except Exception:
        return (SRC_OUTAGE, None)
    status = res.status
    if status == 404:
        return (SRC_LAG, None)
    if not _is_int(status) or status < 200 or status >= 300:
        return (SRC_OUTAGE, None)
    body = res.body
    if body is None or len(body) == 0 or len(body) > MAX_FEED_BODY:
        return (SRC_OUTAGE, None)
    try:
        text = bytes(body).decode("utf-8")
    except Exception:
        return (SRC_OUTAGE, None)
    return (SRC_POSITIVE, parse_feed_json(text))


def collect_and_aggregate(urls: list, terms: dict, stage: int, now: int) -> dict:
    outcomes = []
    for url in urls:
        kind, rec = fetch_source(url)
        if kind == SRC_LAG:
            outcomes.append(
                {"kind": SRC_LAG, "stage": stage, "bucket": 0, "manifest_hash": "", "event_ts": 0}
            )
        elif kind == SRC_OUTAGE:
            outcomes.append(
                {"kind": SRC_OUTAGE, "stage": stage, "bucket": 0, "manifest_hash": "", "event_ts": 0}
            )
        else:
            outcomes.append(evaluate_record(rec, terms, stage, now))
    return aggregate(outcomes, stage)


def validate_feed_url(index: int, url: str):
    """Strictly pinned feed URL for operator `index`. Returns the 40-hex commit
    SHA or raises ERR_INVALID_FEED_URL."""
    if not isinstance(url, str) or len(url) > 300:
        raise _err(ERR_BAD_FEED_URL, "type or length")
    host = FEED_HOSTS[index]
    folder = FEED_DIRS[index]
    prefix = "https://" + host
    if not url.startswith(prefix + "/"):
        raise _err(ERR_BAD_FEED_URL, "host must be " + host)
    path = url[len(prefix) :]
    if "?" in path or "#" in path or "%" in path or "\\" in path or ".." in path or "//" in path:
        raise _err(ERR_BAD_FEED_URL, "illegal characters")
    tail = "/deployments/mock_feeds/" + folder + "/"
    if index == 1:
        head = "/gh/" + REPO_OWNER + "/" + REPO_NAME + "@"
    else:
        head = "/" + REPO_OWNER + "/" + REPO_NAME + "/"
    if not path.startswith(head):
        raise _err(ERR_BAD_FEED_URL, "repository must be " + REPO_OWNER + "/" + REPO_NAME)
    rest = path[len(head) :]
    sha = rest[:40]
    if _unhex(sha, 20) is None:
        raise _err(ERR_BAD_FEED_URL, "commit sha must be 40 lowercase hex")
    rest = rest[40:]
    if not rest.startswith(tail):
        raise _err(ERR_BAD_FEED_URL, "path must be under " + tail)
    name = rest[len(tail) :]
    if len(name) < 6 or len(name) > 64 or not name.endswith(".json"):
        raise _err(ERR_BAD_FEED_URL, "file must be <name>.json")
    for ch in name:
        if ch not in _FILE_CHARS:
            raise _err(ERR_BAD_FEED_URL, "file name charset")
    return sha


# =============================================================================
# Storage
# =============================================================================
@allow_storage
@dataclass
class LetterOfCredit:
    lc_id: str
    importer: Address
    exporter: Address
    container_id: str
    cargo_spec_hash: str
    max_temp_tenths_c: i256
    latest_arrival_ts: u256
    feed_a_url: str
    feed_b_url: str
    feed_c_url: str
    commit_sha: str
    state: str
    created_at: u256
    accept_deadline: u256
    total_deposited: u256
    unreleased: u256
    exporter_credited: u256
    importer_credited: u256
    exporter_withdrawn: u256
    importer_withdrawn: u256
    bol_record_id: str
    bol_verified: bool
    stage1_settled: bool
    stage2_settled: bool
    final_bucket: u256
    stage1_manifest_hash: str
    stage2_manifest_hash: str
    stage1_sources: u256
    stage2_sources: u256
    stage1_event_ts: u256
    stage2_event_ts: u256
    quorum_failures: u256


class CargoClear(gl.contract.Contract):
    carrier_authority_pubkey: str
    deployer: Address
    lcs: TreeMap[str, LetterOfCredit]
    lc_count: u256
    bol_registry: TreeMap[str, str]
    total_deposited: u256
    total_withdrawn: u256

    def __init__(self, carrier_authority_pubkey: str):
        raw = _unhex(carrier_authority_pubkey, 32)
        if raw is None:
            raise _err(ERR_PUBKEY, "32-byte lowercase hex required")
        pt = _pt_decompress(raw)
        if pt is None or _is_small_order(pt):
            raise _err(ERR_PUBKEY, "not a usable Ed25519 point")
        self.carrier_authority_pubkey = carrier_authority_pubkey
        self.deployer = gl.message.sender_address
        self.lc_count = 0
        self.total_deposited = 0
        self.total_withdrawn = 0

    # ------------------------------------------------------------------ utils
    def _lc(self, lc_id: str) -> LetterOfCredit:
        if not isinstance(lc_id, str) or lc_id not in self.lcs:
            raise _err(ERR_UNKNOWN_LC, str(lc_id)[:40])
        return self.lcs[lc_id]

    def _bol_message(self, lc: LetterOfCredit, bol_record_id: str) -> str:
        return canonical_bol_message(
            bol_record_id,
            lc.lc_id,
            lc.container_id,
            _hex_of(lc.exporter),
            lc.cargo_spec_hash,
            int(lc.max_temp_tenths_c),
            int(lc.latest_arrival_ts),
        )

    def _check_bol(self, lc: LetterOfCredit, bol_record_id: str, signature_hex: str) -> bool:
        sig = _unhex(signature_hex, 64)
        if sig is None:
            return False
        pub = bytes.fromhex(self.carrier_authority_pubkey)
        msg = self._bol_message(lc, bol_record_id).encode("utf-8")
        return ed25519_verify(pub, msg, sig)

    def _credit_importer_all(self, lc: LetterOfCredit) -> None:
        amount = int(lc.unreleased)
        lc.importer_credited = int(lc.importer_credited) + amount
        lc.unreleased = 0

    # ------------------------------------------------------------------ views
    @gl.public.view
    def get_lc_state(self, lc_id: str) -> dict:
        lc = self._lc(lc_id)
        return {
            "lc_id": lc.lc_id,
            "state": lc.state,
            "importer": _hex_of(lc.importer),
            "exporter": _hex_of(lc.exporter),
            "container_id": lc.container_id,
            "cargo_spec_hash": lc.cargo_spec_hash,
            "max_temp_tenths_c": int(lc.max_temp_tenths_c),
            "latest_arrival_ts": int(lc.latest_arrival_ts),
            "created_at": int(lc.created_at),
            "accept_deadline": int(lc.accept_deadline),
            "commit_sha": lc.commit_sha,
            "total_deposited": int(lc.total_deposited),
            "unreleased_escrow": int(lc.unreleased),
            "exporter_claimable": int(lc.exporter_credited) - int(lc.exporter_withdrawn),
            "importer_rebate": int(lc.importer_credited) - int(lc.importer_withdrawn),
            "exporter_withdrawn": int(lc.exporter_withdrawn),
            "importer_withdrawn": int(lc.importer_withdrawn),
            "bol_record_id": lc.bol_record_id,
            "bol_verified": lc.bol_verified,
            "stage1_settled": lc.stage1_settled,
            "stage2_settled": lc.stage2_settled,
            "final_bucket": int(lc.final_bucket) if lc.stage2_settled else -1,
            "stage1_manifest_hash": lc.stage1_manifest_hash,
            "stage2_manifest_hash": lc.stage2_manifest_hash,
            "stage1_sources": int(lc.stage1_sources),
            "stage2_sources": int(lc.stage2_sources),
            "stage1_event_ts": int(lc.stage1_event_ts),
            "stage2_event_ts": int(lc.stage2_event_ts),
            "quorum_failures": int(lc.quorum_failures),
        }

    @gl.public.view
    def get_feed_sources(self, lc_id: str) -> dict:
        lc = self._lc(lc_id)
        urls = (lc.feed_a_url, lc.feed_b_url, lc.feed_c_url)
        return {
            "lc_id": lc.lc_id,
            "commit_sha": lc.commit_sha,
            "repository": "https://github.com/" + REPO_OWNER + "/" + REPO_NAME,
            "sources": [
                {"role": FEED_ROLES[i], "host": FEED_HOSTS[i], "url": urls[i]} for i in range(3)
            ],
        }

    @gl.public.view
    def get_protocol_summary(self) -> dict:
        counts = {}
        unreleased = 0
        for i in range(int(self.lc_count)):
            lc = self.lcs["LC-" + str(i + 1)]
            counts[lc.state] = counts.get(lc.state, 0) + 1
            unreleased += int(lc.unreleased)
        return {
            "protocol": "CargoClear",
            "carrier_authority_pubkey": self.carrier_authority_pubkey,
            "deployer": _hex_of(self.deployer),
            "lc_count": int(self.lc_count),
            "lc_state_counts": counts,
            "total_deposited": int(self.total_deposited),
            "total_withdrawn": int(self.total_withdrawn),
            "unreleased_escrow": unreleased,
            "contract_balance": int(self.balance),
            "stage_1_bps": STAGE_1_BPS,
            "stage_2_bps": STAGE_2_BPS,
            "bucket_table_bps": [list(row) for row in BUCKET_TABLE],
            "thermal_tolerance_tenths_c": THERMAL_TOLERANCE_TENTHS,
            "grace_seconds": GRACE_SECONDS,
            "acceptance_window_seconds": ACCEPTANCE_WINDOW,
            "feed_hosts": list(FEED_HOSTS),
        }

    @gl.public.view
    def verify_solvency_invariant(self) -> dict:
        """Recomputes every L/C from scratch and proves conservation of value:
        exporter_claimable + importer_rebate + unreleased + withdrawn == deposited
        for each L/C and for the protocol, and that the contract's balance covers
        everything still owed."""
        sum_dep = 0
        sum_unrel = 0
        sum_exp = 0
        sum_imp = 0
        sum_wd = 0
        per_lc_ok = True
        for i in range(int(self.lc_count)):
            lc = self.lcs["LC-" + str(i + 1)]
            exp_c = int(lc.exporter_credited) - int(lc.exporter_withdrawn)
            imp_c = int(lc.importer_credited) - int(lc.importer_withdrawn)
            wd = int(lc.exporter_withdrawn) + int(lc.importer_withdrawn)
            if exp_c < 0 or imp_c < 0:
                per_lc_ok = False
            if exp_c + imp_c + int(lc.unreleased) + wd != int(lc.total_deposited):
                per_lc_ok = False
            sum_dep += int(lc.total_deposited)
            sum_unrel += int(lc.unreleased)
            sum_exp += exp_c
            sum_imp += imp_c
            sum_wd += wd
        owed = sum_unrel + sum_exp + sum_imp
        balance = int(self.balance)
        ok = (
            per_lc_ok
            and sum_exp + sum_imp + sum_unrel + sum_wd == sum_dep
            and sum_dep == int(self.total_deposited)
            and sum_wd == int(self.total_withdrawn)
            and balance >= owed
        )
        return {
            "solvent": ok,
            "per_lc_conserved": per_lc_ok,
            "total_deposited": sum_dep,
            "unreleased_escrow": sum_unrel,
            "exporter_claimable": sum_exp,
            "importer_rebate": sum_imp,
            "total_withdrawn": sum_wd,
            "owed": owed,
            "contract_balance": balance,
            "lc_count": int(self.lc_count),
        }

    @gl.public.view
    def get_bol_message(self, lc_id: str, bol_record_id: str) -> str:
        """The exact canonical string the Carrier Authority must sign."""
        lc = self._lc(lc_id)
        if not _valid_id(bol_record_id):
            raise _err(ERR_PARAMS, "bol_record_id")
        return self._bol_message(lc, bol_record_id)

    @gl.public.view
    def check_bol_attestation(self, lc_id: str, bol_record_id: str, attestation_signature: str) -> bool:
        lc = self._lc(lc_id)
        if not _valid_id(bol_record_id):
            return False
        return self._check_bol(lc, bol_record_id, attestation_signature)

    @gl.public.view
    def preview_settlement(self, principal: int, bucket: int) -> dict:
        if not _is_int(principal) or principal < 0 or not _is_int(bucket) or bucket < 0 or bucket > 3:
            raise _err(ERR_PARAMS, "principal/bucket")
        s1 = stage1_amount(principal)
        exporter, importer = stage2_split(principal, bucket)
        return {
            "principal": principal,
            "bucket": bucket,
            "stage1_exporter": s1,
            "stage2_exporter": exporter,
            "stage2_importer": importer,
            "exporter_total": s1 + exporter,
            "importer_total": importer,
            "conserved": s1 + exporter + importer == principal,
        }

    @gl.public.view
    def preview_bucket(self, max_temp: int, peak_temp: int, arrival_ts: int, latest_arrival_ts: int) -> int:
        return classify_bucket(max_temp, peak_temp, arrival_ts, latest_arrival_ts)

    # ------------------------------------------------------------ L/C opening
    @gl.public.write.payable
    def open_letter_of_credit(
        self,
        exporter: str,
        container_id: str,
        cargo_spec_hash: str,
        max_temp_tenths_c: int,
        latest_arrival_ts: int,
        feed_a_url: str,
        feed_b_url: str,
        feed_c_url: str,
    ) -> str:
        principal = int(gl.message.value)
        if principal < MIN_PRINCIPAL:
            raise _err(ERR_FUNDS, "attach the L/C principal")
        if not isinstance(exporter, str) or _unhex(exporter[2:], 20) is None or not exporter.startswith("0x"):
            raise _err(ERR_PARAMS, "exporter must be 0x + 40 lowercase hex")
        exporter_addr = Address(exporter)
        importer_addr = gl.message.sender_address
        if exporter_addr == importer_addr:
            raise _err(ERR_PARAMS, "importer and exporter must differ")
        if not _valid_id(container_id):
            raise _err(ERR_PARAMS, "container_id")
        if _unhex(cargo_spec_hash, 32) is None:
            raise _err(ERR_PARAMS, "cargo_spec_hash must be sha256 hex")
        if not _is_int(max_temp_tenths_c) or max_temp_tenths_c < MIN_TEMP_TENTHS or max_temp_tenths_c > MAX_TEMP_TENTHS:
            raise _err(ERR_PARAMS, "max_temp_tenths_c out of range")
        now = _now_ts()
        if not _is_int(latest_arrival_ts) or latest_arrival_ts <= now or latest_arrival_ts > now + 3 * 365 * 24 * 3600:
            raise _err(ERR_PARAMS, "latest_arrival_ts must be in the future")
        sha_a = validate_feed_url(0, feed_a_url)
        sha_b = validate_feed_url(1, feed_b_url)
        sha_c = validate_feed_url(2, feed_c_url)
        if sha_a != sha_b or sha_b != sha_c:
            raise _err(ERR_BAD_FEED_URL, "all feeds must pin the same commit")
        n = int(self.lc_count) + 1
        lc_id = "LC-" + str(n)
        self.lcs[lc_id] = LetterOfCredit(
            lc_id=lc_id,
            importer=importer_addr,
            exporter=exporter_addr,
            container_id=container_id,
            cargo_spec_hash=cargo_spec_hash,
            max_temp_tenths_c=max_temp_tenths_c,
            latest_arrival_ts=latest_arrival_ts,
            feed_a_url=feed_a_url,
            feed_b_url=feed_b_url,
            feed_c_url=feed_c_url,
            commit_sha=sha_a,
            state=ST_PENDING,
            created_at=now,
            accept_deadline=now + ACCEPTANCE_WINDOW,
            total_deposited=principal,
            unreleased=principal,
            exporter_credited=0,
            importer_credited=0,
            exporter_withdrawn=0,
            importer_withdrawn=0,
            bol_record_id="",
            bol_verified=False,
            stage1_settled=False,
            stage2_settled=False,
            final_bucket=0,
            stage1_manifest_hash="",
            stage2_manifest_hash="",
            stage1_sources=0,
            stage2_sources=0,
            stage1_event_ts=0,
            stage2_event_ts=0,
            quorum_failures=0,
        )
        self.lc_count = n
        self.total_deposited = int(self.total_deposited) + principal
        return lc_id

    # ----------------------------------------------- 48h exporter handshake
    @gl.public.write
    def accept_lc_terms(self, lc_id: str) -> str:
        lc = self._lc(lc_id)
        if gl.message.sender_address != lc.exporter:
            raise _err(ERR_UNAUTHORIZED, "only the exporter may accept")
        if lc.state != ST_PENDING:
            raise _err(ERR_STATE, "L/C is not pending acceptance")
        if _now_ts() > int(lc.accept_deadline):
            raise _err(ERR_EXPIRED, "48h acceptance window closed")
        lc.state = ST_ACTIVE
        return ST_ACTIVE

    @gl.public.write
    def reject_lc_terms(self, lc_id: str) -> str:
        lc = self._lc(lc_id)
        if gl.message.sender_address != lc.exporter:
            raise _err(ERR_UNAUTHORIZED, "only the exporter may reject")
        if lc.state != ST_PENDING:
            raise _err(ERR_STATE, "L/C is not pending acceptance")
        lc.state = ST_REJECTED
        return ST_REJECTED

    @gl.public.write
    def cancel_unaccepted_lc(self, lc_id: str) -> str:
        """Importer reclaims 100% of principal when the exporter rejected, or
        when 48h passed without acceptance."""
        lc = self._lc(lc_id)
        if gl.message.sender_address != lc.importer:
            raise _err(ERR_UNAUTHORIZED, "only the importer may cancel")
        if lc.state == ST_REJECTED:
            pass
        elif lc.state == ST_PENDING:
            if _now_ts() <= int(lc.accept_deadline):
                raise _err(ERR_NOT_YET, "acceptance window still open")
        else:
            raise _err(ERR_STATE, "L/C is not unaccepted")
        self._credit_importer_all(lc)
        lc.state = ST_CANCELLED
        return ST_CANCELLED

    # ------------------------------------------ Ed25519 eB/L attestation
    @gl.public.write
    def verify_bill_of_lading(self, lc_id: str, bol_record_id: str, attestation_signature: str) -> str:
        """Verifies the Carrier Authority's Ed25519 signature over
        bol_record_id|lc_id|container_id|exporter_address|cargo_spec_hash|
        max_temp_tenths_c|latest_arrival_ts. Any mismatch reverts BEFORE any
        fetch or state change."""
        lc = self._lc(lc_id)
        sender = gl.message.sender_address
        if sender != lc.importer and sender != lc.exporter:
            raise _err(ERR_UNAUTHORIZED, "only L/C parties")
        if lc.state != ST_ACTIVE:
            raise _err(ERR_STATE, "L/C must be ACTIVE")
        if lc.bol_verified:
            raise _err(ERR_STATE, "bill of lading already verified")
        if not _valid_id(bol_record_id):
            raise _err(ERR_INVALID_BOL, "malformed bol_record_id")
        if not self._check_bol(lc, bol_record_id, attestation_signature):
            raise _err(ERR_INVALID_BOL, "signature does not verify")
        if bol_record_id in self.bol_registry:
            raise _err(ERR_BOL_REPLAY, "bill of lading already bound to " + self.bol_registry[bol_record_id])
        self.bol_registry[bol_record_id] = lc.lc_id
        lc.bol_record_id = bol_record_id
        lc.bol_verified = True
        return bol_record_id

    # -------------------------------------------- 3-host 2-of-3 settlement
    @gl.public.write
    def settle_shipment_stage(self, lc_id: str, stage: int) -> str:
        lc = self._lc(lc_id)
        sender = gl.message.sender_address
        if sender != lc.importer and sender != lc.exporter:
            raise _err(ERR_UNAUTHORIZED, "only L/C parties")
        if not _is_int(stage) or stage not in (STAGE_1_DEPARTURE, STAGE_2_CUSTOMS_CLEARED):
            raise _err(ERR_STAGE, "stage must be 1 or 2")
        if not lc.bol_verified:
            raise _err(ERR_BOL_NOT_VERIFIED, "verify the bill of lading first")
        if stage == STAGE_1_DEPARTURE:
            if lc.state != ST_ACTIVE or lc.stage1_settled:
                raise _err(ERR_STATE, "stage 1 is not settleable")
        else:
            if lc.state != ST_STAGE_1 or not lc.stage1_settled or lc.stage2_settled:
                raise _err(ERR_STATE, "stage 2 requires stage 1 and is not yet settled")
        now = _now_ts()
        urls = [lc.feed_a_url, lc.feed_b_url, lc.feed_c_url]
        terms = {
            "bol_record_id": lc.bol_record_id,
            "lc_id": lc.lc_id,
            "container_id": lc.container_id,
            "latest_arrival_ts": int(lc.latest_arrival_ts),
            "max_temp_tenths_c": int(lc.max_temp_tenths_c),
        }

        def leader_fn():
            return collect_and_aggregate(urls, terms, stage, now)

        def validator_fn(leaders_res: gl.vm.Result) -> bool:
            if not isinstance(leaders_res, gl.vm.Return):
                return False
            return run_validator(leaders_res.calldata, collect_and_aggregate(urls, terms, stage, now))

        payload = gl.vm.run_nondet(leader_fn, validator_fn)
        if not payload_well_formed(payload) or payload["stage"] != stage:
            raise _err(ERR_STATE, "consensus payload rejected")
        verdict = payload["verdict"]
        if verdict == VERDICT_QUORUM_FAILURE:
            lc.quorum_failures = int(lc.quorum_failures) + 1
            return json.dumps(payload, sort_keys=True)
        self._apply_settlement(lc, stage, payload)
        return json.dumps(payload, sort_keys=True)

    def _apply_settlement(self, lc: LetterOfCredit, stage: int, payload: dict) -> None:
        principal = int(lc.total_deposited)
        if stage == STAGE_1_DEPARTURE:
            if payload["verdict"] == VERDICT_REJECTION:
                # Voyage aborted before the departure tranche was ever released:
                # the importer is made whole with everything still in escrow.
                self._credit_importer_all(lc)
                lc.state = ST_ABORTED
                lc.stage1_manifest_hash = payload["manifest_hash"]
                lc.stage1_sources = payload["source_count"]
                lc.stage1_event_ts = payload["event_ts"]
                return
            amount = stage1_amount(principal)
            lc.exporter_credited = int(lc.exporter_credited) + amount
            lc.unreleased = int(lc.unreleased) - amount
            lc.stage1_settled = True
            lc.state = ST_STAGE_1
            lc.stage1_manifest_hash = payload["manifest_hash"]
            lc.stage1_sources = payload["source_count"]
            lc.stage1_event_ts = payload["event_ts"]
            return
        bucket = payload["bucket"]
        exporter, importer = stage2_split(principal, bucket)
        lc.exporter_credited = int(lc.exporter_credited) + exporter
        lc.importer_credited = int(lc.importer_credited) + importer
        lc.unreleased = int(lc.unreleased) - exporter - importer
        lc.stage2_settled = True
        lc.final_bucket = bucket
        lc.state = ST_COMPLETED
        lc.stage2_manifest_hash = payload["manifest_hash"]
        lc.stage2_sources = payload["source_count"]
        lc.stage2_event_ts = payload["event_ts"]

    # --------------------------------------------------------- liveness exit
    @gl.public.write
    def reclaim_expired_lc(self, lc_id: str) -> str:
        """If the voyage is never settled, the importer can recover whatever is
        still in escrow once latest_arrival + grace + settlement window passed."""
        lc = self._lc(lc_id)
        if gl.message.sender_address != lc.importer:
            raise _err(ERR_UNAUTHORIZED, "only the importer may reclaim")
        if lc.state != ST_ACTIVE and lc.state != ST_STAGE_1:
            raise _err(ERR_STATE, "L/C is not open")
        cutoff = int(lc.latest_arrival_ts) + GRACE_SECONDS + SETTLEMENT_WINDOW
        if _now_ts() <= cutoff:
            raise _err(ERR_NOT_YET, "settlement window still open")
        self._credit_importer_all(lc)
        lc.state = ST_EXPIRED
        return ST_EXPIRED

    # ------------------------------------------------------------- payouts
    @gl.public.write
    def claim_funds(self, lc_id: str) -> str:
        """Pull-pattern payout of the caller's credited balance on one L/C
        (checks-effects-interactions; restored if the transfer cannot enqueue)."""
        lc = self._lc(lc_id)
        sender = gl.message.sender_address
        is_exporter = sender == lc.exporter
        is_importer = sender == lc.importer
        if not is_exporter and not is_importer:
            raise _err(ERR_UNAUTHORIZED, "only L/C parties")
        if is_exporter:
            amount = int(lc.exporter_credited) - int(lc.exporter_withdrawn)
        else:
            amount = int(lc.importer_credited) - int(lc.importer_withdrawn)
        if amount <= 0:
            raise _err(ERR_NO_FUNDS)
        if is_exporter:
            lc.exporter_withdrawn = int(lc.exporter_withdrawn) + amount
        else:
            lc.importer_withdrawn = int(lc.importer_withdrawn) + amount
        self.total_withdrawn = int(self.total_withdrawn) + amount
        try:
            gl.chain.Account(sender).emit_transfer(amount, on="finalized")
        except Exception:
            if is_exporter:
                lc.exporter_withdrawn = int(lc.exporter_withdrawn) - amount
            else:
                lc.importer_withdrawn = int(lc.importer_withdrawn) - amount
            self.total_withdrawn = int(self.total_withdrawn) - amount
            raise _err(ERR_TRANSFER)
        return str(amount)
