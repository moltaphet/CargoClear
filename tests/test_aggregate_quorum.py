"""The fault-tolerant 5-step quorum.

Three independent feeds, six possible behaviours each: 6**3 = 216 states per
stage, checked three ways -- against an independently written oracle on the pure
aggregate, end-to-end through the contract, and (for the validator) field by field.
"""

import itertools
import json

import pytest
from conftest import (
    LATEST,
    NOT_FOUND,
    OUTAGE,
    PRINCIPAL,
    T0,
    assert_reverts,
    ok,
    record,
)

H = "11" * 32  # the manifest hash the honest sources share
H2 = "22" * 32  # a conflicting manifest

# ---- the six behaviours of ONE source, per stage ---------------------------
# Stage 2: two distinct CLEARED outcomes (different buckets), a rejection, 404,
# 5xx outage, and a record dated in the future.
S2_STATES = {
    "X": ok(record(manifest_hash=H, peak_temp_tenths_c=-160)),  # BUCKET_2
    "Y": ok(record(manifest_hash=H, peak_temp_tenths_c=-185)),  # BUCKET_0
    "R": ok(record(manifest_hash=H, status="CUSTOMS_REJECTED")),
    "N": NOT_FOUND,
    "O": OUTAGE,
    "F": ok(record(manifest_hash=H, event_ts=T0 + 3601)),  # future-dated
}
# Stage 1: two distinct manifests, an abort, 404, outage, future-dated.
S1_STATES = {
    "X": ok(record(manifest_hash=H, status="VESSEL_DEPARTED", arrival_ts=0, peak_temp_tenths_c=0)),
    "Y": ok(record(manifest_hash=H2, status="VESSEL_DEPARTED", arrival_ts=0, peak_temp_tenths_c=0)),
    "R": ok(record(manifest_hash=H, status="VOYAGE_ABORTED")),
    "N": NOT_FOUND,
    "O": OUTAGE,
    "F": ok(record(manifest_hash=H, status="VESSEL_DEPARTED", event_ts=T0 + 3601)),
}
LETTERS = "XYRNOF"
COMBOS = ["".join(c) for c in itertools.product(LETTERS, repeat=3)]
assert len(COMBOS) == 216


def oracle(combo: str, stage: int) -> dict:
    """Independent statement of the spec (does not share code with the contract)."""
    rejects = combo.count("R")
    x = combo.count("X")
    y = combo.count("Y")
    responders = rejects + x + y
    if rejects >= 2:
        return {"verdict": 0, "stage": stage, "bucket": 3, "source_count": rejects, "manifest_hash": H}
    if stage == 2:
        if x >= 2:
            return {"verdict": 1, "stage": 2, "bucket": 2, "source_count": x, "manifest_hash": H}
        if y >= 2:
            return {"verdict": 1, "stage": 2, "bucket": 0, "source_count": y, "manifest_hash": H}
    else:
        if x >= 2:
            return {"verdict": 1, "stage": 1, "bucket": 0, "source_count": x, "manifest_hash": H}
        if y >= 2:
            return {"verdict": 1, "stage": 1, "bucket": 0, "source_count": y, "manifest_hash": H2}
    return {"verdict": 2, "stage": stage, "bucket": 0, "source_count": responders, "manifest_hash": ""}


def _core(payload: dict) -> dict:
    return {k: payload[k] for k in ("verdict", "stage", "bucket", "source_count", "manifest_hash")}


# ---- pure aggregate over hand-built outcomes -------------------------------
def _outcome(letter: str, stage: int) -> dict:
    n = {"kind": "LAG", "stage": stage, "bucket": 0, "manifest_hash": "", "event_ts": 0}
    out = {
        "X": ("POS", 2 if stage == 2 else 0, H),
        "Y": ("POS", 0, H if stage == 2 else H2),
        "R": ("REJ", 3, H),
    }
    if letter in out:
        kind, bucket, mh = out[letter]
        return {"kind": kind, "stage": stage, "bucket": bucket, "manifest_hash": mh, "event_ts": 100}
    if letter == "N":
        return n
    return {"kind": "OUT", "stage": stage, "bucket": 0, "manifest_hash": "", "event_ts": 0}


@pytest.mark.parametrize("stage", [1, 2])
@pytest.mark.parametrize("combo", COMBOS)
def test_pure_aggregate_matches_oracle_for_all_216_states(cc, combo, stage):
    got = cc.aggregate([_outcome(c, stage) for c in combo], stage)
    assert _core(got) == oracle(combo, stage)
    assert cc.payload_well_formed(got)


@pytest.mark.parametrize("combo", ["".join(p) for p in itertools.permutations("XNO")])
def test_source_order_does_not_change_the_verdict(cc, combo):
    got = cc.aggregate([_outcome(c, 2) for c in combo], 2)
    assert got["verdict"] == 2


# ---- the spec's named lag / outage cases -----------------------------------
@pytest.mark.parametrize(
    "combo",
    ["XNN", "NXN", "NNX", "XNO", "XON", "NXO", "OXN", "ONX", "NOX", "XOO", "OXO", "OOX", "XNF", "XFN"],
)
def test_one_confirmed_plus_lag_or_outage_is_quorum_failure_not_rejection(cc, combo):
    got = cc.aggregate([_outcome(c, 2) for c in combo], 2)
    assert got["verdict"] == 2
    assert got["source_count"] == 1


@pytest.mark.parametrize("combo", ["NNN", "OOO", "NNO", "NOO", "FFF", "NNF"])
def test_no_responders_is_quorum_failure(cc, combo):
    got = cc.aggregate([_outcome(c, 2) for c in combo], 2)
    assert got["verdict"] == 2 and got["source_count"] == 0


@pytest.mark.parametrize("combo", ["XYN", "XYO", "XYF", "YXN", "NXY", "OYX"])
def test_conflicting_positives_with_no_pair_is_quorum_failure(cc, combo):
    got = cc.aggregate([_outcome(c, 2) for c in combo], 2)
    assert got["verdict"] == 2


@pytest.mark.parametrize("combo", ["RNN", "RNO", "RON", "RNF", "NRN", "ORO"])
def test_single_rejection_never_rejects_cargo(cc, combo):
    got = cc.aggregate([_outcome(c, 2) for c in combo], 2)
    assert got["verdict"] == 2


@pytest.mark.parametrize("combo", ["RRN", "RRO", "RRF", "RNR", "NRR", "RRX", "XRR", "RRR", "RYR"])
def test_two_matching_rejections_reject_cargo(cc, combo):
    got = cc.aggregate([_outcome(c, 2) for c in combo], 2)
    assert got["verdict"] == 0 and got["bucket"] == 3


def test_rejections_with_different_manifests_do_not_form_a_quorum(cc):
    a = {"kind": "REJ", "stage": 2, "bucket": 3, "manifest_hash": H, "event_ts": 1}
    b = {"kind": "REJ", "stage": 2, "bucket": 3, "manifest_hash": H2, "event_ts": 1}
    lag = {"kind": "LAG", "stage": 2, "bucket": 0, "manifest_hash": "", "event_ts": 0}
    assert cc.aggregate([a, b, lag], 2)["verdict"] == 2


def test_event_ts_is_the_latest_of_the_agreeing_group(cc):
    mk = lambda ts: {"kind": "POS", "stage": 2, "bucket": 0, "manifest_hash": H, "event_ts": ts}  # noqa: E731
    assert cc.aggregate([mk(10), mk(30), mk(20)], 2)["event_ts"] == 30
    assert cc.aggregate([mk(10), mk(30), {"kind": "OUT", "stage": 2, "bucket": 0, "manifest_hash": "", "event_ts": 0}], 2)["event_ts"] == 30


# ---- end-to-end through the contract, all 216 states per stage -------------
def _prepare_stage2(world):
    world.ready()
    r = record(status="VESSEL_DEPARTED", arrival_ts=0, peak_temp_tenths_c=0)
    world.mock_feeds(ok(r), ok(r), ok(r))
    out = world.settle(1)
    assert out["verdict"] == 1 and out["source_count"] == 3


def _snapshot(world):
    st = world.state()
    return {k: st[k] for k in ("state", "unreleased_escrow", "exporter_claimable", "importer_rebate", "stage1_settled", "stage2_settled")}


@pytest.mark.parametrize("combo", COMBOS)
def test_e2e_stage2_216_states(world, combo):
    _prepare_stage2(world)
    before = _snapshot(world)
    world.mock_feeds(*(S2_STATES[c] for c in combo))
    out = world.settle(2)
    exp = oracle(combo, 2)
    assert _core(out) == exp
    st = world.state()
    inv = world.contract.verify_solvency_invariant()
    assert inv["per_lc_conserved"]
    if exp["verdict"] == 2:
        assert _snapshot(world) == before  # no state lock, nothing moved
        assert st["quorum_failures"] == 1 and not st["stage2_settled"]
        # retryable: with healthy feeds the very next call settles
        good = ok(record(manifest_hash=H, peak_temp_tenths_c=-185))
        world.mock_feeds(good, good, good)
        assert world.settle(2)["verdict"] == 1
    else:
        assert st["stage2_settled"] and st["state"] == "COMPLETED"
        assert st["final_bucket"] == exp["bucket"]
        assert st["unreleased_escrow"] == 0
        assert st["exporter_claimable"] + st["importer_rebate"] == PRINCIPAL
        assert inv["solvent"]


@pytest.mark.parametrize("combo", COMBOS)
def test_e2e_stage1_216_states(world, combo):
    world.ready()
    before = _snapshot(world)
    world.mock_feeds(*(S1_STATES[c] for c in combo))
    out = world.settle(1)
    exp = oracle(combo, 1)
    assert _core(out) == exp
    st = world.state()
    assert world.contract.verify_solvency_invariant()["per_lc_conserved"]
    if exp["verdict"] == 2:
        assert _snapshot(world) == before
        assert st["state"] == "ACTIVE" and not st["stage1_settled"]
    elif exp["verdict"] == 0:
        assert st["state"] == "ABORTED_REFUNDED"
        assert st["importer_rebate"] == PRINCIPAL and st["unreleased_escrow"] == 0
        assert st["exporter_claimable"] == 0
    else:
        assert st["state"] == "STAGE_1_SETTLED" and st["stage1_settled"]
        assert st["exporter_claimable"] == PRINCIPAL * 2000 // 10000
        assert st["unreleased_escrow"] == PRINCIPAL - PRINCIPAL * 2000 // 10000


# ---- feed content strictness: any defect == OUTAGE, never a rejection -------
def _stage2_with_two_good_and(world, bad):
    _prepare_stage2(world)
    good = ok(record(manifest_hash=H, peak_temp_tenths_c=-185))
    world.mock_feeds(good, good, bad)
    return world.settle(2)


def _raw(body: str, status: int = 200):
    return {"status": status, "body": body}


GOOD_JSON = json.dumps(record(manifest_hash=H, peak_temp_tenths_c=-185))
MALFORMED = {
    "float_literal": GOOD_JSON.replace('"peak_temp_tenths_c": -185', '"peak_temp_tenths_c": -185.0'),
    "exponent_literal": GOOD_JSON.replace('"peak_temp_tenths_c": -185', '"peak_temp_tenths_c": -1.85e2'),
    "float_in_event_ts": GOOD_JSON.replace(f'"event_ts": {T0 - 3600}', f'"event_ts": {T0 - 3600}.5'),
    "int_exponent": GOOD_JSON.replace(f'"event_ts": {T0 - 3600}', '"event_ts": 1e3'),
    "nan": GOOD_JSON.replace('"peak_temp_tenths_c": -185', '"peak_temp_tenths_c": NaN'),
    "infinity": GOOD_JSON.replace('"peak_temp_tenths_c": -185', '"peak_temp_tenths_c": Infinity'),
    "neg_infinity": GOOD_JSON.replace('"peak_temp_tenths_c": -185', '"peak_temp_tenths_c": -Infinity'),
    "not_json": "<html>502 bad gateway</html>",
    "empty_object": "{}",
    "list_top_level": "[" + GOOD_JSON + "]",
    "json_string": '"hello"',
    "json_null": "null",
    "truncated": GOOD_JSON[:-5],
    "duplicate_key": GOOD_JSON[:-1] + ', "status": "CUSTOMS_REJECTED"}',
    "extra_key": GOOD_JSON[:-1] + ', "bonus": 1}',
    "bool_for_int": GOOD_JSON.replace(f'"event_ts": {T0 - 3600}', '"event_ts": true'),
    "string_for_int": GOOD_JSON.replace(f'"event_ts": {T0 - 3600}', f'"event_ts": "{T0 - 3600}"'),
    "wrong_schema": GOOD_JSON.replace("cargoclear.feed.v1", "cargoclear.feed.v0"),
    "bad_status": GOOD_JSON.replace("CUSTOMS_CLEARED", "SOMETHING_ELSE"),
    "short_hash": GOOD_JSON.replace(H, "11" * 31),
    "upper_hash": GOOD_JSON.replace(H, "AB" * 32),
    "negative_ts": GOOD_JSON.replace(f'"event_ts": {T0 - 3600}', '"event_ts": -5'),
    "wrong_bol": GOOD_JSON.replace("BOL-CC-0001", "BOL-OTHER"),
    "wrong_lc": GOOD_JSON.replace('"LC-1"', '"LC-2"'),
    "wrong_container": GOOD_JSON.replace("MSKU1234567", "MSKU0000000"),
    "future_event": GOOD_JSON.replace(f'"event_ts": {T0 - 3600}', f'"event_ts": {T0 + 3601}'),
    "future_arrival": GOOD_JSON.replace(f'"arrival_ts": {T0 - 86400}', f'"arrival_ts": {T0 + 99999}'),
    "arrival_before_departure": GOOD_JSON.replace(f'"arrival_ts": {T0 - 86400}', f'"arrival_ts": {T0 - 9 * 86400}'),
    "zero_arrival_when_cleared": GOOD_JSON.replace(f'"arrival_ts": {T0 - 86400}', '"arrival_ts": 0'),
    "huge_int": GOOD_JSON.replace('"peak_temp_tenths_c": -185', '"peak_temp_tenths_c": 99999999999999999999999'),
    "oversized_body": GOOD_JSON[:-1] + ', "pad": "' + "x" * 20000 + '"}',
}


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_malformed_feed_is_an_outage_never_a_rejection(world, name):
    out = _stage2_with_two_good_and(world, _raw(MALFORMED[name]))
    # two honest sources still reach quorum; the bad one simply does not vote
    assert out["verdict"] == 1 and out["source_count"] == 2 and out["bucket"] == 0


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_malformed_feed_plus_one_good_is_retryable_failure(world, name):
    _prepare_stage2(world)
    good = ok(record(manifest_hash=H, peak_temp_tenths_c=-185))
    world.mock_feeds(good, _raw(MALFORMED[name]), NOT_FOUND)
    out = world.settle(2)
    assert out["verdict"] == 2 and out["source_count"] == 1
    assert world.state()["stage2_settled"] is False


@pytest.mark.parametrize("status", [400, 401, 403, 410, 418, 429, 500, 502, 503, 504, 301, 302, 100])
def test_non_404_error_statuses_are_outages(world, status):
    _prepare_stage2(world)
    good = ok(record(manifest_hash=H, peak_temp_tenths_c=-185))
    world.mock_feeds(good, {"status": status, "body": GOOD_JSON}, NOT_FOUND)
    assert world.settle(2)["verdict"] == 2


@pytest.mark.parametrize("status", [200, 201, 204, 299])
def test_any_2xx_with_a_valid_body_is_accepted(world, status):
    _prepare_stage2(world)
    body = json.dumps(record(manifest_hash=H, peak_temp_tenths_c=-185))
    world.mock_feeds({"status": status, "body": body}, {"status": 200, "body": body}, NOT_FOUND)
    assert world.settle(2)["verdict"] == 1


def test_empty_body_is_an_outage(world):
    out = _stage2_with_two_good_and(world, {"status": 200, "body": ""})
    assert out["source_count"] == 2


def test_future_timestamp_boundary(world):
    _prepare_stage2(world)
    edge = ok(record(manifest_hash=H, peak_temp_tenths_c=-185, event_ts=T0 + 3600))  # allowed
    over = ok(record(manifest_hash=H, peak_temp_tenths_c=-185, event_ts=T0 + 3601))  # outage
    world.mock_feeds(edge, over, NOT_FOUND)
    assert world.settle(2)["verdict"] == 2
    world.mock_feeds(edge, edge, over)
    out = world.settle(2)
    assert out["verdict"] == 1 and out["source_count"] == 2


def test_float_literal_cannot_smuggle_a_haircut(world):
    """A peak of -160.0 would be 'equal' to -160 in Python; the parser refuses the
    float outright, so the source is an outage and cannot influence the bucket."""
    _prepare_stage2(world)
    clean = ok(record(manifest_hash=H, peak_temp_tenths_c=-185))
    floaty = _raw(json.dumps(record(manifest_hash=H, peak_temp_tenths_c=-160)).replace("-160", "-160.0"))
    world.mock_feeds(clean, clean, floaty)
    out = world.settle(2)
    assert out["bucket"] == 0 and out["source_count"] == 2


def test_parser_rejects_all_float_spellings(cc):
    for text in ["1.0", "1e2", "1E2", "-0.0", "0.5", "1e-3", "NaN", "Infinity", "-Infinity", "1.5E+3"]:
        assert cc.parse_feed_json('{"k": ' + text + "}") is None, text
    assert cc.parse_feed_json('{"k": 1}') == {"k": 1}
    assert cc.parse_feed_json('{"k": -0}') == {"k": 0}


def test_parser_rejects_duplicate_keys_and_non_objects(cc):
    assert cc.parse_feed_json('{"a": 1, "a": 2}') is None
    for text in ["[]", "1", '"x"', "null", "true", "", "{", "{'a': 1}"]:
        assert cc.parse_feed_json(text) is None, text


# ---- validators: exact key set, exact types, exact equality ----------------
def _leader_payload(world):
    _prepare_stage2(world)
    good = ok(record(manifest_hash=H, peak_temp_tenths_c=-185))
    world.mock_feeds(good, good, good)
    out = world.settle(2)
    return out, world


def test_validator_agrees_with_honest_leader(world):
    out, w = _leader_payload(world)
    assert w.vm.run_validator() is True
    assert w.vm.run_validator(leader_result=out) is True


KEYS = ["verdict", "stage", "bucket", "source_count", "manifest_hash", "event_ts"]


@pytest.mark.parametrize("key", KEYS)
def test_validator_rejects_missing_key(world, key):
    out, w = _leader_payload(world)
    bad = {k: v for k, v in out.items() if k != key}
    assert w.vm.run_validator(leader_result=bad) is False


@pytest.mark.parametrize("extra", ["note", "verdict2", "Verdict", ""])
def test_validator_rejects_extra_key(world, extra):
    out, w = _leader_payload(world)
    assert w.vm.run_validator(leader_result={**out, extra: 1}) is False


@pytest.mark.parametrize("key", KEYS)
def test_validator_rejects_any_field_difference(world, key):
    out, w = _leader_payload(world)
    bad = dict(out)
    bad[key] = (H2 if key == "manifest_hash" else (out[key] + 1 if key != "verdict" else 2))
    assert w.vm.run_validator(leader_result=bad) is False


@pytest.mark.parametrize("key", ["verdict", "stage", "bucket", "source_count", "event_ts"])
@pytest.mark.parametrize("wrong", [str, float, bool, lambda v: None, lambda v: [v]])
def test_validator_rejects_wrong_integer_types(world, key, wrong):
    out, w = _leader_payload(world)
    bad = dict(out)
    bad[key] = wrong(out[key])
    assert w.vm.run_validator(leader_result=bad) is False


@pytest.mark.parametrize("wrong", [5, None, b"x", ["a"], 1.5])
def test_validator_rejects_wrong_manifest_hash_type(world, wrong):
    out, w = _leader_payload(world)
    assert w.vm.run_validator(leader_result={**out, "manifest_hash": wrong}) is False


@pytest.mark.parametrize("junk", [None, 0, 1, "verdict", [], [1, 2, 3], (1, 2)])
def test_validator_rejects_non_dict_leader_results(world, junk):
    out, w = _leader_payload(world)
    assert w.vm.run_validator(leader_result=junk) is False


def test_validator_rejects_leader_error(world):
    out, w = _leader_payload(world)
    assert w.vm.run_validator(leader_error=Exception("boom")) is False


def test_validator_who_sees_lag_disagrees_with_a_confident_leader(world):
    """Leader saw 3 sources; the validator's CDN is lagging on one -> source_count
    differs -> disagree (forces a rotation instead of accepting a different view)."""
    out, w = _leader_payload(world)
    good = ok(record(manifest_hash=H, peak_temp_tenths_c=-185))
    w.mock_feeds(good, good, NOT_FOUND)
    assert w.vm.run_validator(leader_result=out) is False


def test_validator_with_outage_cannot_be_dragged_into_a_false_rejection(world):
    out, w = _leader_payload(world)
    rej = ok(record(manifest_hash=H, status="CUSTOMS_REJECTED"))
    w.mock_feeds(rej, NOT_FOUND, OUTAGE)
    forged_leader = {**out, "verdict": 0, "bucket": 3, "source_count": 2}
    assert w.vm.run_validator(leader_result=forged_leader) is False


def test_validator_compares_a_quorum_failure_too(world):
    _prepare_stage2(world)
    one = ok(record(manifest_hash=H, peak_temp_tenths_c=-185))
    world.mock_feeds(one, NOT_FOUND, NOT_FOUND)
    out = world.settle(2)
    assert out["verdict"] == 2
    assert world.vm.run_validator() is True
    world.mock_feeds(one, one, NOT_FOUND)  # validator sees more than the leader did
    assert world.vm.run_validator(leader_result=out) is False


def test_malformed_payloads_are_never_well_formed(cc):
    good = {"verdict": 1, "stage": 2, "bucket": 0, "source_count": 2, "manifest_hash": H, "event_ts": 5}
    assert cc.payload_well_formed(good)
    for patch in [
        {"verdict": 3},
        {"verdict": -1},
        {"stage": 0},
        {"stage": 3},
        {"bucket": 4},
        {"bucket": -1},
        {"source_count": 4},
        {"source_count": 1},
        {"manifest_hash": ""},
        {"manifest_hash": "zz" * 32},
        {"manifest_hash": "11" * 31},
    ]:
        assert not cc.payload_well_formed({**good, **patch}), patch
    qf = {"verdict": 2, "stage": 2, "bucket": 0, "source_count": 1, "manifest_hash": "", "event_ts": 0}
    assert cc.payload_well_formed(qf)
    assert not cc.payload_well_formed({**qf, "bucket": 1})
    assert not cc.payload_well_formed({**qf, "event_ts": 1})
    assert not cc.payload_well_formed({**qf, "manifest_hash": H})
