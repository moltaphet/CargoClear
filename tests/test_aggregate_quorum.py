"""The fault-tolerant independent-corroboration quorum.

Three independent, individually-signing witnesses, seven possible behaviours each:
7**3 = 343 states per stage, checked three ways -- against an independently written
oracle on the pure aggregate, end-to-end through the contract, and (for the
validator) field by field.
"""

import hashlib
import itertools
import json

import pytest
from conftest import (
    BOL,
    CONTAINER,
    IMO,
    LATEST,
    NOT_FOUND,
    OUTAGE,
    PRINCIPAL,
    T0,
    WITNESSES,
    Carrier,
    assert_reverts,
    binding_of,
    ok,
    record,
    sign_for_slot,
)

BINDING = binding_of()
FOREIGN = Carrier(b"not-a-registered-witness-seed-00")  # a perfectly valid key nobody registered


def digest(stage: int, bucket: int, kind: str) -> str:
    """Independent statement of the corroboration digest."""
    return hashlib.sha256(f"cargoclear.corroboration.v2|{BINDING}|{stage}|{bucket}|{kind}".encode()).hexdigest()


# ---- the seven behaviours of ONE source, per stage -------------------------
# Stage 2: two distinct CLEARED outcomes (different buckets), a rejection, 404,
# 5xx outage, a record dated in the future, and a record that is structurally
# perfect but signed by a key nobody registered ("U" = unauthenticated).
def _foreign(rec):
    return ok(rec, signer=FOREIGN)  # correctly signed, but not by the registered witness


S2_STATES = {
    "X": ok(record(peak_temp_tenths_c=-160)),  # BUCKET_2
    "Y": ok(record(peak_temp_tenths_c=-185)),  # BUCKET_0
    "R": ok(record(status="CUSTOMS_REJECTED")),
    "N": NOT_FOUND,
    "O": OUTAGE,
    "F": ok(record(event_ts=T0 + 3601)),  # future-dated
    "U": _foreign(record(peak_temp_tenths_c=-185)),
}
# Stage 1: two valid-and-agreeing positive spellings, an abort, 404, outage,
# future-dated, unauthenticated.
S1_STATES = {
    "X": ok(record(status="VESSEL_DEPARTED", arrival_ts=0, peak_temp_tenths_c=0)),
    "Y": ok(record(status="CUSTOMS_CLEARED")),
    "R": ok(record(status="VOYAGE_ABORTED")),
    "N": NOT_FOUND,
    "O": OUTAGE,
    "F": ok(record(status="VESSEL_DEPARTED", event_ts=T0 + 3601)),
    "U": _foreign(record(status="VESSEL_DEPARTED", arrival_ts=0, peak_temp_tenths_c=0)),
}
LETTERS = "XYRNOFU"
COMBOS = ["".join(c) for c in itertools.product(LETTERS, repeat=3)]
assert len(COMBOS) == 343


def oracle(combo: str, stage: int) -> dict:
    """Independent statement of the spec (does not share code with the contract)."""
    rejects = combo.count("R")
    x = combo.count("X")
    y = combo.count("Y")
    responders = rejects + x + y
    if rejects >= 2:
        return {"verdict": 0, "stage": stage, "bucket": 3, "source_count": rejects, "evidence_digest": digest(stage, 3, "REJ")}
    if stage == 2:
        if x >= 2:
            return {"verdict": 1, "stage": 2, "bucket": 2, "source_count": x, "evidence_digest": digest(2, 2, "POS")}
        if y >= 2:
            return {"verdict": 1, "stage": 2, "bucket": 0, "source_count": y, "evidence_digest": digest(2, 0, "POS")}
    else:
        if x + y >= 2:
            return {"verdict": 1, "stage": 1, "bucket": 0, "source_count": x + y, "evidence_digest": digest(1, 0, "POS")}
    return {"verdict": 2, "stage": stage, "bucket": 0, "source_count": responders, "evidence_digest": ""}


def _core(payload: dict) -> dict:
    return {k: payload[k] for k in ("verdict", "stage", "bucket", "source_count", "evidence_digest")}


# ---- pure aggregate over hand-built outcomes -------------------------------
def _signer(i: int) -> str:
    return WITNESSES[i].pub_hex


def _outcome(letter: str, stage: int, i: int = 0) -> dict:
    n = {"kind": "LAG", "stage": stage, "bucket": 0, "event_ts": 0, "signer": "", "binding": ""}
    out = {
        "X": ("POS", 2 if stage == 2 else 0),
        "Y": ("POS", 0),
        "R": ("REJ", 3),
    }
    if letter in out:
        kind, bucket = out[letter]
        return {"kind": kind, "stage": stage, "bucket": bucket, "event_ts": 100, "signer": _signer(i), "binding": BINDING}
    if letter == "N":
        return n
    return {"kind": "OUT", "stage": stage, "bucket": 0, "event_ts": 0, "signer": "", "binding": ""}


def _outcomes(combo: str, stage: int) -> list:
    return [_outcome(c, stage, i) for i, c in enumerate(combo)]


@pytest.mark.parametrize("stage", [1, 2])
@pytest.mark.parametrize("combo", COMBOS)
def test_pure_aggregate_matches_oracle_for_all_343_states(cc, combo, stage):
    # "F" and "U" are OUTAGEs by the time they reach the pure aggregate
    got = cc.aggregate(_outcomes(combo, stage), stage)
    assert _core(got) == oracle(combo, stage)
    assert cc.payload_well_formed(got)


@pytest.mark.parametrize("combo", ["".join(p) for p in itertools.permutations("XNO")])
def test_source_order_does_not_change_the_verdict(cc, combo):
    got = cc.aggregate(_outcomes(combo, 2), 2)
    assert got["verdict"] == 2


def test_two_records_from_one_key_are_one_voice(cc):
    """Corroboration needs two DISTINCT witness keys: a single compromised signer
    that somehow fills two slots still can not reach quorum."""
    twin = [_outcome("X", 2, 0), _outcome("X", 2, 0), _outcome("N", 2)]
    got = cc.aggregate(twin, 2)
    assert got["verdict"] == 2 and got["source_count"] == 1
    twin_rej = [_outcome("R", 2, 1), _outcome("R", 2, 1), _outcome("N", 2)]
    got = cc.aggregate(twin_rej, 2)
    assert got["verdict"] == 2 and got["source_count"] == 1


# ---- the spec's named lag / outage cases -----------------------------------
@pytest.mark.parametrize(
    "combo",
    ["XNN", "NXN", "NNX", "XNO", "XON", "NXO", "OXN", "ONX", "NOX", "XOO", "OXO", "OOX", "XNF", "XFN"],
)
def test_one_confirmed_plus_lag_or_outage_is_quorum_failure_not_rejection(cc, combo):
    got = cc.aggregate(_outcomes(combo, 2), 2)
    assert got["verdict"] == 2
    assert got["source_count"] == 1


@pytest.mark.parametrize("combo", ["NNN", "OOO", "NNO", "NOO", "FFF", "NNF"])
def test_no_responders_is_quorum_failure(cc, combo):
    got = cc.aggregate(_outcomes(combo, 2), 2)
    assert got["verdict"] == 2 and got["source_count"] == 0


@pytest.mark.parametrize("combo", ["XYN", "XYO", "XYF", "YXN", "NXY", "OYX"])
def test_conflicting_positives_with_no_pair_is_quorum_failure(cc, combo):
    got = cc.aggregate(_outcomes(combo, 2), 2)
    assert got["verdict"] == 2


@pytest.mark.parametrize("combo", ["RNN", "RNO", "RON", "RNF", "NRN", "ORO"])
def test_single_rejection_never_rejects_cargo(cc, combo):
    got = cc.aggregate(_outcomes(combo, 2), 2)
    assert got["verdict"] == 2


@pytest.mark.parametrize("combo", ["RRN", "RRO", "RRF", "RNR", "NRR", "RRX", "XRR", "RRR", "RYR"])
def test_two_matching_rejections_reject_cargo(cc, combo):
    got = cc.aggregate(_outcomes(combo, 2), 2)
    assert got["verdict"] == 0 and got["bucket"] == 3


def test_rejections_bound_to_different_shipments_do_not_form_a_quorum(cc):
    a = {**_outcome("R", 2, 0), "binding": binding_of("BOL-A")}
    b = {**_outcome("R", 2, 1), "binding": binding_of("BOL-B")}
    assert cc.aggregate([a, b, _outcome("N", 2)], 2)["verdict"] == 2


def test_positives_bound_to_different_shipments_do_not_form_a_quorum(cc):
    a = {**_outcome("Y", 2, 0), "binding": binding_of("BOL-A")}
    b = {**_outcome("Y", 2, 1), "binding": binding_of("BOL-B")}
    assert cc.aggregate([a, b, _outcome("N", 2)], 2)["verdict"] == 2


def test_event_ts_is_the_latest_of_the_agreeing_group(cc):
    mk = lambda ts, i: {**_outcome("Y", 2, i), "event_ts": ts}  # noqa: E731
    assert cc.aggregate([mk(10, 0), mk(30, 1), mk(20, 2)], 2)["event_ts"] == 30
    assert cc.aggregate([mk(10, 0), mk(30, 1), _outcome("O", 2)], 2)["event_ts"] == 30


# ---- end-to-end through the contract, all 343 states per stage -------------
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
def test_e2e_stage2_343_states(world, combo):
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
        good = ok(record(peak_temp_tenths_c=-185))
        world.mock_feeds(good, good, good)
        assert world.settle(2)["verdict"] == 1
    else:
        assert st["stage2_settled"] and st["state"] == "COMPLETED"
        assert st["final_bucket"] == exp["bucket"]
        assert st["unreleased_escrow"] == 0
        assert st["exporter_claimable"] + st["importer_rebate"] == PRINCIPAL
        assert inv["solvent"]


@pytest.mark.parametrize("combo", COMBOS)
def test_e2e_stage1_343_states(world, combo):
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
    good = ok(record(peak_temp_tenths_c=-185))
    world.mock_feeds(good, good, bad)
    return world.settle(2)


def _raw(body: str, status: int = 200):
    return {"status": status, "body": body}


def _signed_json(slot: int, **over) -> str:
    return json.dumps(sign_for_slot(record(**{"peak_temp_tenths_c": -185, **over}), slot))


def _resign(slot: int, **over) -> str:
    """Body whose value is semantically wrong but carries a VALID witness signature,
    so only the contract's own validation can reject it."""
    return _signed_json(slot, **over)


# Syntax-level corruptions of an otherwise validly signed body (slot-independent
# text edits) and semantic defects re-signed by the slot's own witness.
def _text(edit):
    return lambda slot: edit(_signed_json(slot))


MALFORMED = {
    "float_literal": _text(lambda t: t.replace('"peak_temp_tenths_c": -185', '"peak_temp_tenths_c": -185.0')),
    "exponent_literal": _text(lambda t: t.replace('"peak_temp_tenths_c": -185', '"peak_temp_tenths_c": -1.85e2')),
    "float_in_event_ts": _text(lambda t: t.replace(f'"event_ts": {T0 - 3600}', f'"event_ts": {T0 - 3600}.5')),
    "int_exponent": _text(lambda t: t.replace(f'"event_ts": {T0 - 3600}', '"event_ts": 1e3')),
    "nan": _text(lambda t: t.replace('"peak_temp_tenths_c": -185', '"peak_temp_tenths_c": NaN')),
    "infinity": _text(lambda t: t.replace('"peak_temp_tenths_c": -185', '"peak_temp_tenths_c": Infinity')),
    "neg_infinity": _text(lambda t: t.replace('"peak_temp_tenths_c": -185', '"peak_temp_tenths_c": -Infinity')),
    "not_json": lambda slot: "<html>502 bad gateway</html>",
    "empty_object": lambda slot: "{}",
    "list_top_level": _text(lambda t: "[" + t + "]"),
    "json_string": lambda slot: '"hello"',
    "json_null": lambda slot: "null",
    "truncated": _text(lambda t: t[:-5]),
    "duplicate_key": _text(lambda t: t[:-1] + ', "status": "CUSTOMS_REJECTED"}'),
    "extra_key": _text(lambda t: t[:-1] + ', "bonus": 1}'),
    "bool_for_int": _text(lambda t: t.replace(f'"event_ts": {T0 - 3600}', '"event_ts": true')),
    "string_for_int": _text(lambda t: t.replace(f'"event_ts": {T0 - 3600}', f'"event_ts": "{T0 - 3600}"')),
    "wrong_schema": lambda slot: _resign(slot, schema="cargoclear.evidence.v1"),
    "old_feed_schema": lambda slot: _resign(slot, schema="cargoclear.feed.v1"),
    "bad_status": lambda slot: _resign(slot, status="SOMETHING_ELSE"),
    "short_binding": lambda slot: _resign(slot, binding="11" * 31),
    "upper_binding": lambda slot: _resign(slot, binding=BINDING.upper()),
    "negative_ts": lambda slot: _resign(slot, event_ts=-5),
    "wrong_bol": lambda slot: _resign(slot, bol_record_id="BOL-OTHER"),
    "wrong_container": lambda slot: _resign(slot, container_id="MSKU0000000"),
    "wrong_imo": lambda slot: _resign(slot, vessel_imo="9321483"),  # a real-looking, different ship
    "invalid_imo_checkdigit": lambda slot: _resign(slot, vessel_imo="9074720"),
    "foreign_binding": lambda slot: _resign(slot, binding=binding_of("BOL-OTHER")),
    "future_event": lambda slot: _resign(slot, event_ts=T0 + 3601),
    "future_arrival": lambda slot: _resign(slot, arrival_ts=T0 + 99999),
    "arrival_before_departure": lambda slot: _resign(slot, arrival_ts=T0 - 9 * 86400),
    "zero_arrival_when_cleared": lambda slot: _resign(slot, arrival_ts=0),
    "huge_int": lambda slot: _resign(slot, peak_temp_tenths_c=99999999999999999999999),
    "oversized_body": _text(lambda t: t[:-1] + ', "pad": "' + "x" * 20000 + '"}'),
    "missing_signature": lambda slot: json.dumps(
        {k: v for k, v in sign_for_slot(record(peak_temp_tenths_c=-185), slot).items() if k != "signature"}
    ),
    "short_signature": lambda slot: json.dumps(
        {**sign_for_slot(record(peak_temp_tenths_c=-185), slot), "signature": "ab" * 63}
    ),
    "upper_signature": lambda slot: json.dumps(
        {**sign_for_slot(record(peak_temp_tenths_c=-185), slot), "signature": WITNESSES[slot].sign("x").upper()}
    ),
}


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_malformed_feed_is_an_outage_never_a_rejection(world, name):
    out = _stage2_with_two_good_and(world, _raw(MALFORMED[name](2)))
    # two honest sources still reach quorum; the bad one simply does not vote
    assert out["verdict"] == 1 and out["source_count"] == 2 and out["bucket"] == 0


@pytest.mark.parametrize("name", sorted(MALFORMED))
def test_malformed_feed_plus_one_good_is_retryable_failure(world, name):
    _prepare_stage2(world)
    good = ok(record(peak_temp_tenths_c=-185))
    world.mock_feeds(good, _raw(MALFORMED[name](1)), NOT_FOUND)
    out = world.settle(2)
    assert out["verdict"] == 2 and out["source_count"] == 1
    assert world.state()["stage2_settled"] is False


@pytest.mark.parametrize("status", [400, 401, 403, 410, 418, 429, 500, 502, 503, 504, 301, 302, 100])
def test_non_404_error_statuses_are_outages(world, status):
    _prepare_stage2(world)
    good = ok(record(peak_temp_tenths_c=-185))
    world.mock_feeds(good, {"status": status, "body": _signed_json(1)}, NOT_FOUND)
    assert world.settle(2)["verdict"] == 2


@pytest.mark.parametrize("status", [200, 201, 204, 299])
def test_any_2xx_with_a_valid_body_is_accepted(world, status):
    _prepare_stage2(world)
    world.mock_feeds(
        {"status": status, "body": _signed_json(0)}, {"status": 200, "body": _signed_json(1)}, NOT_FOUND
    )
    assert world.settle(2)["verdict"] == 1


def test_empty_body_is_an_outage(world):
    out = _stage2_with_two_good_and(world, {"status": 200, "body": ""})
    assert out["source_count"] == 2


def test_future_timestamp_boundary(world):
    _prepare_stage2(world)
    edge = ok(record(peak_temp_tenths_c=-185, event_ts=T0 + 3600))  # allowed
    over = ok(record(peak_temp_tenths_c=-185, event_ts=T0 + 3601))  # outage
    world.mock_feeds(edge, over, NOT_FOUND)
    assert world.settle(2)["verdict"] == 2
    world.mock_feeds(edge, edge, over)
    out = world.settle(2)
    assert out["verdict"] == 1 and out["source_count"] == 2


def test_float_literal_cannot_smuggle_a_haircut(world):
    """A peak of -160.0 would be 'equal' to -160 in Python; the parser refuses the
    float outright, so the source is an outage and cannot influence the bucket."""
    _prepare_stage2(world)
    clean = ok(record(peak_temp_tenths_c=-185))
    floaty = _raw(json.dumps(sign_for_slot(record(peak_temp_tenths_c=-160), 2)).replace("-160", "-160.0"))
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
    good = ok(record(peak_temp_tenths_c=-185))
    world.mock_feeds(good, good, good)
    out = world.settle(2)
    return out, world


def test_validator_agrees_with_honest_leader(world):
    out, w = _leader_payload(world)
    assert w.vm.run_validator() is True
    assert w.vm.run_validator(leader_result=out) is True


KEYS = ["verdict", "stage", "bucket", "source_count", "evidence_digest", "event_ts"]


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
    bad[key] = digest(2, 1, "POS") if key == "evidence_digest" else (out[key] + 1 if key != "verdict" else 2)
    assert w.vm.run_validator(leader_result=bad) is False


@pytest.mark.parametrize("key", ["verdict", "stage", "bucket", "source_count", "event_ts"])
@pytest.mark.parametrize("wrong", [str, float, bool, lambda v: None, lambda v: [v]])
def test_validator_rejects_wrong_integer_types(world, key, wrong):
    out, w = _leader_payload(world)
    bad = dict(out)
    bad[key] = wrong(out[key])
    assert w.vm.run_validator(leader_result=bad) is False


@pytest.mark.parametrize("wrong", [5, None, b"x", ["a"], 1.5])
def test_validator_rejects_wrong_evidence_digest_type(world, wrong):
    out, w = _leader_payload(world)
    assert w.vm.run_validator(leader_result={**out, "evidence_digest": wrong}) is False


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
    good = ok(record(peak_temp_tenths_c=-185))
    w.mock_feeds(good, good, NOT_FOUND)
    assert w.vm.run_validator(leader_result=out) is False


def test_validator_with_outage_cannot_be_dragged_into_a_false_rejection(world):
    out, w = _leader_payload(world)
    rej = ok(record(status="CUSTOMS_REJECTED"))
    w.mock_feeds(rej, NOT_FOUND, OUTAGE)
    forged_leader = {**out, "verdict": 0, "bucket": 3, "source_count": 2}
    assert w.vm.run_validator(leader_result=forged_leader) is False


def test_validator_compares_a_quorum_failure_too(world):
    _prepare_stage2(world)
    one = ok(record(peak_temp_tenths_c=-185))
    world.mock_feeds(one, NOT_FOUND, NOT_FOUND)
    out = world.settle(2)
    assert out["verdict"] == 2
    assert world.vm.run_validator() is True
    world.mock_feeds(one, one, NOT_FOUND)  # validator sees more than the leader did
    assert world.vm.run_validator(leader_result=out) is False


def test_malformed_payloads_are_never_well_formed(cc):
    D = digest(2, 0, "POS")
    good = {"verdict": 1, "stage": 2, "bucket": 0, "source_count": 2, "evidence_digest": D, "event_ts": 5}
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
        {"evidence_digest": ""},
        {"evidence_digest": "zz" * 32},
        {"evidence_digest": "11" * 31},
    ]:
        assert not cc.payload_well_formed({**good, **patch}), patch
    qf = {"verdict": 2, "stage": 2, "bucket": 0, "source_count": 1, "evidence_digest": "", "event_ts": 0}
    assert cc.payload_well_formed(qf)
    assert not cc.payload_well_formed({**qf, "bucket": 1})
    assert not cc.payload_well_formed({**qf, "event_ts": 1})
    assert not cc.payload_well_formed({**qf, "evidence_digest": D})
