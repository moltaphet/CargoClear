"""Evidence authentication & shipment binding.

A settlement source only counts if its record is signed by the Ed25519 key the
contract holds for THAT witness slot and carries the shipment nonce derived from
the verified Bill of Lading id, container and vessel IMO. Everything else is an
unauthenticated payload: an outage that can not vote, not move money and not
block a retry. The signers here use `cryptography` (OpenSSL); the contract
verifies with its own pure-integer RFC 8032 code, so the two are independent.
"""

import json
import random

import pytest
from conftest import (
    BOL,
    CONTAINER,
    IMO,
    MAX_TEMP,
    NOT_FOUND,
    PRINCIPAL,
    T0,
    WITNESS_ROLES,
    WITNESSES,
    Carrier,
    binding_of,
    evidence_message,
    ok,
    record,
    sign_for_slot,
)

FOREIGN = Carrier(b"not-a-registered-witness-seed-00")


def _departed(**over):
    return record(status="VESSEL_DEPARTED", arrival_ts=0, peak_temp_tenths_c=0, **over)


def _body(rec):
    return {"status": 200, "body": json.dumps(rec)}


def _one_good_one_bad(world, bad_body, bad_slot=1, stage=1):
    """Slot 0 is honest; `bad_slot` serves `bad_body`; the rest 404. If the bad
    record were accepted it would corroborate slot 0 and settle -- so a verdict-2
    result with source_count 1 proves it was refused."""
    world.ready()
    if stage == 2:
        world.mock_feeds(*(ok(_departed()),) * 3)
        assert world.settle(1)["verdict"] == 1
    good = ok(_departed() if stage == 1 else record(peak_temp_tenths_c=MAX_TEMP - 5))
    feeds = [NOT_FOUND, NOT_FOUND, NOT_FOUND]
    feeds[0] = good
    feeds[bad_slot] = bad_body
    world.mock_feeds(*feeds)
    return world.settle(stage)


def _refused(out):
    return out["verdict"] == 2 and out["source_count"] == 1


# ------------------------------------------------------------ shared building blocks
def test_contract_message_and_binding_match_the_independent_statement(cc):
    rec = sign_for_slot(record(), 0)
    assert cc.canonical_evidence_message(rec) == evidence_message(rec)
    assert cc.evidence_binding(BOL, CONTAINER, IMO) == binding_of()
    # the nonce moves with each of the three shipment identifiers
    assert len({binding_of(), binding_of("BOL-2"), binding_of(container="MSKU0000001"), binding_of(imo="9321483")}) == 4


def test_the_three_witness_keys_are_distinct_and_not_the_carrier(witnesses, carrier):
    keys = {w.pub_hex for w in witnesses} | {carrier.pub_hex}
    assert len(keys) == 4


def test_valid_imo_matches_an_independent_check_digit_algorithm(cc):
    def reference(n: int) -> bool:
        d = [int(c) for c in f"{n:07d}"]
        return sum(d[i] * (7 - i) for i in range(6)) % 10 == d[6]

    rng = random.Random(7)
    for n in [rng.randrange(1_000_000, 10_000_000) for _ in range(3000)]:
        assert cc.valid_imo(str(n)) == reference(n), n
    for good in ("9074729", "9321483", "9811000", "8814275", "9136632"):
        assert cc.valid_imo(good), good
    for bad in ("", "123456", "12345678", "abcdefg", "9074720", " 907472", "9074729 ", "IMO9074729", "９０７４７２９", None, 9074729):
        assert not cc.valid_imo(bad), bad


# ------------------------------------------------------------ authentic evidence settles
def test_authentic_evidence_from_three_independent_keys_settles(world):
    world.ready()
    d = ok(_departed())
    world.mock_feeds(d, d, d)
    out = world.settle(1)
    assert out["verdict"] == 1 and out["source_count"] == 3
    st = world.state()
    assert st["evidence_binding"] == binding_of()
    assert st["stage1_evidence_digest"] == out["evidence_digest"]


def test_stage2_two_of_three_with_a_dissenting_witness(world):
    """Two witnesses record a +2.0 degC excursion; the third (AIS) sampled a clean
    reading. 2-of-3 independent corroboration settles BUCKET_2 with source_count 2."""
    world.ready()
    d = ok(_departed())
    world.mock_feeds(d, d, d)
    assert world.settle(1)["source_count"] == 3
    hot = ok(record(peak_temp_tenths_c=MAX_TEMP + 20))
    cold = ok(record(peak_temp_tenths_c=MAX_TEMP - 5))
    world.mock_feeds(hot, hot, cold)
    out = world.settle(2)
    assert out["verdict"] == 1 and out["bucket"] == 2 and out["source_count"] == 2


# ------------------------------------------------------------ unauthenticated payloads
def test_unsigned_legacy_records_are_all_outages(world):
    """The old v1 shape (plain JSON, no signature) can not settle anything."""
    world.ready()
    legacy = {
        "schema": "cargoclear.feed.v1",
        "bol_record_id": BOL,
        "lc_id": "LC-1",
        "container_id": CONTAINER,
        "status": "CUSTOMS_CLEARED",
        "departure_ts": T0 - 6 * 86400,
        "arrival_ts": T0 - 86400,
        "peak_temp_tenths_c": -185,
        "manifest_hash": "11" * 32,
        "event_ts": T0 - 3600,
    }
    world.mock_feeds(*(_body(legacy),) * 3)
    out = world.settle(1)
    assert out["verdict"] == 2 and out["source_count"] == 0
    assert world.state()["state"] == "ACTIVE" and not world.state()["stage1_settled"]


def test_v2_shape_without_a_signature_is_refused(world):
    rec = sign_for_slot(_departed(), 1)
    del rec["signature"]
    assert _refused(_one_good_one_bad(world, _body(rec)))


def test_a_structurally_perfect_record_from_an_unregistered_key_is_refused(world):
    rec = sign_for_slot(_departed(), 1, signer=FOREIGN)
    assert _refused(_one_good_one_bad(world, _body(rec)))


def test_the_carrier_authority_key_can_not_sign_settlement_evidence(world, carrier):
    rec = sign_for_slot(_departed(), 1, signer=carrier)
    assert _refused(_one_good_one_bad(world, _body(rec)))


@pytest.mark.parametrize("signer_slot", [0, 2])
def test_another_slots_witness_can_not_speak_for_this_slot(world, signer_slot):
    """Slot 1 is served a record correctly role-tagged for slot 1 but signed by a
    DIFFERENT registered witness: still refused (the key is per slot)."""
    rec = sign_for_slot(_departed(), 1, signer=WITNESSES[signer_slot])
    assert _refused(_one_good_one_bad(world, _body(rec)))


@pytest.mark.parametrize("role_slot", [0, 2])
def test_role_must_match_the_slot_even_with_the_right_key(world, role_slot):
    rec = dict(_departed(), role=WITNESS_ROLES[role_slot])
    rec = sign_for_slot(rec, 1)  # signed by slot 1's key over the wrong role
    assert _refused(_one_good_one_bad(world, _body(rec)))


def test_one_compromised_key_can_not_fill_two_slots(world):
    """Witness 0 signs three records, tagging them as three different roles. Only
    slot 0 verifies; slots 1 and 2 reject the foreign signature: no quorum."""
    world.ready()
    feeds = []
    for slot in range(3):
        rec = dict(_departed(), role=WITNESS_ROLES[slot])
        feeds.append(_body(sign_for_slot(rec, slot, signer=WITNESSES[0])))
    world.mock_feeds(*feeds)
    out = world.settle(1)
    assert _refused(out)
    assert world.state()["stage1_settled"] is False


@pytest.mark.parametrize(
    "field,tweak",
    [
        ("status", lambda _r: {"status": "CUSTOMS_CLEARED"}),
        ("departure_ts", lambda r: {"departure_ts": r["departure_ts"] - 1}),
        ("arrival_ts", lambda _r: {"arrival_ts": 1}),
        ("event_ts", lambda r: {"event_ts": r["event_ts"] - 1}),
        ("peak_temp_tenths_c", lambda _r: {"peak_temp_tenths_c": 1}),
    ],
)
def test_tampering_with_any_signed_field_after_signing_is_refused(world, field, tweak):
    """Each tweak leaves the record positive for Stage 1, so a lax verifier would
    count it. The signature covers the field, so it does not."""
    signed = sign_for_slot(_departed(), 1)
    tampered = {**signed, **tweak(signed)}
    assert tampered[field] != signed[field]
    assert _refused(_one_good_one_bad(world, _body(tampered)))


@pytest.mark.parametrize(
    "field,value",
    [
        ("bol_record_id", "BOL-OTHER"),
        ("container_id", "MSKU9999999"),
        ("vessel_imo", "9321483"),
        ("binding", binding_of("BOL-OTHER")),
    ],
)
def test_shipment_identity_fields_are_bound_even_when_re_signed(world, field, value):
    """The attacker is a REGISTERED witness lying about which shipment this is,
    re-signing correctly. The contract compares to the verified BoL/container/IMO."""
    rec = sign_for_slot({**_departed(), field: value}, 1)
    assert _refused(_one_good_one_bad(world, _body(rec)))


def test_consistent_but_foreign_shipment_evidence_is_refused(world):
    """Another ship's perfectly valid, correctly signed evidence: all identifiers and the
    nonce agree with each other, just not with THIS shipment's BoL."""
    other = _departed(
        bol_record_id="BOL-OTHER", container_id="MSKU0000001", vessel_imo="9321483",
        binding=binding_of("BOL-OTHER", "MSKU0000001", "9321483"),
    )
    assert _refused(_one_good_one_bad(world, ok(other)))


def test_evidence_replayed_from_a_previous_signature_over_other_content_is_refused(world):
    """A genuine signature by the right witness, but over a different message."""
    rec = _departed()
    rec["role"] = WITNESS_ROLES[1]
    rec["signature"] = WITNESSES[1].sign(evidence_message({**rec, "peak_temp_tenths_c": -300}))
    assert _refused(_one_good_one_bad(world, _body(rec)))


@pytest.mark.parametrize("bad_sig", ["", "00" * 64, "zz" * 64, "ab" * 63, "AB" * 64, "ab" * 65])
def test_garbage_signatures_are_refused(world, bad_sig):
    rec = {**sign_for_slot(_departed(), 1), "signature": bad_sig}
    assert _refused(_one_good_one_bad(world, _body(rec)))


def test_non_canonical_signature_scalar_is_refused(world):
    """S >= L (malleated) must not verify even though S mod L would."""
    L = 2**252 + 27742317777372353535851937790883648493
    rec = sign_for_slot(_departed(), 1)
    sig = bytes.fromhex(rec["signature"])
    s = int.from_bytes(sig[32:], "little") + L
    if s < 2**256:
        rec["signature"] = (sig[:32] + s.to_bytes(32, "little")).hex()
        assert _refused(_one_good_one_bad(world, _body(rec)))


def test_stage2_unauthenticated_witnesses_can_not_decide_a_haircut(world):
    """Two honest signed records say clean (bucket 0); an unregistered key shouts
    'spoiled'. The forged record is ignored and the honest pair settles."""
    world.ready()
    d = ok(_departed())
    world.mock_feeds(d, d, d)
    assert world.settle(1)["verdict"] == 1
    clean = ok(record(peak_temp_tenths_c=MAX_TEMP - 5))
    liar = ok(record(status="CUSTOMS_REJECTED"), signer=FOREIGN)
    world.mock_feeds(clean, clean, liar)
    out = world.settle(2)
    assert out["verdict"] == 1 and out["bucket"] == 0 and out["source_count"] == 2


def test_two_forged_rejections_can_not_trigger_a_refund(world):
    world.ready()
    liar = ok(record(status="VOYAGE_ABORTED"), signer=FOREIGN)
    world.mock_feeds(liar, liar, NOT_FOUND)
    out = world.settle(1)
    assert out["verdict"] == 2
    st = world.state()
    assert st["state"] == "ACTIVE" and st["importer_rebate"] == 0 and st["unreleased_escrow"] == PRINCIPAL


def test_authentic_rejections_still_refund(world):
    world.ready()
    ab = ok(record(status="VOYAGE_ABORTED"))
    world.mock_feeds(ab, ab, NOT_FOUND)
    out = world.settle(1)
    assert out["verdict"] == 0 and out["source_count"] == 2
    assert world.state()["state"] == "ABORTED_REFUNDED"


def test_a_failed_authentication_is_retryable_without_side_effects(world):
    world.ready()
    liar = ok(_departed(), signer=FOREIGN)
    world.mock_feeds(liar, liar, liar)
    assert world.settle(1)["verdict"] == 2
    assert world.state()["quorum_failures"] == 1
    good = ok(_departed())
    world.mock_feeds(good, good, good)
    assert world.settle(1)["verdict"] == 1


def test_validator_does_not_follow_a_leader_that_accepted_forged_evidence(world):
    """The leader claims a 3-source Stage-2 haircut backed by forgeries. A validator
    that re-fetches sees only one authenticated record, derives QUORUM_FAILURE and disagrees."""
    world.ready()
    d = ok(_departed())
    world.mock_feeds(d, d, d)
    out = world.settle(1)
    assert out["verdict"] == 1
    honest = ok(record(peak_temp_tenths_c=MAX_TEMP - 5))
    forged = ok(record(peak_temp_tenths_c=MAX_TEMP + 25), signer=FOREIGN)
    world.mock_feeds(honest, forged, forged)
    forged_leader = {
        "verdict": 1, "stage": 2, "bucket": 2, "source_count": 2,
        "evidence_digest": out["evidence_digest"], "event_ts": T0 - 3600,
    }
    assert world.vm.run_validator(leader_result=forged_leader) is False


# ------------------------------------------------------------ check_evidence view
def _check(world, slot, rec_or_text):
    text = rec_or_text if isinstance(rec_or_text, str) else json.dumps(rec_or_text)
    return world.contract.check_evidence("LC-1", slot, text)


@pytest.mark.parametrize("slot", [0, 1, 2])
def test_check_evidence_accepts_only_the_slots_own_authentic_record(world, slot):
    world.ready()
    rec = sign_for_slot(_departed(), slot)
    res = _check(world, slot, rec)
    assert res["authentic"] is True
    assert res["role"] == WITNESS_ROLES[slot]
    assert res["witness_pubkey"] == WITNESSES[slot].pub_hex
    assert res["binding"] == binding_of()
    for other in (s for s in range(3) if s != slot):
        assert _check(world, other, rec)["authentic"] is False


def test_check_evidence_rejects_tampering_foreign_keys_and_garbage(world):
    world.ready()
    rec = sign_for_slot(_departed(), 0)
    assert _check(world, 0, {**rec, "peak_temp_tenths_c": 7})["authentic"] is False
    assert _check(world, 0, sign_for_slot(_departed(), 0, signer=FOREIGN))["authentic"] is False
    assert _check(world, 0, {k: v for k, v in rec.items() if k != "signature"})["authentic"] is False
    assert _check(world, 0, {**rec, "vessel_imo": "9321483"})["authentic"] is False
    for junk in ("", "{}", "[]", "null", "not json", '{"a": 1.5}'):
        assert _check(world, 0, junk)["authentic"] is False


def test_check_evidence_guards(world):
    world.open()
    world.accept()
    rec = sign_for_slot(_departed(), 0)
    from conftest import assert_reverts

    assert_reverts("ERR_BOL_NOT_VERIFIED", world.contract.check_evidence, "LC-1", 0, json.dumps(rec))
    world.verify_bol()
    for bad_slot in (-1, 3, 99):
        assert_reverts("ERR_INVALID_PARAMS", world.contract.check_evidence, "LC-1", bad_slot, json.dumps(rec))
    assert_reverts("ERR_INVALID_PARAMS", world.contract.check_evidence, "LC-1", 0, "x" * 20000)
    assert_reverts("ERR_UNKNOWN_LC", world.contract.check_evidence, "LC-9", 0, json.dumps(rec))
