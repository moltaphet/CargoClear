"""Lifecycle, authorization, handshake timing, feed pinning, replay, liveness --
and a mutation harness that proves the suite notices when the contract is broken."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import (
    BOL,
    CARGO_HASH,
    CONTAINER,
    CONTRACT,
    IMO,
    LATEST,
    MAX_TEMP,
    NOT_FOUND,
    PRINCIPAL,
    ROOT,
    T0,
    WITNESSES,
    assert_reverts,
    binding_of,
    feed_urls,
    hex_of,
    ok,
    record,
)

HOUR = 3600
ACCEPT_DEADLINE = T0 + 48 * HOUR
GRACE = 7 * 86400
SETTLEMENT_WINDOW = 30 * 86400


def _departed(**kw):
    return ok(record(status="VESSEL_DEPARTED", arrival_ts=0, peak_temp_tenths_c=0, **kw))


def _cleared(peak=MAX_TEMP - 5, **kw):
    return ok(record(peak_temp_tenths_c=peak, **kw))


def _stage1(world):
    d = _departed()
    world.mock_feeds(d, d, d)
    return world.settle(1)


def _stage2(world, peak=MAX_TEMP - 5):
    c = _cleared(peak)
    world.mock_feeds(c, c, c)
    return world.settle(2)


# =============================================================== happy path
def test_full_lifecycle_clean_delivery(world):
    assert world.open() == "LC-1"
    assert world.state()["state"] == "PENDING_EXPORTER_ACCEPTANCE"
    world.accept()
    assert world.state()["state"] == "ACTIVE"
    world.verify_bol()
    assert _stage1(world)["verdict"] == 1
    assert world.state()["state"] == "STAGE_1_SETTLED"
    assert _stage2(world)["verdict"] == 1
    st = world.state()
    assert st["state"] == "COMPLETED" and st["final_bucket"] == 0
    assert st["exporter_claimable"] == PRINCIPAL and st["importer_rebate"] == 0
    world.as_(world.exporter)
    assert int(world.contract.claim_funds("LC-1")) == PRINCIPAL
    assert world.balance_of(world.exporter) == PRINCIPAL
    assert world.contract.verify_solvency_invariant()["solvent"]


def test_stage1_alone_lets_the_exporter_withdraw_twenty_percent(world):
    world.ready()
    _stage1(world)
    world.as_(world.exporter)
    assert int(world.contract.claim_funds("LC-1")) == PRINCIPAL * 2000 // 10000
    assert world.contract_balance() == PRINCIPAL - PRINCIPAL * 2000 // 10000
    assert world.contract.verify_solvency_invariant()["solvent"]


def test_summary_tracks_the_protocol(world):
    world.ready()
    s = world.contract.get_protocol_summary()
    assert s["lc_count"] == 1 and s["total_deposited"] == PRINCIPAL
    assert s["lc_state_counts"] == {"ACTIVE": 1}
    assert s["stage_1_bps"] == 2000 and s["stage_2_bps"] == 8000
    assert s["bucket_table_bps"] == [[8000, 0], [6000, 2000], [4000, 4000], [0, 8000]]
    assert s["witness_pubkeys"] == [w.pub_hex for w in WITNESSES]
    assert s["witness_roles"] == ["CARRIER_MANIFEST_WITNESS", "PORT_CUSTOMS_WITNESS", "COLD_CHAIN_AIS_WITNESS"]
    assert s["evidence_schema"] == "cargoclear.evidence.v2"


def test_get_evidence_sources_lists_three_distinct_keyed_witnesses(world):
    world.open()
    fs = world.contract.get_evidence_sources("LC-1")
    assert fs["vessel_imo"] == IMO and fs["evidence_binding"] == ""  # no BoL yet -> no binding
    hosts = [s["host"] for s in fs["sources"]]
    assert len(set(hosts)) == 3
    assert [s["url"] for s in fs["sources"]] == list(feed_urls())
    assert [s["role"] for s in fs["sources"]] == ["CARRIER_MANIFEST_WITNESS", "PORT_CUSTOMS_WITNESS", "COLD_CHAIN_AIS_WITNESS"]
    assert [s["witness_pubkey"] for s in fs["sources"]] == [w.pub_hex for w in WITNESSES]
    assert len({s["witness_pubkey"] for s in fs["sources"]}) == 3


def test_binding_is_published_once_the_bol_is_verified(world):
    world.ready()
    expect = binding_of()
    assert world.contract.get_evidence_sources("LC-1")["evidence_binding"] == expect
    assert world.state()["evidence_binding"] == expect
    assert world.contract.get_evidence_binding(BOL, CONTAINER, IMO) == expect
    assert_reverts("ERR_INVALID_PARAMS", world.contract.get_evidence_binding, BOL, CONTAINER, "9074720")


def test_unknown_views_revert(world):
    for fn in (world.contract.get_lc_state, world.contract.get_evidence_sources):
        assert_reverts("ERR_UNKNOWN_LC", fn, "LC-1")
        assert_reverts("ERR_UNKNOWN_LC", fn, "")
        assert_reverts("ERR_UNKNOWN_LC", fn, "lc-1")


def test_empty_protocol_is_trivially_solvent(world):
    inv = world.contract.verify_solvency_invariant()
    assert inv["solvent"] and inv["lc_count"] == 0 and inv["owed"] == 0


# ================================================================= opening
BAD_OPEN = {
    "zero_value": dict(principal=0),
    "dust_value": dict(principal=999),
    "exporter_not_hex": dict(exporter="exporter"),
    "exporter_short": dict(exporter="0x1234"),
    "exporter_no_prefix": dict(exporter="29b220d49cd6a1ed8396172f46fce4211ca0fa0d"),
    "exporter_uppercase": dict(exporter="0x" + "AB" * 20),
    "container_empty": dict(container_id=""),
    "container_pipe": dict(container_id="MSKU|123"),
    "container_long": dict(container_id="M" * 65),
    "container_space": dict(container_id="MSKU 123"),
    "imo_empty": dict(vessel_imo=""),
    "imo_short": dict(vessel_imo="907472"),
    "imo_long": dict(vessel_imo="90747290"),
    "imo_bad_check_digit": dict(vessel_imo="9074720"),
    "imo_letters": dict(vessel_imo="IMO90747"),
    "imo_prefixed": dict(vessel_imo="IMO9074729"),
    "imo_with_space": dict(vessel_imo="907 4729"),
    "cargo_hash_short": dict(cargo_spec_hash="ab" * 31),
    "cargo_hash_upper": dict(cargo_spec_hash="AB" * 32),
    "cargo_hash_nonhex": dict(cargo_spec_hash="zz" * 32),
    "temp_too_cold": dict(max_temp_tenths_c=-701),
    "temp_too_warm": dict(max_temp_tenths_c=501),
    "arrival_now": dict(latest_arrival_ts=T0),
    "arrival_past": dict(latest_arrival_ts=T0 - 1),
    "arrival_far_future": dict(latest_arrival_ts=T0 + 4 * 365 * 86400),
}


@pytest.mark.parametrize("name", sorted(BAD_OPEN))
def test_open_rejects_bad_parameters(world, name):
    over = dict(BAD_OPEN[name])
    principal = over.pop("principal", PRINCIPAL)
    code = "ERR_INVALID_PARAMS"
    if name in ("zero_value", "dust_value"):
        code = "ERR_PRINCIPAL_REQUIRED"
    elif name.startswith("imo_"):
        code = "ERR_INVALID_VESSEL_IMO"
    world.as_(world.importer)
    world.vm.value = principal
    args = dict(
        exporter=hex_of(world.exporter), container_id=CONTAINER, vessel_imo=IMO, cargo_spec_hash=CARGO_HASH,
        max_temp_tenths_c=MAX_TEMP, latest_arrival_ts=LATEST,
        feed_a_url=feed_urls()[0], feed_b_url=feed_urls()[1], feed_c_url=feed_urls()[2],
    )
    args.update(over)
    assert_reverts(code, world.contract.open_letter_of_credit, **args)
    assert world.contract.get_protocol_summary()["lc_count"] == 0


def test_importer_cannot_be_their_own_exporter(world):
    world.as_(world.importer)
    world.vm.value = PRINCIPAL
    assert_reverts(
        "ERR_INVALID_PARAMS", world.contract.open_letter_of_credit,
        exporter=hex_of(world.importer), container_id=CONTAINER, vessel_imo=IMO, cargo_spec_hash=CARGO_HASH,
        max_temp_tenths_c=MAX_TEMP, latest_arrival_ts=LATEST,
        feed_a_url=feed_urls()[0], feed_b_url=feed_urls()[1], feed_c_url=feed_urls()[2],
    )


@pytest.mark.parametrize("temp", [-700, -180, 0, 40, 500])
def test_open_accepts_the_full_temperature_range(world, temp):
    assert world.open(max_temp_tenths_c=temp) == "LC-1"
    assert world.state()["max_temp_tenths_c"] == temp


def test_open_records_terms_and_escrows_the_principal(world):
    world.open()
    st = world.state()
    assert st["importer"] == hex_of(world.importer) and st["exporter"] == hex_of(world.exporter)
    assert st["container_id"] == CONTAINER and st["cargo_spec_hash"] == CARGO_HASH
    assert st["vessel_imo"] == IMO
    assert st["total_deposited"] == st["unreleased_escrow"] == PRINCIPAL
    assert st["accept_deadline"] == ACCEPT_DEADLINE == st["created_at"] + 48 * HOUR
    assert world.contract_balance() == PRINCIPAL


def test_lc_ids_are_sequential_and_independent(world):
    assert [world.open(principal=p) for p in (2000, 3000, 4000)] == ["LC-1", "LC-2", "LC-3"]
    assert [world.state(f"LC-{i}")["total_deposited"] for i in (1, 2, 3)] == [2000, 3000, 4000]
    inv = world.contract.verify_solvency_invariant()
    assert inv["total_deposited"] == 9000 and inv["solvent"]


# ====================================================== witness endpoints
GOOD = list(feed_urls())


def _bad_urls():
    a, b, c = GOOD
    yield "http_scheme", 0, a.replace("https", "http")
    yield "no_scheme", 0, a[len("https://"):]
    yield "userinfo", 0, a.replace("https://", "https://user@")
    yield "port", 0, a.replace(".net/", ".net:8443/")
    yield "query", 0, a + "?x=1"
    yield "fragment", 0, a + "#frag"
    yield "ipv4_literal", 0, "https://203.0.113.7/v1/evidence/X1"
    yield "ipv6_literal", 0, "https://[2001:db8::1]/v1/evidence/X1"
    yield "single_label_host", 0, "https://localhost/v1/evidence/X1"
    yield "uppercase_host", 0, a.replace("carrier-witness", "Carrier-Witness")
    yield "underscore_host", 1, b.replace("customs-witness", "customs_witness")
    yield "leading_hyphen_label", 1, b.replace("customs-witness", "-customs")
    yield "trailing_dot_host", 2, c.replace(".com/", ".com./")
    yield "empty_label", 2, c.replace("ais-witness.example", "ais-witness..example")
    yield "idn_host", 0, a.replace("carrier-witness", "cärrier")
    yield "host_only", 0, "https://carrier-witness.example.net"
    yield "host_trailing_slash_only", 0, "https://carrier-witness.example.net/"
    yield "traversal", 0, a.replace("/v1/", "/v1/../v1/")
    yield "double_slash", 0, a.replace("/v1/evidence", "/v1//evidence")
    yield "percent_encoding", 0, a.replace("evidence", "evid%65nce")
    yield "backslash", 0, a.replace("/v1/evidence", "\\v1\\evidence")
    yield "space_in_path", 0, a.replace("evidence", "evi dence")
    yield "empty", 0, ""
    yield "too_long", 0, a + "x" * 1100
    # a git repository behind a CDN is one publisher, not a witness
    yield "raw_github_mirror", 0, f"https://raw.githubusercontent.com/moltaphet/CargoClear/{'a' * 40}/x/LC-1.json"
    yield "jsdelivr_mirror", 1, f"https://cdn.jsdelivr.net/gh/moltaphet/CargoClear@{'a' * 40}/x/LC-1.json"
    yield "githack_mirror", 2, f"https://raw.githack.com/moltaphet/CargoClear/{'a' * 40}/x/LC-1.json"
    yield "github_pages", 0, "https://moltaphet.github.io/CargoClear/evidence/X1"
    yield "gitlab_pages", 1, "https://moltaphet.gitlab.io/cargoclear/evidence/X1"
    yield "mirror_subdomain", 0, "https://a.b.githubusercontent.com/evidence/X1"


BAD_URLS = list(_bad_urls())


def _open_raw(world, urls, **over):
    world.as_(world.importer)
    world.vm.value = PRINCIPAL
    args = dict(
        exporter=hex_of(world.exporter), container_id=CONTAINER, vessel_imo=IMO, cargo_spec_hash=CARGO_HASH,
        max_temp_tenths_c=MAX_TEMP, latest_arrival_ts=LATEST,
        feed_a_url=urls[0], feed_b_url=urls[1], feed_c_url=urls[2],
    )
    args.update(over)
    return world.contract.open_letter_of_credit(**args)


@pytest.mark.parametrize("name,idx,url", BAD_URLS, ids=[b[0] for b in BAD_URLS])
def test_witness_endpoint_rules_reject(world, name, idx, url):
    urls = list(GOOD)
    urls[idx] = url
    assert_reverts("ERR_INVALID_FEED_URL", _open_raw, world, urls)
    assert world.contract.get_protocol_summary()["lc_count"] == 0


@pytest.mark.parametrize("pair", [(0, 1), (0, 2), (1, 2)])
def test_one_host_cannot_serve_two_witness_slots(world, pair):
    """Three slots on one host would be one transport path, one outage domain."""
    urls = list(GOOD)
    urls[pair[1]] = urls[pair[0]].replace("/evidence/", "/other/")
    assert_reverts("ERR_INVALID_FEED_URL", _open_raw, world, urls)


def test_distinct_hosts_on_one_domain_are_accepted(world):
    """Distinct hostnames are the contract's transport rule; operator independence
    is carried by the witness KEYS (see test_evidence_auth)."""
    urls = [f"https://{n}.shared-platform.example/v1/evidence/{CONTAINER}" for n in ("w1", "w2", "w3")]
    assert _open_raw(world, urls) == "LC-1"


def test_witness_urls_are_not_pinned_to_any_repository(world):
    urls = [f"https://{n}.{d}/anything/at/all/{CONTAINER}" for n, d in (("a", "one.example"), ("b", "two.example"), ("c", "three.example"))]
    assert _open_raw(world, urls) == "LC-1"
    assert [s["url"] for s in world.contract.get_evidence_sources("LC-1")["sources"]] == urls


def test_validate_evidence_urls_returns_the_hosts(cc):
    assert cc.validate_evidence_urls(GOOD) == [
        "carrier-witness.example.net",
        "customs-witness.example.org",
        "ais-witness.example.com",
    ]


@pytest.mark.parametrize("name", ["LC-1.json", "a_b.c-d", "X" * 59, "shipment.2026.json", "MSKU1234567"])
def test_path_tails_that_are_allowed(cc, name):
    urls = [u.rsplit("/", 1)[0] + "/" + name for u in GOOD]
    assert cc.validate_evidence_urls(urls) == [
        "carrier-witness.example.net",
        "customs-witness.example.org",
        "ais-witness.example.com",
    ]


# ======================================================= 48h exporter handshake
def test_exporter_accepts_inside_the_window(world):
    world.open()
    world.warp(ACCEPT_DEADLINE)  # the deadline itself is still inside the window
    world.accept()
    assert world.state()["state"] == "ACTIVE"


def test_acceptance_after_48h_is_refused(world):
    world.open()
    world.warp(ACCEPT_DEADLINE + 1)
    world.as_(world.exporter)
    assert_reverts("ERR_ACCEPTANCE_WINDOW_CLOSED", world.contract.accept_lc_terms, "LC-1")


def test_only_the_named_exporter_may_accept_or_reject(world):
    world.open()
    for who in (world.importer, world.stranger):
        world.as_(who)
        assert_reverts("ERR_UNAUTHORIZED_PARTY", world.contract.accept_lc_terms, "LC-1")
        assert_reverts("ERR_UNAUTHORIZED_PARTY", world.contract.reject_lc_terms, "LC-1")


def test_exporter_rejection_then_importer_reclaims_everything(world):
    world.open()
    world.as_(world.exporter)
    assert world.contract.reject_lc_terms("LC-1") == "REJECTED_BY_EXPORTER"
    world.as_(world.importer)
    assert world.contract.cancel_unaccepted_lc("LC-1") == "CANCELLED"
    st = world.state()
    assert st["importer_rebate"] == PRINCIPAL and st["unreleased_escrow"] == 0
    assert int(world.contract.claim_funds("LC-1")) == PRINCIPAL
    assert world.contract_balance() == 0
    assert world.contract.verify_solvency_invariant()["solvent"]


def test_cancel_unaccepted_after_48h(world):
    world.open()
    world.warp(ACCEPT_DEADLINE + 1)
    world.as_(world.importer)
    assert world.contract.cancel_unaccepted_lc("LC-1") == "CANCELLED"
    assert world.state()["importer_rebate"] == PRINCIPAL


def test_cancel_inside_the_window_is_refused(world):
    world.open()
    world.as_(world.importer)
    assert_reverts("ERR_NOT_YET_AVAILABLE", world.contract.cancel_unaccepted_lc, "LC-1")
    world.warp(ACCEPT_DEADLINE)
    assert_reverts("ERR_NOT_YET_AVAILABLE", world.contract.cancel_unaccepted_lc, "LC-1")


def test_only_the_importer_may_cancel(world):
    world.open()
    world.warp(ACCEPT_DEADLINE + 1)
    for who in (world.exporter, world.stranger):
        world.as_(who)
        assert_reverts("ERR_UNAUTHORIZED_PARTY", world.contract.cancel_unaccepted_lc, "LC-1")


def test_cannot_cancel_an_accepted_lc(world):
    world.open()
    world.accept()
    world.warp(ACCEPT_DEADLINE + 10)
    world.as_(world.importer)
    assert_reverts("ERR_INVALID_STATE", world.contract.cancel_unaccepted_lc, "LC-1")


def test_cannot_accept_after_rejecting_or_cancelling(world):
    world.open()
    world.as_(world.exporter)
    world.contract.reject_lc_terms("LC-1")
    assert_reverts("ERR_INVALID_STATE", world.contract.accept_lc_terms, "LC-1")
    assert_reverts("ERR_INVALID_STATE", world.contract.reject_lc_terms, "LC-1")


def test_cannot_accept_twice(world):
    world.open()
    world.accept()
    world.as_(world.exporter)
    assert_reverts("ERR_INVALID_STATE", world.contract.accept_lc_terms, "LC-1")
    assert_reverts("ERR_INVALID_STATE", world.contract.reject_lc_terms, "LC-1")


def test_cancel_twice_cannot_double_credit(world):
    world.open()
    world.warp(ACCEPT_DEADLINE + 1)
    world.as_(world.importer)
    world.contract.cancel_unaccepted_lc("LC-1")
    assert_reverts("ERR_INVALID_STATE", world.contract.cancel_unaccepted_lc, "LC-1")
    assert world.state()["importer_rebate"] == PRINCIPAL


def test_settlement_impossible_before_acceptance(world):
    world.open()
    world.as_(world.importer)
    assert_reverts("ERR_BOL_NOT_VERIFIED", world.contract.settle_shipment_stage, "LC-1", 1)


def test_bol_impossible_before_acceptance(world):
    world.open()
    world.as_(world.importer)
    assert_reverts("ERR_INVALID_STATE", world.contract.verify_bill_of_lading, "LC-1", BOL, world.sign_bol())


# ======================================================== staging / replay
def test_stage_must_be_one_or_two(world):
    world.ready()
    world.as_(world.importer)
    for stage in (0, 3, -1, 99):
        assert_reverts("ERR_INVALID_STAGE", world.contract.settle_shipment_stage, "LC-1", stage)


def test_stage2_cannot_precede_stage1(world):
    world.ready()
    c = _cleared()
    world.mock_feeds(c, c, c)
    world.as_(world.importer)
    assert_reverts("ERR_INVALID_STATE", world.contract.settle_shipment_stage, "LC-1", 2)


def test_stage1_cannot_be_settled_twice(world):
    world.ready()
    _stage1(world)
    world.as_(world.importer)
    assert_reverts("ERR_INVALID_STATE", world.contract.settle_shipment_stage, "LC-1", 1)
    assert world.state()["exporter_claimable"] == PRINCIPAL * 2000 // 10000


def test_stage2_cannot_be_settled_twice(world):
    world.ready()
    _stage1(world)
    _stage2(world)
    world.as_(world.importer)
    assert_reverts("ERR_INVALID_STATE", world.contract.settle_shipment_stage, "LC-1", 2)
    st = world.state()
    assert st["exporter_claimable"] + st["importer_rebate"] == PRINCIPAL


def test_a_settled_lc_cannot_be_replayed_with_flipped_feeds(world):
    world.ready()
    _stage1(world)
    _stage2(world)  # clean -> exporter gets everything
    rej = ok(record(status="CUSTOMS_REJECTED"))
    world.mock_feeds(rej, rej, rej)
    world.as_(world.importer)
    assert_reverts("ERR_INVALID_STATE", world.contract.settle_shipment_stage, "LC-1", 2)
    assert world.state()["final_bucket"] == 0


def test_only_lc_parties_can_trigger_settlement(world):
    world.ready()
    world.as_(world.stranger)
    assert_reverts("ERR_UNAUTHORIZED_PARTY", world.contract.settle_shipment_stage, "LC-1", 1)


def test_exporter_can_trigger_settlement_too(world):
    world.ready()
    d = _departed()
    world.mock_feeds(d, d, d)
    assert world.settle(1, who=world.exporter)["verdict"] == 1


def test_stage1_departure_after_deadline_does_not_unlock(world):
    world.ready()
    late = ok(record(status="VESSEL_DEPARTED", departure_ts=LATEST + 1, arrival_ts=0, peak_temp_tenths_c=0, event_ts=T0 - 10))
    world.mock_feeds(late, late, late)
    out = world.settle(1)
    assert out["verdict"] == 2 and out["source_count"] == 0
    assert world.state()["stage1_settled"] is False


def test_stage1_departure_exactly_at_deadline_unlocks(world):
    world.ready()
    edge = ok(record(status="VESSEL_DEPARTED", departure_ts=T0 - 10, arrival_ts=0, peak_temp_tenths_c=0))
    world.mock_feeds(edge, edge, edge)
    assert world.settle(1)["verdict"] == 1


def test_stage1_zero_departure_does_not_unlock(world):
    world.ready()
    z = ok(record(status="VESSEL_DEPARTED", departure_ts=0, arrival_ts=0, peak_temp_tenths_c=0))
    world.mock_feeds(z, z, z)
    assert world.settle(1)["verdict"] == 2


@pytest.mark.parametrize("status", ["VESSEL_DEPARTED", "CUSTOMS_CLEARED", "CUSTOMS_REJECTED"])
def test_stage1_accepts_any_record_proving_departure(world, status):
    world.ready()
    r = ok(record(status=status))
    world.mock_feeds(r, r, NOT_FOUND)
    assert world.settle(1)["verdict"] == 1


def test_stage2_with_vessel_still_at_sea_is_lag_not_failure_of_cargo(world):
    world.ready()
    _stage1(world)
    d = _departed()
    world.mock_feeds(d, d, d)
    out = world.settle(2)
    assert out["verdict"] == 2 and out["source_count"] == 0
    assert world.state()["state"] == "STAGE_1_SETTLED"


def test_records_for_a_different_shipment_are_ignored(world):
    world.ready()
    other = ok(record(status="VESSEL_DEPARTED", container_id="MSKU9999999"))
    world.mock_feeds(other, other, other)
    assert world.settle(1)["verdict"] == 2


def test_voyage_aborted_before_departure_refunds_everything(world):
    world.ready()
    ab = ok(record(status="VOYAGE_ABORTED"))
    world.mock_feeds(ab, ab, NOT_FOUND)
    out = world.settle(1)
    assert out["verdict"] == 0 and out["bucket"] == 3
    st = world.state()
    assert st["state"] == "ABORTED_REFUNDED"
    assert st["importer_rebate"] == PRINCIPAL and st["exporter_claimable"] == 0
    world.as_(world.importer)
    assert int(world.contract.claim_funds("LC-1")) == PRINCIPAL
    assert_reverts("ERR_INVALID_STATE", world.contract.settle_shipment_stage, "LC-1", 1)


def test_customs_rejection_after_departure_refunds_stage2_only(world):
    world.ready()
    _stage1(world)
    rej = ok(record(status="CUSTOMS_REJECTED"))
    world.mock_feeds(rej, rej, NOT_FOUND)
    out = world.settle(2)
    assert out["verdict"] == 0 and out["bucket"] == 3 and out["source_count"] == 2
    st = world.state()
    assert st["exporter_claimable"] == PRINCIPAL * 2000 // 10000
    assert st["importer_rebate"] == PRINCIPAL - PRINCIPAL * 2000 // 10000


def test_single_rejection_never_confiscates(world):
    world.ready()
    _stage1(world)
    rej = ok(record(status="CUSTOMS_REJECTED"))
    world.mock_feeds(rej, NOT_FOUND, NOT_FOUND)
    assert world.settle(2)["verdict"] == 2
    assert world.state()["importer_rebate"] == 0


def test_quorum_failure_counter_and_retry(world):
    world.ready()
    for i in range(3):
        world.mock_feeds(NOT_FOUND, NOT_FOUND, NOT_FOUND)
        assert world.settle(1)["verdict"] == 2
        assert world.state()["quorum_failures"] == i + 1
    d = _departed()
    world.mock_feeds(d, d, d)
    assert world.settle(1)["verdict"] == 1


# ============================================================== claims
def test_stranger_cannot_claim(world):
    world.ready()
    _stage1(world)
    world.as_(world.stranger)
    assert_reverts("ERR_UNAUTHORIZED_PARTY", world.contract.claim_funds, "LC-1")


def test_importer_cannot_claim_the_exporters_share(world):
    world.ready()
    _stage1(world)
    world.as_(world.importer)
    assert_reverts("ERR_NO_CLAIMABLE_BALANCE", world.contract.claim_funds, "LC-1")


def test_claim_on_unknown_lc(world):
    world.as_(world.exporter)
    assert_reverts("ERR_UNKNOWN_LC", world.contract.claim_funds, "LC-1")


def test_double_claim_pays_once(world):
    world.ready()
    _stage1(world)
    world.as_(world.exporter)
    first = int(world.contract.claim_funds("LC-1"))
    assert_reverts("ERR_NO_CLAIMABLE_BALANCE", world.contract.claim_funds, "LC-1")
    assert len(world.transfers) == 1 and world.transfers[0][1] == first


def test_failed_transfer_restores_the_balance(world, monkeypatch):
    world.ready()
    _stage1(world)

    def boom(vm, request):
        if "EmitInternalMessage" in request:
            raise RuntimeError("enqueue failed")
        return None

    world.vm._gl_call_hook = boom
    world.as_(world.exporter)
    assert_reverts("ERR_TRANSFER_FAILED_RESTORED", world.contract.claim_funds, "LC-1")
    st = world.state()
    assert st["exporter_claimable"] == PRINCIPAL * 2000 // 10000 and st["exporter_withdrawn"] == 0
    world.vm._gl_call_hook = world._on_gl_call
    assert int(world.contract.claim_funds("LC-1")) == PRINCIPAL * 2000 // 10000


def test_partial_then_final_claim(world):
    world.ready()
    _stage1(world)
    world.as_(world.exporter)
    part = int(world.contract.claim_funds("LC-1"))
    _stage2(world)
    world.as_(world.exporter)
    rest = int(world.contract.claim_funds("LC-1"))
    assert part + rest == PRINCIPAL
    assert world.contract_balance() == 0


def test_contract_never_pays_out_more_than_deposited_across_lcs(world):
    for _ in range(3):
        world.open(principal=777_777_777_777_777_779)
    for n in (1, 2, 3):
        world.as_(world.exporter)
        world.contract.accept_lc_terms(f"LC-{n}")
        world.verify_bol(f"LC-{n}", f"BOL-{n}")
    for n in (1, 2, 3):
        pass
    assert world.contract.verify_solvency_invariant()["solvent"]
    world.warp(LATEST + GRACE + SETTLEMENT_WINDOW + 1)
    world.as_(world.importer)
    for n in (1, 2, 3):
        world.contract.reclaim_expired_lc(f"LC-{n}")
        assert int(world.contract.claim_funds(f"LC-{n}")) == 777_777_777_777_777_779
    assert world.contract_balance() == 0
    assert world.contract.verify_solvency_invariant()["solvent"]


# ======================================================== liveness / expiry
def test_reclaim_expired_boundaries(world):
    world.ready()
    cutoff = LATEST + GRACE + SETTLEMENT_WINDOW
    world.as_(world.importer)
    world.warp(cutoff)
    assert_reverts("ERR_NOT_YET_AVAILABLE", world.contract.reclaim_expired_lc, "LC-1")
    world.warp(cutoff + 1)
    assert world.contract.reclaim_expired_lc("LC-1") == "EXPIRED_REFUNDED"
    assert world.state()["importer_rebate"] == PRINCIPAL


def test_reclaim_after_stage1_returns_only_the_remainder(world):
    world.ready()
    _stage1(world)
    world.warp(LATEST + GRACE + SETTLEMENT_WINDOW + 1)
    world.as_(world.importer)
    world.contract.reclaim_expired_lc("LC-1")
    st = world.state()
    s1 = PRINCIPAL * 2000 // 10000
    assert st["exporter_claimable"] == s1 and st["importer_rebate"] == PRINCIPAL - s1
    assert world.contract.verify_solvency_invariant()["solvent"]


def test_only_importer_can_reclaim(world):
    world.ready()
    world.warp(LATEST + GRACE + SETTLEMENT_WINDOW + 1)
    for who in (world.exporter, world.stranger):
        world.as_(who)
        assert_reverts("ERR_UNAUTHORIZED_PARTY", world.contract.reclaim_expired_lc, "LC-1")


@pytest.mark.parametrize("terminal", ["completed", "cancelled", "rejected"])
def test_cannot_reclaim_a_closed_lc(world, terminal):
    if terminal == "completed":
        world.ready()
        _stage1(world)
        _stage2(world)
    elif terminal == "cancelled":
        world.open()
        world.warp(ACCEPT_DEADLINE + 1)
        world.as_(world.importer)
        world.contract.cancel_unaccepted_lc("LC-1")
    else:
        world.open()
        world.as_(world.exporter)
        world.contract.reject_lc_terms("LC-1")
    world.warp(LATEST + GRACE + SETTLEMENT_WINDOW + 1)
    world.as_(world.importer)
    assert_reverts("ERR_INVALID_STATE", world.contract.reclaim_expired_lc, "LC-1")


def test_cannot_settle_after_expiry_refund(world):
    world.ready()
    world.warp(LATEST + GRACE + SETTLEMENT_WINDOW + 1)
    world.as_(world.importer)
    world.contract.reclaim_expired_lc("LC-1")
    c = _departed()
    world.mock_feeds(c, c, c)
    assert_reverts("ERR_INVALID_STATE", world.contract.settle_shipment_stage, "LC-1", 1)


# ============================================================ adversarial
def _public_methods():
    """{name: decorator text} for every @gl.public.* method, read from the source."""
    import ast

    tree = ast.parse(Path(CONTRACT).read_text())
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for dec in node.decorator_list:
                text = ast.unparse(dec)
                if text.startswith("gl.public"):
                    out[node.name] = text
    return out


def test_only_open_letter_of_credit_is_payable():
    payable = [n for n, d in _public_methods().items() if "payable" in d]
    assert payable == ["open_letter_of_credit"]


def test_a_witness_signing_for_another_shipment_cannot_split_or_join_the_quorum(world):
    """Validly signed evidence bound to a DIFFERENT bill of lading is not evidence
    about this container: it is an outage, so it can neither add to nor split quorum."""
    world.ready()
    _stage1(world)
    a = ok(record(peak_temp_tenths_c=MAX_TEMP - 5))
    b = ok(record(peak_temp_tenths_c=MAX_TEMP - 5, bol_record_id="BOL-OTHER", binding=binding_of("BOL-OTHER")))
    c = ok(record(peak_temp_tenths_c=MAX_TEMP - 5, bol_record_id="BOL-OTHER", binding=binding_of("BOL-OTHER")))
    world.mock_feeds(a, b, c)
    out = world.settle(2)
    assert out["verdict"] == 2 and out["source_count"] == 1


def test_two_colluding_sources_are_outvoted_only_when_they_disagree_with_each_other(world):
    world.ready()
    _stage1(world)
    honest = ok(record(peak_temp_tenths_c=MAX_TEMP - 5))
    lie1 = ok(record(peak_temp_tenths_c=MAX_TEMP + 25))
    lie2 = ok(record(peak_temp_tenths_c=MAX_TEMP + 25))
    world.mock_feeds(honest, lie1, lie2)
    out = world.settle(2)
    assert out["bucket"] == 2 and out["source_count"] == 2  # 2-of-3 is the trust assumption


def test_exporter_cannot_fund_or_alter_anyone_elses_lc(world):
    world.ready()
    world.as_(world.exporter)
    world.vm.value = 10_000
    assert_reverts("ERR_UNAUTHORIZED_PARTY", world.contract.cancel_unaccepted_lc, "LC-1")


def test_double_spend_of_one_principal_across_two_lcs_is_impossible(world):
    world.open(principal=2_000)
    world.open(principal=3_000)
    assert world.contract_balance() == 5_000
    assert world.contract.verify_solvency_invariant()["total_deposited"] == 5_000


def test_state_after_a_reverted_call_is_untouched(world):
    world.ready()
    before = world.state()
    world.as_(world.stranger)
    for fn, args in (
        (world.contract.accept_lc_terms, ("LC-1",)),
        (world.contract.claim_funds, ("LC-1",)),
        (world.contract.settle_shipment_stage, ("LC-1", 1)),
        (world.contract.reclaim_expired_lc, ("LC-1",)),
    ):
        assert world_revert(fn, *args)
    assert world.state() == before


def world_revert(fn, *args):
    from conftest import revert_message

    return revert_message(fn, *args) is not None


def test_contract_does_not_import_anything_nondeterministic(cc):
    src = Path(CONTRACT).read_text()
    for banned in ("import random", "import time", "import os", "import requests", "urllib.request", "exec_prompt"):
        assert banned not in src, banned


def test_contract_exposes_exactly_the_documented_surface():
    methods = _public_methods()
    writes = {n for n, d in methods.items() if d.startswith("gl.public.write")}
    views = {n for n, d in methods.items() if d == "gl.public.view"}
    assert writes == {
        "open_letter_of_credit", "accept_lc_terms", "reject_lc_terms", "cancel_unaccepted_lc",
        "verify_bill_of_lading", "settle_shipment_stage", "reclaim_expired_lc", "claim_funds",
    }
    assert {
        "get_lc_state", "get_protocol_summary", "get_evidence_sources", "get_evidence_binding", "check_evidence", "verify_solvency_invariant",
        "get_bol_message", "check_bol_attestation", "preview_settlement", "preview_bucket",
    } == views
    # there is deliberately no admin, no pause, no upgrade, no fee-taking path
    for forbidden in ("owner", "withdraw_all", "drain", "pause", "upgrade", "set_fee", "set_pubkey", "rotate"):
        assert not any(forbidden in n for n in methods), forbidden


# ================================================== safe fetch / O(1) summary
class _Resp:
    def __init__(self, **kw):
        self.__dict__.update(kw)


GOOD_BODY = json.dumps(record()).encode()


@pytest.mark.parametrize(
    "name,resp,kind",
    [
        ("no_status_attr", _Resp(body=GOOD_BODY), "OUT"),
        ("status_none", _Resp(status=None, body=GOOD_BODY), "OUT"),
        ("status_str", _Resp(status="200", body=GOOD_BODY), "OUT"),
        ("status_bool", _Resp(status=True, body=GOOD_BODY), "OUT"),
        ("status_float", _Resp(status=200.0, body=GOOD_BODY), "OUT"),
        ("no_body_attr", _Resp(status=200), "OUT"),
        ("body_none", _Resp(status=200, body=None), "OUT"),
        ("body_empty", _Resp(status=200, body=b""), "OUT"),
        ("body_int", _Resp(status=200, body=5), "OUT"),
        ("body_bad_utf8", _Resp(status=200, body=b"\xff\xfe"), "OUT"),
        ("plain_object", object(), "OUT"),
        ("none_response", None, "OUT"),
        ("dict_without_status", {"body": GOOD_BODY}, "OUT"),
        ("dict_404", {"status": 404, "body": b""}, "LAG"),
        ("obj_404", _Resp(status=404), "LAG"),
        ("obj_ok", _Resp(status=200, body=GOOD_BODY), "POS"),
        ("dict_ok", {"status": 200, "body": GOOD_BODY}, "POS"),
        ("bytearray_ok", _Resp(status=200, body=bytearray(GOOD_BODY)), "POS"),
    ],
)
def test_fetch_source_never_raises_on_odd_responses(world, cc, monkeypatch, name, resp, kind):
    monkeypatch.setattr(cc.gl.nondet.web, "get", lambda url, **kw: resp)
    got, _ = cc.fetch_source("https://example.invalid/x.json")
    assert got == kind


def test_fetch_source_treats_a_raising_fetch_as_outage(world, cc, monkeypatch):
    def boom(url, **kw):
        raise RuntimeError("rpc outlier")

    monkeypatch.setattr(cc.gl.nondet.web, "get", boom)
    assert cc.fetch_source("https://example.invalid/x.json")[0] == "OUT"


def test_malformed_response_cannot_revert_settlement(world, monkeypatch, cc):
    """A broken fetch is an outage that cannot vote: settlement returns a retryable
    QUORUM_FAILURE instead of reverting the transaction."""
    world.ready()
    monkeypatch.setattr(cc.gl.nondet.web, "get", lambda url, **kw: _Resp(body=GOOD_BODY))
    out = world.settle(1)
    assert out["verdict"] == 2 and out["source_count"] == 0
    assert world.state()["stage1_settled"] is False


def _recount(world, n):
    counts, unreleased = {}, 0
    for i in range(1, n + 1):
        st = world.state(f"LC-{i}")
        counts[st["state"]] = counts.get(st["state"], 0) + 1
        unreleased += st["unreleased_escrow"]
    return counts, unreleased


def _assert_summary_consistent(world, n):
    s = world.contract.get_protocol_summary()
    counts, unreleased = _recount(world, n)
    assert s["lc_state_counts"] == counts
    assert s["unreleased_escrow"] == unreleased
    assert s["lc_count"] == n
    assert world.contract.verify_solvency_invariant()["unreleased_escrow"] == unreleased


def test_summary_counters_track_every_transition(world):
    world.open(principal=PRINCIPAL)  # LC-1 -> completed
    world.open(principal=5_000)  # LC-2 -> rejected + cancelled
    world.open(principal=7_001)  # LC-3 -> unaccepted + cancelled after 48h
    world.open(principal=9_999)  # LC-4 -> accepted, expires
    world.open(principal=3_333)  # LC-5 -> stays pending
    world.open(principal=8_888)  # LC-6 -> aborted before departure
    _assert_summary_consistent(world, 6)
    world.accept("LC-1")
    world.verify_bol("LC-1", BOL)
    _stage1(world)
    _assert_summary_consistent(world, 6)
    _stage2(world)
    _assert_summary_consistent(world, 6)
    world.as_(world.exporter)
    world.contract.reject_lc_terms("LC-2")
    _assert_summary_consistent(world, 6)
    world.as_(world.importer)
    world.contract.cancel_unaccepted_lc("LC-2")
    _assert_summary_consistent(world, 6)
    world.as_(world.exporter)
    world.contract.accept_lc_terms("LC-4")
    world.contract.accept_lc_terms("LC-6")
    world.verify_bol("LC-6", "BOL-6")
    ab = ok(record(status="VOYAGE_ABORTED", bol_record_id="BOL-6", binding=binding_of("BOL-6")))
    world.mock_feeds(ab, ab, ab)
    world.as_(world.importer)
    assert json.loads(world.contract.settle_shipment_stage("LC-6", 1))["verdict"] == 0
    _assert_summary_consistent(world, 6)
    world.warp(ACCEPT_DEADLINE + 1)
    world.as_(world.importer)
    world.contract.cancel_unaccepted_lc("LC-3")
    _assert_summary_consistent(world, 6)
    world.warp(LATEST + GRACE + SETTLEMENT_WINDOW + 1)
    world.as_(world.importer)
    world.contract.reclaim_expired_lc("LC-4")
    _assert_summary_consistent(world, 6)
    s = world.contract.get_protocol_summary()
    assert s["lc_state_counts"] == {
        "COMPLETED": 1, "CANCELLED": 2, "EXPIRED_REFUNDED": 1, "PENDING_EXPORTER_ACCEPTANCE": 1,
        "ABORTED_REFUNDED": 1,
    }
    assert s["unreleased_escrow"] == 3_333


def test_summary_does_not_scan_the_letters(world):
    """get_protocol_summary must stay O(1): it reads counters, never the LC map."""
    import ast

    src = Path(CONTRACT).read_text()
    fn = next(
        n for n in ast.walk(ast.parse(src))
        if isinstance(n, ast.FunctionDef) and n.name == "get_protocol_summary"
    )
    assert not any(isinstance(n, (ast.For, ast.While, ast.ListComp)) and "lcs" in ast.unparse(n) for n in ast.walk(fn))
    assert "self.lcs" not in ast.unparse(fn)


# ====================================================== mutation analysis
MUTATIONS = [
    # --- money math
    ("stage1_bps", "STAGE_1_BPS = 2000", "STAGE_1_BPS = 2001"),
    ("stage2_bps", "STAGE_2_BPS = 8000", "STAGE_2_BPS = 7999"),
    ("bucket1_importer_share", "(6000, 2000)", "(6000, 2500)"),
    ("bucket2_split", "(4000, 4000)", "(4500, 3500)"),
    ("bucket3_refund", "(0, 8000)", "(500, 7500)"),
    ("thermal_tolerance", "THERMAL_TOLERANCE_TENTHS = 30", "THERMAL_TOLERANCE_TENTHS = 31"),
    ("spoiled_boundary", "if peak_temp > max_temp + THERMAL_TOLERANCE_TENTHS:", "if peak_temp >= max_temp + THERMAL_TOLERANCE_TENTHS:"),
    ("grace_boundary", "if arrival_ts > latest_arrival_ts + GRACE_SECONDS:", "if arrival_ts >= latest_arrival_ts + GRACE_SECONDS:"),
    ("grace_length", "GRACE_SECONDS = 7 * 24 * 3600", "GRACE_SECONDS = 6 * 24 * 3600"),
    ("drift_boundary", "    if peak_temp > max_temp:\n        bucket = BUCKET_2_MINOR_THERMAL_DRIFT", "    if peak_temp >= max_temp:\n        bucket = BUCKET_2_MINOR_THERMAL_DRIFT"),
    ("late_boundary", "    if arrival_ts > latest_arrival_ts:\n        bucket = BUCKET_1_LATE_DEMURRAGE", "    if arrival_ts >= latest_arrival_ts:\n        bucket = BUCKET_1_LATE_DEMURRAGE"),
    ("dust_to_wrong_party", "    if bucket == BUCKET_0_CLEAN_DELIVERY:\n        exporter += dust", "    if bucket != BUCKET_0_CLEAN_DELIVERY:\n        exporter += dust"),
    ("dust_dropped", "        importer += dust\n    return exporter, importer", "        importer += 0\n    return exporter, importer"),
    ("stage1_not_deducted", "            lc.unreleased = int(lc.unreleased) - amount\n            lc.stage1_settled = True", "            lc.stage1_settled = True"),
    ("stage2_not_deducted", "        lc.unreleased = int(lc.unreleased) - exporter - importer", "        lc.unreleased = int(lc.unreleased)"),
    ("credit_all_leaves_escrow", "        lc.importer_credited = int(lc.importer_credited) + amount\n        lc.unreleased = 0", "        lc.importer_credited = int(lc.importer_credited) + amount"),
    # --- Ed25519 / BoL
    ("sig_always_true", "    return _pt_compress(lhs) == r_raw", "    return True"),
    ("sig_hash_reduce", "% _L\n    # [S]B - [k]A must equal R", "% (_L - 1)\n    # [S]B - [k]A must equal R"),
    ("sig_scalar_unchecked", "    if s >= _L:\n        return False\n", ""),
    ("bol_check_removed", "        if not self._check_bol(lc, bol_record_id, attestation_signature):", "        if False:"),
    ("bol_message_drops_container", "            container_id,\n            vessel_imo,\n            exporter_address,", "            vessel_imo,\n            exporter_address,"),
    ("bol_message_drops_imo", "            vessel_imo,\n            exporter_address,", "            exporter_address,"),
    ("imo_check_digit_skipped", "    return total % 10 == int(imo[6])", "    return True"),
    ("bol_replay_allowed", "        if bol_record_id in self.bol_registry:", "        if False:"),
    ("bol_not_required", "        if not lc.bol_verified:\n            raise _err(ERR_BOL_NOT_VERIFIED, \"verify the bill of lading first\")\n        if stage == STAGE_1_DEPARTURE:", "        if False:\n            raise _err(ERR_BOL_NOT_VERIFIED, \"verify the bill of lading first\")\n        if stage == STAGE_1_DEPARTURE:"),
    ("pubkey_small_order_allowed", "            if pt is None or _is_small_order(pt):", "            if pt is None:"),
    ("witness_keys_not_distinct", "        if len(set(keys)) != 4:", "        if False:"),
    # --- quorum
    ("reject_needs_one", "        if len(signers) >= 2:\n            return {\n                \"verdict\": VERDICT_REJECTION", "        if len(signers) >= 1:\n            return {\n                \"verdict\": VERDICT_REJECTION"),
    ("positive_needs_one", "        if len(signers) >= 2:\n            return {\n                \"verdict\": VERDICT_VERIFIED", "        if len(signers) >= 1:\n            return {\n                \"verdict\": VERDICT_VERIFIED"),
    ("reject_signers_not_distinct", "        if len(signers) >= 2:\n            return {\n                \"verdict\": VERDICT_REJECTION", "        if len(grp) >= 2:\n            return {\n                \"verdict\": VERDICT_REJECTION"),
    ("positive_signers_not_distinct", "        if len(signers) >= 2:\n            return {\n                \"verdict\": VERDICT_VERIFIED", "        if len(grp) >= 2:\n            return {\n                \"verdict\": VERDICT_VERIFIED"),
    ("evidence_signature_unchecked", "    return ed25519_verify(bytes.fromhex(witness_hex), msg, sig)", "    return True"),
    ("evidence_wrong_slot_key", "    witness_hex = terms[\"witness_pubkeys\"][slot]\n    sig = bytes.fromhex", "    witness_hex = terms[\"witness_pubkeys\"][0]\n    sig = bytes.fromhex"),
    ("evidence_binding_unchecked", "        or rec[\"binding\"] != terms[\"binding\"]\n", ""),
    ("evidence_imo_unchecked", "        or rec[\"vessel_imo\"] != terms[\"vessel_imo\"]\n", ""),
    ("evidence_role_unchecked", "    if rec[\"role\"] != WITNESS_ROLES[slot]:\n        return False", "    if False:\n        return False"),
    ("evidence_message_drops_binding", "            rec[\"binding\"],\n            rec[\"bol_record_id\"],\n            rec[\"container_id\"],\n            rec[\"vessel_imo\"],", "            rec[\"bol_record_id\"],\n            rec[\"container_id\"],\n            rec[\"vessel_imo\"],"),
    ("evidence_message_drops_status", "            rec[\"status\"],\n            str(rec[\"departure_ts\"]),", "            str(rec[\"departure_ts\"]),"),
    ("evidence_message_drops_temperature", "            str(rec[\"event_ts\"]),\n            str(rec[\"peak_temp_tenths_c\"]),", "            str(rec[\"event_ts\"]),"),
    ("validator_ignores_fields", "        if leader_payload[key] != own_payload[key]:", "        if False:"),
    ("future_skew_off_by_one", "if rec[\"event_ts\"] > horizon or", "if rec[\"event_ts\"] >= horizon or"),
    ("float_literals_allowed", "            parse_float=_reject_float,\n", ""),
    ("duplicate_keys_allowed", "            object_pairs_hook=_reject_pairs,\n", ""),
    ("positive_binding_ignored", "            groups_pos.setdefault((o[\"stage\"], o[\"bucket\"], o[\"binding\"]), []).append(o)", "            groups_pos.setdefault((o[\"stage\"], o[\"bucket\"], \"\"), []).append(o)"),
    ("reject_binding_ignored", "            groups_rej.setdefault((o[\"stage\"], o[\"bucket\"], o[\"binding\"]), []).append(o)", "            groups_rej.setdefault((o[\"stage\"], o[\"bucket\"], \"\"), []).append(o)"),
    ("ids_not_matched", "        rec[\"bol_record_id\"] != terms[\"bol_record_id\"]\n        or ", "        False\n        or "),
    ("departure_deadline_ignored", "rec[\"departure_ts\"] > 0 and rec[\"departure_ts\"] <= latest", "rec[\"departure_ts\"] > 0"),
    # --- handshake and authorization
    ("accept_by_importer", "        if gl.message.sender_address != lc.exporter:\n            raise _err(ERR_UNAUTHORIZED, \"only the exporter may accept\")", "        if gl.message.sender_address != lc.importer:\n            raise _err(ERR_UNAUTHORIZED, \"only the exporter may accept\")"),
    ("accept_deadline_exclusive", "        if _now_ts() > int(lc.accept_deadline):", "        if _now_ts() >= int(lc.accept_deadline):"),
    ("cancel_window_off_by_one", "            if _now_ts() <= int(lc.accept_deadline):", "            if _now_ts() < int(lc.accept_deadline):"),
    ("acceptance_window_length", "ACCEPTANCE_WINDOW = 48 * 3600", "ACCEPTANCE_WINDOW = 24 * 3600"),
    ("cancel_by_anyone", "            raise _err(ERR_UNAUTHORIZED, \"only the importer may cancel\")", "            pass"),
    ("witness_hosts_not_distinct", "    if len(set(hosts)) != 3:", "    if False:"),
    ("git_mirrors_allowed", "            if host == banned or host.endswith(\".\" + banned):", "            if False:"),
    ("http_allowed", "    if not url.startswith(\"https://\"):", "    if False:"),
    ("self_dealing_allowed", "        if exporter_addr == importer_addr:", "        if False:"),
    ("stage_order_ignored", "            if lc.state != ST_STAGE_1 or not lc.stage1_settled or lc.stage2_settled:", "            if lc.stage2_settled:"),
    ("double_stage1", "            if lc.state != ST_ACTIVE or lc.stage1_settled:", "            if lc.state != ST_ACTIVE:"),
    ("stranger_may_settle", "        if sender != lc.importer and sender != lc.exporter:\n            raise _err(ERR_UNAUTHORIZED, \"only L/C parties\")\n        if not _is_int(stage)", "        if False:\n            raise _err(ERR_UNAUTHORIZED, \"only L/C parties\")\n        if not _is_int(stage)"),
    # --- payouts / liveness
    ("claim_never_marks_withdrawn", "            lc.exporter_withdrawn = int(lc.exporter_withdrawn) + amount\n        else:\n            lc.importer_withdrawn = int(lc.importer_withdrawn) + amount\n        self.total_withdrawn", "            lc.exporter_withdrawn = int(lc.exporter_withdrawn)\n        else:\n            lc.importer_withdrawn = int(lc.importer_withdrawn) + amount\n        self.total_withdrawn"),
    ("claim_pays_importer_the_exporters_amount", "            amount = int(lc.importer_credited) - int(lc.importer_withdrawn)", "            amount = int(lc.exporter_credited) - int(lc.exporter_withdrawn)"),
    ("reclaim_cutoff_off_by_one", "        if _now_ts() <= cutoff:", "        if _now_ts() < cutoff:"),
    ("reclaim_ignores_state", "        if lc.state != ST_ACTIVE and lc.state != ST_STAGE_1:\n            raise _err(ERR_STATE, \"L/C is not open\")", "        if False:\n            raise _err(ERR_STATE, \"L/C is not open\")"),
    ("quorum_failure_applies_state", "            lc.quorum_failures = int(lc.quorum_failures) + 1\n            return json.dumps(payload, sort_keys=True)", "            lc.quorum_failures = int(lc.quorum_failures) + 1\n            self._apply_settlement(lc, stage, payload)\n            return json.dumps(payload, sort_keys=True)"),
    ("summary_unreleased_not_reduced", "        amount = int(lc.unreleased)\n        self.total_unreleased = int(self.total_unreleased) - amount", "        amount = int(lc.unreleased)"),
    ("summary_state_never_leaves_old", "            self.state_counts[old] = int(self.state_counts[old]) - 1\n", "            pass\n"),
    ("summary_stage1_not_reduced", "            self.total_unreleased = int(self.total_unreleased) - amount\n            self._set_state(lc, ST_STAGE_1)", "            self._set_state(lc, ST_STAGE_1)"),
    ("summary_stage2_not_reduced", "        self.total_unreleased = int(self.total_unreleased) - exporter - importer\n", ""),
    ("fetch_status_unchecked", "    if not isinstance(status, int) or isinstance(status, bool) or status < 200 or status >= 300:", "    if status is None or status < 200 or status >= 300:"),
    ("solvency_check_disabled", "            and balance >= owed\n", "            and True\n"),
]

KILL_SUITE = [
    "tests/test_contract_flows.py",
    "tests/test_settlement_math.py",
    "tests/test_ed25519_bol.py",
    "tests/test_aggregate_quorum.py",
]


def _run_kill_suite(mutant_path: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ, CARGOCLEAR_CONTRACT=str(mutant_path), CARGOCLEAR_MUTANT="1")
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", "-m", "not mutation", *KILL_SUITE],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=900,
    )


@pytest.fixture(scope="module")
def mutant_dir():
    d = ROOT / ".mutants"
    d.mkdir(exist_ok=True)
    return d


def test_mutation_table_is_well_formed():
    src = Path(CONTRACT).read_text()
    names = [m[0] for m in MUTATIONS]
    assert len(names) == len(set(names))
    for name, old, new in MUTATIONS:
        assert src.count(old) == 1, f"{name}: pattern must occur exactly once ({src.count(old)})"
        assert old != new


@pytest.mark.mutation
@pytest.mark.skipif(os.environ.get("CARGOCLEAR_MUTANT") == "1", reason="already inside a mutation run")
@pytest.mark.parametrize("name,old,new", MUTATIONS, ids=[m[0] for m in MUTATIONS])
def test_mutant_is_killed(mutant_dir, name, old, new):
    src = Path(CONTRACT).read_text()
    assert src.count(old) == 1
    path = mutant_dir / f"{name}.py"
    path.write_text(src.replace(old, new, 1))
    res = _run_kill_suite(path)
    assert res.returncode != 0, f"mutant {name!r} SURVIVED the suite"
