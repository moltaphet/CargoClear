"""4-bucket cold-chain / demurrage settlement in integer basis points.

Zero floats, zero drift: exporter + importer + unreleased + withdrawn == deposited
for every principal, bucket and rounding remainder.
"""

import ast
import itertools
import random
from pathlib import Path

import pytest
from conftest import (
    CONTRACT,
    LATEST,
    MAX_TEMP,
    PRINCIPAL,
    T0,
    assert_reverts,
    hex_of,
    ok,
    record,
)

GRACE = 7 * 86400
BPS = 10000


# ------------------------------------------------- bucket boundary classification
def expected_bucket(peak_off: int, arrival_off: int) -> int:
    """Independent restatement of the spec. peak_off is peak - max_temp (tenths),
    arrival_off is arrival - latest_arrival (seconds)."""
    if peak_off > 30 or arrival_off > GRACE:
        return 3  # BUCKET_3_SPOILED_OR_REJECTED
    if 0 < peak_off <= 30:
        return 2  # BUCKET_2_MINOR_THERMAL_DRIFT
    if arrival_off > 0:
        return 1  # BUCKET_1_LATE_DEMURRAGE
    return 0  # BUCKET_0_CLEAN_DELIVERY


PEAK_OFFSETS = [-120, -1, 0, 1, 15, 29, 30, 31, 100]
ARRIVAL_OFFSETS = [-86400, -1, 0, 1, 3600, GRACE - 1, GRACE, GRACE + 1, 30 * 86400]


@pytest.mark.parametrize("arrival_off", ARRIVAL_OFFSETS)
@pytest.mark.parametrize("peak_off", PEAK_OFFSETS)
def test_bucket_boundaries(cc, peak_off, arrival_off):
    got = cc.classify_bucket(MAX_TEMP, MAX_TEMP + peak_off, LATEST + arrival_off, LATEST)
    assert got == expected_bucket(peak_off, arrival_off)


@pytest.mark.parametrize("max_temp", [-700, -250, -180, -1, 0, 1, 40, 120, 500])
@pytest.mark.parametrize("peak_off", [0, 1, 30, 31])
def test_bucket_is_independent_of_the_absolute_temperature(cc, max_temp, peak_off):
    got = cc.classify_bucket(max_temp, max_temp + peak_off, LATEST, LATEST)
    assert got == expected_bucket(peak_off, 0)


@pytest.mark.parametrize(
    "max_temp,peak,bucket",
    [
        (-180, -180, 0),  # exactly at the limit is clean
        (-180, -179, 2),  # +0.1 degC is already a minor excursion
        (-180, -150, 2),  # +3.0 degC is the last minor excursion
        (-180, -149, 3),  # +3.1 degC is spoiled
        (40, 40, 0),
        (40, 70, 2),
        (40, 71, 3),
        (-180, -200, 0),
    ],
)
def test_spec_examples_in_tenths_of_a_degree(cc, max_temp, peak, bucket):
    assert cc.classify_bucket(max_temp, peak, LATEST, LATEST) == bucket


def test_thermal_and_lateness_take_the_worse_bucket(cc):
    # late (bucket 1) and +1.0 degC (bucket 2) -> 2; late and +3.1 -> 3
    assert cc.classify_bucket(MAX_TEMP, MAX_TEMP + 10, LATEST + 3600, LATEST) == 2
    assert cc.classify_bucket(MAX_TEMP, MAX_TEMP + 31, LATEST + 3600, LATEST) == 3
    assert cc.classify_bucket(MAX_TEMP, MAX_TEMP, LATEST + GRACE + 1, LATEST) == 3


def test_preview_bucket_view_matches_helper(world, cc):
    for peak_off, arrival_off in itertools.product([0, 15, 31], [0, 99, GRACE + 1]):
        a = world.contract.preview_bucket(MAX_TEMP, MAX_TEMP + peak_off, LATEST + arrival_off, LATEST)
        assert a == cc.classify_bucket(MAX_TEMP, MAX_TEMP + peak_off, LATEST + arrival_off, LATEST)


# ------------------------------------------------------ exact BPS on round numbers
ONE = 10**18


@pytest.mark.parametrize(
    "bucket,exporter_total,importer",
    [
        (0, 10000, 0),  # exporter 20% + 80%
        (1, 8000, 2000),  # 20% + 60% / 20% demurrage rebate
        (2, 6000, 4000),  # 20% + 40% / 40% quality rebate  (spec: 4000 + 4000)
        (3, 2000, 8000),  # 20% / 100% Stage-2 refund
    ],
)
def test_exact_bps_on_round_principal(cc, bucket, exporter_total, importer):
    s1 = cc.stage1_amount(ONE)
    exp2, imp2 = cc.stage2_split(ONE, bucket)
    assert s1 == ONE * 2000 // BPS
    assert (s1 + exp2) * BPS // ONE == exporter_total
    assert imp2 * BPS // ONE == importer
    assert s1 + exp2 + imp2 == ONE


@pytest.mark.parametrize(
    "bucket,stage2_exporter_bps,stage2_importer_bps",
    [(0, 8000, 0), (1, 6000, 2000), (2, 4000, 4000), (3, 0, 8000)],
)
def test_stage2_shares_in_bps_of_the_whole_lc(cc, bucket, stage2_exporter_bps, stage2_importer_bps):
    exp2, imp2 = cc.stage2_split(10 * ONE, bucket)
    assert exp2 == 10 * ONE * stage2_exporter_bps // BPS
    assert imp2 == 10 * ONE * stage2_importer_bps // BPS


def test_stage1_is_twenty_percent(cc):
    assert cc.STAGE_1_BPS == 2000 and cc.STAGE_2_BPS == 8000
    assert cc.STAGE_1_BPS + cc.STAGE_2_BPS == cc.BPS == 10000


def test_bucket_table_is_consistent(cc):
    for exp_bps, imp_bps in cc.BUCKET_TABLE:
        assert exp_bps + imp_bps == cc.STAGE_2_BPS
    assert cc.BUCKET_TABLE[0] == (8000, 0)
    assert cc.BUCKET_TABLE[1] == (6000, 2000)
    assert cc.BUCKET_TABLE[2] == (4000, 4000)
    assert cc.BUCKET_TABLE[3] == (0, 8000)


# ------------------------------------------------ zero-dust conservation properties
RNG = random.Random(20261018)
PRINCIPALS = sorted(
    {1, 2, 3, 4, 5, 6, 7, 9, 11, 13, 99, 100, 101, 999, 1000, 1001, 1003, 1004, 12345, 10**9 + 7, 10**18 - 1, 10**18, 10**18 + 3}
    | {RNG.randrange(1000, 10**21) for _ in range(40)}
)


@pytest.mark.parametrize("bucket", range(4))
@pytest.mark.parametrize("principal", PRINCIPALS)
def test_every_wei_is_accounted_for(cc, principal, bucket):
    s1 = cc.stage1_amount(principal)
    exp2, imp2 = cc.stage2_split(principal, bucket)
    assert s1 >= 0 and exp2 >= 0 and imp2 >= 0
    assert s1 + exp2 + imp2 == principal


@pytest.mark.parametrize("principal", [p for p in PRINCIPALS if p % 5])
def test_dust_goes_to_exporter_on_clean_and_importer_on_haircuts(cc, principal):
    s1 = cc.stage1_amount(principal)
    clean_exp, clean_imp = cc.stage2_split(principal, 0)
    assert clean_imp == 0  # no importer rebate on a clean delivery, ever
    assert clean_exp == principal - s1  # the whole remainder is the exporter's
    spoiled_exp, spoiled_imp = cc.stage2_split(principal, 3)
    assert spoiled_exp == 0  # a full refund leaves the exporter nothing, dust included
    assert spoiled_imp == principal - s1


@pytest.mark.parametrize("principal", [p for p in PRINCIPALS if p >= 10])
def test_exporter_share_is_monotonic_in_severity(cc, principal):
    shares = [cc.stage2_split(principal, b)[0] for b in range(4)]
    assert shares == sorted(shares, reverse=True)
    rebates = [cc.stage2_split(principal, b)[1] for b in range(4)]
    assert rebates == sorted(rebates)


@pytest.mark.parametrize("principal", [p for p in PRINCIPALS if p >= 100])
def test_rounding_error_is_below_three_wei(cc, principal):
    """Floor division loses at most one wei per share; dust handling keeps it
    inside the discretionary side only."""
    for bucket in range(4):
        exp_bps, imp_bps = cc.BUCKET_TABLE[bucket]
        exp2, imp2 = cc.stage2_split(principal, bucket)
        assert 0 <= exp2 - principal * exp_bps // BPS <= 3
        assert 0 <= imp2 - principal * imp_bps // BPS <= 3


def test_preview_settlement_view_conserves(world):
    for principal, bucket in itertools.product([1, 7, 1003, ONE + 3], range(4)):
        p = world.contract.preview_settlement(principal, bucket)
        assert p["conserved"] is True
        assert p["exporter_total"] + p["importer_total"] == principal


@pytest.mark.parametrize("bad", [(-1, 0), (10, -1), (10, 4), (10, 99)])
def test_preview_settlement_rejects_bad_inputs(world, bad):
    assert_reverts("ERR_INVALID_PARAMS", world.contract.preview_settlement, *bad)


# --------------------------------------------- full L/C lifecycle per bucket (e2e)
SCENARIOS = {
    # name: (peak offset vs max, arrival offset vs latest, feed status, expected bucket)
    "clean": (-5, -86400, "CUSTOMS_CLEARED", 0),
    "clean_at_limit": (0, 0, "CUSTOMS_CLEARED", 0),
    "late_1s": (-5, 1, "CUSTOMS_CLEARED", 1),
    "late_within_grace": (-5, GRACE, "CUSTOMS_CLEARED", 1),
    "drift_0_1": (1, -10, "CUSTOMS_CLEARED", 2),
    "drift_3_0": (30, -10, "CUSTOMS_CLEARED", 2),
    "drift_and_late": (10, 3600, "CUSTOMS_CLEARED", 2),
    "spoiled_3_1": (31, -10, "CUSTOMS_CLEARED", 3),
    "too_late": (-5, GRACE + 1, "CUSTOMS_CLEARED", 3),
    "customs_rejected": (-5, -10, "CUSTOMS_REJECTED", 3),
    "voyage_aborted": (-5, -10, "VOYAGE_ABORTED", 3),
}


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_scenario_buckets_and_money(world, cc, scenario):
    peak_off, arrival_off, status, bucket = SCENARIOS[scenario]
    # Use a "now" late enough that every arrival offset is in the past.
    now = 1_798_675_200
    world.ready(PRINCIPAL)
    world.warp(now)
    dep = record(status="VESSEL_DEPARTED", arrival_ts=0, peak_temp_tenths_c=0, event_ts=now - 5000, departure_ts=T0 - 6 * 86400)
    world.mock_feeds(ok(dep), ok(dep), ok(dep))
    assert world.settle(1)["verdict"] == 1
    rec = record(
        status=status,
        peak_temp_tenths_c=MAX_TEMP + peak_off,
        arrival_ts=LATEST + arrival_off,
        departure_ts=T0 - 6 * 86400,
        event_ts=now - 50,
    )
    world.mock_feeds(ok(rec), ok(rec), ok(rec))
    out = world.settle(2)
    assert out["verdict"] == (0 if status != "CUSTOMS_CLEARED" else 1)
    assert out["bucket"] == bucket
    st = world.state()
    s1 = PRINCIPAL * 2000 // BPS
    exp2, imp2 = cc.stage2_split(PRINCIPAL, bucket)
    assert st["final_bucket"] == bucket
    assert st["exporter_claimable"] == s1 + exp2
    assert st["importer_rebate"] == imp2
    assert st["unreleased_escrow"] == 0
    assert st["exporter_claimable"] + st["importer_rebate"] + st["unreleased_escrow"] == st["total_deposited"] == PRINCIPAL
    inv = world.contract.verify_solvency_invariant()
    assert inv["solvent"] and inv["per_lc_conserved"]


@pytest.mark.parametrize("scenario", ["clean", "late_1s", "drift_3_0", "spoiled_3_1", "customs_rejected"])
@pytest.mark.parametrize("principal", [PRINCIPAL, 1003, 10**18, 7 * 10**17 + 1])
def test_payouts_drain_exactly_what_is_owed(world, cc, scenario, principal):
    peak_off, arrival_off, status, bucket = SCENARIOS[scenario]
    now = 1_798_675_200
    world.ready(principal)
    world.warp(now)
    dep = record(status="VESSEL_DEPARTED", arrival_ts=0, peak_temp_tenths_c=0, event_ts=now - 5000, departure_ts=T0 - 6 * 86400)
    world.mock_feeds(ok(dep), ok(dep), ok(dep))
    world.settle(1)
    rec = record(
        status=status, peak_temp_tenths_c=MAX_TEMP + peak_off,
        arrival_ts=LATEST + arrival_off, departure_ts=T0 - 6 * 86400, event_ts=now - 50,
    )
    world.mock_feeds(ok(rec), ok(rec), ok(rec))
    world.settle(2)
    st = world.state()
    exp_due, imp_due = st["exporter_claimable"], st["importer_rebate"]
    assert world.contract_balance() == principal
    paid_exporter = paid_importer = 0
    if exp_due:
        world.as_(world.exporter)
        paid_exporter = int(world.contract.claim_funds("LC-1"))
        assert paid_exporter == exp_due
        assert_reverts("ERR_NO_CLAIMABLE_BALANCE", world.contract.claim_funds, "LC-1")  # no double claim
    if imp_due:
        world.as_(world.importer)
        paid_importer = int(world.contract.claim_funds("LC-1"))
        assert paid_importer == imp_due
        assert_reverts("ERR_NO_CLAIMABLE_BALANCE", world.contract.claim_funds, "LC-1")
    assert paid_exporter + paid_importer == principal
    assert world.contract_balance() == 0
    assert world.balance_of(world.exporter) == paid_exporter
    st = world.state()
    assert st["exporter_claimable"] == 0 and st["importer_rebate"] == 0
    assert st["exporter_withdrawn"] + st["importer_withdrawn"] == principal
    inv = world.contract.verify_solvency_invariant()
    assert inv["solvent"] and inv["owed"] == 0 and inv["total_withdrawn"] == principal


def test_stage1_pays_exactly_twenty_percent_floor(world):
    world.ready(1003)
    dep = record(status="VESSEL_DEPARTED", arrival_ts=0, peak_temp_tenths_c=0)
    world.mock_feeds(ok(dep), ok(dep), ok(dep))
    world.settle(1)
    st = world.state()
    assert st["exporter_claimable"] == 1003 * 2000 // BPS == 200
    assert st["unreleased_escrow"] == 803


def test_nothing_is_released_before_consensus(world):
    world.ready()
    st = world.state()
    assert st["exporter_claimable"] == 0 and st["importer_rebate"] == 0
    assert st["unreleased_escrow"] == PRINCIPAL


# ------------------------------------------------------------------ no floats
def _contract_ast():
    return ast.parse(Path(CONTRACT).read_text())


def test_contract_source_has_no_float_constants():
    for node in ast.walk(_contract_ast()):
        if isinstance(node, ast.Constant):
            assert not isinstance(node.value, float), f"float literal on line {node.lineno}"
            assert not isinstance(node.value, complex)


def test_contract_source_never_uses_true_division():
    for node in ast.walk(_contract_ast()):
        if isinstance(node, ast.BinOp):
            assert not isinstance(node.op, ast.Div), f"'/' on line {node.lineno}"
        if isinstance(node, ast.AugAssign):
            assert not isinstance(node.op, ast.Div), f"'/=' on line {node.lineno}"


def test_contract_source_never_calls_float_or_math():
    names = {n.id for n in ast.walk(_contract_ast()) if isinstance(n, ast.Name)}
    assert "float" not in names and "Decimal" not in names
    imports = [
        n.module if isinstance(n, ast.ImportFrom) else a.name
        for n in ast.walk(_contract_ast())
        if isinstance(n, (ast.Import, ast.ImportFrom))
        for a in (n.names if isinstance(n, ast.Import) else [None])
    ]
    assert "math" not in imports and "decimal" not in imports and "random" not in imports


def _no_floats(value, path="$"):
    if isinstance(value, float):
        raise AssertionError(f"float at {path}")
    if isinstance(value, dict):
        for k, v in value.items():
            assert not isinstance(k, float), f"float key at {path}"
            _no_floats(v, f"{path}.{k}")
    if isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _no_floats(v, f"{path}[{i}]")


def test_every_view_return_is_float_free(world):
    world.ready()
    for call in (
        lambda: world.contract.get_lc_state("LC-1"),
        lambda: world.contract.get_protocol_summary(),
        lambda: world.contract.get_evidence_sources("LC-1"),
        lambda: world.contract.verify_solvency_invariant(),
        lambda: world.contract.get_bol_message("LC-1", "BOL-X"),
        lambda: world.contract.preview_settlement(PRINCIPAL, 2),
        lambda: world.contract.preview_bucket(-180, -170, 1, 2),
        lambda: world.contract.check_bol_attestation("LC-1", "BOL-X", "00" * 64),
    ):
        _no_floats(call())


def test_every_view_return_survives_calldata_roundtrip(world):
    """gen_call fails on anything calldata cannot encode; floats are the classic."""
    from genlayer import calldata

    world.ready()
    for value in (
        world.contract.get_lc_state("LC-1"),
        world.contract.get_protocol_summary(),
        world.contract.get_evidence_sources("LC-1"),
        world.contract.verify_solvency_invariant(),
    ):
        assert calldata.decode(calldata.encode(value)) == value


def test_settle_result_is_float_free_json(world):
    import json

    world.ready()
    dep = record(status="VESSEL_DEPARTED", arrival_ts=0, peak_temp_tenths_c=0)
    world.mock_feeds(ok(dep), ok(dep), ok(dep))
    world.as_(world.importer)
    raw = world.contract.settle_shipment_stage("LC-1", 1)
    assert "." not in raw
    _no_floats(json.loads(raw))
