"""Writes the commit-pinned mock maritime feeds for LC-1.

Three independent operators each publish their own view of container
MSKU4471290 (BoL BOL-CC-20261009-0001):

  a  Maritime Carrier Manifest Feed      (raw.githubusercontent.com)
  b  Port Customs Clearance Feed         (cdn.jsdelivr.net)
  c  Cold-Chain AIS Telemetry Mirror     (raw.githack.com)

The reefer logged a +2.0 degC excursion (-16.0 vs the -18.0 limit). Carrier and
Customs both recorded it; the AIS mirror's sensor sample missed the spike and
reports a clean -17.5. 2-of-3 therefore settles BUCKET_2_MINOR_THERMAL_DRIFT
with source_count == 2, which is exactly the dissent the quorum must survive.
"""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FEEDS = ROOT / "deployments" / "mock_feeds"

BOL = "BOL-CC-20261009-0001"
CONTAINER = "MSKU4471290"
DEPARTURE_TS = 1_791_532_800  # 2026-10-09T08:00:00Z
ARRIVAL_TS = 1_792_247_400  # 2026-10-17T14:30:00Z (before latest_arrival_ts)
EVENT_TS = 1_792_252_800  # 2026-10-17T16:00:00Z
LATEST_ARRIVAL_TS = 1_792_886_400  # 2026-10-25T00:00:00Z
MAX_TEMP_TENTHS_C = -180
CARGO_SPEC = "Frozen Atlantic shrimp, grade A, 18 t, reefer -18.0C"
MANIFEST = "CargoClear mock customs manifest | LC-1 | MSKU4471290 | 18t shrimp | HS 030617"
CARGO_SPEC_HASH = hashlib.sha256(CARGO_SPEC.encode()).hexdigest()
MANIFEST_HASH = hashlib.sha256(MANIFEST.encode()).hexdigest()

PEAKS = {"a": -160, "b": -160, "c": -175}


def feed(peak: int) -> dict:
    return {
        "schema": "cargoclear.feed.v1",
        "bol_record_id": BOL,
        "lc_id": "LC-1",
        "container_id": CONTAINER,
        "status": "CUSTOMS_CLEARED",
        "departure_ts": DEPARTURE_TS,
        "arrival_ts": ARRIVAL_TS,
        "peak_temp_tenths_c": peak,
        "manifest_hash": MANIFEST_HASH,
        "event_ts": EVENT_TS,
    }


def main() -> None:
    for host, peak in PEAKS.items():
        d = FEEDS / host
        d.mkdir(parents=True, exist_ok=True)
        (d / "LC-1.json").write_text(json.dumps(feed(peak), sort_keys=True, separators=(",", ":")) + "\n")
    print("cargo_spec_hash", CARGO_SPEC_HASH)
    print("manifest_hash  ", MANIFEST_HASH)


if __name__ == "__main__":
    main()
