"""Replay the canonical campaign into an in-memory store and show the PS alert fields.

Usage:  python scripts/show_sample_alert.py [--detector c2]

Prints one full incident (default: the C2 beacon) and a per-incident table of
timestamp / flow_id / threat class / confidence / calibrated_on / latency_ms,
then writes benchmarks/sample_alert_<UTC>.json with the machine spec.
Uses a fresh in-memory database, so nothing on disk is modified except the
benchmarks/ output file.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import types
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
if "api" not in sys.modules:  # api/__init__ imports FastAPI; the state module does not need it
    _pkg = types.ModuleType("api"); _pkg.__path__ = [str(ROOT / "api")]; sys.modules["api"] = _pkg

from api.state import AppState  # noqa: E402
from detectors.pipeline import DetectionPipeline  # noqa: E402
from ingest.capability import raise_from_observed  # noqa: E402
from machine_spec import machine_spec  # noqa: E402
from scenarios.canonical_campaign import generate_canonical_campaign_events  # noqa: E402

PS_KEYS = ("timestamp", "flow_id", "ps_class", "threat_class", "confidence", "calibrated_on", "latency_ms", "evidence")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--detector", default="c2")
    parser.add_argument("--contains", default="198.51.100.44", help="pick the incident whose evidence text contains this (default: the real C2 beacon)")
    args = parser.parse_args()

    events = generate_canonical_campaign_events()
    state = AppState(db_path=":memory:")
    raise_from_observed(state.capability_state, events)
    pipeline = DetectionPipeline()
    for event in events:
        t0 = time.perf_counter_ns()
        for alert in pipeline.process_event(event, ingest_perf_ns=t0):
            state.ingest_alert(alert, ingest_perf_ns=t0)
    t0 = time.perf_counter_ns()
    for alert in pipeline.flush(ingest_perf_ns=t0):
        state.ingest_alert(alert, ingest_perf_ns=t0)

    incidents = state.store.list_incidents(limit=1000)
    matches = [i for i in incidents if i["detector"] == args.detector]
    chosen = next((i for i in matches if args.contains in json.dumps(i["evidence"])), matches[0] if matches else incidents[0])
    print("== sample incident ==")
    print(json.dumps({k: chosen.get(k) for k in PS_KEYS + ("score", "score_type", "calibrated", "severity", "incident_id")}, indent=2))
    print("\n== all incidents ==")
    print(f"{'detector':9} {'threat_class':30} {'conf':>6} {'calibrated_on':14} {'latency_ms':>10} null_PS_fields")
    for inc in incidents:
        nulls = [k for k in ("timestamp", "flow_id", "ps_class", "threat_class", "confidence", "evidence") if inc.get(k) is None]
        print(f"{inc['detector']:9} {inc['threat_class']:30} {inc['confidence']:6.3f} {inc['calibrated_on']:14} {inc['latency_ms']:10.4f} {nulls or '-'}")
    latencies = [i["latency_ms"] for i in incidents]
    print(f"\nincidents={len(incidents)} latency_ms median={statistics.median(latencies):.4f} max={max(latencies):.4f}")
    print("capabilities:", {k: v for k, v in state.get_capabilities().items() if v == "OBSERVABLE"})

    out = ROOT / "benchmarks"; out.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = out / f"sample_alert_{stamp}.json"
    path.write_text(json.dumps({"machine": machine_spec(), "note": "latency_ms = event entering pipeline -> incident signed into hash chain; in-memory SQLite",
                                "sample": chosen, "incidents": incidents}, indent=2, default=str), encoding="utf-8")
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
