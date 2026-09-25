"""Threshold sensitivity (jury question: "how did you choose 100 ports / CV 0.15 / 10x ratio?").

Usage (project root, venv active):
    python scripts/sweep_thresholds.py                 # seeds 4 5 6 (NOT the seeds used by evaluate.py)
    python scripts/sweep_thresholds.py --seeds 4

For each detector, the key threshold is varied around the shipped value while everything else
is fixed. Each setting runs that detector alone over the synthetic benign replay + labelled
attack suite and reports: recall on its own PS class, and false incidents per hour of
background. Seeds 4-6 are disjoint from the evaluation seeds 1-3 and the calibration seed 101,
so this is a sensitivity analysis, not tuning on the test set. SYNTHETIC data - the shape of the
trade-off is the point, not the absolute numbers. Writes benchmarks/thresholds_<UTC>.json/.md.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from machine_spec import machine_spec, spec_markdown  # noqa: E402
from scenarios.attack_suite import generate_attack_suite  # noqa: E402
from scenarios.benign_background import BackgroundConfig, generate_benign_background  # noqa: E402
from scenarios.evaluation import attribute  # noqa: E402


def _grid():
    from detectors.c2 import C2Detector
    from detectors.ddos import DDoSDetector
    from detectors.exfil import ExfilDetector
    from detectors.reflection import ReflectionDetector
    from detectors.scan import ScanDetector

    return [
        ("scan", "e", "unique_port_min (vertical)", 100, [25, 50, 100, 150, 200], lambda v: ScanDetector(unique_port_min=v)),
        ("scan", "e", "unique_dst_min (horizontal)", 50, [10, 25, 50, 75, 100], lambda v: ScanDetector(unique_dst_min=v)),
        ("c2", "b", "cv_max", 0.15, [0.05, 0.10, 0.15, 0.20, 0.30, 0.40], lambda v: C2Detector(cv_max=v)),
        ("exfil", "f", "outbound_ratio_min", 10.0, [2.0, 5.0, 10.0, 20.0, 50.0], lambda v: ExfilDetector(outbound_ratio_min=v)),
        ("exfil", "f", "min_outbound_bytes", 250_000, [50_000, 250_000, 1_000_000, 5_000_000], lambda v: ExfilDetector(min_outbound_bytes=v)),
        ("ddos", "a", "min_pps", 5000, [1000, 2500, 5000, 8000, 12000], lambda v: DDoSDetector(min_pps=v)),
        ("reflection", "a", "min_fan_in", 10, [3, 5, 10, 20, 40], lambda v: ReflectionDetector(min_fan_in=v)),
    ]


def _run(detector_name: str, detector, events):
    alerts = []
    if detector_name == "ddos":
        from detectors.pipeline import _declared_resolvers
        from features.rolling import TumblingWindowAggregator

        agg = TumblingWindowAggregator(window_duration_s=1.0, watermark_delay_s=0.3, resolvers=_declared_resolvers())
        for ev in events:
            for w in agg.add_event(ev):
                alerts.extend(detector.evaluate_window(w))
        for w in agg.flush():
            alerts.extend(detector.evaluate_window(w))
    else:
        for ev in events:
            a = detector.evaluate_event(ev)
            if a is not None:
                alerts.append(a)
    return alerts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seeds", type=int, nargs="+", default=[4, 5, 6])
    parser.add_argument("--duration", type=float, default=8400.0)
    parser.add_argument("--out-dir", default=str(ROOT / "benchmarks"))
    args = parser.parse_args()

    streams = []
    for seed in args.seeds:
        bg = generate_benign_background(BackgroundConfig(seed=seed, duration_s=args.duration))
        start = min(float(e.observed_time) for e in bg)
        attacks, labels = generate_attack_suite(seed=11 + seed, start_time=start)
        streams.append((sorted(bg + attacks, key=lambda e: float(e.observed_time)), labels, args.duration / 3600.0))
        print(f"seed {seed}: {len(bg) + len(attacks):,} events", flush=True)

    rows = []
    for det_name, letter, param, shipped, values, make in _grid():
        for v in values:
            attacks = detected = 0
            false_keys = 0
            hours = 0.0
            for events, labels, h in streams:
                alerts = _run(det_name, make(v), events)
                hit_ids, false = set(), set()
                for a in alerts:
                    lab = attribute(a, labels)
                    if lab is not None and lab.ps_letter == letter:
                        hit_ids.add(lab.attack_id)
                    elif lab is None:
                        false.add(a["dedup_key"])
                own = [l for l in labels if l.ps_letter == letter and (det_name != "reflection" or "reflection" in l.variant)]
                attacks += len(own)
                detected += sum(1 for l in own if l.attack_id in hit_ids)
                false_keys += len(false)
                hours += h
            rows.append({"detector": det_name, "ps_letter": letter, "parameter": param, "value": v, "shipped": v == shipped,
                         "recall": round(detected / attacks, 3) if attacks else None, "detected": detected, "attacks": attacks,
                         "false_incidents_per_hour": round(false_keys / hours, 3)})
            print(f"  {det_name:10} {param:28} {v!s:>9}  recall {detected}/{attacks}  false/h {false_keys / hours:.2f}", flush=True)

    spec = machine_spec()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    (out / f"thresholds_{stamp}.json").write_text(json.dumps({"machine": spec, "seeds": args.seeds, "rows": rows}, indent=2), encoding="utf-8")
    lines = [f"# Threshold sensitivity ({stamp})", "",
             f"**Synthetic benign replay + labelled attack suite, seeds {args.seeds}** (disjoint from evaluation seeds 1-3). One detector at a time; "
             "recall is on that detector's own PS class (reflection: the reflection attacks only), false incidents per hour are over the whole background. **Bold** = shipped value.", "",
             "| Detector | Parameter | Value | Recall | False incidents / h |", "|---|---|---|---|---|"]
    for r in rows:
        v = f"**{r['value']}**" if r["shipped"] else str(r["value"])
        lines.append(f"| {r['detector']} | {r['parameter']} | {v} | {r['detected']}/{r['attacks']} ({r['recall']}) | {r['false_incidents_per_hour']} |")
    lines += ["", "## Machine", "| key | value |", "|---|---|", spec_markdown(spec)]
    (out / f"thresholds_{stamp}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nwrote {out / f'thresholds_{stamp}.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
