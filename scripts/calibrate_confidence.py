"""Fit per-detector confidence calibration on a labelled SYNTHETIC replay.

Usage (project root, venv active):
    python scripts/calibrate_confidence.py            # calibration seed 101 (never used by evaluate.py)

For every detector, raw alerts from a mixed stream (synthetic benign replay +
synthetic attack suite) are labelled 1 if attributed to an attack of the same
PS class, else 0, and a logistic model  P(true) = sigmoid(a * x + b)  is fitted
on the detector's normalised score x (alerts/confidence.normalized_score).

A detector is calibrated only when it has at least --min-pos true and
--min-neg false alerts; otherwise it stays "uncalibrated" and the reason is
recorded.  Writes config/confidence_calibration.json (read by
alerts/confidence.py -> calibrated_on="synthetic_replay") and
benchmarks/calibration_<UTC>.json with the machine spec.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from alerts.confidence import CALIBRATION_FILE, normalized_score  # noqa: E402
from machine_spec import machine_spec  # noqa: E402
from scenarios.attack_suite import generate_attack_suite  # noqa: E402
from scenarios.benign_background import BackgroundConfig, generate_benign_background  # noqa: E402
from scenarios.evaluation import run_stream  # noqa: E402


def fit_logistic(xs: list[float], ys: list[float]) -> tuple[float, float]:
    from scipy.optimize import minimize

    def nll(params):
        a, b = params
        total = 0.0
        for x, y in zip(xs, ys):
            z = max(min(a * x + b, 60.0), -60.0)
            p = 1.0 / (1.0 + math.exp(-z))
            total -= y * math.log(max(p, 1e-12)) + (1 - y) * math.log(max(1 - p, 1e-12))
        return total + 1e-3 * (a * a + b * b)          # tiny ridge keeps separable data finite

    res = minimize(nll, x0=(1.0, 0.0), method="BFGS")
    return float(res.x[0]), float(res.x[1])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seed", type=int, default=101)
    parser.add_argument("--duration", type=float, default=8400.0)
    parser.add_argument("--min-pos", type=int, default=5)
    parser.add_argument("--min-neg", type=int, default=5)
    parser.add_argument("--dry-run", action="store_true", help="report only; do not write config/confidence_calibration.json")
    args = parser.parse_args()

    background = generate_benign_background(BackgroundConfig(seed=args.seed, duration_s=args.duration))
    start = min(float(e.observed_time) for e in background)
    attacks, labels = generate_attack_suite(seed=args.seed + 1000, start_time=start)
    mixed = sorted(background + attacks, key=lambda e: float(e.observed_time))
    run = run_stream(mixed, labels, f"calibration seed {args.seed}", args.duration)

    samples = defaultdict(list)
    for alert, (kind, _aid) in zip(run.alerts, run.outcomes):
        x = normalized_score(alert["detector"], alert.get("score"), alert.get("score_type", "anomaly_score"))
        samples[alert["detector"]].append((x, 1.0 if kind == "TP" else 0.0))

    detectors, report = {}, {}
    for det, rows in sorted(samples.items()):
        pos = int(sum(y for _, y in rows)); neg = len(rows) - pos
        if pos >= args.min_pos and neg >= args.min_neg:
            a, b = fit_logistic([x for x, _ in rows], [y for _, y in rows])
            if a <= 0:
                report[det] = {"status": "uncalibrated", "n": len(rows), "positives": pos, "negatives": neg,
                               "reason": f"score is not predictive: fitted slope a={a:.3f} <= 0 (false alerts score as high as true ones)"}
                continue
            detectors[det] = {"a": round(a, 6), "b": round(b, 6), "n": len(rows), "positives": pos, "negatives": neg}
            report[det] = {"status": "calibrated", **detectors[det]}
        else:
            report[det] = {"status": "uncalibrated", "reason": f"needs >= {args.min_pos} true and >= {args.min_neg} false alerts; has {pos} / {neg}", "n": len(rows)}

    payload = {"source": "synthetic_replay", "note": "fitted on synthetic benign replay + synthetic attack suite; re-fit after any detector change",
               "seed": args.seed, "background_seconds": args.duration, "fitted_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "detectors": detectors}
    if not args.dry_run:
        CALIBRATION_FILE.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    out = ROOT / "benchmarks"; out.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    (out / f"calibration_{stamp}.json").write_text(json.dumps({"machine": machine_spec(), "calibration": payload, "per_detector": report,
                                                                "written": not args.dry_run}, indent=2), encoding="utf-8")
    for det, row in report.items():
        print(f"{det:9} {row['status']:12} " + (f"a={row['a']:.3f} b={row['b']:.3f} pos={row['positives']} neg={row['negatives']}" if row["status"] == "calibrated" else row["reason"]))
    print(("wrote " + str(CALIBRATION_FILE)) if not args.dry_run else "dry run: calibration file not written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
