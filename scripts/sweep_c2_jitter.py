"""C2 beacon detection vs jitter (jury question: "what if the attacker randomises the interval?").

Usage (project root, venv active):
    python scripts/sweep_c2_jitter.py                  # 40 trials per cell
    python scripts/sweep_c2_jitter.py --trials 100

For each beacon period (5, 30, 90 s) and jitter level (0-60 % uniform around the period) it runs
--trials independent beacons of 12 connections (10 for 90 s, the same counts as the attack suite)
through a fresh C2Detector and reports the share detected. SYNTHETIC beacons; measures the
detector's statistical limit, not a real implant. Writes benchmarks/c2_jitter_<UTC>.json/.md.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from random import Random

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from detectors.c2 import C2Detector  # noqa: E402
from ingest.capability import CapabilityState, InputMode  # noqa: E402
from ingest.normalized_event import NormalizedEvent  # noqa: E402
from machine_spec import machine_spec, spec_markdown  # noqa: E402

PERIODS = (5.0, 30.0, 90.0)
JITTERS = (0.0, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.40, 0.50, 0.60)
CAP = CapabilityState(InputMode.PCAP_REPLAY)


def beacon_detected(period: float, jitter: float, rng: Random, count: int) -> bool:
    det = C2Detector()
    t = 1773280000.0 + rng.uniform(0, 60)
    dst = f"203.0.113.{rng.randint(1, 254)}"
    for _ in range(count):
        ev = NormalizedEvent.from_flow(observed_time=t, input_mode=InputMode.PCAP_REPLAY, capability=CAP, src_ip="10.0.9.9", dst_ip=dst,
                                       src_port=rng.randint(49152, 65535), dst_port=443, protocol="TCP", packets=2,
                                       bytes=rng.randint(180, 260), direction="outbound")
        if det.evaluate_event(ev) is not None:
            return True
        t += period * (1 + rng.uniform(-jitter, jitter))
    return False


def sweep(trials: int, seed: int = 26145) -> dict[str, dict[str, float]]:
    rng = Random(seed)
    table: dict[str, dict[str, float]] = {}
    for period in PERIODS:
        count = 10 if period >= 90 else 12
        table[f"{period:g}"] = {f"{j:.2f}": round(sum(beacon_detected(period, j, rng, count) for _ in range(trials)) / trials, 3) for j in JITTERS}
    return table


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--trials", type=int, default=40)
    parser.add_argument("--out-dir", default=str(ROOT / "benchmarks"))
    args = parser.parse_args()
    table = sweep(args.trials)
    spec = machine_spec()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    cv_max = C2Detector().cv_max
    (out / f"c2_jitter_{stamp}.json").write_text(json.dumps({"machine": spec, "trials": args.trials, "cv_max": cv_max,
                                                             "detection_rate": table}, indent=2), encoding="utf-8")
    head = "| Period \\ jitter | " + " | ".join(f"±{int(j * 100)} %" for j in JITTERS) + " |"
    lines = [f"# C2 beacon detection vs jitter ({stamp})", "",
             f"**Synthetic beacons**, {args.trials} trials per cell, C2Detector cv_max = {cv_max} (uniform jitter ±x % around the period; "
             "12 connections, 10 for 90 s). Share of beacons detected:", "", head, "|" + "---|" * (len(JITTERS) + 1)]
    for period, row in table.items():
        lines.append(f"| {period} s | " + " | ".join(f"{v:.2f}" for v in row.values()) + " |")
    lines += ["", "Uniform ±x % jitter has a coefficient of variation of about x / sqrt(3); the detector alerts at CV <= cv_max, "
              "so detection falls off once x exceeds roughly sqrt(3) x cv_max.", "", "## Machine", "| key | value |", "|---|---|", spec_markdown(spec)]
    (out / f"c2_jitter_{stamp}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:8 + len(PERIODS)]))
    print(f"\nwrote {out / f'c2_jitter_{stamp}.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
