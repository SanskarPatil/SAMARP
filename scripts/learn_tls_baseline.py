"""Learn the site's TLS client-fingerprint baseline (JA3 / JA4) from benign traffic.

Usage (project root, venv active):
    python scripts/learn_tls_baseline.py                       # synthetic benign replay, seed 202
    python scripts/learn_tls_baseline.py --source capture.pcap # a real benign capture

Writes config/tls_fingerprint_baseline.json: every JA3/JA4 seen, with its last
sighting time. detectors/tls_quic.py loads it through the pipeline; a
fingerprint absent from it (or last seen more than novelty_days before an
event) is "novel". Seed 202 is never used by scripts/evaluate.py (seeds 1-3)
or scripts/calibrate_confidence.py (seed 101).

Read-only with respect to traffic: it only reads events and writes this one
config file.
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

from detectors.tls_quic import BASELINE_FILE  # noqa: E402
from machine_spec import machine_spec  # noqa: E402
from scenarios.benign_background import BackgroundConfig, load_background  # noqa: E402


def learn(events) -> dict[str, dict[str, float]]:
    seen: dict[str, dict[str, float]] = {"ja3": {}, "ja4": {}}
    for ev in events:
        meta = ev.tls or ev.quic
        if not meta:
            continue
        t = float(ev.observed_time.timestamp()) if isinstance(ev.observed_time, datetime) else float(ev.observed_time)
        for kind in ("ja3", "ja4"):
            fp = meta.get(kind)
            if fp:
                key = str(fp).lower()
                seen[kind][key] = max(t, seen[kind].get(key, t))
    return seen


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", default="synthetic", help='"synthetic" or a path to a benign .pcap')
    parser.add_argument("--seed", type=int, default=202)
    parser.add_argument("--duration", type=float, default=8400.0)
    parser.add_argument("--out", default=str(BASELINE_FILE))
    args = parser.parse_args()

    events, provenance = load_background(args.source, BackgroundConfig(seed=args.seed, duration_s=args.duration))
    seen = learn(events)
    payload = {
        "source": f"{provenance} (seed {args.seed})" if args.source == "synthetic" else provenance,
        "learned_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "events_read": len(events),
        "note": "synthetic benign replay uses a small fixed set of client fingerprints; a real network has many more, so expect more novelty alerts on real traffic",
        "machine": machine_spec(),
        **seen,
    }
    Path(args.out).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"{len(seen['ja3'])} JA3 and {len(seen['ja4'])} JA4 fingerprints from {len(events):,} events ({payload['source']})")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
