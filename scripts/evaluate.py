"""Ground-truth evaluation: per PS class a-f, on a SYNTHETIC benign replay plus a labelled attack suite.

Usage (project root, venv active):
    python scripts/evaluate.py                          # seeds 1 2 3, 2 h 20 min of background each
    python scripts/evaluate.py --seeds 1 --duration 3600
    python scripts/evaluate.py --background path\\to\\capture.pcap   # plug in a real benign capture

Reports, per class: attacks, detected, missed, recall, alerts, TP / overlap /
false alerts, precision, false incidents per hour of background; a per-attack
table; the overlap matrix (one attack raising another class); a benign-only
run for clean false-alert rates; and the Brier score of the emitted
confidence per detector.  Writes benchmarks/evaluation_<UTC>.json and .md.

EVERY false-alert figure is labelled "synthetic benign replay" unless a pcap
background is given, in which case it is labelled with the capture file name.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from machine_spec import machine_spec, spec_markdown  # noqa: E402
from scenarios.attack_suite import PS_CLASSES, generate_attack_suite  # noqa: E402
from scenarios.benign_background import BackgroundConfig, load_background  # noqa: E402
from scenarios.evaluation import false_alerts_benign_only, run_stream, score  # noqa: E402


PCAP_OBSERVABILITY = ("header-only PCAP replay: DNS names and TLS / JA3 / JA4 fields are not parsed from raw packets, so the "
                      "dga, dns and tls_quic detectors receive no input (NOT_OBSERVABLE, never 'benign'); scan, c2, ddos, "
                      "reflection and exfil run on the real headers")


def brier_by_detector(runs) -> dict[str, dict[str, float]]:
    buckets = defaultdict(list)
    for run in runs:
        for alert, (kind, _aid) in zip(run.alerts, run.outcomes):
            buckets[alert["detector"]].append((alert["confidence"], 1.0 if kind == "TP" else 0.0, alert.get("calibrated_on")))
    out = {}
    for det, rows in sorted(buckets.items()):
        out[det] = {"n": len(rows), "positives": int(sum(y for _, y, _ in rows)),
                    "brier": round(statistics.fmean((c - y) ** 2 for c, y, _ in rows), 4),
                    "mean_confidence": round(statistics.fmean(c for c, _, _ in rows), 4),
                    "calibrated_on": sorted({src for _, _, src in rows})}
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3])
    parser.add_argument("--duration", type=float, default=8400.0, help="background seconds per seed (attack suite needs ~8,000 s)")
    parser.add_argument("--background", default="synthetic", help='"synthetic" or a path to a benign classic .pcap')
    parser.add_argument("--address-plan", default=None,
                        help="address plan YAML for a pcap background (which prefixes are internal); "
                             "e.g. config/address_plan_home.example.yaml for a home / office capture")
    parser.add_argument("--attack-seed", type=int, default=11)
    parser.add_argument("--out-dir", default=str(ROOT / "benchmarks"))
    args = parser.parse_args()

    t_wall = time.perf_counter()
    runs, labels_per_run, benign_only = [], [], []
    provenance = None
    for seed in args.seeds:
        plan = None
        if args.address_plan:
            from ingest.address_plan import AddressPlan
            plan = AddressPlan.load(args.address_plan)
        background, provenance = load_background(args.background, BackgroundConfig(seed=seed, duration_s=args.duration), address_plan=plan)
        start = min(float(e.observed_time) for e in background)
        duration = max(float(e.observed_time) for e in background) - start
        print(f"seed {seed}: {len(background):,} background events ({provenance}), {duration / 3600:.2f} h", flush=True)
        benign_only.append(false_alerts_benign_only(background, f"{provenance} seed {seed}", duration))
        attacks, labels = generate_attack_suite(seed=args.attack_seed + seed, start_time=start)
        mixed = sorted(background + attacks, key=lambda e: float(e.observed_time))
        runs.append(run_stream(mixed, labels, f"{provenance} seed {seed}", duration))
        labels_per_run.append(labels)
        if args.background != "synthetic":
            break                                   # a pcap is one fixed background

    scored = score(runs, labels_per_run)
    hours = sum(b["hours"] for b in benign_only)
    total_false_incidents = sum(b["false_incidents"] for b in benign_only)
    by_class_fp = defaultdict(int)
    for b in benign_only:
        for letter, row in b["by_ps_class"].items():
            by_class_fp[letter] += row["incidents"]
    result = {
        "machine": machine_spec(),
        "data_label": (f"REAL benign capture {provenance} + synthetic attack suite" if provenance.startswith("pcap:")
                       else "synthetic benign replay + synthetic attack suite"),
        "observability": (PCAP_OBSERVABILITY if provenance.startswith("pcap:") else "synthetic events carry DNS / TLS metadata; all 8 detectors see input"),
        "address_plan": args.address_plan or ("none: traffic direction unknown" if provenance.startswith("pcap:") else "config/address_plan.yaml"),
        "config": {"seeds": args.seeds, "background_seconds_per_seed": args.duration, "attack_suite_seed_base": args.attack_seed,
                   "attacks_per_run": len(labels_per_run[0]), "attribution": "shared address + time overlap (grace 120 s)"},
        "benign_only": {"label": provenance, "hours": round(hours, 3), "false_incidents": total_false_incidents,
                        "false_incidents_per_hour": round(total_false_incidents / hours, 3) if hours else None,
                        "per_class_incidents_per_hour": {k: round(v / hours, 3) for k, v in sorted(by_class_fp.items())}, "runs": benign_only},
        "mixed": scored,
        "confidence_brier_by_detector": brier_by_detector(runs),
        "wall_seconds": round(time.perf_counter() - t_wall, 1),
    }

    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    (out / f"evaluation_{stamp}.json").write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")

    label = result["data_label"]
    per_class_counts = ", ".join(f"{k}: {sum(1 for l in labels_per_run[0] if l.ps_letter == k)}" for k in sorted({l.ps_letter for l in labels_per_run[0]}))
    lines = [f"# Detection evaluation ({stamp})", "", f"Observability: {result['observability']}. Address plan: {result['address_plan']}.", "", f"**Data: {label}.** Seeds {args.seeds}; {len(labels_per_run[0])} labelled attacks per run "
             f"({per_class_counts}, incl. deliberately weak variants); {hours:.2f} h of background in total.", "",
             "## Machine", "| key | value |", "|---|---|", spec_markdown(result["machine"]), "",
             f"## Per PS class (mixed stream, {len(runs)} run(s))", "",
             "| PS | Class | Attacks | Detected | Missed | Recall | Class alerts | TP | Overlap | False | Precision | False incidents / h |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for letter, row in scored["per_class"].items():
        lines.append(f"| {letter} | {row['ps_class']} | {row['attacks']} | {row['detected']} | {row['missed']} | {row['recall']} | {row['alerts']} | "
                     f"{row['tp_alerts']} | {row['overlap_alerts']} | {row['false_alerts']} | {row['precision']} | {row['false_incidents_per_hour']} |")
    lines += ["", f"## False alerts on benign-only background ({provenance}, no attacks injected)", "",
              f"{total_false_incidents} false incidents in {hours:.2f} h = **{result['benign_only']['false_incidents_per_hour']} per hour**.", "",
              "| PS | False incidents / h |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in result["benign_only"]["per_class_incidents_per_hour"].items()] or ["| - | 0 |"]
    lines += ["", "## Per attack (all runs)", "", "| Run | Attack | Variant | Expected hard | Detected (same class) | Alerts by detector |", "|---|---|---|---|---|---|"]
    for a in scored["per_attack"]:
        lines.append(f"| {a['run'][-6:]} | {a['attack_id']} | {a['variant']} | {'yes' if a['expected_hard'] else ''} | {'yes' if a['detected'] else '**no**'} | {a['alerts_by_detector'] or '-'} |")
    lines += ["", "## Overlap matrix (alert class raised on an attack of another class)", "", "| Alert class | Attack class | Alerts |", "|---|---|---|"]
    lines += [f"| {o['alert_class']} | {o['attack_class']} | {o['alerts']} |" for o in scored["overlap_matrix"]] or ["| - | - | 0 |"]
    lines += ["", "## Confidence quality (Brier score, lower is better)", "", "| Detector | Alerts | True | Mean confidence | Brier | calibrated_on |", "|---|---|---|---|---|---|"]
    lines += [f"| {d} | {r['n']} | {r['positives']} | {r['mean_confidence']} | {r['brier']} | {', '.join(r['calibrated_on'])} |" for d, r in result["confidence_brier_by_detector"].items()]
    (out / f"evaluation_{stamp}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    cut = next(i for i, l in enumerate(lines) if l.startswith("## Per attack"))
    print("\n".join(lines[:cut]))
    print(f"\nwrote {out / f'evaluation_{stamp}.json'}  ({result['wall_seconds']} s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
