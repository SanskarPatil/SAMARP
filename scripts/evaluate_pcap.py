"""Score SAMARP on a REAL labelled capture (lab attacks recorded with tcpdump / Wireshark).

Usage (project root, venv active):
    python scripts/evaluate_pcap.py --pcap captures/lab_run1.pcap --labels captures/lab_run1.labels.json \
        --address-plan config/address_plan_lab.yaml

labels.json - one entry per attack you ran (times are capture epoch seconds, e.g. from `date +%s`):
    [
      {"attack_id": "a1", "ps_letter": "a", "variant": "hping3 SYN flood 5k pps",
       "key_ips": ["192.168.56.20"], "t_start": 1790400000, "t_end": 1790400030},
      ...
    ]
ps_letter: a DDoS/reflection, b C2, c DGA/DNS, d encrypted sessions, e scanning, f exfiltration.
key_ips: addresses that identify the attack in an alert (victim for floods, attacker for scans / C2 / exfil).

Reports per class detected / missed / precision and false incidents per hour outside the labelled
windows, labelled "REAL capture". Header-only replay: DNS / TLS fields are not parsed from raw
packets, so the dga, dns and tls_quic detectors see no input (reported, not counted as misses of
the pipeline design). Writes benchmarks/pcap_eval_<UTC>.json and .md with the machine spec and the
capture's sha256; the capture itself is never copied (it may contain payload).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from machine_spec import machine_spec, spec_markdown  # noqa: E402
from scenarios.attack_suite import AttackLabel  # noqa: E402
from scenarios.evaluation import run_stream, score  # noqa: E402

HEADER_ONLY_BLIND = ("dga", "dns", "tls_quic")


def load_labels(path: str | Path) -> list[AttackLabel]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    labels = []
    for i, r in enumerate(raw):
        letter = str(r["ps_letter"]).lower()
        if letter not in "abcdef" or len(letter) != 1:
            raise ValueError(f"label {i}: ps_letter must be one of a-f, got {r['ps_letter']!r}")
        t0, t1 = float(r["t_start"]), float(r["t_end"])
        if t1 < t0:
            raise ValueError(f"label {i}: t_end before t_start")
        labels.append(AttackLabel(str(r.get("attack_id", f"{letter}{i + 1}")), letter, str(r.get("variant", "")),
                                  frozenset(str(ip) for ip in r["key_ips"]), t0, t1, bool(r.get("expected_hard", False))))
    return labels


def evaluate_capture(pcap: str | Path, labels: list[AttackLabel], address_plan=None) -> dict:
    from ingest.replay import replay_to_events

    events, stats = replay_to_events(pcap, address_plan=address_plan)
    if not events:
        raise SystemExit("capture produced no events (empty file, or no IPv4/IPv6 packets)")
    t = [e.observed_time.timestamp() if isinstance(e.observed_time, datetime) else float(e.observed_time) for e in events]
    start, end = min(t), max(t)
    run = run_stream(events, labels, f"pcap:{Path(pcap).name}", end - start)
    scored = score([run], [labels])
    labelled = sum(l.t_end - l.t_start for l in labels)
    return {"events": len(events), "capture_start_utc": datetime.fromtimestamp(start, tz=timezone.utc).isoformat(),
            "capture_seconds": round(end - start, 1), "labelled_attack_seconds": round(labelled, 1),
            "packets_parsed": getattr(stats, "packets_parsed", None), "scored": scored,
            "alerts_by_detector": {d: sum(1 for a in run.alerts if a["detector"] == d) for d in sorted({a["detector"] for a in run.alerts})}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pcap", required=True, help="classic .pcap (convert pcapng: editcap -F pcap in.pcapng out.pcap)")
    parser.add_argument("--labels", required=True)
    parser.add_argument("--address-plan", default=None, help="YAML declaring the lab's internal prefixes")
    parser.add_argument("--out-dir", default=str(ROOT / "benchmarks"))
    args = parser.parse_args()

    plan = None
    if args.address_plan:
        from ingest.address_plan import AddressPlan
        plan = AddressPlan.load(args.address_plan)
    labels = load_labels(args.labels)
    res = evaluate_capture(args.pcap, labels, plan)
    pcap = Path(args.pcap)
    result = {"machine": machine_spec(), "data_label": f"REAL capture {pcap.name} with {len(labels)} labelled attacks",
              "capture": {"file": pcap.name, "sha256": hashlib.sha256(pcap.read_bytes()).hexdigest(), "bytes": pcap.stat().st_size},
              "labels_file": Path(args.labels).name, "address_plan": args.address_plan or "none: direction unknown",
              "observability": f"header-only replay: {', '.join(HEADER_ONLY_BLIND)} receive no DNS / TLS input", **res}
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    (out / f"pcap_eval_{stamp}.json").write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    sc = res["scored"]
    lines = [f"# REAL capture evaluation ({stamp})", "", f"**Data: {result['data_label']}** (sha256 `{result['capture']['sha256'][:16]}...`). "
             f"{res['events']:,} header-only events over {res['capture_seconds'] / 3600:.2f} h; address plan: {result['address_plan']}.", "",
             f"Observability: {result['observability']}.", "", "## Machine", "| key | value |", "|---|---|", spec_markdown(result["machine"]), "",
             "## Per PS class", "", "| PS | Attacks | Detected | Missed | Recall | Class alerts | TP | False | Precision | False incidents / h |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for letter, row in sc["per_class"].items():
        if row["attacks"] or row["alerts"]:
            lines.append(f"| {letter} | {row['attacks']} | {row['detected']} | {row['missed']} | {row['recall']} | {row['alerts']} | "
                         f"{row['tp_alerts']} | {row['false_alerts']} | {row['precision']} | {row['false_incidents_per_hour']} |")
    lines += ["", "## Per labelled attack", "", "| Attack | PS | Variant | Detected | Alerts by detector |", "|---|---|---|---|---|"]
    lines += [f"| {a['attack_id']} | {a['ps_letter']} | {a['variant']} | {'yes' if a['detected'] else '**no**'} | {a['alerts_by_detector'] or '-'} |" for a in sc["per_attack"]]
    lines += ["", f"Alerts by detector: {res['alerts_by_detector']}"]
    (out / f"pcap_eval_{stamp}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nwrote {out / f'pcap_eval_{stamp}.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
