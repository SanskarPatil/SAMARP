"""Write benchmarks/README.md: every result file, the exact command, machine, power, git commit.

Usage:  python scripts/benchmarks_index.py
The command / machine / power / commit columns are read from each file's
own "machine" block, not typed by hand. STATUS below is the reviewer's note.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
B = ROOT / "benchmarks"

STATUS = {
    "throughput_20260924T072338Z": "SUPERSEDED - first ladder; steps above 10k invalid (sender copied dropped events, fixed in bf04cb1)",
    "throughput_20260924T073116Z": "valid (5k-9k all pass); battery, see NOTES.md",
    "throughput_20260924T074054Z": "CEILING: 10k passes, 15k fails (backlog); battery 82 %, Ultimate Performance",
    "throughput_20260924T185020Z": "CURRENT: 10k passes with LightGBM DGA shadow scoring (CPU 91 %)",
    "dga_eval_20260924T062601Z": "task 1 leakage fix (grouped split, leave-one-family-out); synthetic only",
    "dga_eval_20260924T184620Z": "task 8, synthetic-only training + REAL Tranco test: real FPR 11.7 % (negative finding)",
    "dga_eval_20260924T191002Z": "CURRENT task 8: trained with real Tranco half; real FPR 0.98 %; model stays in shadow",
    "evaluation_20260924T144334Z": "BASELINE before detector fixes: 2,029 false incidents/h",
    "evaluation_20260924T145523Z": "after exfil/C2/DDoS/TLS-shape fixes: 2.0/h",
    "evaluation_20260924T150825Z": "after TLS JA3/JA4 novelty: class d recall 1.0",
    "evaluation_20260924T181052Z": "CURRENT: + UDP reflection + declared resolver; 99 attacks; 2.0/h (battery; counts deterministic)",
    "calibration_20260924T144055Z": "ddos fitted; c2/exfil refused (negative slope) - superseded",
    "calibration_20260924T145401Z": "CURRENT: no detector has >= 5 true and >= 5 false alerts -> all uncalibrated",
    "sample_alert_20260924T070542Z": "task 3: confidence + calibrated_on + latency_ms on every alert",
    "sample_alert_20260924T151143Z": "task 6: TLS novelty alert (canonical beat 10.0.0.75)",
    "sample_alert_20260924T184623Z": "task 8: DGA alert with shadow model evidence (synthetic-only model)",
    "sample_alert_20260924T191325Z": "CURRENT task 8: DGA alert with shadow evidence (real-trained model)",
    "verify_20260924T193037Z": "CURRENT: all 8 checks pass - 412 tests (10 API/integration), read-only 405, no write routes, replay 8 incidents + chain verified, dashboard 7/7 + build",
}
LABELS = {
    "throughput": "Throughput / latency / CPU / RSS ladder (synthetic canonical events, file SQLite)",
    "dga_eval": "DGA model evaluation (synthetic corpus; rows labelled real = Tranco)",
    "evaluation": "Per-class detection metrics - synthetic benign replay + synthetic attack suite",
    "calibration": "Confidence calibration fit (synthetic benign replay, seed 101)",
    "sample_alert": "Sample alert JSON from the canonical replay",
    "verify": "Final verification: all test suites, replay, chain, read-only, dashboard",
}


def _power(m):
    p = m.get("power") or {}
    if not p.get("power_source"):
        return "not recorded (see NOTES.md)"
    return f"{p['power_source']}, {p.get('power_plan')}" + (f", battery {p.get('battery_percent')} %" if p.get("power_source") == "battery" else "")


def main() -> int:
    rows = []
    for path in sorted(B.glob("*.json")):
        stem = path.stem
        kind = next((k for k in LABELS if stem.startswith(k + "_")), None)
        if kind is None:
            continue
        m = json.loads(path.read_text(encoding="utf-8")).get("machine") or {}
        companions = [f"`{p.name}`" for p in sorted(B.glob(stem + ".*")) if p.suffix != ".json"]
        rows.append((kind, stem, companions, m))
    lines = ["# Benchmarks and evaluation results", "",
             "Every number used in reports or slides comes from a file listed here. Each JSON file carries its own `machine` block "
             "(CPU, logical CPUs, RAM, OS, Python, power source/plan, git commit, exact command). Commands below are copied from those blocks; "
             "re-run them from the project root with the venv active.", "",
             "**Data labels.** *synthetic benign replay* = `scenarios/benign_background.py`; attack suite = `scenarios/attack_suite.py`; "
             "*real* = Tranco top-1m list (sha256 in the DGA JSON). No real network capture has been evaluated yet; "
             "`load_background()` accepts a `.pcap` path when one is available.", "",
             "Machine for every run below unless stated: 12th Gen Intel Core i5-12450H, 12 logical CPUs, 15.7 GB RAM, Windows 11 (10.0.26200), CPython 3.13.14.", ""]
    for kind, label in LABELS.items():
        group = [r for r in rows if r[0] == kind]
        if not group:
            continue
        lines += [f"## {label}", "", "| File | Command | Power | Commit | Status |", "|---|---|---|---|---|"]
        for _, stem, companions, m in group:
            files = " ".join([f"`{stem}.json`"] + companions)
            lines.append(f"| {files} | `{m.get('command', '?')}` | {_power(m)} | `{m.get('git_commit') or '?'}` | {STATUS.get(stem, '')} |")
        lines.append("")
    lines += ["## Other files", "", "| File | What |", "|---|---|",
              "| `NOTES.md` | Power conditions for the early runs (battery, power-saving), and why results differ between laptops |",
              "| `task2_dashboard_live_feed10_api10.png` | Task 2: live feed shows exactly the API incident count (FEED 10 = API 10) |",
              "| `task2_dashboard_demo_mode_on.png` | Task 2: demo data only behind an explicit toggle, with a DEMO DATA banner |", "",
              "Model artifacts (`models/artifact/`) are gitignored by project policy; their SHA-256 hashes are in the DGA JSON files.", ""]
    (B / "README.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {B / 'README.md'} ({len(rows)} result files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
