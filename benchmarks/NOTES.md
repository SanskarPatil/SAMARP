# Benchmark run conditions (recorded by hand where the JSON could not)

Raw result files in this folder are never edited. Conditions the scripts did not
capture at the time are recorded here, as stated by the operator.

| Result file | Operator-stated condition |
|---|---|
| `dga_eval_20260924T062601Z.*` | laptop on battery, Windows power settings tuned for battery saving |
| `sample_alert_20260924T070542Z.json` | laptop on battery, Windows power settings tuned for battery saving |
| `throughput_20260924T072338Z.*` | laptop on battery, battery-saving tuning; ALSO produced by the first bench version whose sender copied dropped events (overload rows 10k/20k/40k are not valid capacity figures) |
| `throughput_20260924T073116Z.*` | laptop on battery, battery-saving tuning |

Consequence: all throughput and latency figures from 2026-09-24 are **throttled lower bounds**
for the i5-12450H. From commit after bf04cb1, `scripts/machine_spec.py` records power
source, battery percentage, battery-saver flag and active power plan in every result file.
Re-run plugged in, on the Balanced or Best-performance plan, before quoting a ceiling.
