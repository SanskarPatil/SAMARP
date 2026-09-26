# Benchmarks and evaluation results

Every number used in reports or slides comes from a file listed here. Each JSON file carries its own `machine` block (CPU, logical CPUs, RAM, OS, Python, power source/plan, git commit, exact command). Commands below are copied from those blocks; re-run them from the project root with the venv active.

**Data labels.** *synthetic benign replay* = `scenarios/benign_background.py`; attack suite = `scenarios/attack_suite.py`; *real* = Tranco top-1m list (sha256 in the DGA JSON). No real network capture has been evaluated yet; the harness is ready (`scripts/evaluate.py --background <file>.pcap --address-plan ...`, `scripts/evaluate_pcap.py`; see docs/lab_capture.md).

Machine for every run below unless stated: 12th Gen Intel Core i5-12450H, 12 logical CPUs, 15.7 GB RAM, Windows 11 (10.0.26200), CPython 3.13.14.

## Throughput / latency / CPU / RSS ladder (synthetic canonical events, file SQLite)

| File | Command | Power | Commit | Status |
|---|---|---|---|---|
| `throughput_20260924T072338Z.json` `throughput_20260924T072338Z.md` | `python.exe scripts\bench_throughput.py` | not recorded (see NOTES.md) | `bda1753` | SUPERSEDED - first ladder; steps above 10k invalid (sender copied dropped events, fixed in bf04cb1) |
| `throughput_20260924T073116Z.json` `throughput_20260924T073116Z.md` | `python.exe scripts\bench_throughput.py --rates 5000 6000 7000 8000 9000 --stop-on-loss` | not recorded (see NOTES.md) | `312a608` | valid (5k-9k all pass); battery, see NOTES.md |
| `throughput_20260924T074054Z.json` `throughput_20260924T074054Z.md` | `python.exe scripts\bench_throughput.py --rates 5000 10000 15000 20000 25000 --stop-on-loss` | battery, Ultimate Performance, battery 82 % | `efea925` | CEILING: 10k passes, 15k fails (backlog); battery 82 %, Ultimate Performance |
| `throughput_20260924T185020Z.json` `throughput_20260924T185020Z.md` | `python.exe scripts\bench_throughput.py --rates 10000 --duration 60` | ac, Normal mode | `e37d1c4` | 10k passes with LightGBM DGA shadow scoring (CPU 91 %); AC, Normal power plan |
| `throughput_20260926T185159Z.json` `throughput_20260926T185159Z.md` | `python.exe scripts\bench_throughput.py --rates 1000 5000 10000 15000 25000 50000 --duration 60` | ac, Ultimate Performance | `08dbe43` | CURRENT scaling curve: 1k-25k pass (0 drops, p95 <= 7.3 ms), 50k fails (22.5 % dropped); AC, Ultimate Performance plan. CPU % is summed over cores |

## DGA model evaluation (synthetic corpus; rows labelled real = Tranco)

| File | Command | Power | Commit | Status |
|---|---|---|---|---|
| `dga_eval_20260924T062601Z.json` `dga_eval_20260924T062601Z.md` | `python.exe scripts\train_eval_dga.py` | not recorded (see NOTES.md) | `b071781` | task 1 leakage fix (grouped split, leave-one-family-out); synthetic only |
| `dga_eval_20260924T184620Z.json` `dga_eval_20260924T184620Z.md` | `python.exe scripts\train_eval_dga.py --save-model --real-benign intel\tranco\top-1m.csv` | ac, Normal mode | `e37d1c4` | task 8, synthetic-only training + REAL Tranco test: real FPR 11.7 % (negative finding) |
| `dga_eval_20260924T191002Z.json` `dga_eval_20260924T191002Z.md` | `python.exe scripts\train_eval_dga.py --save-model --real-benign intel\tranco\top-1m.csv --train-real --real-top 30000` | ac, Normal mode | `2890620` | CURRENT task 8: trained with real Tranco half; real FPR 0.98 %; model stays in shadow |

## Per-class detection metrics - synthetic benign replay + synthetic attack suite

| File | Command | Power | Commit | Status |
|---|---|---|---|---|
| `evaluation_20260924T144334Z.json` `evaluation_20260924T144334Z.md` | `python.exe scripts\evaluate.py` | ac, Ultimate Performance | `6e12d55` | BASELINE before detector fixes: 2,029 false incidents/h |
| `evaluation_20260924T145523Z.json` `evaluation_20260924T145523Z.md` | `python.exe scripts\evaluate.py` | ac, Ultimate Performance | `b292797` | after exfil/C2/DDoS/TLS-shape fixes: 2.0/h |
| `evaluation_20260924T150825Z.json` `evaluation_20260924T150825Z.md` | `python.exe scripts\evaluate.py` | ac, Ultimate Performance | `63fc94b` | after TLS JA3/JA4 novelty: class d recall 1.0 |
| `evaluation_20260924T181052Z.json` `evaluation_20260924T181052Z.md` | `python.exe scripts\evaluate.py` | battery, Normal mode, battery 96 % | `0692ed2` | CURRENT: + UDP reflection + declared resolver; 99 attacks; 2.0/h (battery; counts deterministic) |

## Confidence calibration fit (synthetic benign replay, seed 101)

| File | Command | Power | Commit | Status |
|---|---|---|---|---|
| `calibration_20260924T144055Z.json` | `python.exe scripts\calibrate_confidence.py` | ac, Ultimate Performance | `6e12d55` | ddos fitted; c2/exfil refused (negative slope) - superseded |
| `calibration_20260924T145401Z.json` | `python.exe scripts\calibrate_confidence.py` | ac, Ultimate Performance | `b292797` | CURRENT: no detector has >= 5 true and >= 5 false alerts -> all uncalibrated |

## Sample alert JSON from the canonical replay

| File | Command | Power | Commit | Status |
|---|---|---|---|---|
| `sample_alert_20260924T070542Z.json` | `python.exe scripts\show_sample_alert.py` | not recorded (see NOTES.md) | `584b5b2` | task 3: confidence + calibrated_on + latency_ms on every alert |
| `sample_alert_20260924T151143Z.json` | `python.exe scripts\show_sample_alert.py --detector tls_quic --contains 10.0.0.75` | ac, Ultimate Performance | `63fc94b` | task 6: TLS novelty alert (canonical beat 10.0.0.75) |
| `sample_alert_20260924T184623Z.json` | `python.exe scripts\show_sample_alert.py --detector dga` | ac, Normal mode | `e37d1c4` | task 8: DGA alert with shadow model evidence (synthetic-only model) |
| `sample_alert_20260924T191325Z.json` | `python.exe scripts\show_sample_alert.py --detector dga` | ac, Normal mode | `2890620` | CURRENT task 8: DGA alert with shadow evidence (real-trained model) |

## C2 beacon detection vs timing jitter (synthetic beacons, C2Detector only)

| File | Command | Power | Commit | Status |
|---|---|---|---|---|
| `c2_jitter_20260926T183941Z.json` `c2_jitter_20260926T183941Z.md` | `python.exe scripts\sweep_c2_jitter.py` | ac, Ultimate Performance | `08dbe43` | CURRENT: synthetic beacons, 40 trials/cell; >= 97 % detected up to +-20 % jitter, 62-80 % at +-25 %, <= 45 % from +-30 % |

## Threshold sensitivity - recall vs false incidents/h (synthetic benign replay + synthetic attack suite)

| File | Command | Power | Commit | Status |
|---|---|---|---|---|
| `thresholds_20260926T184406Z.json` `thresholds_20260926T184406Z.md` | `python.exe scripts\sweep_thresholds.py` | ac, Ultimate Performance | `08dbe43` | CURRENT: one-at-a-time threshold sweep, seeds 4-6 (synthetic benign + synthetic attacks); recall vs false incidents/h per detector |

## Final verification: all test suites, replay, chain, read-only, dashboard

| File | Command | Power | Commit | Status |
|---|---|---|---|---|
| `verify_20260924T193037Z.json` `verify_20260924T193037Z.log` `verify_20260924T193037Z.md` | `python.exe scripts\verify_all.py` | ac, Normal mode | `af003e1` | CURRENT: all 8 checks pass - 412 tests (10 API/integration), read-only 405, no write routes, replay 8 incidents + chain verified, dashboard 7/7 + build |
| `verify_20260925T032258Z.json` `verify_20260925T032258Z.log` `verify_20260925T032258Z.md` | `python.exe scripts\verify_all.py` | battery, Normal mode, battery 91 % | `5b98b55` |  |
| `verify_20260926T190827Z.json` `verify_20260926T190827Z.log` `verify_20260926T190827Z.md` | `python.exe scripts\verify_all.py` | ac, Ultimate Performance | `cb38cfa` |  |
| `verify_20260926T191219Z.json` `verify_20260926T191219Z.log` `verify_20260926T191219Z.md` | `python.exe scripts\verify_all.py` | ac, Ultimate Performance | `cb38cfa` |  |

## Other files

| File | What |
|---|---|
| `NOTES.md` | Power conditions for the early runs (battery, power-saving), and why results differ between laptops |
| `task2_dashboard_live_feed10_api10.png` | Task 2: live feed shows exactly the API incident count (FEED 10 = API 10) |
| `task2_dashboard_demo_mode_on.png` | Task 2: demo data only behind an explicit toggle, with a DEMO DATA banner |

Model artifacts (`models/artifact/`) are gitignored by project policy; their SHA-256 hashes are in the DGA JSON files.
