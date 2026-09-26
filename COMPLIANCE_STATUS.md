# PS SIH26145 compliance status (branch `fix/ps-compliance`)

Status after tasks 1-10. Every figure comes from a file in `benchmarks/` (see `benchmarks/README.md` for the command,
machine and power state of each). Machine: Intel Core i5-12450H, 12 logical CPUs, 15.7 GB RAM, Windows 11, CPython 3.13.14.
**Data label:** detection metrics use a *synthetic benign replay* plus a *synthetic attack suite*; the only real data is the
Tranco benign domain list used for the DGA model.

Final verification: `benchmarks/verify_20260924T193037Z.md` - all 8 checks pass (412 tests incl. 10 API/integration,
read-only 405 proof, no write routes, replay 12,137 events -> 8 incidents with a valid hash chain, dashboard 7/7 tests + build).

## Summary

| | MET | PARTIAL | MISSING |
|---|---|---|---|
| Before (v3 review, `ppt_v2_review/COMPLIANCE.md`) | 9 | 10 | 1 |
| **Now** | **18** | **2** | **0** |

## Threat classes a-f

| # | PS requirement | Status | Evidence (numbers: `evaluation_20260924T181052Z.md`, 3 seeds, 7 h synthetic benign replay, 99 attacks) |
|---|---|---|---|
| a | Volumetric / protocol DDoS incl. SYN, UDP reflection/amplification, spoofed floods | **MET** | `detectors/ddos.py` + streaming `ReflectionDetector` wired into the pipeline (task 7). Recall 18/24 (0.75), precision 0.84, 1.3 false incidents/h. Misses: low-rate 800 pps SYN and memcached reflection from 6 amplifiers (below gates, expected). Tests `test_ddos.py`, `test_reflection_stream.py`, `test_declared_resolver.py` |
| b | Botnet C2 beaconing (periodicity, inter-arrival) | **MET** | `detectors/c2.py`: IAT CV <= 0.15; NTP/DNS exempt, fleet-prevalence and bulk-record rules (task 5). Recall 14/15, precision 0.82, 0 false incidents/h. Known limit: a botnet with >= 3 bots on one C2 server is suppressed (`fleet_min_hosts=0` disables) |
| c | DGA + DNS tunnelling | **MET** | `detectors/dga.py` (rules decide) + LightGBM in shadow; `detectors/dns.py`. Recall 12/15, precision 1.0, 0 false incidents/h. Miss: word-based DGA (dictcat). Model: `docs/model_card.md` |
| d | Malware in encrypted sessions, metadata only | **MET** | `detectors/tls_quic.py`: known-bad JA3, no-SNI direct IP, fixed small-packet shape, **JA3/JA4 novelty over `novelty_days`** (task 6). Recall 15/15, precision 0.88, 0 false incidents/h. Canonical TLS beat now detected. Caveat: synthetic background has only 4 client fingerprints |
| e | Recon / port scanning | **MET** | `detectors/scan.py`; replies from service ports no longer counted as probes (task 7). Recall 9/15, precision 1.0, 0 false incidents/h. Misses: hybrid 20x10 and small 40-port scans (below thresholds) |
| f | Data exfiltration (asymmetric volume) | **MET** | `detectors/exfil.py`: direction-correct byte accounting (task 5). Recall 15/15, precision 0.63, 1.3 false incidents/h - all from cloud-backup uploads, which volume and direction alone cannot tell apart from exfiltration |

## Constraints

| # | PS requirement | Status | Evidence |
|---|---|---|---|
| Ca | Read-only ingest, no return path | **MET** | Only `@router.get` + WebSocket; CORS GET/HEAD/OPTIONS; `test_plane_b_strictly_read_only` (405 on POST/PUT/DELETE) passes; static scan finds no write routes (`verify_20260924T193037Z.md` checks 3-4). No task added a route |
| Cb | No payload decryption | **MET** | Event schema has no payload field (`test_schema_has_no_payload_or_content_field`); every TLS alert states "no decrypted payload bytes inspected" (`test_statistical_detectors.py`) |
| Cc | Streaming, bounded latency | **MET** | `latency_ms` measured on every alert (task 3): canonical replay median 0.34 ms (`sample_alert_20260924T191325Z.json`); at 10,000 events/s event-to-alert p50 2.5 / p95 14.5 / p99 17.8 ms on the Normal power plan (`throughput_20260924T185020Z.md`); scaling curve on the Ultimate Performance plan: p95 0.59 ms at 1k/s, 4.7 ms at 10k/s, 7.2 ms at 25k/s (`throughput_20260926T185159Z.md`). Stream-time detection delay still depends on the class (C2 needs 8 beacons) |
| Cd | Throughput stated and demonstrated | **MET** (flow-event level) | Target 1,000 flows/s (`config/thresholds.yaml`). Measured: **10,000 normalized events/s sustained 60 s, 0 % drop** on the Normal power plan (`throughput_20260924T185020Z.md`); scaling curve on AC + Ultimate Performance plan: **1k-25k events/s pass (0 drops), 50k/s fails (22.5 % dropped, ~38k/s processed)** (`throughput_20260926T185159Z.md`). Earlier 15k failure was on battery (`throughput_20260924T074054Z.md`). Starts at normalized events - capture/NIC pps and Mbps not measured |
| Ce | Alert schema: timestamp, flow ID, threat class, confidence, evidence | **MET** | Schema 1.3: `confidence` in [0,1] on every alert plus `calibrated_on` and `latency_ms` (task 3); null-field test `tests/schema/test_alert_ps_fields.py`. All current confidences are `uncalibrated` (see limits) |

## Deliverables

| # | PS requirement | Status | Evidence |
|---|---|---|---|
| E1 | AI/ML model inference in the pipeline | **MET** (shadow) | LightGBM DGA runs on every DNS query in shadow mode; its probability is in each DGA alert's evidence (`sample_alert_20260924T191325Z.json`). Rules decide because the model's real-domain false-positive rate (0.98 %) is above the rules' (0.05-0.25 %) |
| E2 | Working prototype / repo | **MET** | End-to-end `scripts/run_demo.py`; `verify_all.py` all pass |
| E3 | One-directional stream ingest | **MET** | PCAP replay, NetFlow v9 / IPFIX adapter; benign replay loader accepts a `.pcap` path |
| E4 | Documentation: models used | **MET** | `docs/model_card.md` |
| E5 | Documentation: features | **MET** | `features/feature_order.py`, `features/extractor.py`, model card feature list |
| E6 | Documentation: training / validation approach | **MET** | Leakage fixed (task 1): grouped split, word-level hold-out, leave-one-family-out, real benign half (`dga_eval_20260924T191002Z.md`) |
| E7 | Validation results / metrics | **PARTIAL** | Per-class detected / missed / precision / recall / false incidents per hour / overlap exist (`evaluation_*.md`) - but on **synthetic** traffic only; DGA has a real benign test set, nothing else is real |
| E8 | Dashboard: live detections with severity + confidence | **MET** | Live feed = API count (task 2 screenshots), demo data only behind a DEMO DATA toggle, header renamed SAMARP, confidence shown |
| D1 | Datasets: synthetic/lab benign + PS attack tools | **PARTIAL** | Synthetic benign generator + labelled attack suite built (task 5); **none of hping3 / dnscat2 / iodine / iperf3 / TRex / DGArchive was run** and no real capture was evaluated |

## Could not do, and why

1. **No real network traffic.** All detection metrics except the DGA benign set are from synthetic replay. The PS tools (hping3, Slowloris, dnscat2, iodine, iperf3, TRex/Ostinato) need an isolated Linux lab network; this work ran on a Windows laptop and a cloud workspace without one. The harness is ready: `python scripts/evaluate.py --background capture.pcap --address-plan config/address_plan_home.yaml` (real benign) and `scripts/evaluate_pcap.py` (labelled lab capture); steps in docs/lab_capture.md. Header-only PCAP replay cannot see DNS/TLS fields, so dga/dns/tls_quic are reported NOT_OBSERVABLE on a capture.
2. **No real DGA samples.** DGArchive needs registration; the DGA side of the model is 5 generic DGA styles written locally (not DGArchive copies). Real-domain false positives were measured (Tranco), real DGA recall was not.
3. **Confidence calibration.** After the detector fixes, no detector has >= 5 true and >= 5 false alerts on the synthetic replay, so every alert is `calibrated_on: "uncalibrated"`. Calibrating needs real benign traffic with real false alerts.
4. **LightGBM not switched on.** It runs in shadow. Real-domain false-positive rate 0.98 % vs rules 0.05-0.25 %, and unseen word-based families are missed once real benign names are in training (dictcat recall 0.00, wordmix 0.55, base32 0.50).
5. **Capture-level throughput.** The benchmark starts at normalized events; the Suricata/NIC sensor path is not built, so packets/s and Mbps at the wire are not measured.
6. **Remaining known false alerts / misses** (synthetic replay): cloud backups as exfiltration (1.3/h); a few bursty DDoS windows (0.7/h); misses listed per class above; scan reply rule has a gap for scanners that fix a source port < 1024 and probe ports >= 1024.
7. **Robustness sweeps** (synthetic): C2 beacons detected >= 97 % up to +-20 % timing jitter, 62-80 % at +-25 %, <= 45 % from +-30 % (`c2_jitter_20260926T183941Z.md`). Threshold sweep (`thresholds_20260926T184406Z.md`): scan horizontal `unique_dst_min` 10 gives 16.6 false/h, 50 gives 0; DDoS `min_pps` 1000 gives 13.7 false/h, 2500+ gives 1.3; exfil ratio 2-20 leaves the 1.3/h backup false alerts unchanged (ratio cannot separate backups from exfiltration); reflection recall 6/9 at every fan-in <= 20.
7. **Measurement conditions.** Early benchmark files have no recorded power state (they ran on battery, `benchmarks/NOTES.md`); later runs mix "Ultimate Performance" and "Normal" power plans. Numbers are for this laptop only.
8. **From you:** team name and the SIH portal link for the deck. Deck v4 is not built yet (next phase).
