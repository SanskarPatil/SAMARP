# PS26145 Traceability Matrix — V6.3

**Project:** PS26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic  
**Source:** `PS26145_Final_Technical_Plan_V6.pdf`  
**Companion to:** `FINAL_DEVELOPMENT_PLAN_V6.3.md`

This matrix maps the PS wording to an observable input, implementation, evidence, and test. It is intended to be used during implementation review and judge Q&A.

## 1. PS constraints

| PS requirement | Implementation | Evidence / proof | Test |
|---|---|---|---|
| Passive one-directional monitoring | Plane B has no actionable return route; copied traffic only | boundary test artifact | `tests/boundary/` |
| No payload decryption | TLS/QUIC fingerprint + traffic-shape metadata only | field allowlist, evidence drawer | `tests/replay/test_tls_quic.py` |
| Streaming, not batch | bounded windows + watermark + WebSocket | live incident arrival + p50/p95 latency | `tests/latency/` |
| Stated throughput | flows/sec primary; Mbps + pps secondary | machine/resource benchmark | `tests/throughput/` |
| Standard alert schema | timestamp + non-null flow_id + PS class + confidence + evidence | JSON Schema v1.3 | `tests/schema/` |

## 2. Passive input coverage

| PS-named input | V6.3 status | Normalized contract | Capability behavior |
|---|---|---|---|
| Packet capture / copied packets | Implemented | header/EVE events | full packet-visible capabilities |
| NetFlow v9 | Implemented | shared flow-record adapter | flow-level detectors remain usable; DNS/TLS capabilities depend on exported fields |
| IPFIX v10 | Implemented | shared flow-record adapter + template cache | same capability rules as NetFlow |
| sFlow | Recognized, not packet-equivalent | capability state | sampled detectors degrade; name/fingerprint/order-sensitive detectors may be `NOT_OBSERVABLE` |
| Derived metadata | Implemented | normalized events/features | governed by source capability |

## 3. Six PS threat classes → eight internal modules

| PS class | Internal module(s) | Key evidence | Primary test |
|---|---|---|---|
| Volumetric DDoS / flooding | `ddos.py`, `reflection.py` | pps/bytes, baseline, SYN behavior, source entropy, reflection fan-in; Slowloris concurrency/duration | DDoS/reflection/Slowloris replay |
| Botnet C2 beaconing | `c2.py` | repeated destination, inter-arrival CV/MAD, persistence, novelty | beacon replay |
| DGA domains / DNS tunnelling | `dga.py`, `dns.py` | lexical entropy, bigram/trigram LM, NXDOMAIN, qtype distribution, TXT/NULL/CNAME share | DGA/tunnel replay |
| Malware in encrypted sessions | `tls_quic.py` | JA3/JA3S/JA4, destination novelty, packet-size/direction/IAT shape | TLS/QUIC replay |
| Reconnaissance / port scanning | `scan.py` | distinct hosts/ports, fan-out, spread | scan replay |
| Data exfiltration | `exfil.py` | directional bytes, ratio, duration, destination novelty, baseline | exfil replay |

## 4. Mandatory alert-field mapping

| PS term | Schema field | Frozen rule |
|---|---|---|
| timestamp | `timestamp` | required ISO-8601 alert/display time |
| flow identifier | `flow_id` | required and never null |
| threat class | `ps_class` + concrete `threat_class` | `ps_class` is one of six; concrete detector label remains internal |
| confidence score | `confidence` | semantics defined by `score_type` + `calibrated` |
| supporting evidence feature | `evidence` | actual observed feature values and interpretation |

### Flow identity

```text
flow_ref_type = flow_5tuple | aggregate | entity
flow_id = sha256(canonical(5-tuple))[:16]
        | sha256(canonical(dedup_key))[:16]
        | sha256(canonical(entity))[:16]
```

For spoofed/multi-flow floods, use `aggregate`; bounded underlying `flow_ids` may be included as evidence but never replace `flow_id`.

## 5. PS-named generation sources

| PS source/tool | V6.3 project treatment |
|---|---|
| iperf3 | benign throughput and large-transfer fixture |
| Ostinato | benign packet/port-diversity fixture where useful |
| TRex | optional high-rate benign stress generation |
| hping3 | isolated SYN/UDP flood generation |
| Slowloris | isolated low-rate HTTP exhaustion generation |
| dnscat2 / iodine | DNS tunnel fixture coverage |
| DGArchive | not a runtime/download dependency; published DGA families reimplemented locally for deterministic evaluation |
| sandboxed C2 emulator | deterministic beacon fixture |

## 6. Detector evidence details

### DNS

Required frozen evidence includes query length/entropy, encoded-character indicators, frequency, source/entity context, response behavior where available, and qtype distribution. DGA additionally uses bigram/trigram LM scores.

### TLS/QUIC

Required frozen metadata includes JA3, JA3S, JA4 where supported, destination novelty, first-N packet sizes, direction sequence/ratios, and inter-arrival statistics. No decrypted payload fields are permitted.

### Slowloris

Slowloris remains a real detector path inside `ddos.py`: concurrent half-open/long-lived connections, duration percentile, bytes/connection, low rate, and destination/service context.

## 7. Capability states

```text
OBSERVABLE
DEGRADED
NOT_OBSERVABLE
UNAVAILABLE
```

Missing evidence is never converted into a benign result. The dashboard displays the capability state and the alert records the visibility limitation.

## 8. Evaluation

Publish per-class precision/recall/F1/PR-AUC, false alerts/hour on pure-benign replay, p50/p95 latency, throughput, threshold sweeps, baseline comparison, and DGA calibration/Brier score. Detector-level and incident-level evaluation units are kept separate.

Every published number retains its scenario/dataset, command, configuration, and output artifact.
