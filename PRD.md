# Product Requirements Document

**Project:** Cyber Sentinel — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
**Problem Statement:** SIH 2026 PS26145 (NTRO)
**Requirement authority:** PS26145
**Implementation source of truth:** `FINAL_DEVELOPMENT_PLAN_V6.3.md`
**Compliance checklist:** `ps26145_traceability_matrix.md`

This document defines **what** the product must do and **why**. It is not an implementation manual. Architecture lives in `design.md`; build order lives in `implementation_plan.md`; verification lives in `testing.md`.

---

## 1. Product Overview

Cyber Sentinel is a **passive, streaming cyber-intelligence layer** for a monitored enclave sitting behind a one-way boundary or data diode.

It consumes copied network traffic, sensor-derived metadata, and exported flow records; it converts those observations into evidence-rich, deduplicated **incidents**; and it presents them to an operator with explicit statements of what it could and could not see.

The output is **intelligence, not a control surface**. The system produces alerts, evidence and advisory text. It never produces an action across the monitored boundary.

---

## 2. Problem Statement

A monitored enclave is protected by a unidirectional boundary. Traffic can be copied out of it; nothing may be sent back in. Conventional defensive tooling assumes bidirectional reach — active probing, session interception, inline blocking, TLS termination. None of that is available here.

Signature engines remain valuable but are limited to behaviour a rule already describes. Threats that present as *behaviour* rather than *content* — a periodic beacon, a slow port sweep, a low-rate connection-exhaustion attack, a burst of algorithmically generated domains, a steady outbound byte asymmetry — are visible in metadata but not in any single packet.

The problem is therefore: **detect, classify and score cyber threats using only passively observed, non-decrypted IP traffic metadata, in near-real-time, with evidence a human analyst can act on.**

---

## 3. Objective

Deliver a system that can prove, on demand and reproducibly:

1. Traffic enters only through the intended passive path.
2. The monitor cannot send traffic back across the boundary.
3. The same replay produces deterministic observations.
4. Real traffic produces real alerts.
5. Alerts carry actual observed feature values and a baseline comparison.
6. The operator interface survives high-volume flood conditions.
7. Every published measurement is reproducible from a recorded command, configuration and artifact.
8. Limitations are explicitly represented rather than hidden.

The objective is explicitly **not maximum detector count**. A stable, explainable system that survives scrutiny outranks a larger one that cannot.

---

## 4. Target Users

| User | Need |
|---|---|
| Enclave SOC analyst | A prioritised incident feed with evidence sufficient to triage without access to the enclave |
| Security engineer | Reproducible thresholds, measurable false-alert rate, documented model behaviour |
| Compliance / audit reviewer | Tamper-evident incident history and exportable records |
| Evaluator / judge | Verifiable claims: read-only proof, no-decryption proof, measured throughput and latency |

---

## 5. Core User Outcomes

- An operator sees a **small number of evolving incidents**, not an alert storm.
- Every incident answers *"why do you think this?"* with observed values, a baseline and a threshold.
- An operator can tell the difference between *"nothing suspicious"* and *"I could not see this"*.
- An operator can export the incident history and independently verify it was not modified.
- An operator knows the system's blind spots without having to discover them during an incident.

---

## 6. Core Features

1. **Passive ingest** of copied packets, sensor metadata, and exported flow records.
2. **Normalisation** of every input path into a single event contract.
3. **Capability negotiation** — the system declares per-detector what evidence is available for the current input.
4. **Streaming feature extraction** over bounded windows with bounded memory.
5. **Detection** across the six PS threat classes.
6. **Scoring** that distinguishes a calibrated model probability from a statistical or rule-derived evidence strength.
7. **Deduplication and incident lifecycle** — many observations collapse into one evolving incident.
8. **Evidence** — actual feature values, baseline, threshold and interpretation on every incident.
9. **Tamper-evident history** — hash-chained incident records.
10. **Operator dashboard** — live incident feed, evidence drawer, capability and health banner, history, export.
11. **Scenario Console** — a separate application, on the attacker side, for deterministic replay.
12. **Export** — JSON and CSV, produced continuously rather than as a batch job.

---

## 7. Threat Classes

The product presents the **six PS26145 threat classes**. These strings are the frozen external vocabulary and appear verbatim in the UI, the schema `ps_class` field, the README, the deck and the evaluation report.

1. **Volumetric DDoS / flooding**
2. **Port scanning / reconnaissance**
3. **Botnet C2 beaconing**
4. **DGA / DNS tunnelling**
5. **Malware in encrypted sessions**
6. **Data exfiltration**

Internally the implementation contains **eight detector modules**:

`ddos.py` · `reflection.py` · `scan.py` · `dns.py` · `dga.py` · `c2.py` · `tls_quic.py` · `exfil.py`

The mapping is many-to-one and is asserted by a contract test. Two PS classes are served by two modules each: *Volumetric DDoS / flooding* by `ddos.py` and `reflection.py`; *DGA / DNS tunnelling* by `dga.py` and `dns.py`. Module names are internal terminology and never appear as class labels in external material. The class-to-module table is owned by `design.md`.

**Slowloris** is a required low-rate connection-exhaustion detection path inside `ddos.py`. It is part of the *Volumetric DDoS / flooding* class and must not be reduced to a packets-per-second threshold.

*Malware in encrypted sessions* is a **suspicion** class. The product never claims payload identification, malware family attribution, or decrypted-content inspection.

---

## 8. Hard Constraints

These are non-negotiable. A change to any of them is a change to the problem statement, not a design decision.

### 8.1 The five PS-graded constraints

| # | Constraint | Product requirement |
|---|---|---|
| 1 | **Read-only ingest** | The monitoring side has no actionable return path to the monitored or attacker network |
| 2 | **No payload decryption** | TLS and QUIC are analysed by handshake metadata, fingerprints and traffic shape only |
| 3 | **Streaming operation** | Incidents arrive continuously during observation, never only at end-of-run |
| 4 | **Stated throughput** | A measured, reproducible throughput figure published beside the machine specification |
| 5 | **Standard alert schema** | Every alert carries timestamp, non-null flow identifier, threat class, confidence and supporting evidence |

### 8.2 Additional project constraints

- **Offline operation.** Zero internet dependency at run time. No live threat-intel lookup, no runtime LLM inference, no external geolocation service.
- **Attack generation is lab-only.** Generation occurs only inside an isolated namespace/veth environment during the authorised build phase, and stops at the Hour-6 gate. The demonstration runs deterministic replay only.
- **One trained model.** The DGA LightGBM classifier is the only trained ML model in scope. Every other detector is statistical, rule-based, or offline-intelligence driven. Adding a second trained model requires an explicit plan change.
- **Bounded state.** No unbounded data structure keyed on attacker-controlled values. The attacker must not be able to weaponise the detector's own memory.
- **Two separate planes.** The Scenario Console and the Monitoring Dashboard are separate applications on opposite sides of the boundary. The Scenario Console never informs the dashboard that an attack occurred.

---

## 9. Functional Requirements

### FR-1 — Passive input coverage
The system shall accept, as passive inputs: packet capture / copied packets, live passive tap, **NetFlow v9**, **IPFIX v10**, and derived sensor metadata. **sFlow** shall be recognised as a sampled input mode.

The `input_mode` vocabulary is frozen: `pcap_replay | live_tap | ipfix | netflow_v9 | sflow`.

### FR-2 — Single normalised contract
All input paths shall converge on one normalised event contract. The only difference between paths shall be the capability state attached by the adapter.

### FR-3 — Capability declaration
For every input, each detector shall declare its evidence visibility as `OBSERVABLE`, `DEGRADED` or `NOT_OBSERVABLE`. Missing evidence shall **never** be converted into a benign result. The operator shall see the state.

### FR-4 — Detection coverage
Each of the six PS classes shall have at least one implementation module, a minimum-evidence contract, a replay fixture and an acceptance test.

### FR-5 — Mandatory alert fields
Every alert shall carry:

| PS term | Field | Rule |
|---|---|---|
| timestamp | `timestamp` | Required, ISO-8601 |
| flow identifier | `flow_id` | Required, **never null** |
| threat class | `ps_class` + `threat_class` | `ps_class` is one of the six; `threat_class` is the concrete detector label |
| confidence score | `confidence` | Qualified by `score_type` and `calibrated` |
| supporting evidence | `evidence` | Actual observed values and their interpretation |

### FR-6 — Flow identity for multi-flow events
Alerts shall carry `flow_ref_type` drawn from `flow_5tuple`, `aggregate` or `entity`. Where a single concrete flow is not an honest representation — a spoofed flood, a DGA burst, a scan — the alert shall use `aggregate` or `entity` and derive `flow_id` from the frozen aggregate or entity identity. A bounded sample of contributing flow identifiers may appear as evidence but shall never substitute for `flow_id`.

### FR-7 — Incident lifecycle
Detections shall be deduplicated into incidents with a stable identity, a lifecycle (`NEW` to `ACTIVE` to `UPDATED` to `RESOLVED`), evolving counters and evidence history. A 50 000 pps flood shall produce **one evolving incident**, not one alert per packet or per window.

### FR-8 — Evidence contract
Every incident shall expose actual feature values, the baseline compared against, the detector threshold, an interpretation, the observability state, the model/intel version, and capture-loss information.

### FR-9 — Scoring semantics
The system shall distinguish `robust_z`, `anomaly_score`, `model_probability` and `rule_score`. A percentage shall be displayed only where `calibrated: true`. Statistical detector output shall be labelled a risk or anomaly score, never a probability.

### FR-10 — Tamper-evident history
Incident records and updates shall be hash-chained. Export shall include the chain, and an independent verifier shall be able to detect post-hoc modification from the exported file alone.

### FR-11 — Continuous persistence and export
The incident store shall be written continuously. JSON and CSV export shall be a view over that store, available mid-run. PDF export is optional.

### FR-12 — Read-only monitoring API
The monitoring plane shall expose `GET` and WebSocket only. No `POST`, `PUT` or `DELETE` route shall exist on the monitoring application. Scenario control shall live exclusively in the separate Scenario Console application.

### FR-13 — Capture-loss visibility
The system shall surface sensor and kernel drop information rather than concealing it. Loss is reported as evidence, and where only a single estimator is available it shall be labelled a lower bound.

### FR-14 — Deterministic replay
A recorded scenario shall replay deterministically with a recorded seed, manifest and PCAP hash, producing the same observations.

---

## 10. Non-Functional Requirements

| # | Requirement | Target |
|---|---|---|
| NFR-1 | End-to-end latency | p95 < **2.0 s**, measured from observation to WebSocket emission, never estimated |
| NFR-2 | Throughput — primary PS KPI | **at least 1 000 normalized flows/sec sustained for 60 s**, at **below 1 %** measured loss. Published first |
| NFR-3 | Throughput — secondary system metrics | **at least 50 000 pps** and **at least 400 Mbps**, each sustained for 60 s at **below 1 %** loss |
| NFR-4 | Capture loss at every declared target | below **1 %** |
| NFR-5 | Memory | Bounded under sustained flood; no unbounded growth in flow, template or detector state |
| NFR-6 | UI survivability | Interactive under a 50 000-alert synthetic burst; client ring buffer bounded |
| NFR-7 | Offline | Full cold boot on a second machine with networking disabled |
| NFR-8 | Reproducibility | Every published number carries dataset, command, configuration and output artifact |
| NFR-9 | Determinism | Same replay, same seed, same observations |
| NFR-10 | Measurement context | Throughput is never published without the machine specification beside it, and is never extrapolated |

**Metric-separation rule.** Normalized flows/sec, packets/sec and Mbps are three independent measurements. They are measured separately, published separately, and **never conflated** — a flows/sec figure is never derived from a pps figure, and neither is derived from Mbps. NFR-2 is the primary PS-aligned acceptance target; NFR-3 are secondary system metrics retained from `FINAL_DEVELOPMENT_PLAN_V6.3.md` section 14.1.

---

## 11. Dashboard Requirements

The dashboard is an **operator console**, not a landing page.

Permanent elements:
- LIVE / REPLAY badge
- Capability and health banner
- Risk / severity indication
- Active incident feed

Incident feed rows show: class, severity, confidence or score, current status, key metric, last update.

Evidence drawer shows: actual feature values, baseline, detector threshold, evidence interpretation, observability state, model and intel version, capture-loss information.

Additional operator surfaces: history view, low-confidence tab, visibility/limitations panel, top talkers, advisory panel, replay controls, JSON/CSV export.

The dashboard shall render `NOT_OBSERVABLE` and `DEGRADED` states visibly. It shall never append a percent sign to an uncalibrated score.

The **threat map is optional** and is the first item cut. If retained it must use offline geolocation data only, must badge unresolvable addresses as demo fixtures, and must state that geolocation is not attribution.

---

## 12. Scenario Console Requirements

The Scenario Console is a **separate application** on the attacker side of the boundary, in its own namespace and process.

It provides: a scenario menu, a randomiser with seed logging, PCAP generation during the authorised build phase only, deterministic replay, scenario manifests, and replay speed control.

**It must never notify the Monitoring Dashboard that an attack has occurred.** The dashboard learns only from the observed packet stream. No convenience routing between the planes is permitted for any reason.

During the demonstration the console runs in **REPLAY mode**. After the Hour-6 gate the lab is replay-only; GENERATE is made unreachable outside the build machine during hardening.

---

## 13. Evidence and Alert Requirements

Each PS class carries a **minimum evidence contract**. An alert that cannot meet its contract is not downgraded to benign — it is reported with its observability state.

| Class | Minimum evidence (summary) |
|---|---|
| Volumetric DDoS / flooding | Packet rate, baseline comparison, SYN/SYN-ACK behaviour, unique source count, source entropy, time window. **Reflection:** source/destination relationship, fan-in or amplifier-port evidence, source entropy, reserved-source-space share, rate. **Slowloris:** concurrent half-open/long-lived connections, connection-duration percentile, bytes per connection, low rate, destination/service context |
| Port scanning / reconnaissance | Unique destinations and ports, source-window behaviour, scan pattern, spread, baseline |
| Botnet C2 beaconing | Repeated destination, inter-arrival timing, coefficient of variation, robust timing statistic, persistence across windows, destination novelty |
| DGA / DNS tunnelling | **DGA:** DNS query availability, lexical features, bigram/trigram language-model scores, model score, calibration status, NXDOMAIN context, model version. **Tunnelling:** query length and entropy, encoded-character indicators, query frequency, **qtype distribution including TXT/NULL/CNAME shares**, source/entity context, response behaviour |
| Malware in encrypted sessions | **JA3, JA3S, JA4** where available; destination novelty; first-N packet-size sequence; direction sequence and directional ratio; inter-arrival median, p95 and coefficient of variation; explicit statement that this is suspicion, not payload identification |
| Data exfiltration | Outbound byte/packet behaviour, destination or entity, burst or sustained-transfer evidence, baseline comparison, protocol metadata |

Detailed evidence contracts are owned by `design.md`.

---

## 14. Reporting Requirements

The evaluation report shall publish, per class where applicable: precision, recall, F1, PR-AUC; false alerts per hour on a pure-benign replay; p50 and p95 latency; throughput; threshold sweep results; a baseline comparison; and, for DGA, a reliability diagram and Brier score.

**Detector-level and incident-level evaluation are reported separately.** A run producing 1 842 anomalous windows, 17 candidate alerts and 1 deduplicated incident counts as **one** predicted incident at incident level. The report states the matching key, the time-overlap rule, the tolerance, how duplicates collapse and how simultaneous classes are handled.

The baseline comparison covers the implemented system, static thresholds, and stock signature rules where meaningful. Where rules perform better, the report concedes it.

Deliverable documents required by the plan and referenced from here: `README.md`, `LIMITATIONS.md`, the model card, the feature dictionary, the evaluation report, scenario manifests, PCAP hashes, expected-alert contracts, and the PS26145 traceability matrix.

---

## 15. Acceptance Criteria

The product is acceptable when all of the following hold. Ownership and gate hours are in `implementation_plan.md`; verification methods are in `testing.md`.

- [ ] Real PCAP replay produces contract-valid normalised events through both capture paths.
- [ ] NetFlow v9 and IPFIX fixtures normalise through the shared adapter and preserve template and sampling metadata.
- [ ] The `input_mode` enum contract test passes.
- [ ] Capability state is computed and rendered; `NOT_OBSERVABLE` is visible to the operator.
- [ ] Every emitted alert has a non-null `flow_id` and a valid `flow_ref_type`.
- [ ] All six PS classes detect on their fixtures, or ship a documented fallback.
- [ ] Slowloris is exercised independently with low-rate, long-duration fixtures.
- [ ] DNS tunnel evidence contains the qtype distribution and TXT/NULL/CNAME shares where visible.
- [ ] TLS/QUIC evidence contains JA3S and concrete packet-size, direction and inter-arrival fields where visible.
- [ ] Alerts deduplicate into incidents; a flood yields one evolving incident.
- [ ] The evidence drawer contains real observed values and a baseline comparison.
- [ ] The UI survives the 50 000-alert burst and remains interactive.
- [ ] The negative-connectivity test passes and its output is archived as an artifact.
- [ ] The hash-chain verifier passes from a clean process against exported data.
- [ ] Throughput meets NFR-2 (at least 1 000 normalized flows/sec for 60 s at below 1 % loss) and is published with the machine specification, alongside the NFR-3 secondary metrics.
- [ ] p95 latency is measured against the 2.0 s SLO.
- [ ] False alerts per hour is measured on the BENIGN_STRESS replay.
- [ ] A threshold sweep exists with artifacts for every published threshold.
- [ ] DGA hard-negative evaluation is included.
- [ ] Detector-level and incident-level evaluation rules are documented and reproducible.
- [ ] Resource metrics are captured alongside the throughput result.
- [ ] Sensor/API restart and recovery tests pass.
- [ ] Offline asset audit and second-machine cold boot pass.
- [ ] README and model card state exactly one trained ML model and identify all non-ML detectors.

**Resolved at Phase 0.** `FINAL_DEVELOPMENT_PLAN_V6.3.md` section 14.1 named sustained **flows/sec** the primary PS throughput KPI but declared numeric targets only for pps and Mbps, leaving the primary metric without a stopping condition. The project owner set the acceptance target at **at least 1 000 normalized flows/sec sustained for 60 s at below 1 % measured loss** (NFR-2), retaining the V6.3 pps and Mbps figures unchanged as secondary system metrics (NFR-3). Recorded in `bugs.md` `DOC-004` and `memory.md`.

---

## 16. Explicitly Out of Scope

- Payload decryption of any kind, including TLS termination, key escrow and DoH/DoT interception.
- Malware family identification or attribution from encrypted sessions.
- Any mitigation, blocking, quarantine or response action.
- Any outbound request across the monitored boundary, including active probing and enrichment lookups.
- Live threat-intelligence feeds, live geolocation services, or runtime LLM inference.
- A second trained ML model.
- Additional detector families beyond the eight modules.
- Attack generation outside the isolated laboratory environment.
- Runtime address anonymisation. All capture is lab-synthetic; the forward path for real enclave traffic is documented in `LIMITATIONS.md`.
- Inter-stage JSON file transport. JSON exists only at the sensor input boundary, the storage boundary and the WebSocket output.

---

## 17. Stretch Features

Ordered by cut priority — first to be cut appears first. These are built only when all scheduled work is green, and are cut before any core detection capability.

1. Threat map (offline geolocation).
2. PDF export.
3. Scenario Console visual polish.
4. Clock-servo Kalman filtering.
5. Capture-loss Kalman fusion.
6. Lomb-Scargle periodicity analysis.
7. Sophisticated fusion and cross-detector correlation.
8. SHAP attribution.

**Never sacrifice a core capability for a stretch feature.** The protected set — incident feed, evidence drawer, DGA model, DDoS statistics, scan statistics, capability banner, read-only negative test, measured throughput, and the NetFlow v9/IPFIX normalisation contract with capability degradation — is never cut.
