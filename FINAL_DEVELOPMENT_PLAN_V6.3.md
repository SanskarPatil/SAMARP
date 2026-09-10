# Final Development Plan — Passive Streaming Cyber Intelligence Layer

**Project:** PS26145  
**Version:** V6.3 — V6.2 plus PS-alignment hardening for passive flow-record ingest, alert identity, DNS/TLS evidence, dataset traceability, and capability contracts. No architecture change, no detector-family expansion.  
**Source baseline:** `PS26145_Final_Technical_Plan_V6.pdf`  
**Document status:** Development-ready  
**Purpose:** Operational source of truth for the 24-hour implementation  
**Rule:** Build the spine before the brains.

---

## 0.0 Changelog — V6.2 to V6.3

### High severity

1. `POST /simulate/scenario/{id}` removed from the Plane B API (§17). V6 put an attack-starting endpoint on the monitoring side; that reads as a return path and collapses the read-only argument.
2. Detector count corrected — eight modules, six PS classes — with an explicit mapping table (§1.1). V6 said "seven" and listed eight.
3. Lab Address Plan added (§2A). Reflection reserved-source share, geolocation, direction inference and destination novelty all depend on it.
4. Suricata mandatory configuration restored (§7A). Five silent defaults each disable a detector without erroring.
5. Replay timestamp formula corrected (§6.1). `now` evaluated per packet double-counts elapsed time.
6. Per-class deduplication keys frozen (§13.1).
7. DGA artifact pre-built and vendored; rule fallback added to the kill ladder (§10.3, §40).
8. Latency budget restored (§6.5). V6 measured p95 with no declared target.
9. Hash-chain canonical serialisation specified (§19.1).

### Medium severity

10. PCAP generation scheduled as Ticket 0 and frozen at the hour-6 gate (§30, §45).
11. OS/box decision moved before hour 0; WSL2 ruled out for the throughput number (§29).
12. Throughput target declared (§14.1).
13. Documentation moved to incremental from hour 6; hours 19–22 are rehearsal only (§37).
14. Backup recording moved to immediately after the hour-16 gate (§34).
15. Rest rotation added (§39.1).
16. UI load-test versus demo-narrative conflict resolved (§23.5).
17. Anonymisation position stated explicitly (§2A.4).

### Low severity

18. Baseline warm-up versus startup snapshot clarified (§12).
19. CSV export flattening rule defined (§18).
20. Boundary-test output archived as an artifact (§23.5).
21. `thresholds.yaml` seeded with starting values (§22.1).
22. Definition of Done given owner and gate hour (§46).


### V6.2 hardening (carried forward)

23. Added a PS26145 traceability matrix linking each PS class to inputs, features, detector modules, evidence contracts, and tests.
24. Defined detector-level and incident-level evaluation units to prevent alert-window/deduplication ambiguity.
25. Separated statistical/risk scores from calibrated model probabilities in the alert and UI semantics.
26. Added DGA hard negatives and a dedicated `BENIGN_STRESS` replay scenario.
27. Added a detector capability matrix covering `OBSERVABLE`, `DEGRADED`, and `NOT_OBSERVABLE` outcomes.
28. Added sensor degradation/failure and restart/recovery acceptance tests.
29. Expanded performance reporting to include CPU, RAM, queue depth, active state, events/sec, packet loss, and related resource metrics.
30. Added an optional throughput-vs-loss operating-envelope benchmark.
31. Added an Hour-12 integration checkpoint before the final detector push.
32. Replaced judge-facing "zero-day" claims with "previously unseen patterns" wording.
33. Changed TLS/QUIC UI wording to `Suspicious Encrypted Session` / `Encrypted Session Anomaly`; payload identification remains explicitly out of scope.
34. Added an operator-facing visibility/limitations panel.
35. Added a hash-chain tamper demonstration and a concise Suricata-vs-intelligence comparison view.
36. Updated the Definition of Done, tickets, demo, Q&A, and deliverables to cover the new proof obligations.

---

### V6.3 PS-alignment hardening

36. Added a shared NetFlow v9 / IPFIX flow-record adapter with a template cache; sFlow is recognized as a capability mode and remains `NOT_OBSERVABLE` for detectors that require unsampled packet/flow semantics.
37. Added a literal PS constraint-(e) mapping for `timestamp`, `flow_id`, `threat_class`, `confidence`, and `supporting evidence`, with non-null `flow_id` and explicit `flow_ref_type`.
38. Restored explicit DNS record-type features (`qtype` distribution, TXT/NULL/CNAME shares) to the frozen feature/evidence contract.
39. Restored Slowloris as a real low-rate exhaustion detector inside `ddos.py` using half-open concurrency, connection duration, bytes/connection, and low-rate evidence.
40. Restored JA3S throughout the TLS/QUIC normalized event, evidence, capability, and alert contracts.
41. Changed benchmark presentation to report **flows/sec first**, followed by Mbps and pps, matching the PS throughput wording.
42. Added an explicit mapping from PS-named benign/attack generation sources to project fixtures, including the documented DGArchive substitution.
43. Froze DGA bigram/trigram language-model features and made their provenance explicit.
44. Defined TLS/QUIC shape concretely as packet-size sequence, direction sequence, and inter-arrival statistics rather than an undefined generic "shape" score.
45. Froze `input_mode` enum values and replaced the generic capability matrix with detector-specific partial-visibility conditions.
46. Explicitly documented that the build contains one trained ML model (DGA); all other detectors are statistical, rule-based, or offline-intelligence based.
47. Updated the execution plan, tickets, Definition of Done, demo, Q&A, repository structure, and final decision summary for the above PS-alignment requirements.

---

## 0. Executive Definition

We are building a **passive, streaming cyber-intelligence layer** for a monitored enclave behind a one-way boundary/diode.

The system:

- consumes copied network traffic, Suricata EVE metadata, and offline exported flow records where supplied;
- never sends traffic to monitored/production endpoints;
- never decrypts TLS or QUIC payloads;
- detects suspicious behavior using streaming statistics, bounded state, offline intelligence, and one calibrated DGA ML model;
- converts observations into evidence-rich incidents;
- explicitly reports when required evidence is **`not_observable`**;
- maintains a tamper-evident incident chain;
- provides an operator dashboard and deterministic PCAP replay;
- works with networking disabled after the build assets are prepared.

The primary objective is **not maximum detector count**. It is a reliable end-to-end system that can prove:

1. traffic enters through the intended passive path;
2. the monitor cannot send traffic back;
3. the same replay produces deterministic observations;
4. real traffic produces real alerts;
5. alerts contain evidence and baselines;
6. the UI survives high-volume floods;
7. measurements are reproducible;
8. limitations are explicitly represented.

---

# 1. Scope

## 1.1 Threat classes

The implementation contains **eight detector modules** mapped to the **six PS 26145 threat classes**.

| PS 26145 class (external wording) | Detector modules (internal) | Note |
|---|---|---|
| Volumetric DDoS / flooding | `ddos.py`, `reflection.py` | One presented class, two modules |
| Port scanning / reconnaissance | `scan.py` | |
| Botnet C2 beaconing | `c2.py` | |
| DGA / DNS tunnelling | `dga.py`, `dns.py` | One presented class, separate evidence contracts |
| Malware in encrypted sessions | `tls_quic.py` | Suspicion only, never payload identification |
| Data exfiltration | `exfil.py` | |

### Terminology rule

V6 said "seven classes" and listed eight, while the PS defines six. That drift was the exact failure §1 warns against.

- **External wording** — PS response, UI class labels, README, deck, evaluation report — uses the six PS class names in the left column, verbatim.
- **Internal wording** — module filenames, detector registry, the `detector` field — uses the eight module names in the middle column.

The alert schema carries both:

```text
ps_class   one of the six PS class names
detector   one of the eight module names
```

The detector registry is the source of truth for modules. The problem statement is the source of truth for classes. A contract test asserts every `detector` value maps to exactly one `ps_class`.


## 1.2 PS26145 Traceability Matrix

This is the single requirement-to-implementation map used for development, testing, and the judge presentation.

| PS 26145 class | Observable input | Core features | Internal detector module(s) | Minimum evidence | Primary test |
|---|---|---|---|---|---|
| Volumetric / protocol DDoS | IP/TCP/UDP headers, packet/flow timing; IPFIX/NetFlow where packet detail is absent | pps, byte rate, SYN/SYN-ACK behavior where visible, unique sources, source entropy, half-open concurrency for Slowloris | `ddos.py`, `reflection.py` | rate, baseline delta, TCP behavior if visible, source count/entropy, half-open count/duration for Slowloris, window | `test_ddos.py`, `test_reflection.py`, `test_slowloris.py` |
| Botnet C2 beaconing | repeated flow metadata | inter-arrival time, CV, robust timing deviation, persistence, destination novelty | `c2.py` | repeated destination, timing statistics, persistence, novelty | `test_c2.py` |
| DGA domains / DNS tunnelling | DNS metadata where available | name length, entropy, bigram/trigram LM scores, NXDOMAIN rate, query frequency, qtype distribution | `dga.py`, `dns.py` | DNS availability, lexical/n-gram features, qtype distribution, model/rule score, query behavior | `test_dga.py`, `test_dns_tunnel.py` |
| Malware inside encrypted sessions | TLS/QUIC metadata | JA3/JA3S/JA4 if available, destination novelty, packet-size sequence, direction sequence, inter-arrival statistics | `tls_quic.py` | client/server fingerprints where visible, novelty, concrete shape features, explicit suspicion wording | `test_tls_quic.py` |
| Reconnaissance / port scanning | flow headers | unique hosts, unique ports, fan-out, spread over time | `scan.py` | destination/port spread, scan pattern, baseline | `test_scan.py` |
| Data exfiltration | directional flow metadata | outbound bytes, inbound/outbound ratio, burst/sustained transfer behavior | `exfil.py` | direction, volume asymmetry, destination, temporal evidence | `test_exfil.py` |

**Traceability rule:** every externally presented PS class must have at least one implementation module, an evidence contract, a replay fixture, and an acceptance test. The six PS classes remain the external terminology; the eight internal modules remain implementation terminology.

## 1.3 PS requirement-level traceability

| PS requirement | V6.3 implementation | Proof artifact |
|---|---|---|
| Passive one-directional monitoring | read-only Plane B, no return route, negative-connectivity test | `artifacts/boundary_test_*.txt` |
| Passive inputs include PCAP / flow records / derived metadata | PCAP/EVE path plus shared NetFlow v9/IPFIX adapter; sFlow capability recognition | flow fixtures + capability report |
| Near-real-time streaming | bounded windows, watermark, WebSocket streaming | p50/p95 latency report |
| No TLS/QUIC decryption | field allowlist, fingerprint/shape-only detector | sensor config + evidence drawer |
| DDoS / protocol flooding | `ddos.py`, `reflection.py`, Slowloris path | replay fixtures + evidence contracts |
| Botnet C2 beaconing | periodicity detector | beacon fixture + timing evidence |
| DGA / DNS tunnelling | LightGBM DGA + DNS rule ensemble, n-grams, qtypes | calibrated model + DNS evidence |
| Malware in encrypted sessions | JA3/JA3S/JA4 + novelty + concrete shape features | TLS/QUIC fixture + metadata evidence |
| Reconnaissance / port scanning | bounded fan-out/cardinality detector | scan fixture |
| Data exfiltration | directional byte asymmetry + baseline | exfil fixture |
| Standard alert schema | `timestamp`, non-null `flow_id`, PS class, confidence, evidence | JSON Schema v1.3 + contract tests |
| Stated throughput | flows/sec primary, Mbps + pps secondary | benchmark artifact |
| Model/features/training documentation | one trained LightGBM DGA model; all other detectors documented as statistical/rule/intel | README + model card + feature dictionary |

---

# 2. Non-Negotiable Constraints

## 2.1 Passive / read-only

The monitoring side must not have an actionable return path.

The negative-connectivity test must demonstrate:

- the monitor has no route to the attacker/monitored network;
- outbound connection attempts from the enclave fail;
- alerts continue to flow through the monitoring pipeline.

Recommendations shown by the dashboard are **advisory text only**. There is no mitigation button, command, API call, or return path.

## 2.2 No decryption

TLS/QUIC detection uses:

- visible handshake metadata where available;
- JA3/JA3S/JA4 fingerprints where supported;
- destination novelty;
- behavioral/shape features;
- offline intelligence.

Never claim payload identification or decrypted-content inspection.

## 2.3 Offline operation

Assume zero internet connectivity at the venue.

Vendor/cache:

- Python wheels/dependencies;
- Node dependencies;
- Suricata package/build;
- GeoLite2 if map is retained;
- TopoJSON if map is retained;
- offline intelligence bundle;
- model artifact;
- all required test PCAPs;
- scenario manifests.

Run an offline asset audit before the demo.

## 2.4 Passive flow-record ingest

The PS background explicitly names packet captures, exported flow records (**NetFlow/IPFIX/sFlow**), and derived metadata as passive inputs. V6.3 therefore supports a real flow-record path without changing the detector architecture.

### Input adapter contract

Use one shared template-based decoder for **NetFlow v9 and IPFIX v10**:

```text
NetFlow v9 ──┐
             ├──> shared template cache + record decoder ──> NormalizedEvent
IPFIX v10 ──┘

Sampled sFlow ──> capability recognition ──> DEGRADED / NOT_OBSERVABLE
```

Do not write two independent parsers. NetFlow v9 and IPFIX both use template-defined records; the adapter normalizes the common fields into the same event contract used by PCAP/EVE.

Offline fixtures are generated during the build/preparation step from project PCAPs using an exporter such as `yaf`, `nfpcapd`, or `softflowd`, then copied into the offline asset bundle. No exporter runs inside Plane B during the demo.

The normalized event must set:

```text
input_mode: ipfix | netflow_v9
```

The adapter must preserve source/observation time, exporter/template metadata, five-tuple fields where present, byte/packet counters, direction where available, and sampling metadata.

### Capability behavior

Plain NetFlow/IPFIX normally preserves flow-level rate, cardinality, direction and timing information but may not contain DNS names or TLS/QUIC fingerprints. Packet-level and name-dependent detectors therefore degrade explicitly rather than silently failing.

Sampled sFlow is recognized but is not a full packet-equivalent input. Sampling-aware volumetric statistics may remain usable; detectors that depend on unsampled packet order, complete port spread, DNS names, or TLS fingerprints declare `DEGRADED` or `NOT_OBSERVABLE` according to §7C.

**Demo beat:** switch from PCAP/EVE input to an IPFIX fixture; packet/DNS/TLS-specific capabilities visibly degrade while flow-based detectors remain available.

---

## 2.5 Attack generation safety

Attack generation is permitted only in the isolated laboratory environment.

Use:

- Linux network namespaces;
- veth pairs;
- or a host-only virtual network with no bridge to a physical interface.

Before every generation run verify:

1. output interface is a veth/host-only adapter, never a physical NIC;
2. target is inside the declared lab subnet.

Generate attack PCAPs only during the early build phase. After the generation phase, switch to deterministic replay.

Never run attack tools against:

- college networks;
- hostel Wi-Fi;
- hackathon venue networks;
- cloud VMs;
- third-party IPs;
- any system not personally owned/authorized.

Treat malware-capture datasets as hostile packet data. Never execute binaries contained inside them.

---

# 2A. Lab Address Plan

**New in V6.2.** Several detector features carry address semantics. Without a declared plan they misfire in an RFC 1918 lab.

## 2A.1 Declared ranges

```text
Monitored enclave (internal)    10.10.0.0/16
Enclave DNS resolver            10.10.0.53
Monitoring enclave (Plane B)    10.20.0.0/16   no route to 10.10/16, no route external
Lab transport (veth pairs)      10.99.0.0/24

External / attacker-side sources
  benign external               curated public ranges, GeoLite2-resolvable
  synthetic malicious           curated public ranges, GeoLite2-resolvable
  amplifier hosts               curated public ranges, ports 53 / 123 / 389 / 1900 / 11211
```

The plan lives in:

```text
config/address_plan.yaml
```

Every module needing address semantics reads it. No hardcoded prefix checks inside detector code.

## 2A.2 Consumers

| Feature | Depends on the plan for |
|---|---|
| Direction (inbound / outbound) | enclave prefix list |
| Exfiltration outbound bytes | direction |
| Reflection reserved-source share | bogon list **excluding** declared lab prefixes |
| Destination novelty | enclave + known-good external |
| Geolocation / threat map | external ranges must be GeoLite2-resolvable |
| IPv6 `/48` entropy bucketing | declared v6 prefixes |

Direction was never defined anywhere in V6, yet `exfil.py` cannot exist without it.

## 2A.3 The trap this fixes

Reflection minimum evidence (§9.2) includes reserved/invalid source-space share. In a pure RFC 1918 lab that share is **100 % on benign traffic**, so the detector fires continuously and the false-alerts-per-hour number is destroyed.

Rule: the reserved-share feature is computed against the **external** address space only. Declared lab prefixes are excluded from the bogon set, and the exclusion is stated in the evidence drawer text.

Same failure family as the geolocation trap — private lab addresses have no country. Both are fixed by this one plan.

## 2A.4 Anonymisation

Position: **no runtime anonymisation in V6.3.**

Reason: all capture is lab-synthetic. There is no real subscriber data to protect.

State it in `LIMITATIONS.md` with the forward path: for real enclave traffic, CryptoPAn is applied **after** geolocation and **before** persistence, because prefix-preserving anonymisation destroys geo lookup if applied first.

Do not leave this ambiguous. A judge will ask whether you store raw addresses.

---

# 3. MVP Definition

## Tier 0 — Must Work

```text
Isolated lab
   ↓
PCAP replay
   ↓
veth / passive capture path
   ↓
Fast header counter + Suricata
   ↓
EVE normalizer
   ↓
Capability state
   ↓
Window features / bounded state
   ↓
DDoS + scan + DGA
   ↓
Frozen alert schema
   ↓
Incident deduplication/lifecycle
   ↓
FastAPI/WebSocket
   ↓
Dashboard
```

The Tier 0 system must work before serious Tier 1 work begins.

## Tier 1 — Strong differentiators

- DNS tunnel detector
- C2 beaconing
- exfiltration
- TLS/QUIC metadata detector
- evidence drawer
- baseline comparison
- calibration
- hash chain
- capability/health banner
- read-only proof

## Tier 2 — Stretch / first to cut

- threat map
- PDF export
- clock-servo Kalman filter
- Lomb-Scargle periodicity
- sophisticated fusion/correlation
- Scenario Console visual polish
- additional model training

**Never sacrifice Tier 0 for Tier 2.**

---

# 4. Architecture

## 4.1 Two-plane architecture

The project contains two separate applications.

### Plane A — Attacker / Scenario Console

Runs in the isolated attacker-side environment.

Responsibilities:

- scenario menu;
- randomizer + seed logging;
- PCAP generation during the authorized build phase;
- deterministic PCAP replay;
- scenario manifests;
- replay speed;
- GENERATE/REPLAY mode.

### Plane B — Monitoring Dashboard

Runs inside the monitoring enclave.

Responsibilities:

- receive passive copied traffic;
- consume Suricata EVE;
- consume normalized NetFlow v9/IPFIX flow records;
- normalize events;
- calculate features;
- run detectors;
- create/update incidents;
- persist history;
- provide evidence;
- export results;
- show capability state.

### Critical separation rule

The Scenario Console must **never notify the Monitoring Dashboard that an attack has happened**.

The dashboard learns only from the observed packet stream.

During the final demo, the Scenario Console runs in **REPLAY mode**.

---

# 5. Data Flow

```text
                         ATTACKER / OFFLINE SIDE
┌──────────────────────────────────────────────────────────────┐
│ Scenario Console / offline asset builder                    │
│ Scenario → Manifest → Hashed PCAP                            │
│ PCAP → IPFIX/NetFlow fixture export (build time only)       │
└───────────────────────────┬──────────────────────────────────┘
                            │
                            │ one-way copied data / replay only
                            ▼
====================== ONE-WAY BOUNDARY ========================
                            │
                            ▼
                     MONITORING ENCLAVE
                            │
          ┌─────────────────┼──────────────────┐
          ▼                 ▼                  ▼
   Header-only path     Suricata EVE      Flow-record adapter
          │                 │             NetFlow v9 / IPFIX
          │                 │                  │
          └─────────────────┼──────────────────┘
                            ▼
                       Normalizer
                            │
                  Capability negotiation
                            │
                  Window/state processing
                            │
                         Features
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
          Statistics       DGA       Intel / shape
              │             │             │
              └─────────────┼─────────────┘
                            ▼
                       Alert scorer
                            │
                       Deduplication
                            │
                    Incident lifecycle
                            │
                ┌───────────┴───────────┐
                ▼                       ▼
             SQLite                 WebSocket
                │                       │
                └───────────┬───────────┘
                            ▼
                        Dashboard

BOUNDARY RULE: nothing above writes back toward the packet source.
```

The same normalized event contract is used for PCAP/EVE and flow-record inputs. The only difference is the capability state attached by the adapter.

For NetFlow v9/IPFIX, the shared template cache is bounded and evicted by exporter/template identity and timeout. A malformed or attacker-controlled template stream must not create unbounded parser state.


# 6. Frozen Contracts

These are the boundaries that all tracks code against.

## 6.1 Normalized Event Contract

The normalizer must expose a stable internal event representation containing, as applicable:

- observed timestamp;
- source/destination IP;
- source/destination port;
- protocol;
- TCP flags;
- packet/byte counts;
- flow identity;
- DNS fields;
- TLS fields;
- QUIC fields;
- direction;
- capture source;
- sensor loss information;
- capability/observability fields;
- `input_mode`;
- flow identity metadata (`flow_id`, `flow_ref_type`) where an alertable observation exists.

### Frozen `input_mode` enum

```text
pcap_replay | live_tap | ipfix | netflow_v9 | sflow
```

`input_mode` describes the primary input contract, not an internal combination such as `pcap_replay+eve`. Sensor subpaths are represented separately in capability state.

### Timestamp rule

For replay:

```text
t_display = t_replay_start + (t_packet - t_pcap_start) / replay_speed
```

`t_replay_start` is captured **once** when replay begins and written into the scenario manifest.

V6 wrote `now` here. Implemented literally, `now` is re-evaluated per packet, so wall-clock elapsed is added on top of PCAP-relative elapsed and the displayed clock drifts at roughly 2x. This is the dual-clock correlation failure; do not reintroduce it.

Preserve the original timestamp separately as `observed_time`.

Never silently treat old PCAP timestamps as current live time.

---

## 6.2 `flow_summary` ownership

Suricata EVE flow events are intentionally disabled to reduce flow-event output pressure.

Therefore:

> **`flow_summary` is produced by the bounded in-process flow tracker/header path, not by Suricata EVE flow output.**

The implementation must not re-enable Suricata EVE flow events merely to populate this field.

The flow tracker must be bounded by:

- memory cap;
- eviction policy;
- maximum active state;
- timeout.

A spoofed flood must not be able to exhaust detector memory.

---

## 6.3 Alert Schema v1.3

Create the actual schema file:

```text
schemas/alert.schema.json
```

It is the source of truth for:

- required fields;
- types;
- enum values;
- evidence structure;
- observability state;
- detector metadata;
- incident identity;
- sequence/hash-chain fields.

Contract tests must fail on schema drift.

Do not use commented JSON as the canonical schema. If documentation needs comments, label the example as JSONC.

### 6.3.1 PS constraint-(e) field mapping — frozen

The PS names five mandatory alert concepts. They map literally as follows:

| PS term | V6.3 schema field | Rule |
|---|---|---|
| timestamp | `timestamp` | Required ISO-8601 display/alert time |
| flow identifier | `flow_id` | Required non-null stable identifier |
| threat class | `ps_class` / `threat_class` | Must map to one of the six PS classes; `threat_class` remains the concrete detector label |
| confidence score | `confidence` | Required numeric confidence/evidence-strength representation with `score_type` and `calibrated` semantics |
| supporting evidence feature | `evidence` | Required object containing actual feature values and their interpretation |

### Flow identity rule

A single incident may represent many underlying flows, so `flow_id` identifies the alertable observation context rather than pretending one packet/flow exists when the event is an aggregate. Freeze:

```text
flow_ref_type = flow_5tuple | aggregate | entity

flow_id = sha256(canonical(5-tuple))[:16]
          | sha256(canonical(dedup_key))[:16]
          | sha256(canonical(entity))[:16]
```

Mapping:

- `flow_5tuple` — one concrete flow is observable;
- `aggregate` — DDoS/reflection or another multi-flow event; the canonical aggregate identity is hashed;
- `entity` — DGA, scan, or similar behavior is best represented by a source/entity identity.

`flow_id` is **never null**. For a spoofed flood there is no honest single source flow, so the alert uses `flow_ref_type: aggregate` and hashes the frozen aggregate/dedup identity. Bounded `flow_ids` may remain as a sample of underlying flows, but they do not replace the mandatory `flow_id`.

---

## 6.4 Feature Order

Create:

```text
features/feature_order.py
```

or an equivalent single authoritative artifact.

Training and inference must import the same feature order.

Example:

```python
FEATURE_ORDER = (
    # DGA
    "length", "entropy", "digit_ratio", "vowel_ratio", "label_count",
    "lm_bigram", "lm_trigram", "nxdomain_rate",
    # DNS tunnel
    "qtype_txt_ratio", "qtype_null_ratio", "qtype_cname_ratio", "qtype_entropy",
    # TLS/QUIC shape
    "packet_size_first_n", "packet_size_mean", "packet_size_p95", "iat_median", "iat_p95", "iat_cv",
    "upstream_packet_ratio", "downstream_packet_ratio",
)
```

The exact tuple shipped in code is the frozen source of truth; the above is the required semantic minimum, not permission to reorder features.


No detector/model is allowed to construct its own feature ordering.

Add a parity test:

```text
offline feature extraction
        ==
streaming feature extraction
```

for the same traffic fixture.

---

## 6.5 Latency Budget

Frozen. Every track codes against these numbers. V6 measured p95 without declaring a target, which leaves no answer to "what is your bound?".

```text
watermark / out-of-order grace        300 ms
window close + feature emit          ~1.0 s     (1 s tumbling window)
detector scoring + dedup             ~100 ms
API + WebSocket batch push            250 ms
------------------------------------------------
structural floor                     ~1.6 s
SLO                                   p95 < 2.0 s
```

`latency_ms` in the alert schema measures `t_observed` to `t_websocket_emit`. Measured, never estimated.

If p95 exceeds the SLO, fix in this order: batch push interval, then window size, then detector cost. **Never shrink the watermark** — that drops late packets silently and trades a visible latency number for invisible missed detections.

These values live in `config/thresholds.yaml` and appear on deck Slide 5.

---

# 7. Capability Model

The system must distinguish:

- `OBSERVABLE`;
- `DEGRADED`;
- `NOT_OBSERVABLE`;
- `UNAVAILABLE`.

Never infer "benign" from missing evidence.

## 7.1 Serialized capability state

```text
input_mode
ipv4
ipv6
dns_names
dns_responses
tls_handshake
quic_metadata
ja3
ja3s
ja4
flow_records
flow_sampling
geo
capture_loss
bidirectional_visibility
```

The exact enum values are frozen by the contract. `input_mode` is one of:

```text
pcap_replay | live_tap | ipfix | netflow_v9 | sflow
```

## 7.2 Detector-specific visibility behavior

| Detector | Full evidence | Partial evidence → `DEGRADED` | Missing evidence → `NOT_OBSERVABLE` |
|---|---|---|---|
| DDoS | packet/flow rate + headers/timing | flow records without TCP flags; sampled rate with sampling metadata | no usable packet/flow rate |
| Reflection | flow/header rate + UDP service/source semantics | flow records with incomplete source-port/service detail | no usable source/destination/protocol evidence |
| Scan | source + destination + port spread | IPFIX/NetFlow with sampled or partial spread | no source/port spread |
| Slowloris | half-open/long-lived connection state + low-rate bytes | flow records with duration/bytes but no TCP-state detail | no duration/connection state evidence |
| DGA | DNS names + query context + NXDOMAIN | names visible but missing response context | no DNS names |
| DNS tunnel | DNS names + qtype + timing + response context | names/timing but missing qtype or responses | no DNS names |
| C2 | repeated flow timing + entity persistence | sampled flow timing with uncertainty | insufficient repeated flow observations |
| Exfiltration | directional bytes + destination/entity | one-direction source volume only; no reply side | no usable byte/direction evidence |
| TLS/QUIC | handshake + JA3/JA3S/JA4 + packet shape | partial handshake or fingerprint visibility | no relevant TLS/QUIC metadata |

For plain NetFlow/IPFIX, DDoS/scan remain generally flow-observable; C2 and exfiltration may remain usable depending on timing/direction fields; DNS names and TLS/QUIC fingerprints are normally `NOT_OBSERVABLE`. For sFlow, sampling state is always surfaced and packet-order-sensitive detectors degrade accordingly.

## 7.3 `not_observable`

Examples:

```text
DNS unavailable → DGA = NOT_OBSERVABLE
sampled flow input → packet-order detector = DEGRADED / NOT_OBSERVABLE
v4-only detector on v6 → NOT_OBSERVABLE
ECH hides SNI → SNI-dependent evidence = NOT_OBSERVABLE
IPFIX record omits DNS/TLS fields → name/fingerprint detector = NOT_OBSERVABLE
```

The dashboard must visibly render these states.


# 7A. Suricata Sensor Configuration — Mandatory

**Verified/hardened in V6.3.** Suricata ships with defaults that silently disable detectors. A detector with no input does not error; it simply never alerts, and the team spends four hours debugging the detector instead of the sensor.

Every item below is verified by the hour-0 capability probe, and the result is recorded in the capability state.

## 7A.1 Version pin

```text
Suricata >= 7.0.3     required for JA4
```

Record the exact version in the capability state and in every alert's sensor metadata.

## 7A.2 The five silent defaults

**1. EVE log types.** The default eve-log does not emit what the detectors need.

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - dns:
            requests: yes
            responses: yes
        - tls:
            extended: yes
        - quic
        - anomaly
        - stats
        # flow: intentionally NOT enabled — see §6.2
```

Missing `dns.responses` removes NXDOMAIN context, which is minimum evidence for DGA (§9.4) **and** a required feature for the DNS-tunnel ensemble (§10.4).

**2. Fingerprints are off by default.**

```yaml
app-layer:
  protocols:
    tls:
      enabled: yes
      ja3-fingerprints: yes
      ja4-fingerprints: yes
    quic:
      enabled: yes
```

If JA4 is unavailable in the built version: record it and use JA3/JA3S plus the remaining visible metadata. Render unavailable fingerprint fields as `NOT_OBSERVABLE`. Never silently omit.

**3. Stats disabled means no capture-loss counters.**

```yaml
stats:
  enabled: yes
  interval: 1
```

Without this there is no `kernel_drops`, therefore no `sensor_drop_pct`, therefore the entire capture-loss story in §14 does not exist and the "loss is evidence" Q&A answer is unsupported.

**4. Capture ring too small — drops under the demo flood.**

```yaml
af-packet:
  - interface: <veth>
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    ring-size: 200000
    block-size: 1048576
```

The default ring drops during the 50 000 pps flood, and the loss is then wrongly attributed to the detection pipeline rather than the capture layer.

**5. Stream reassembly depth truncates sessions.**

```yaml
stream:
  memcap: 512mb
  reassembly:
    memcap: 256mb
    depth: 1mb
```

Truncated reassembly silently shortens the flows that the exfiltration and beaconing detectors depend on.

## 7A.3 Probe acceptance criteria

The hour-0 gate fails unless the probe reports, against a known fixture PCAP:

```text
dns request events       > 0
dns response events      > 0
tls handshake events     > 0
ja3 present              yes
ja3s present             yes | recorded-unavailable
ja4 present              yes | recorded-unavailable
quic events              > 0 | recorded-unavailable
stats.kernel_drops       field present
flow events              == 0        (must stay off — §6.2)
```

---


## 7B. Score and Confidence Semantics

Do not treat every detector score as a probability.

### Score types

| `score_type` | Meaning | Example | Calibrated? |
|---|---|---:|---|
| `robust_z` | Distance from a robust baseline | `9.2` | No |
| `anomaly_score` | Detector-specific evidence strength | `0.87` | No unless explicitly calibrated |
| `model_probability` | Calibrated ML probability estimate | `0.94` | Yes, only after calibration |
| `rule_score` | Deterministic evidence/rule aggregation | `4` | No |

The alert schema should therefore preserve:

```text
score
score_type
confidence
calibrated
```

`confidence` is the PS-required confidence field. For calibrated DGA output it is a probability-like estimate. For statistical/rule detectors it is an explicitly documented evidence-strength mapping, not a probability. The UI must never append `%` unless `calibrated: true`.

For statistical detectors, `confidence` may be null. The UI must label these as **risk/anomaly scores**, not percentages.

For the DGA model, `confidence` may equal the calibrated model probability and must show its calibration status and model version.

**Judge-facing rule:** never say that a robust z-score or rule score is a probability.


## 7C. Detector Capability Matrix

Every detector declares what evidence it requires and what happens when that evidence is unavailable.

| Detector | Required capability/evidence | If available | If partially available | If unavailable |
|---|---|---|---|---|
| DDoS | IP/TCP/UDP headers + timing | `OBSERVABLE` | `DEGRADED` | `NOT_OBSERVABLE` |
| Reflection | source/destination + protocol/port semantics | `OBSERVABLE` | `DEGRADED` | `NOT_OBSERVABLE` |
| Scan | source/destination/port headers | `OBSERVABLE` | `DEGRADED` | `NOT_OBSERVABLE` |
| DGA | DNS query names | `OBSERVABLE` | `DEGRADED` | `NOT_OBSERVABLE` |
| DNS tunnel | DNS names + query timing | `OBSERVABLE` | `DEGRADED` | `NOT_OBSERVABLE` |
| C2 | repeated flow timing | `OBSERVABLE` | `DEGRADED` | `NOT_OBSERVABLE` |
| Exfiltration | reliable direction + byte counts | `OBSERVABLE` | `DEGRADED` | `NOT_OBSERVABLE` |
| TLS/QUIC | visible protocol metadata | `OBSERVABLE` | `DEGRADED` | `NOT_OBSERVABLE` |

**Rule:** missing evidence must never silently become a benign result. The operator sees the capability/degradation state.

# 8. Detector Architecture

Every detector follows:

```text
capability check
      ↓
window/features
      ↓
baseline comparison
      ↓
detector score
      ↓
minimum evidence check
      ↓
alert or NOT_OBSERVABLE
      ↓
deduplication
      ↓
incident lifecycle
```

Every alert should contain, where applicable:

- detector;
- severity;
- score/confidence;
- evidence;
- baseline;
- window;
- observed timestamp;
- model/intel version;
- capability state;
- sensor-loss information;
- incident sequence.

---

# 9. Minimum Evidence Contracts

## 9.1 DDoS / SYN flood

Minimum evidence:

- packet rate / pps;
- baseline comparison;
- SYN/SYN-ACK behavior;
- unique source count;
- source entropy or estimation method;
- time window.

## 9.2 Reflection / spoofed flooding

Minimum evidence:

- source/destination relationship;
- fan-in or amplifier-port evidence;
- source entropy;
- reserved/invalid source-space share where applicable;
- traffic rate.

### Slowloris minimum evidence

- concurrent half-open/long-lived connections;
- connection-duration percentile;
- bytes per connection;
- low packet/byte rate;
- destination/service context.

## 9.3 Reconnaissance / scanning

Minimum evidence:

- unique destinations/ports;
- source-window behavior;
- scan pattern;
- port spread or target spread;
- baseline comparison.

## 9.4 DGA

Minimum evidence:

- DNS query availability;
- lexical feature values;
- model score;
- calibration status;
- NXDOMAIN context;
- model version.

## 9.5 DNS tunnelling

Minimum evidence:

- query-name availability;
- query length/entropy features;
- encoded-character indicators;
- query frequency;
- qtype distribution, including TXT/NULL/CNAME shares;
- source/entity context;
- DNS response behavior where available.

## 9.6 C2 beaconing

Minimum evidence:

- repeated destination;
- inter-arrival timing;
- coefficient of variation;
- robust timing statistic;
- persistence across windows;
- destination novelty/intel where available.

## 9.7 Exfiltration

Minimum evidence:

- outbound byte/packet behavior;
- destination/entity;
- temporal burst or sustained-transfer evidence;
- baseline comparison;
- relevant protocol metadata.

## 9.8 TLS/QUIC encrypted-session suspicion

Minimum evidence:

- JA3/JA3S/JA4 fingerprint if available;
- destination novelty;
- first-N packet-size sequence or quantiles;
- packet direction sequence / directional ratio;
- inter-arrival median, p95 and coefficient of variation;
- available TLS/QUIC metadata;
- explicit statement that this is suspicion, not payload identification.

---

# 10. Detector Details

## 10.1 DDoS / flooding

Use robust statistics and hard gates.

Preferred:

- robust z-score;
- median/MAD;
- hysteresis `N=2`;
- baseline warm-up gate for adaptive deltas only.

### Slowloris inside `ddos.py`

Slowloris is a distinct low-rate exhaustion path inside the same PS DDoS class. It must not be reduced to a pps threshold. Use:

- concurrent half-open/long-lived connection count;
- connection-duration percentile;
- bytes per connection;
- low packet/byte rate;
- destination/service-specific baseline.

A Slowloris incident fires only when concurrency and duration gates agree. The evidence drawer must show the low-rate nature of the event rather than hiding it behind the generic flood detector.

Do not create one alert per packet or one alert per window.

Target behavior:

```text
50,000 pps flood
        ↓
one evolving incident
        ↓
count/risk/evidence updates
```

---

## 10.2 Scan

Use:

- unique destination/port spread;
- windowed source behavior;
- robust thresholds;
- hard gates;
- bounded state.

---

## 10.3 DGA

Use LightGBM as the single trained model.

### Frozen lexical and language features

At minimum, `FEATURE_ORDER` contains:

```text
length
entropy
digit_ratio
vowel_ratio
label_count
lm_bigram
lm_trigram
nxdomain_rate
```

The bigram/trigram background model is trained from the benign Tranco-derived hostname corpus. The score is a feature, not a standalone verdict. It is especially important for wordlist-style DGAs that can defeat raw entropy.


Required:

- time-based holdout;
- entity-based holdout;
- DGA-family holdout;
- TLD stripping where specified;
- calibration;
- reliability diagram;
- Brier score;
- model card.

Do not claim generic "AI accuracy."

### Artifact policy

The trained artifact is **pre-built and vendored** into `models/artifact` before the window opens. In-window training is a refresh, not a dependency.

DGA is on the never-cut list (§40). In V6 it also sat on the hour-10 critical path with no fallback, which made the never-cut list a bluff. Both cannot be true.

### Fallback

If the artifact is unusable and retraining fails:

```text
lexical features + Shannon entropy + NXDOMAIN rate + Tranco allowlist
```

Ship it with `calibrated: false` and `model_version: "rules-fallback"`. The evidence drawer must state that the number is a rule score, not a calibrated probability.

Do not present a Brier score or a reliability diagram for the fallback — a rule score is not a probability and claiming otherwise is the one thing §27 exists to prevent.

---

## 10.4 DNS tunnel

Use an ensemble of:

- lexical/entropy signals;
- encoded-name characteristics;
- frequency;
- length;
- NXDOMAIN behavior;
- qtype distribution (`TXT`, `NULL`, `CNAME`, and other shares);
- source/entity context.

The evidence drawer must expose the qtype distribution because it is a PS-named DNS-tunnel discriminator.


Avoid relying on one suspicious string feature.

---

## 10.5 Beaconing

Start with:

- coefficient of variation;
- median/MAD.

Only add Lomb-Scargle if all scheduled work is green.

Fallback:

```text
CV + MAD + fixed threshold
```

---

## 10.6 TLS/QUIC

Use:

- JA3;
- JA3S;
- JA4 where supported;
- destination novelty;
- first-N packet-size sequence and summary quantiles;
- packet direction sequence and directional ratios;
- inter-arrival median, p95 and coefficient of variation;
- offline intel.

### Shape definition

"Shape" means concrete traffic metadata, not a generic anomaly label. The feature service records, where visible:

```text
packet_size_first_n
direction_first_n
iat_median
iat_p95
iat_cv
upstream_packet_ratio
downstream_packet_ratio
```

The shape score compares these features with a per-service benign profile. It never inspects decrypted payload bytes.

A TLS session may expose both client and server fingerprints: JA3 for the client-side handshake and JA3S for the server-side response. JA4 is used where the installed Suricata build exposes it. Missing fingerprints are capability state, not evidence of benign traffic.


## 10.7 Exfiltration

Use per-entity outbound behavior and baseline comparison.

Keep the detector simple enough to explain in the evidence drawer.

---

# 11. Streaming State and Memory Safety

All rolling state must be bounded.

Required techniques include:

- tumbling/sliding windows;
- watermarks;
- out-of-order handling;
- bounded flow state;
- Space-Saving;
- HyperLogLog;
- Count-Min;
- reservoir sampling;
- bounded ring buffers;
- explicit eviction;
- hard caps.

Never maintain an unbounded dictionary keyed by arbitrary source/destination tuples.

The attacker must not be able to weaponize the detector's own state.

---

# 12. Baseline

The baseline is generated from the benign corpus.

It must be available at startup.

Avoid cold-start behavior where every event appears anomalous.

**Clarification.** V6 said both "baseline available at startup" and "baseline warm-up gate", which read as contradictory. Resolution: the snapshot loads at boot, so there is no cold start and detection is live from the first window. The `warmup_windows` gate in §10.1 applies only to the **adaptive delta** layered on top of the snapshot, never to detection itself.

Baseline updates must be capped to prevent slow poisoning.

Keep an immutable long-term reference snapshot in the offline intelligence bundle.

---

# 13. Incident Lifecycle

The system must produce **incidents**, not alert storms.

Suggested lifecycle:

```text
NEW
 ↓
ACTIVE
 ↓
UPDATED
 ↓
RESOLVED
```

An incident has:

- stable identity/deduplication key;
- severity;
- first/last observed;
- evolving counters;
- evidence history;
- detector/model version;
- hash-chain sequence.

Deduplication is mandatory even if the optional fusion layer is cut.

## 13.1 Deduplication Keys — Frozen

One key per class. V6 said "stable identity key" without enumerating them, which guarantees two developers pick differently. A wrong key produces either an alert storm or two unrelated events merged into one incident.

```text
ddos          (ps_class, dst_ip, dst_port)
reflection    (ps_class, dst_ip, amplifier_port)
scan          (ps_class, src_ip)
dga           (ps_class, src_ip)
dns_tunnel    (ps_class, src_ip, registered_domain)
c2            (ps_class, src_ip, dst_ip, dst_port)
exfil         (ps_class, src_ip, dst_ip)
tls_quic      (ps_class, src_ip, ja3, dst_ip)
```

Two of these are counter-intuitive and both were wrong by default:

- **`ddos` never keys on source.** Sources are spoofed, so a source key produces one incident per packet — the precise failure the incident model exists to prevent, demonstrated live on stage in §41.
- **`dga` never keys on domain.** A DGA burst is hundreds of distinct domains. Domains are evidence rows *inside* one incident, not incident identities.

`dns_tunnel` keys on the registered domain (eTLD+1 after TLD stripping), not the full query name — the full name is the thing that varies.

Keys live in `config/dedup_keys.yaml` and are asserted by a contract test.

Incident identity is `sha256(canonical(key))[:16]`, stable across restarts.

---

# 14. Capture Loss and Measurement

Surface loss rather than hiding it.

Use:

- Suricata kernel-drop counters;
- ring-buffer counters;
- TCP sequence gaps;
- packet-count comparison;
- capture-loss estimators.

If the Kalman fusion is not ready:

> report the raw `kernel_drops` ratio and label it as a lower-bound/single-estimator measurement.

Do not invent a more precise number.

---

## 14.1 Throughput Target — Declared

Throughput is on the never-cut list, but V6 declared no target. A measured number with no target has no stopping condition and no answer to "is that enough?".

```text
Target         >= 50 000 pps sustained, >= 400 Mbps, over a 60 s replay
Primary PS KPI  sustained flows/sec (publish first)
Secondary       Mbps, then pps
Loss ceiling    capture loss < 1 % at target
Box             declared on deck Slide 5 — CPU, RAM, NIC, kernel version
```

Rules:

- Optimise until the target is met, then stop and move to hardening. Throughput work is a well-known time sink.
- If the target is not met, publish the number actually achieved together with the loss at that rate. Never extrapolate toward 10 Gbps (§42).
- The number is meaningless without the box spec beside it. Always show both.

---

# 15. UI/UX

The dashboard is an operator console, not a landing page.

## 15.1 Permanent elements

- LIVE/REPLAY badge;
- capability/health banner;
- risk/severity indication;
- active incident feed.

## 15.2 Incident feed

Each incident should show:

- class;
- severity;
- confidence/score;
- current status;
- key metric;
- last update.

## 15.3 Evidence drawer

Show:

- actual feature values;
- baseline;
- detector threshold;
- evidence interpretation;
- observability state;
- model/intel version;
- capture-loss information.

## 15.4 Performance rules

Use:

- batched WebSocket pushes around 250 ms;
- client ring buffer of 500 incidents;
- virtualized incident list;
- `requestAnimationFrame` counters;
- a single CSS severity accent variable.

Load-test with a synthetic 50,000-alert burst.

The page must remain interactive.

---

# 16. Threat Map

The threat map is **optional**.

Only build it if the hour-16 gate is completely green.

Requirements if retained:

- offline GeoLite2;
- offline TopoJSON;
- no live geolocation lookup;
- demo fixtures for private/documentation IPs;
- explicit `demo_fixture` badge;
- geolocation is not attribution.

If it threatens core functionality:

> CUT IT.

---

# 17. API / Persistence

## FastAPI

Minimum endpoints:

```text
GET  /health
GET  /capabilities
GET  /incidents
GET  /incidents/{id}
GET  /export/json
GET  /export/csv
```

**Plane B is read-only over HTTP. `GET` and WebSocket only. No `POST`, no `PUT`, no `DELETE`.**

`POST /simulate/scenario/{id}` existed on this list in V6 and is removed. It placed an attack-starting endpoint on the monitoring API — a judge reads that as a return path and the entire read-only argument, which the demo is built around, collapses in one question.

Scenario control lives **only** in the Scenario Console application: attacker side, separate namespace, separate port, separate process. During the demo, drive it from a second window. Do not add convenience routing between the two planes for any reason.

The API contract test asserts that no non-`GET` route is registered on the Plane B app.

Use WebSocket for live incident delivery.

The exact route contract should be frozen before UI implementation.

## SQLite

Persist:

- incidents;
- incident updates;
- evidence;
- timestamps;
- hash-chain metadata;
- scenario/replay metadata.

The report/export layer reads the continuously written incident store.

---

# 18. Export

Preferred:

- JSON;
- CSV.

PDF is optional.

### CSV flattening rule

CSV is one row per **incident**, not per evidence item.

```text
evidence.<key>    scalar values, dotted path, one column each
evidence_json     full evidence object, JSON-encoded, single column
```

JSON export is lossless and canonical. CSV exists for eyeballing in a spreadsheet. Where they disagree, JSON wins, and the hash chain is computed over the JSON form only.

If PDF becomes a risk:

> keep incident store + history + hash chain + JSON/CSV.

The report is a view over continuously stored data, not a batch-only pipeline.

---

# 19. Tamper-Evident Chain

Each incident/update sequence is hash-chained to its predecessor.

The export must include the chain data.

Provide:

```text
tests/verify_hash_chain.py
```

or equivalent.

The demo must run the verifier on the exported data.

## 19.1 Chain Specification — Frozen

Writer and verifier are built in the same ticket, against this spec. An unspecified chain means writer and verifier disagree, and it fails at hour 17 on a scripted demo beat.

```text
canonical(x)        JSON, keys sorted, no whitespace, UTF-8, NaN/Inf rejected
payload_hash        sha256(canonical(incident_payload))
entry_hash          sha256(prev_hash || seq || incident_id || last_updated || payload_hash)
genesis prev_hash   "0" * 64
```

- `seq` is a monotonic integer across the whole store, not per incident.
- `||` is byte concatenation of the ASCII/hex representations, defined **once** in `alerts/hash_chain.py` and imported by the verifier. The verifier must not reimplement it.
- Every incident update appends a new entry. Entries are never rewritten in place.
- Export carries `seq`, `prev_hash` and `entry_hash` for every entry.

`tests/verify_hash_chain.py` runs in a clean process against the exported JSON only, with no import of writer runtime state.

---

# 20. Offline Intelligence Bundle

Bundle/version:

- allowlists;
- SSLBL JA3 data if used;
- DGA family data;
- Tranco list;
- baseline snapshot;
- explainer text;
- recommendations;
- GeoLite2 if map retained;
- version manifest.

Every relevant alert/report must contain the bundle/model version.

No runtime LLM or internet service is allowed.

---

# 21. Repository Structure

```text
cyber-sentinel/
├── sensor/
│   ├── suricata.yaml
│   ├── field_allowlist
│   └── capability_probe
│
├── ingest/
│   ├── tcpreplay_driver
│   ├── clock
│   ├── header_counter
│   ├── eve_tail
│   ├── normalizer
│   ├── flow_tracker
│   ├── flow_record_adapter.py      # shared NetFlow v9 / IPFIX template decoder
│   └── capture_loss
│
├── features/
│   ├── feature_order.py
│   ├── stateless.py
│   ├── rolling.py
│   ├── sketches.py
│   └── entropy.py
│
├── detectors/
│   ├── ddos.py
│   ├── reflection.py
│   ├── scan.py
│   ├── dns.py
│   ├── dga.py
│   ├── c2.py
│   ├── tls_quic.py
│   └── exfil.py
│
├── models/
│   ├── train_dga.py
│   ├── artifact
│   ├── model_card.md
│   └── calibration.py
│
├── intel/
│   ├── allowlists
│   ├── sslbl_ja3
│   ├── dga_families
│   ├── tranco
│   ├── baseline_snapshot.json
│   ├── recommendations
│   ├── version_manifest.json
│   └── geolite2/
│
├── schemas/
│   ├── normalized_event.schema.json
│   └── alert.schema.json
│
├── alerts/
│   ├── scorer
│   ├── deduplicator
│   ├── lifecycle
│   └── hash_chain
│
├── lab_console/
│   ├── scenario_menu
│   ├── randomizer
│   ├── seed_log
│   ├── generate
│   └── replay
│
├── api/
│   ├── main.py            # GET + WebSocket only, no POST routes
│   ├── websocket
│   └── persistence
│
├── dashboard/
│   ├── React
│   ├── incident_feed
│   ├── evidence_drawer
│   ├── capability_banner
│   ├── history
│   └── replay_controls
│
├── scenarios/
│   ├── manifests
│   ├── pcaps
│   ├── expected_alerts
│   ├── flow_records
│   │   ├── ipfix
│   │   └── netflow_v9
│   └── canonical_campaign
│
├── tests/
│   ├── schema
│   ├── parity
│   ├── replay
│   ├── latency
│   ├── boundary
│   ├── capture_loss
│   ├── hash_chain
│   └── ui_load
│
├── config/
│   ├── thresholds.yaml
│   ├── address_plan.yaml
│   └── dedup_keys.yaml
│
├── docs/
│   ├── architecture.md
│   ├── feature_dictionary.md
│   ├── evaluation.md
│   ├── model_card.md
│   ├── qna.md
│   └── threshold_sweep/
│
├── README.md
├── PRD.md
├── CLAUDE.md
├── agents.md
├── implementation_plan.md
├── STATUS.md
├── testing.md
├── LIMITATIONS.md
└── git.md
```

---

# 22. Configuration

All tunable values belong in:

```text
config/thresholds.yaml
```

Do not scatter thresholds through detector code.

Record:

- threshold value;
- reason;
- sweep result;
- selected operating point.

Every published threshold must have a corresponding evaluation artifact.

## 22.1 Seed Values

Ship `thresholds.yaml` populated on day one. An empty file costs hours of guessing at hour 7, when nobody has spare hours.

```yaml
ddos:
  robust_z: 6.0
  min_pps: 5000
  hysteresis_windows: 2
  warmup_windows: 30
scan:
  unique_dst_min: 50
  unique_port_min: 100
  window_s: 10
dga:
  score_threshold: 0.85
  min_queries: 5
  nxdomain_rate_min: 0.4
dns_tunnel:
  qname_len_min: 50
  entropy_min: 3.5
  qps_per_domain_min: 10
c2:
  cv_max: 0.15
  min_events: 8
  window_s: 300
exfil:
  outbound_ratio_min: 10.0
  robust_z: 5.0
tls_quic:
  novelty_days: 7
latency:
  watermark_ms: 300
  batch_push_ms: 250
  slo_p95_ms: 2000
```

These are starting points, not published values. Every threshold that reaches the deck or the evaluation report must first be replaced by a sweep result with its artifact.

---

# 23. Testing Strategy

## 23.1 Contract tests

Must cover:

- normalized event schema;
- alert schema;
- `FEATURE_ORDER`;
- enum values;
- required evidence;
- `not_observable`;
- `input_mode` enum;
- non-null `flow_id` / valid `flow_ref_type`;
- six PS classes ↔ eight detector modules mapping;
- qtype and TLS/QUIC shape feature presence.

## 23.2 Flow-record tests

Provide at least one known-good NetFlow v9 fixture and one IPFIX fixture. Acceptance:

- templates decode correctly;
- records normalize to the common event contract;
- malformed/expired templates do not exhaust state;
- capability degradation is correct;
- flow-based detectors continue to operate where required fields are present.

## 23.3 Replay tests

At least one replay fixture per detector class.

Expected alert contracts are stored with the scenario.

## 23.4 Feature parity

Given the same packet fixture:

```text
offline extractor == streaming extractor
```

## 23.5 Boundary test

Prove:

```text
monitor → external network
```

is blocked.

The test must be scripted and repeatable.

Assert all three:

```text
monitor -> external internet      blocked
monitor -> attacker-side veth     blocked
monitor -> monitored enclave      no route present
```

Archive the output as `artifacts/boundary_test_<timestamp>.txt` and include it in the export bundle.

The proof must survive outside the live demo moment. If venue networking misbehaves during the run, the artifact still exists.

## 23.6 UI load test

Generate a 50,000-alert synthetic burst.

**This harness deliberately bypasses deduplication.** It stresses the render path only.

It does not contradict the §41 demo claim that a 50 000 pps flood produces one incident — that claim concerns the detector path, which sits upstream of this injection point. State the distinction if a judge watches the test run.

Acceptance:

- page remains interactive;
- memory remains bounded;
- incident feed does not grow without limit.

## 23.7 Flood survivability

Replay a flood with concurrent:

- SYN events;
- DNS events;
- TLS handshake events.

Confirm all expected event categories survive.

## 23.8 Hash-chain test

Export incidents and verify the chain from a clean process.

## 23.9 Cold boot

Boot the complete stack on a second machine that has never run the project.

Networking must be disabled.


## 23.10 Sensor Failure / Recovery

Test controlled failure of:
- Suricata/EVE input;
- normalizer;
- detector process;
- API;
- WebSocket connection.

Acceptance:
- health state changes to `DEGRADED` or `UNAVAILABLE`;
- no false healthy state is shown;
- buffered/persisted incidents remain consistent;
- WebSocket clients can reconnect;
- API `GET` endpoints remain authoritative after reconnect;
- restart does not silently erase persisted incident history.

## 23.11 Restart / State Recovery

Restart the stack during or immediately after replay.

Verify:
- SQLite history remains readable;
- incident sequence/hash-chain state resumes correctly;
- no duplicate incident is created solely by restart;
- capability state is recomputed;
- the UI clearly indicates replay/session restart where relevant.


---

# 24. Canonical Campaign Scenario

Create one deterministic scenario that becomes:

- the integration test;
- the main demo;
- the backup recording;
- the expected-alert contract.

Example sequence:

```text
T+00:00   reconnaissance / scan
T+00:30   beaconing
T+01:30   DGA burst
T+03:00   DNS tunnel
T+04:00   exfiltration
T+05:00   suspicious TLS/QUIC session
T+06:00   DDoS/flood
```

The exact timing may be adjusted to the generated PCAPs.

The important requirement is deterministic ordering and seed/hash recording.

The dashboard must not receive this ground truth directly.

---


## 24A. `BENIGN_STRESS` Scenario

In addition to attack campaigns, maintain a deterministic benign stress replay designed to resemble suspicious behavior without being malicious.

Include, where available:
- high-volume legitimate DNS;
- long/large legitimate transfers;
- TLS-heavy traffic;
- legitimate periodic polling;
- many short-lived connections;
- legitimate port/destination diversity;
- long or machine-generated but benign domain names.

Expected result:

```text
BENIGN_STRESS
     ↓
low/acceptable false-alert rate
     ↓
no critical incident unless the evidence contract is genuinely met
```

This scenario is mandatory for false-alert/hour measurement.

### DGA hard negatives

The DGA corpus must include legitimate domains that are difficult lexical cases, such as:
- CDN-generated names;
- UUID-like identifiers;
- long API/service subdomains;
- tracking/telemetry names;
- random-looking but legitimate hostnames;
- software/update infrastructure.

The objective is to prevent the model from learning the shortcut `random-looking == malicious`.

# 25. Ground Truth vs Actual Detection

Keep these two data paths separate.

```text
Scenario Manifest / Expected Alerts
              │
              │ offline evaluation only
              ▼
       Evaluation Harness
              ▲
              │
        Actual Alerts
              ▲
              │
PCAP → Sensor → Features → Detectors
```

The live dashboard receives **actual detector output only**.

Ground truth is used for evaluation after/beside the replay, not as an input to detection.

---

# 26. Evaluation

Required metrics:

- per-class precision;
- per-class recall;
- per-class F1;
- PR-AUC;
- false alerts per hour on pure-benign replay;
- p50 latency;
- p95 latency;
- throughput;
- threshold sweep;
- baseline comparison;
- DGA reliability diagram;
- DGA Brier score.

For every published number, preserve:

- input dataset/scenario;
- command used;
- configuration;
- output artifact.

Never improvise numbers during Q&A.

---


## 26A. Evaluation Units

Evaluation must distinguish raw detector outputs from operational incidents.

### Detector-level evaluation

A detector prediction is evaluated against the matching ground-truth behavior interval and entity/context.

Examples:
- DGA: domain/query entity + query observation interval.
- Scan: source + target/port spread interval.
- DDoS: source/destination context + flood interval.
- C2: source + destination + repeated-flow interval.

### Incident-level evaluation

After hysteresis and deduplication, the resulting incident is evaluated as one operational detection.

Example:

```text
1,842 anomalous windows
        ↓
17 candidate alerts
        ↓
1 deduplicated incident
```

For incident metrics, this counts as **one predicted incident**, not 1,842 predictions.

The evaluation report must state:
- matching key/entity;
- time-overlap rule;
- minimum overlap or tolerance;
- how duplicates are collapsed;
- how simultaneous classes are handled.

This prevents inflated recall from repeated windows and inflated false-positive counts from alert storms.


## 26B. Resource and Operating-Envelope Measurements

The published benchmark should preserve, where measurable:

- packets/sec;
- flows/sec;
- events/sec;
- Mbps;
- p50/p95 latency;
- CPU utilization;
- RAM utilization;
- active flow-state count;
- detector-state memory;
- WebSocket queue depth;
- SQLite write/commit rate;
- capture-loss percentage;
- kernel/ring drops.

### Optional throughput-vs-loss sweep

If time permits, measure multiple replay rates rather than publishing only one point:

```text
rate → CPU / RAM / p95 latency / capture loss
```

Use the result to define the **measured operating envelope**. Do not extrapolate beyond the measured hardware/configuration.

# 27. DGA Evaluation Rules

The model must not simply memorize the dataset.

Use:

- time-based holdout;
- entity-based holdout;
- DGA-family holdout;
- deduplication before splitting;
- TLD stripping;
- wordlist families represented in evaluation.

Show calibration.

State explicitly:

> confidence represents evidence strength, not attacker intent.

---

# 28. Baseline Comparison

Compare against:

1. the implemented system;
2. static thresholds;
3. stock Suricata rules where the comparison is meaningful.

Concede where rules perform better.

The ML/statistical layer exists to cover behavior where signatures do not.

---

# 29. 24-Hour Execution Plan

## Hours 0–1 — Phase 0, all four together

### Freeze

- event schema;
- alert schema v1.3;
- `FEATURE_ORDER`;
- repository skeleton;
- threshold configuration;
- branch rules.

### Environment

**Decided before the window opens, not at hour 0.** V6 spent gate time on a decision that costs nothing to make in advance.

- OS: native Linux preferred, full VM acceptable. **WSL2 is not acceptable for the published throughput number** — the capture path differs and the figure will be challenged.
- The box used for the published throughput number: chosen in advance, spec recorded.
- Suricata build/capability check;
- JA3/JA4 check;
- isolated veth lab;
- egress DROP.

### Exit gate

Contract tests exist.

JA3/JA3S/JA4 capability result is recorded.

The lab interface has no route/egress.

---

# 30. Hours 1–6 — Build the Spine

## Track A — Ingestion

- tcpreplay driver;
- veth;
- unified replay clock;
- header-only packet counter;
- Suricata EVE tail;
- normalizer;
- bounded flow tracker;
- capture-loss fields.

## Track B — Ground Truth / Detection

- deterministic synthetic event generator;
- attack/benign corpus;
- scenario manifests;
- DGA corpus;
- holdout definition;
- initial DDoS/scan/DGA logic.

## Track C — UI/API

- FastAPI;
- WebSocket;
- SQLite;
- React/Vite skeleton;
- incident feed;
- LIVE/REPLAY badge;
- recorded JSONL replay.

## Hour-6 Gate

A real PCAP:

```text
PCAP
 ↓
veth
 ↓
both input paths
 ↓
normalized event
 ↓
dashboard
```

must work.

If it fails:

> all four people stop and fix the spine.

No new detector work.

### Additional hour-6 gate items

- **The attack PCAP set is complete, hashed and manifested.** Generation stops here; after hour 6 the lab is replay-only (Ticket 0, §45).
- `config/address_plan.yaml` is loaded by the normalizer and the `direction` field is populated on real events.
- Capability probe output recorded, including the JA3/JA3S/JA4 verdict and every acceptance line in §7A.3.
- IPFIX and NetFlow v9 fixture files exist and their input-mode/capability contracts are known.
- JA3/JA3S/JA4 capability result is recorded.

---

# 31. Hours 6–10

## Track A

- rolling windows;
- bounded sketches;
- entropy;
- baseline snapshot;
- latency field.

## Track B

- DDoS;
- reflection/spoofed-source;
- scan;
- DNS feature extraction;
- DGA model;
- Platt calibration.

## Track C

- 250 ms batched pushes;
- 500-item client ring;
- virtualization;
- rAF counters;
- evidence drawer.

## Hour-10 Gate

Required:

- at least one real alert;
- real PCAP;
- populated evidence;
- correct `latency_ms`;
- concurrency test passed;
- UI remains responsive under flood.

---


## Hour-12 Integration Checkpoint

Before adding the final detector set, run the complete integrated path:

```text
PCAP
 ↓
veth
 ↓
sensor + EVE
 ↓
normalizer
 ↓
features
 ↓
DDoS / Scan / DGA
 ↓
incident lifecycle
 ↓
SQLite
 ↓
WebSocket
 ↓
dashboard evidence
```

Must be green:
- real PCAP replay;
- DDoS;
- scan;
- DGA;
- evidence drawer;
- persistence;
- deduplication;
- latency measurement;
- capability state;
- dashboard responsiveness.

If not green, stop detector expansion and fix integration.

# 32. Hours 10–16

## Track A

- complete NetFlow v9/IPFIX adapter hardening and fixture replay;
- throughput harness;
- measurement;
- threshold sweep;
- read-only negative test;
- sequence-gap/capture-loss reporting;
- provenance;
- hash chain.

## Track B

- beaconing;
- DNS tunnel with qtype evidence;
- Slowloris low-rate exhaustion path inside `ddos.py`;
- exfiltration;
- TLS/QUIC detector with JA3/JA3S/JA4 and concrete shape features;
- deduplication;
- lifecycle.

## Track C

- capability banner;
- PS-required alert fields: timestamp, flow_id, threat class, confidence, evidence.
- health panel;
- history;
- low-confidence tab;
- JSON/CSV export;
- top talkers;
- advisory panel;
- replay controls.

---

# 33. Hour-13 Optional Gate

The NetFlow v9/IPFIX adapter is **not optional**. It must be complete and tested by H13.

Only the following remain optional if all scheduled work is green:

- clock servo;
- Lomb-Scargle;
- unix-stream ingest.

Otherwise skip them. They are not part of the demo-critical path.

---

# 34. Hour-16 Kill Gate

At hour 16, execute the kill ladder.

Do not begin new detector work after this point.

### Record the backup video immediately on gate pass

This is the earliest moment a complete run exists, and a recording is the only insurance that survives a dead laptop, a failed cold boot or a venue projector problem.

V6 scheduled the recording at hours 19–22, where it competes with three rehearsals for the same three hours and gets dropped.

Re-record after hour 19 if the run improved. Keep both files.

---

# 35. Hours 16–19 — Hardening

- switch Scenario Console to REPLAY mode;
- make GENERATE unreachable outside the build machine;
- campaign-mode demo sequence;
- cold boot on second machine;
- PCAP hash audit;
- hash-chain verifier;
- offline asset grep;
- UI load test;
- screenshots;
- severity palette review.

### Threat map rule

Build only if all core gates are green.

---

# 36. Hour-19 Feature Freeze

After hour 19:

Allowed:

- documentation;
- rehearsal;
- bug fixes;
- evidence corrections;
- demo stability fixes.

Not allowed:

- new detectors;
- new models;
- architecture changes;
- new dependencies;
- new major UI features.

---

# 37. Hours 19–22

**Documentation is not written in this block.** V6 put roughly twelve hours of work into three hours and it will not happen.

Documentation is written incrementally from hour 6, by whoever is gate-blocked. A track waiting on another track's gate writes docs. It does not idle, and it does not start unplanned features.

Drafted and substantially complete by hour 16:

- README;
- architecture diagram;
- packet-to-alert flow diagram;
- incident lifecycle diagram;
- LIMITATIONS.md;
- model card;
- seven-slide deck (numbers left as placeholders).

Hours 19–22 contain only:

- evaluation report — it needs the final measured numbers, so it lands here;
- filling final numbers into the deck and README;
- **three full rehearsals**;
- re-recording the backup video if the run improved.

Three rehearsals in three hours is already tight. Nothing else goes in this block.

---

# 38. Hours 22–24

Buffer only.

- final cold boot;
- final rehearsal;
- verify backup;
- do not touch working architecture.

---

# 39. Staffing

## Track A — Ingestion

Owns:

- lab;
- replay;
- clock;
- capture;
- normalization;
- flow state;
- loss;
- throughput.

## Track B — AI/ML + Detection

Owns:

- ground truth;
- features;
- DGA;
- detectors;
- fusion if retained;
- dedup;
- lifecycle;
- evaluation.

## Track C — UI/UX + API

Owns:

- FastAPI;
- WebSocket;
- SQLite;
- dashboard;
- export;
- operator experience.

The ingestion spine is blocking until the hour-6 gate.

Do not allow ownership to become ambiguous.

## 39.1 Rest Rotation

Four people, twenty-four hours, zero scheduled rest is a plan to be at your worst during hours 16–22 — which is exactly where the kill gate, cold boot, hardening and all three rehearsals live.

```text
Hours 10-19    each person takes 2 x 90 min off, staggered
               never two people from the same track resting at once
               Track A rests first — its blocking work ends at the hour-10 gate
               Track C rests last  — its work sits on the demo critical path
```

Rest is a scheduled item with an owner and a time, not something that happens if convenient.

---

# 40. Kill Ladder

If a component is not working by hour 16:

| Priority | Component | Fallback |
|---|---|---|
| 1 | Threat map | Cut entirely |
| 2 | PDF | JSON/CSV |
| 3 | Scenario Console UI | Shell script + menu |
| 4 | Clock-servo Kalman | Fixed 300 ms watermark |
| 5 | Capture-loss Kalman | Raw `kernel_drops` lower bound |
| 6 | Lomb-Scargle | CV + MAD |
| 7 | Fusion/correlation | Separate detector alerts + dedup |
| 8 | SHAP | LightGBM `pred_contrib` / evidence templates |
| 9 | Slowloris duration/shape refinement | Keep concurrency + duration + bytes/connection detector |
| 10 | TLS/QUIC shape refinement | JA3 + JA3S + intel + destination novelty |
| 11 | Real PCAP replay | Synthetic generator |
| 12 | LightGBM DGA artifact | Lexical + entropy + NXDOMAIN rules, `calibrated: false` |

Row 12 is a **fallback inside a never-cut item**, not a cut. DGA still ships; only the model is downgraded, and the downgrade is stated in the evidence drawer (§10.3).

## Never cut

1. incident feed;
2. evidence drawer;
3. DGA model;
4. DDoS statistics;
5. scan statistics;
6. capability banner;
7. read-only negative test;
8. measured throughput;
9. NetFlow v9/IPFIX normalization contract and capability degradation.

---


## 41A. Two Fast Proof Moments

### Hash-chain tamper demonstration

Export incidents, modify one exported record, then run the verifier:

```text
verify_hash_chain
      ↓
FAIL
      ↓
entry N modified
```

Use the phrase:

> "The chain makes post-hoc modification detectable; it is tamper-evident, not a claim that the storage system is magically immutable."

### Suricata vs intelligence layer

Show a concise comparison:

| Capability | Suricata/signatures | This intelligence layer |
|---|---|---|
| Known signatures | Strong | Consumes/augments sensor output |
| Behavioral baselines | Limited | Core feature |
| Beacon periodicity | Limited | Core detector |
| DGA lexical ML | Not the primary role | Core detector |
| Evidence correlation | Sensor-centric | Incident-centric |
| Passive/read-only | Yes | Yes |

Positioning:

> **This system is an intelligence layer on top of passive sensor data, not a replacement for Suricata.**

# 41. Demo Script — 7 Minutes

## 0:00–0:30 — Problem

Explain:

- read-only;
- no decryption;
- streaming.

Point to the LIVE/REPLAY badge.

State the replay speed.

## 0:30–1:15 — Prove read-only

Show:

- capability banner;
- negative-connectivity test;
- egress failure;
- alerts still flowing.

## 1:15–3:00 — Scenario

Switch to Scenario Console.

Use a deterministic scenario or randomize using the recorded seed.

Return to dashboard.

Show:

- DDoS;
- evidence drawer;
- pps vs baseline;
- SYN/ACK ratio;
- source entropy;
- scan;
- DGA;
- NXDOMAIN context.

Say **"advisory"** when showing recommendations.

## 3:00–4:00 — Incident lifecycle

Show one evolving incident.

Contrast:

```text
naive detector:
50,000 alerts

ours:
one evolving incident
```

Mention bounded flow state.

## 3:45–4:00 — Input-mode capability beat

Switch from PCAP/EVE replay to a pre-generated IPFIX fixture. Show:

- `input_mode: ipfix`;
- packet/DNS/TLS-specific detectors moving to `DEGRADED` / `NOT_OBSERVABLE`;
- flow-level DDoS/scan/C2/exfiltration remaining available where their required fields exist.

State: "The detector negotiates what it can see from the input; it never assumes unavailable evidence."

## 4:00–5:00 — Advanced detections

Show:

- beacon;
- encrypted-session suspicion;
- exfiltration.

State:

> fingerprint and behavior-based suspicion, never payload identification.

## 5:00–6:15 — Measurements

Show:

- throughput;
- p95 latency;
- false alerts/hour;
- per-class PR-AUC;
- calibration;
- threshold sweep;
- baseline comparison.

Export mid-run.

Verify hash chain.

## 6:15–7:00 — Limitations

Explicitly discuss:

- QUIC;
- ECH;
- DoH/DoT;
- sampled flows;
- NAT;
- slow scans;
- concept drift;
- geolocation caveat;
- encrypted-session limitation;
- `not_observable`.

Close with:

> "Our system is a passive intelligence layer. It never connects to production endpoints, never decrypts TLS or QUIC content, and never sends a mitigation command across the monitored link. It incrementally turns copied traffic metadata into structured, evidence-rich alerts with known and displayed visibility limits."

---

# 42. Judge Q&A

## Do you support NetFlow/IPFIX?

Yes. NetFlow v9 and IPFIX use one shared template-based adapter and normalize into the same event contract. DNS names and TLS fingerprints may be absent, so those detectors explicitly degrade to `NOT_OBSERVABLE`, while flow-level DDoS, scan, beaconing or exfiltration logic remains usable when the required flow fields are present. sFlow is recognized as a sampled input mode and is capability-limited rather than treated as equivalent to full packet capture.

## Why does every alert have a `flow_id` even for a DDoS aggregate?

The PS requires a flow identifier. For a multi-flow event such as a spoofed flood, a single underlying 5-tuple would be misleading, so `flow_ref_type: aggregate` is used and `flow_id` hashes the frozen aggregate identity. The alert may additionally carry a bounded sample of contributing `flow_ids`.

## Why ML rather than Suricata rules?

Rules are excellent where signatures exist.

Our statistical/ML layer adds behavioral coverage for previously unseen patterns where a fixed signature may not exist.

Show the baseline comparison.

## Why gradient-boosted trees instead of deep learning?

- latency;
- small/noisy data;
- interpretability;
- native per-feature attribution;
- practical 24-hour scope.

## What is your false-positive rate?

Give the measured number.

Never improvise.

Then explain the base-rate problem.

## How were thresholds chosen?

Open:

```text
config/thresholds.yaml
```

and the threshold sweep.

Show the selected operating point.

## How do you prevent dataset memorization?

Explain:

- time split;
- entity split;
- DGA-family split;
- dedup before splitting;
- TLD stripping;
- feature parity.

## Which PS-named traffic generators/datasets do you use?

We map the named sources to deterministic fixtures: iperf3/Ostinato/TRex for benign traffic where useful, hping3 and Slowloris for flooding, dnscat2/iodine for DNS tunnelling, and a sandboxed C2 emulator for beaconing. DGArchive is not a runtime dependency; published DGA families are reimplemented locally so the evaluation is reproducible offline. Every substitution is documented.

## Why not CIC-IDS2017?

Use the documented project position:

- port-label leakage/mislabeling concerns;
- large download;
- reproducibility concerns.

Emphasize that your ground truth is generated reproducibly in the repository.

## What throughput do you report?

The primary PS-aligned metric is sustained **flows/sec**, followed by Mbps and pps. We also publish CPU, RAM, queue depth and capture-loss information beside the measured point.

## What happens at 10 Gbps?

Do not extrapolate.

Discuss:

- sketches;
- bounded state;
- sampling trade-offs;
- flow-hash sharding.

Then give the measured rate and where the prototype breaks.

## Does the system detect Slowloris?

Yes, as a low-rate exhaustion path inside the DDoS class. It does not rely on a high pps threshold; it uses concurrent long-lived connections, connection duration, bytes per connection and low-rate evidence.

## Can an attacker evade you?

Yes.

Mention:

- slow scans;
- jitter;
- domain fronting;
- wordlist DGAs;
- DoH.

An honest limitation is preferable to a false claim.

## Can an attacker poison the baseline?

In principle, yes.

Mitigations:

- capped update rate;
- immutable reference snapshot;
- offline bundle versioning.

## How do you know the diode/TAP dropped packets?

Use:

- kernel drops;
- ring counters;
- TCP sequence gaps;
- `capture_loss`;
- `sensor_drop_pct`.

Loss is evidence.

## How do you distinguish reflection from spoofed direct flood?

Reflection:

- moderate source entropy;
- fan-in from known amplifier ports;
- real source addresses.

Spoofed flood:

- very high entropy;
- reserved/invalid source-space share where applicable.

## IPv6?

Parse it in the fast path.

Use `/48` for entropy where specified.

If a detector is v4-only:

```text
NOT_OBSERVABLE
```

not silent omission.

## How are alerts tamper-evident?

Hash-chain incidents.

Export includes the chain.

Run the verifier.

## How does retraining work in an air-gapped environment?

Versioned offline model/intel bundle.

Version stamped into alerts.

Drift monitored passively for the next bundle cycle.

## Why Suricata rather than Zeek?

Suricata provides the desired EVE JSON stream and native fingerprint support for the selected build.

Zeek remains a viable alternative if required by capability/plugin constraints.

## Is the Scenario Console a return path?

No.

Two applications, separate namespaces, separate sides of the monitored boundary.

The dashboard does not know the scenario ground truth.

It only sees copied packets.

## Are you launching attacks during the demo?

No.

The final console is in REPLAY mode.

PCAPs were generated in the isolated lab and hashed.

## Do you use Kalman filtering?

Only where justified.

Detection does not rely on a scalar Kalman as a detector baseline because it can absorb the attack into its own state.

If implemented, Kalman fusion belongs to ingest/loss estimation.

Otherwise use the fixed watermark/raw loss estimator fallback.

## Does data move between stages as files?

No.

The only runtime file on the input path is Suricata's `eve.json`, which is tailed.

Post-normalization processing is in-process.

JSON exists at controlled boundaries:

- EVE input;
- SQLite/storage boundary;
- WebSocket output.

## Why do you call some detector scores confidence?

We separate the raw detector `score` from the PS-required `confidence` field. DGA confidence is calibrated with Platt scaling. Statistical and rule detectors expose evidence-strength mappings and are explicitly marked uncalibrated; they are never presented as probabilities.

## Why trust the confidence score?

DGA:

- Platt calibration;
- reliability curve;
- Brier score.

Statistical detectors:

- explicitly marked uncalibrated;
- evidence strength is documented.

## Does the recommendation break read-only?

No.

It is advisory text only.

There is no action path.

## Is the report batch processing?

No.

The incident store is written continuously.

The report/export is a view over the current store.

## What is your end-to-end latency?

Give the measured p95 against the declared SLO of 2.0 s, then show the budget in §6.5.

Explain the 300 ms watermark: it is the out-of-order grace period, a floor we accept deliberately. Shrinking it would improve the latency number by silently dropping late packets.

## Can the dashboard trigger anything?

No. Plane B exposes `GET` and WebSocket only. There is no `POST` on the monitoring API, and a contract test asserts it.

Scenario control is a separate application, on the other side of the boundary, in its own namespace.

## Your lab is all private addressing — how does geolocation work?

For RFC 1918 addresses it does not, and we say so.

The lab address plan (§2A) assigns the external side to GeoLite2-resolvable ranges. Anything that cannot resolve renders with a visible `demo_fixture` badge.

Geolocation is not attribution.

## Does your reflection detector work in a private-address lab?

Only because the reserved-source-share feature is computed against the external address space, with the declared lab prefixes excluded from the bogon set (§2A.3).

Without that exclusion the share is 100 % on benign traffic and the detector fires continuously.

## Do you store raw IP addresses?

Yes, and there is nothing to anonymise — all capture is lab-synthetic.

For real enclave traffic, CryptoPAn applies after geolocation and before persistence. Applying it first destroys the geo lookup. Documented in `LIMITATIONS.md`.

## What happens if the DGA model fails?

Documented fallback: lexical features, entropy and NXDOMAIN rate, shipped with `calibrated: false`.

We would not show a Brier score for the fallback, because a rule score is not a probability.

---

# 43. Deliverables

Required:

- `README.md`;
- architecture diagram;
- packet-to-alert data-flow diagram;
- incident lifecycle diagram;
- model card (one trained ML model: DGA LightGBM; all other detectors statistical/rule/intel);
- feature table;
- `LIMITATIONS.md`;
- evaluation report;
- scenario manifests;
- PCAP hashes;
- expected alert contracts;
- tests;
- pitch deck;
- backup recording.

- PS26145 traceability matrix;
- evaluation-unit definition;
- benign-stress scenario and hard-negative corpus;
- capability/`NOT_OBSERVABLE` matrix;
- resource/operating-envelope benchmark;
- recovery/failure test results;
- hash-chain tamper demonstration artifact;
## Seven-slide deck

### Slide 1 — Problem

Monitoring enclave behind a diode.

### Slide 2 — Three constraints

- read-only;
- no decryption;
- streaming.

### Slide 3 — Architecture

Two-plane architecture.

### Slide 4 — Detection

Six PS 26145 threat classes, eight detector modules.

Show the mapping table from §1.1. Do not improvise the count on stage.

### Slide 5 — Results

Numbers only:

- throughput;
- p95 latency;
- PR-AUC;
- false alerts/hour;
- calibration;
- baseline comparison.

### Slide 6 — Demo

Handoff slide while dashboard loads.

### Slide 7 — Limits

What cannot be seen and roadmap.

---

# 44. Documentation Rules

Every important implementation decision should have one source of truth.

Use:

```text
PRD.md
```

for product requirements and scope.

Use:

```text
design.md
```

for architecture/contracts.

Use:

```text
implementation_plan.md
```

for implementation sequence.

Use:

```text
STATUS.md
```

for current completion state.

Use:

```text
testing.md
```

for test commands and acceptance criteria.

Use:

```text
LIMITATIONS.md
```

for known visibility/engineering limitations.

Do not duplicate changing values across multiple documents.

---

# 45. Immediate First Tickets

## Ticket 0 — PCAP generator scripts

**Carried forward from V6.2.** No preparation phase exists, so every attack PCAP must be produced inside the window, inside the veth lab, before the console switches to replay-only at hour 16. V6 scheduled no time for this at all, while Track B hours 1–6 already carried the corpus, the manifests, the DGA data and three detectors.

Map the project fixtures to the PS-named generation sources:

| PS source/tool | Project use |
|---|---|
| `iperf3` | benign throughput/large-transfer traffic |
| Ostinato | benign packet/port-diversity fixtures where available |
| TRex | optional high-rate benign stress generation |
| `hping3` | isolated SYN/UDP flood fixtures |
| Slowloris | isolated low-rate HTTP exhaustion fixture |
| `dnscat2` / `iodine` | DNS-tunnel fixture coverage |
| DGArchive | not treated as a runtime/download dependency; reimplemented published DGA families provide deterministic positives |
| sandboxed C2 emulator | deterministic beacon fixture |

Where a PS-named source is not used directly, record the substitution in `README.md` and the scenario manifest. Generation is seeded and the seed is logged.

Run generation in the background during hours 1–6 while Track A builds ingest.

**Done when:** the PCAP set is complete, hashed and manifested at the hour-6 gate. Generation stops there.

## Ticket 1 — Freeze contracts

Create:

```text
schemas/normalized_event.schema.json
schemas/alert.schema.json
features/feature_order.py
tests/schema/
```

Add contract tests.

**Done when:** all tracks can build against mocks.

## Ticket 2 — Replay harness

Implement:

```text
tcpreplay → veth
```

with:

- replay speed;
- timestamp rebasing;
- packet-count comparison;
- two consumers.

**Done when:** both consumers see the same replay within declared loss.

## Ticket 3 — Header counter + EVE normalizer

Implement:

- header-only counter;
- EVE tailer;
- partial-line handling;
- source timestamps;
- normalized event mapping;
- capture-loss fields.

**Done when:** one real PCAP becomes normalized events.

## Ticket 4 — Capability probe

Check:

- Suricata version;
- JA3;
- JA3S;
- JA4;
- DNS;
- TLS;
- QUIC;
- IPv4/IPv6.

**Done when:** dashboard can render capability state before detection begins.

## Ticket 5 — Dashboard skeleton

Build:

```text
LIVE/REPLAY
Capability banner
Incident feed
Evidence drawer
```

using recorded JSONL before detectors exist.

**Done when:** UI can render a fake incident end-to-end.


## Ticket 6 — Traceability + evaluation harness

Implement:
- PS26145 traceability matrix;
- detector/incident evaluation units;
- matching and deduplication rules;
- benign stress replay;
- hard-negative DGA evaluation.

**Done when:** one command can evaluate the canonical campaign and BENIGN_STRESS and emit reproducible metrics.

## Ticket 7 — Capability + recovery harness

Implement:
- detector capability matrix;
- `OBSERVABLE` / `DEGRADED` / `NOT_OBSERVABLE`;
- sensor/API failure simulation;
- restart/recovery checks.

**Done when:** failure is visible to the operator and persisted history remains consistent after restart.

## Ticket 8 — Performance/resource report

Implement:
- throughput;
- capture loss;
- p50/p95 latency;
- CPU/RAM;
- active state;
- queue depth;
- events/sec.

**Done when:** the benchmark emits one reproducible machine-readable report.

## Ticket 9 — Flow-record adapter

Implement the shared template-based NetFlow v9/IPFIX decoder and offline fixtures.

Requirements:
- one template cache shared by NetFlow v9 and IPFIX v10;
- bounded template state with expiry;
- normalize records into the same event contract as PCAP/EVE;
- set `input_mode` to `ipfix` or `netflow_v9`;
- preserve exporter/template identity and sampling metadata where present;
- expose detector-specific capability degradation;
- include one known-good fixture for each protocol.

The exporter is used only to create fixtures from project PCAPs during the build/preparation step. No exporter or external network service runs inside Plane B during the demo.

**Done when:** both fixture types produce contract-valid normalized events, malformed/expired templates remain bounded, and an IPFIX replay visibly degrades DNS/TLS-specific capabilities while flow-based detectors continue where required fields are present.

---

# 46. Definition of Done

The project is demo-ready only when all of these are true.

Each item carries **owner track / gate hour**. V6 listed twenty-nine unowned checkboxes, which means nobody owns any of them.

Owners: A = ingestion, B = detection/ML, C = UI/API.

- [ ] **A / H6** — Real PCAP replay works.
- [ ] **A / H6** — Both capture paths are validated.
- [ ] **A / H6** — Normalizer produces contract-valid events.
- [ ] **A / H10** — `flow_summary` comes from bounded local flow tracking.
- [ ] **A+C / H6** — Capability state works.
- [ ] **C / H10** — `not_observable` is visible.
- [ ] **B / H10** — DDoS detector works.
- [ ] **B / H10** — Scan detector works.
- [ ] **B / H10** — DGA model works and is calibrated.
- [ ] **B / H16** — Remaining selected detectors work or have documented fallbacks.
- [ ] **B / H16** — Alerts deduplicate into incidents.
- [ ] **C / H10** — Evidence drawer contains real values.
- [ ] **C / H16** — Baseline comparison is visible.
- [ ] **C / H10** — UI survives flood load.
- [ ] **A / H16** — Negative-connectivity test passes.
- [ ] **A / H16** — Hash-chain verifier passes.
- [ ] **A / H16** — Throughput is measured.
- [ ] **A / H10** — p95 latency is measured.
- [ ] **B / H16** — False alerts/hour is measured.
- [ ] **B / H16** — Threshold sweep exists.
- [ ] **A+B / H16** — Canonical campaign replay works.
- [ ] **B / H6** — Ground truth is separated from detector input.
- [ ] **A / H19** — Offline asset audit passes.
- [ ] **A / H19** — Second-machine cold boot passes.
- [ ] **C / H16** — Backup recording exists.
- [ ] **all / H22** — README is complete.
- [ ] **all / H22** — LIMITATIONS.md is complete.
- [ ] **B / H22** — Model card is complete.
- [ ] **C / H22** — Seven-slide deck is complete.
- [ ] **all / H19** — Feature freeze is respected.

- [ ] **B / H16** — Detector-level and incident-level evaluation rules are documented and reproducible.
- [ ] **B / H16** — BENIGN_STRESS replay passes with measured false-alert rate.
- [ ] **B / H16** — DGA hard-negative evaluation is included.
- [ ] **A / H16** — Resource metrics are captured with the throughput result.
- [ ] **A / H16** — Sensor/API restart and recovery tests pass.
- [ ] **C / H16** — Visibility/limitations panel is visible.
- [ ] **C / H16** — TLS/QUIC UI uses suspicion/anomaly wording, not malware identification.
- [ ] **A / H19** — Hash-chain tamper demonstration artifact exists.
- [ ] **all / H12** — Integration checkpoint passes before detector expansion.
- [ ] **A / H13** — NetFlow v9/IPFIX fixtures normalize through the shared adapter and preserve template/sampling metadata.
- [ ] **A / H13** — `input_mode` enum contract test passes.
- [ ] **all / H10** — Every emitted alert has non-null `flow_id` and valid `flow_ref_type`.
- [ ] **B / H16** — DNS tunnel evidence contains qtype distribution and TXT/NULL/CNAME shares where visible.
- [ ] **B / H16** — Slowloris is independently exercised with low-rate, long-duration fixtures.
- [ ] **B / H16** — TLS/QUIC evidence contains JA3S and concrete packet-size/direction/IAT fields where visible.
- [ ] **all / H22** — README/model card state exactly one trained ML model and identify all non-ML detectors.
---

# 47. Final Engineering Principles

1. **Build the spine before the brains.**
2. **Never allow attacker-controlled traffic to exhaust detector state.**
3. **Never infer benign from missing evidence.**
4. **Every important alert must explain itself with evidence.**
5. **Every published number must be reproducible.**
6. **One model is enough.**
7. **No live LLM inference.**
8. **No runtime internet dependency.**
9. **Replay is the final demo path.**
10. **The Scenario Console never feeds ground truth to the dashboard.**
11. **Read-only must be demonstrated, not merely claimed.**
12. **Feature freeze at hour 19.**
13. **Cut stretch features before cutting core detection.**
14. **Honest limitations increase credibility.**
15. **A stable, explainable detector beats a sophisticated detector that cannot survive the demo.**
16. **Do not add detector families after V6.3; spend remaining time on proof, integration, and evidence quality.**
17. **PS-named inputs and evidence fields are implementation contracts, not optional documentation.**

---

# 48. Final Architecture Decision Summary

| Decision | Final choice |
|---|---|
| Sensor | Suricata + header-only fast path |
| Input | Passive copied traffic / deterministic replay / offline NetFlow v9-IPFIX fixtures; sFlow capability mode |
| TLS | Metadata/fingerprint only: JA3/JA3S/JA4 where visible |
| QUIC | Metadata only |
| ML | One LightGBM DGA model |
| Statistical detection | Robust z-score, median/MAD, windowed behavior |
| State | Bounded |
| Flow summary | Local bounded flow tracker; IPFIX/NetFlow records normalized when supplied |
| Baseline | Benign snapshot + capped updates |
| Alerting | Deduplicated incident lifecycle |
| Evidence | Mandatory minimum evidence per detector |
| Missing fields | `not_observable` |
| Storage | SQLite |
| Transport | WebSocket |
| UI | React/Vite |
| Scenario | Separate application |
| Replay | tcpreplay |
| Report | JSON/CSV first; PDF optional |
| Geo | Offline only; map optional |
| Integrity | Hash chain |
| Deployment | Offline |
| Attack generation | Isolated lab only |
| Demo | Deterministic replay |
| Stretch priority | Map → PDF → clock servo → advanced algorithms |

---

## 49. Input-Mode Limitations

NetFlow v9/IPFIX support is intentionally limited to the fields present in the exported records. The adapter does not reconstruct packets, DNS names, TLS fingerprints, or TCP state that the exporter did not export. Those capabilities become `DEGRADED` or `NOT_OBSERVABLE`.

sFlow is recognized as a sampled input mode but is not implemented as a packet-equivalent detector source in this 24-hour build. Sampling metadata is surfaced so the operator can see the limitation.

This is a capability boundary, not a claim that the underlying threat is absent.

---

## START HERE

The first development action is **not** to build a detector.

Create the contracts and run the first end-to-end replay:

```text
1. schemas
2. FEATURE_ORDER
3. contract tests
4. veth lab
5. tcpreplay
6. header counter
7. Suricata EVE
8. normalizer
9. recorded event
10. IPFIX/NetFlow fixture normalization
11. dashboard
```

When that path works, the project has a spine.

Then add the brains.
