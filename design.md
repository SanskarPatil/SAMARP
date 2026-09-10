# System Design

**Project:** Cyber Sentinel — PS26145
**Derived from:** `FINAL_DEVELOPMENT_PLAN_V6.3.md` (implementation source of truth)
**Compliance mapping:** `ps26145_traceability_matrix.md`

This is the technical source of truth for architecture and contracts. Product scope lives in `PRD.md`; build order lives in `implementation_plan.md`; verification lives in `testing.md`. Where this document and `FINAL_DEVELOPMENT_PLAN_V6.3.md` disagree, the development plan wins and this document is corrected.

---

## 1. Architecture Overview

The system is a passive, streaming pipeline. Traffic is observed, never solicited. Every stage is bounded, and every stage can declare that it could not see something.

```text
                 Packet path
                     │
                     ├──────────┐
                     │          │
                 Flow path      │
                     │          │
                     └────┬─────┘
                          ↓
                   Normalized Event
                          ↓
                   Capability State
                          ↓
                     Features
                          ↓
                     Detectors
                          ↓
                 Fusion / Dedup / Lifecycle
                          ↓
                       SQLite
                          ↓
                  FastAPI/WebSocket
                          ↓
                   Monitoring UI
```

Three invariants hold at every stage:

1. **Nothing writes back toward the packet source.**
2. **No payload bytes are decrypted or interpreted as content.**
3. **Missing evidence is reported, never converted into a benign result.**

---

## 2. Deployment / Network Boundary

### 2.1 Boundary model

```text
                         ATTACKER / OFFLINE SIDE
┌──────────────────────────────────────────────────────────────┐
│ Scenario Console / offline asset builder                     │
│ Scenario → Manifest → Hashed PCAP                            │
│ PCAP → IPFIX/NetFlow fixture export (build time only)        │
└───────────────────────────┬──────────────────────────────────┘
                            │
                            │ one-way copied data / replay only
                            ▼
====================== ONE-WAY BOUNDARY ========================
                            │
                            ▼
                     MONITORING ENCLAVE
```

The monitoring side has **no actionable return path**. This is demonstrated, not asserted: a scripted negative-connectivity test proves that the monitor cannot reach the external network, cannot reach the attacker-side veth, and holds no route to the monitored enclave. Its output is archived as `artifacts/boundary_test_<timestamp>.txt` and shipped in the export bundle so the proof survives outside the live demo moment.

Recommendations rendered by the dashboard are **advisory text only**. There is no mitigation button, command, API call or return path anywhere in the system.

### 2.2 Lab Address Plan

Several detector features carry address semantics. Without a declared plan they misfire inside an RFC 1918 lab. The plan is configuration, loaded by every module that needs address meaning; no detector hardcodes a prefix check.

```text
config/address_plan.yaml
```

| Range | Role |
|---|---|
| `10.10.0.0/16` | Monitored enclave (internal) |
| `10.10.0.53` | Enclave DNS resolver |
| `10.20.0.0/16` | Monitoring enclave (Plane B) — no route to `10.10/16`, no external route |
| `10.99.0.0/24` | Lab transport (veth pairs) |
| Curated public ranges | External benign, synthetic malicious, and amplifier hosts (ports 53 / 123 / 389 / 1900 / 11211), all GeoLite2-resolvable |

Consumers of the plan: inbound/outbound direction; exfiltration outbound bytes; reflection reserved-source share; destination novelty; geolocation; IPv6 `/48` entropy bucketing.

**The trap this fixes.** Reflection minimum evidence includes the reserved/invalid source-space share. In a pure RFC 1918 lab that share is 100 % on benign traffic, so the detector fires continuously and destroys the false-alerts-per-hour figure. The rule: the reserved-share feature is computed against the **external** address space only, declared lab prefixes are excluded from the bogon set, and the exclusion is stated in the evidence drawer text. The geolocation trap is the same failure family and the same plan fixes it.

**Anonymisation.** None at runtime in this build — all capture is lab-synthetic and there is no subscriber data to protect. The forward path for real enclave traffic is CryptoPAn applied **after** geolocation and **before** persistence, because prefix-preserving anonymisation destroys geo lookup if applied first. This position is stated in `LIMITATIONS.md`.

---

## 3. Two-Plane UI Architecture

The project contains **two separate applications** on opposite sides of the boundary.

| | Plane A — Scenario Console | Plane B — Monitoring Dashboard |
|---|---|---|
| Side | Attacker / offline | Monitoring enclave |
| Owns | Scenario menu, randomiser and seed log, PCAP generation (build phase only), deterministic replay, manifests, replay speed, GENERATE/REPLAY mode | Passive ingest, EVE consumption, flow-record consumption, normalisation, features, detectors, incident lifecycle, persistence, evidence, export, capability state |
| HTTP | Its own app, own namespace, own port, own process | `GET` and WebSocket only |

**Critical separation rule.** The Scenario Console must **never** notify the Monitoring Dashboard that an attack has happened. The dashboard learns only from the observed packet stream. During the final demo the console runs in REPLAY mode, driven from a second window. No convenience routing is added between the planes for any reason.

`POST /simulate/scenario/{id}` was removed from the Plane B API and must never return. An attack-starting endpoint on the monitoring side reads as a return path and collapses the entire read-only argument in one question.

---

## 4. Ingestion Layer

Two passive input paths converge on one contract.

### 4.1 Packet input path

```text
PCAP / live tap
      ↓
tcpreplay / passive capture
      ↓
veth / monitored boundary
      ↓
Fast header counter + Suricata metadata
      ↓
Normalizer
```

### 4.2 Flow-record input path

```text
NetFlow v9 ──┐
             ├──> shared template cache + record decoder ──> NormalizedEvent
IPFIX v10 ──┘

Sampled sFlow ──> capability recognition ──> DEGRADED / NOT_OBSERVABLE per detector
```

**One shared decoder, not two parsers.** NetFlow v9 and IPFIX v10 both use template-defined records. `ingest/flow_record_adapter.py` holds a single template cache and record decoder that normalises the common fields into the same event contract used by the packet path.

The adapter preserves: source/observation time, exporter and template identity, five-tuple fields where present, byte and packet counters, direction where available, and sampling metadata. It sets `input_mode` to `ipfix` or `netflow_v9`.

**Bounded template state.** The template cache is bounded and evicted by exporter/template identity and timeout. A malformed or attacker-controlled template stream must not create unbounded parser state.

**Fixture provenance.** Flow-record fixtures are generated during the build/preparation step from project PCAPs using an exporter such as `yaf`, `nfpcapd` or `softflowd`, then copied into the offline asset bundle. **No exporter and no external network service runs inside Plane B during the demo.**

### 4.3 sFlow

`sflow` is a **valid, frozen `input_mode` value**. It is recognised as a sampled input mode and sampling state is always surfaced to the operator.

It is **not** implemented as a packet-equivalent detector source in this build. Sampling-aware volumetric statistics may remain usable; detectors depending on unsampled packet order, complete port spread, DNS names or TLS fingerprints declare `DEGRADED` or `NOT_OBSERVABLE` per section 23.

`NOT_OBSERVABLE` is a **per-detector evidence state**, never a property of an input mode. "sFlow is NOT_OBSERVABLE" is not a valid statement in this system.

---

## 5. Replay and Clock Model

**One clock.** Suricata and the fast header counter consume the same tcpreplay-driven interface. Running them independently against the PCAP creates divergent clocks and breaks correlation.

Replay display time is rebased once, not per packet:

```text
t_display = t_replay_start + (t_packet - t_pcap_start) / replay_speed
```

`t_replay_start` is captured **once** when replay begins and written into the scenario manifest.

Evaluating `now` per packet adds wall-clock elapsed on top of PCAP-relative elapsed, so the displayed clock drifts at roughly 2x. That is the dual-clock correlation failure; it must not be reintroduced.

The original packet timestamp is preserved separately as `observed_time`. Old PCAP timestamps are never silently treated as current live time. The LIVE/REPLAY badge and the replay speed are always visible.

---

## 6. Fast Header Counter

A header-only path parses IP/TCP/UDP headers and maintains rate, cardinality and entropy inputs without touching payload. It runs alongside Suricata on the same replayed interface.

It also owns the **bounded in-process flow tracker** that produces `flow_summary` (see section 9.2). The tracker is bounded by memory cap, eviction policy, maximum active state and timeout, so a spoofed flood cannot exhaust detector memory.

IPv6 is parsed in the fast path. Where a detector is IPv4-only, it reports `NOT_OBSERVABLE` rather than silently omitting the traffic. IPv6 entropy is bucketed at `/48` using the declared prefixes.

---

## 7. Suricata Metadata Path

**Version pin: Suricata 7.0.3 or later** (required for JA4). The exact version is recorded in the capability state and in every alert's sensor metadata.

Suricata ships with defaults that silently disable detectors. A detector with no input does not error — it simply never alerts. All five are configured explicitly and verified by the hour-0 capability probe.

| # | Default | Consequence if left alone | Required setting |
|---|---|---|---|
| 1 | EVE log types incomplete | Missing `dns.responses` removes NXDOMAIN context — minimum evidence for DGA and a required feature for the DNS-tunnel ensemble | Enable `alert`, `dns` (requests + responses), `tls` (extended), `quic`, `anomaly`, `stats` |
| 2 | Fingerprints off | No JA3/JA3S/JA4 | `ja3-fingerprints: yes`, `ja4-fingerprints: yes`, `quic.enabled: yes` |
| 3 | Stats disabled | No `kernel_drops`, therefore no `sensor_drop_pct`, therefore no capture-loss story at all | `stats.enabled: yes`, `interval: 1` |
| 4 | Capture ring too small | Drops during the flood are wrongly attributed to the detection pipeline instead of the capture layer | `ring-size: 200000`, `block-size: 1048576`, `use-mmap`, `cluster_flow` |
| 5 | Stream reassembly depth | Truncated reassembly silently shortens the flows exfiltration and beaconing depend on | `stream.memcap: 512mb`, `reassembly.memcap: 256mb`, `depth: 1mb` |

**EVE flow events stay off** (see section 9.2). The probe asserts `flow events == 0`.

### Probe acceptance criteria

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
flow events              == 0
```

Where JA4 is unavailable in the built version, that fact is recorded and JA3/JA3S plus remaining visible metadata are used. Unavailable fingerprint fields render as `NOT_OBSERVABLE`. They are never silently omitted.

---

## 8. Normalization

The normalizer accepts header-path events, EVE records and decoded flow records, and emits one event type. It attaches direction using `config/address_plan.yaml`, attaches capture-loss fields, and attaches the capability state supplied by the source adapter.

A **field allowlist** governs what may cross from the sensor into the pipeline. Decrypted or payload-content fields have no representation in the contract, so no decryption can enter the system even by accident.

---

## 9. Event Contract

### 9.1 Normalized Event

Frozen in `schemas/normalized_event.schema.json`. The event exposes, as applicable: observed timestamp; source and destination IP; source and destination port; protocol; TCP flags; packet and byte counts; flow identity; DNS fields; TLS fields; QUIC fields; direction; capture source; sensor loss information; capability/observability fields; `input_mode`; and `flow_id` / `flow_ref_type` where an alertable observation exists.

**Frozen `input_mode` enum:**

```text
pcap_replay | live_tap | ipfix | netflow_v9 | sflow
```

`input_mode` describes the primary input contract, not an internal combination such as `pcap_replay+eve`. Sensor subpaths are represented separately in capability state.

### 9.2 `flow_summary` ownership

Suricata EVE flow events are intentionally disabled to reduce flow-event output pressure. Therefore:

> **`flow_summary` is produced by the bounded in-process flow tracker on the header path, not by Suricata EVE flow output.**

Re-enabling EVE flow events merely to populate this field is forbidden.

### 9.3 Alert Schema v1.3

Frozen in `schemas/alert.schema.json`. That file — not this document, and not a commented JSON example — is the source of truth for required fields, types, enum values, evidence structure, observability state, detector metadata, incident identity, and sequence/hash-chain fields. Contract tests fail on schema drift. If documentation needs comments, the example is labelled JSONC.

**PS constraint-(e) mapping — frozen:**

| PS term | Schema field | Rule |
|---|---|---|
| timestamp | `timestamp` | Required ISO-8601 display/alert time |
| flow identifier | `flow_id` | Required, non-null, stable |
| threat class | `ps_class` / `threat_class` | `ps_class` is one of the six PS classes; `threat_class` is the concrete detector label |
| confidence score | `confidence` | Required numeric confidence/evidence-strength value, qualified by `score_type` and `calibrated` |
| supporting evidence | `evidence` | Required object of actual feature values and their interpretation |

### 9.4 Flow identity rule

A single incident may represent many underlying flows, so `flow_id` identifies the **alertable observation context** rather than pretending one flow exists when the event is an aggregate.

```text
flow_ref_type = flow_5tuple | aggregate | entity

flow_id = sha256(canonical(5-tuple)).hexdigest()[:16]
        | sha256(canonical(dedup_key)).hexdigest()[:16]
        | sha256(canonical(entity)).hexdigest()[:16]
```

- `flow_5tuple` — one concrete flow is observable.
- `aggregate` — DDoS, reflection or another multi-flow event; the canonical aggregate identity is hashed.
- `entity` — DGA, scan or similar behaviour best represented by a source/entity identity.

`flow_id` is **never null**. For a spoofed flood there is no honest single source flow, so the alert uses `flow_ref_type: aggregate`. A bounded sample of contributing `flow_ids` may appear as evidence but never replaces the mandatory `flow_id`.

### Canonical identifier representation — frozen

```text
identifier = sha256(canonical_value).hexdigest()[:16]
```

- **Exactly 16 lowercase hexadecimal characters** — a 64-bit truncated SHA-256. Schema pattern: `^[0-9a-f]{16}$`.
- **`[:16]` is applied to the hex digest, never to `digest()`.** It is not 16 bytes.
- Applies to `flow_id` and `incident_id`.
- **Does not apply to the hash chain.** `payload_hash`, `entry_hash` and `prev_hash` are full 64-character SHA-256 digests and are never truncated (see section 18).
- The canonicalisation helper and the truncation are defined **once** in `alerts/hash_chain.py`. Every producer and every verifier imports them; neither reimplements.

### 9.5 Terminology contract

```text
ps_class   one of the six PS class names (external wording, verbatim)
detector   one of the eight module names (internal wording)
```

| PS 26145 class (external, frozen) | Detector modules (internal) |
|---|---|
| Volumetric DDoS / flooding | `ddos.py`, `reflection.py` |
| Port scanning / reconnaissance | `scan.py` |
| Botnet C2 beaconing | `c2.py` |
| DGA / DNS tunnelling | `dga.py`, `dns.py` |
| Malware in encrypted sessions | `tls_quic.py` |
| Data exfiltration | `exfil.py` |

The detector registry is the source of truth for modules; the problem statement is the source of truth for classes. A contract test asserts every `detector` value maps to exactly one `ps_class`. Six classes, eight modules — the count is never improvised.

---

## 10. Feature Service

`features/feature_order.py` holds a single authoritative `FEATURE_ORDER` tuple. Training and inference import the same object. **No detector or model constructs its own feature ordering.**

The shipped tuple is the frozen source of truth. The following is the required semantic minimum, not permission to reorder:

```python
FEATURE_ORDER = (
    # DGA
    "length", "entropy", "digit_ratio", "vowel_ratio", "label_count",
    "lm_bigram", "lm_trigram", "nxdomain_rate",
    # DNS tunnel
    "qtype_txt_ratio", "qtype_null_ratio", "qtype_cname_ratio", "qtype_entropy",
    # TLS/QUIC shape
    "packet_size_first_n", "packet_size_mean", "packet_size_p95",
    "iat_median", "iat_p95", "iat_cv",
    "upstream_packet_ratio", "downstream_packet_ratio",
)
```

A parity test asserts `offline feature extraction == streaming feature extraction` for the same traffic fixture.

---

## 11. Rolling Windows and Bounded State

All rolling state is bounded. Available techniques: tumbling and sliding windows, watermarks, out-of-order handling, bounded flow state, Space-Saving, HyperLogLog, Count-Min, reservoir sampling, bounded ring buffers, explicit eviction, hard caps.

**Never maintain an unbounded dictionary keyed by arbitrary source/destination tuples.** The attacker must not be able to weaponise the detector's own state.

### Baseline

The baseline is generated from the benign corpus and **loads as a snapshot at boot**, so there is no cold start and detection is live from the first window.

The `warmup_windows` gate applies **only to the adaptive delta** layered on top of the snapshot — never to detection itself. Baseline updates are capped to prevent slow poisoning, and an immutable long-term reference snapshot lives in the offline intelligence bundle.

---

## 12. Detection Architecture

Every detector follows the same path:

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

Every alert carries, where applicable: detector; severity; score and confidence; evidence; baseline; window; observed timestamp; model and intel version; capability state; sensor-loss information; incident sequence.

### Minimum evidence contracts

| Detector | Minimum evidence |
|---|---|
| `ddos.py` — flood | Packet rate / pps; baseline comparison; SYN/SYN-ACK behaviour; unique source count; source entropy or estimation method; time window |
| `ddos.py` — Slowloris | Concurrent half-open / long-lived connections; connection-duration percentile; bytes per connection; low packet/byte rate; destination and service context |
| `reflection.py` | Source/destination relationship; fan-in or amplifier-port evidence; source entropy; reserved/invalid source-space share where applicable; traffic rate |
| `scan.py` | Unique destinations and ports; source-window behaviour; scan pattern; port or target spread; baseline comparison |
| `dga.py` | DNS query availability; lexical feature values; model score; calibration status; NXDOMAIN context; model version |
| `dns.py` | Query-name availability; query length and entropy; encoded-character indicators; query frequency; **qtype distribution including TXT/NULL/CNAME shares**; source/entity context; DNS response behaviour where available |
| `c2.py` | Repeated destination; inter-arrival timing; coefficient of variation; robust timing statistic; persistence across windows; destination novelty/intel where available |
| `exfil.py` | Outbound byte/packet behaviour; destination or entity; temporal burst or sustained-transfer evidence; baseline comparison; relevant protocol metadata |
| `tls_quic.py` | JA3/JA3S/JA4 where available; destination novelty; first-N packet-size sequence or quantiles; direction sequence and directional ratio; inter-arrival median, p95 and CV; available TLS/QUIC metadata; explicit statement that this is suspicion, not payload identification |

---

## 13. DGA Model

**LightGBM is the single trained model in the system.** Every other detector is statistical, rule-based or offline-intelligence driven.

### Frozen lexical and language features

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

The bigram/trigram background model is trained from the benign Tranco-derived hostname corpus. Its score is a **feature, not a standalone verdict**, and it is what defeats wordlist-style DGAs that raw entropy cannot separate.

### Training and evaluation discipline

Time-based holdout; entity-based holdout; DGA-family holdout; deduplication before splitting; TLD stripping where specified; Platt calibration; reliability diagram; Brier score; model card. Wordlist families are represented in evaluation. Generic "AI accuracy" is never claimed.

The corpus includes **hard negatives** — CDN-generated names, UUID-like identifiers, long API/service subdomains, tracking and telemetry names, random-looking but legitimate hostnames, software update infrastructure — so the model cannot learn the shortcut `random-looking == malicious`.

### Artifact policy and fallback

The trained artifact is **pre-built and vendored** into `models/artifact` before the build window opens. In-window training is a refresh, not a dependency.

If the artifact is unusable and retraining fails, the documented fallback is:

```text
lexical features + Shannon entropy + NXDOMAIN rate + Tranco allowlist
```

shipped with `calibrated: false` and `model_version: "rules-fallback"`. The evidence drawer states that the number is a rule score, not a calibrated probability. **No Brier score or reliability diagram is shown for the fallback** — a rule score is not a probability.

DGA is on the never-cut list. Row 12 of the kill ladder is a fallback *inside* a never-cut item, not a cut.

---

## 14. Statistical Detectors

| Module | Method |
|---|---|
| `ddos.py` — flood | Robust z-score, median/MAD, hysteresis `N=2`, hard gates; baseline warm-up applies to the adaptive delta only |
| `ddos.py` — Slowloris | Concurrent half-open / long-lived connection count, connection-duration percentile, bytes per connection, low rate, destination-specific baseline. **An incident fires only when the concurrency and duration gates agree.** The evidence drawer shows the low-rate nature rather than hiding it behind the generic flood detector |
| `reflection.py` | Fan-in, amplifier-port semantics, source entropy, reserved-source share computed against external space only |
| `scan.py` | Unique destination and port spread, windowed source behaviour, robust thresholds, hard gates, bounded state |
| `dns.py` | Ensemble: lexical/entropy signals, encoded-name characteristics, frequency, length, NXDOMAIN behaviour, **qtype distribution (TXT, NULL, CNAME and other shares)**, source/entity context. Never relies on one suspicious string feature. The evidence drawer exposes the qtype distribution because it is a PS-named tunnelling discriminator |
| `c2.py` | Coefficient of variation plus median/MAD. Lomb-Scargle only if all scheduled work is green; fallback is CV + MAD + fixed threshold |
| `exfil.py` | Per-entity outbound behaviour and baseline comparison, kept simple enough to explain in the evidence drawer |

A flood produces **one evolving incident** with updating counters, risk and evidence — never one alert per packet or per window.

---

## 15. TLS/QUIC Metadata Detection

Inputs: JA3; JA3S; JA4 where supported; destination novelty; first-N packet-size sequence and summary quantiles; packet direction sequence and directional ratios; inter-arrival median, p95 and coefficient of variation; offline intel.

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

The shape score compares these against a per-service benign profile. **It never inspects decrypted payload bytes.**

A TLS session may expose both client and server fingerprints: JA3 for the client handshake, JA3S for the server response. JA4 is used where the installed Suricata build exposes it. Missing fingerprints are **capability state, not evidence of benign traffic**.

UI wording is `Suspicious Encrypted Session` / `Encrypted Session Anomaly`. Payload identification and malware-family attribution are explicitly out of scope.

---

## 16. Fusion and Risk Scoring

Detector scores are not interchangeable with probabilities.

| `score_type` | Meaning | Calibrated? |
|---|---|---|
| `robust_z` | Distance from a robust baseline | No |
| `anomaly_score` | Detector-specific evidence strength | No unless explicitly calibrated |
| `model_probability` | Calibrated ML probability estimate | Yes, only after calibration |
| `rule_score` | Deterministic evidence/rule aggregation | No |

The schema preserves `score`, `score_type`, `confidence` and `calibrated`.

`confidence` is the PS-required field. For calibrated DGA output it is a probability-like estimate carrying its calibration status and model version. For statistical and rule detectors it is a documented evidence-strength mapping and may be null; the UI labels these as **risk / anomaly scores** and **never appends a percent sign unless `calibrated: true`**.

A robust z-score or rule score is never described as a probability, in the UI or on stage.

Cross-detector fusion and correlation are optional (kill-ladder priority 7). **Deduplication is mandatory even if fusion is cut.**

---

## 17. Deduplication and Incident Lifecycle

```text
NEW → ACTIVE → UPDATED → RESOLVED
```

An incident carries: stable identity/deduplication key; severity; first and last observed; evolving counters; evidence history; detector and model version; hash-chain sequence.

Incident identity is `sha256(canonical(key)).hexdigest()[:16]` — the frozen 16-hex-character form defined in section 9.4 — stable across restarts.

### Frozen deduplication keys

Held in `config/dedup_keys.yaml` and asserted by a contract test.

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

Two of these are counter-intuitive and both are wrong by default:

- **`ddos` never keys on source.** Sources are spoofed, so a source key produces one incident per packet — the precise failure the incident model exists to prevent.
- **`dga` never keys on domain.** A DGA burst is hundreds of distinct domains. Domains are evidence rows *inside* one incident, not incident identities.

`dns_tunnel` keys on the registered domain (eTLD+1 after TLD stripping), not the full query name — the full name is the thing that varies.

### Unavailable key components — frozen sentinel

Three keys reference evidence the capability model says may be absent: `tls_quic` uses `ja3`, `dns_tunnel` uses `registered_domain`, `reflection` uses `amplifier_port`. Under NetFlow/IPFIX these are normally not visible.

**Where a key component is unavailable under the current observation mode, it takes the exact canonical sentinel string:**

```text
NOT_OBSERVABLE
```

- **Never** substitute null, an empty string, zero, `unknown`, or any other placeholder.
- Deduplication operates on the **canonical serialized key containing the sentinel**, so identity stays deterministic and stable across restarts regardless of input mode.
- Because `flow_id` for an `aggregate` reference is derived from the canonical dedup key, the sentinel propagates into `flow_id` deterministically. That is intended.

Worked examples:

```text
tls_quic      (ps_class, src_ip, NOT_OBSERVABLE, dst_ip)      ja3 absent under IPFIX
dns_tunnel    (ps_class, src_ip, NOT_OBSERVABLE)              registered_domain absent
reflection    (ps_class, dst_ip, NOT_OBSERVABLE)              amplifier_port absent
```

**This sentinel is an identity rule, not a detection rule.** It governs how an incident is identified once a detector has decided to alert. It does **not** authorise alerting on absent evidence: the capability check and the minimum-evidence check in section 12 still run first, and a detector whose required evidence is missing reports `NOT_OBSERVABLE` as its capability state instead of emitting an incident. The two uses of the word are deliberately the same string and deliberately different mechanisms — one is a capability state, the other is a key component placeholder.

---

## 18. Persistence and Hash Chain

SQLite persists incidents, incident updates, evidence, timestamps, hash-chain metadata, and scenario/replay metadata. The store is written **continuously**; the report and export layers are views over it, not a batch pipeline.

### Chain specification — frozen

```text
canonical(x)        JSON, keys sorted, no whitespace, UTF-8, NaN/Inf rejected
payload_hash        sha256(canonical(incident_payload))
entry_hash          sha256(prev_hash || seq || incident_id || last_updated || payload_hash)
genesis prev_hash   "0" * 64
```

- `seq` is a monotonic integer across the whole store, not per incident.
- `||` is byte concatenation of the ASCII/hex representations, defined **once** in `alerts/hash_chain.py` and imported by the verifier. The verifier never reimplements it.
- **Chain hashes are never truncated.** `payload_hash`, `entry_hash` and `prev_hash` are full 64-character SHA-256 hex digests. The 16-character truncation in section 9.4 applies only to `flow_id` and `incident_id`. The genesis `prev_hash` of `"0" * 64` is consistent with the full-length form.
- Every incident update appends a new entry. Entries are never rewritten in place.
- Export carries `seq`, `prev_hash` and `entry_hash` for every entry.
- `tests/hash_chain/verify_hash_chain.py` runs in a clean process against the exported JSON only, with no import of writer runtime state.

Writer and verifier are built in the same ticket against this spec. An unspecified chain means they disagree, and it fails at hour 17 on a scripted demo beat.

The claim is precise: the chain makes post-hoc modification **detectable**. It is tamper-evident, not a claim that the storage system is immutable.

### Export

JSON and CSV. PDF is optional and is kill-ladder priority 2.

```text
CSV: one row per incident, not per evidence item
evidence.<key>    scalar values, dotted path, one column each
evidence_json     full evidence object, JSON-encoded, single column
```

JSON export is lossless and canonical. CSV exists for eyeballing in a spreadsheet. Where they disagree, JSON wins, and **the hash chain is computed over the JSON form only.**

---

## 19. API and WebSocket

```text
GET  /health
GET  /capabilities
GET  /incidents
GET  /incidents/{id}
GET  /export/json
GET  /export/csv
```

**Plane B is read-only over HTTP: `GET` and WebSocket only. No `POST`, no `PUT`, no `DELETE`.** A contract test asserts that no non-`GET` route is registered on the Plane B application.

WebSocket delivers live incidents in batches of approximately 250 ms. The route contract is frozen before UI implementation begins.

Scenario control lives **only** in the Scenario Console application — attacker side, separate namespace, separate port, separate process.

---

## 20. Monitoring Dashboard

React/Vite. Permanent elements: LIVE/REPLAY badge, capability and health banner, risk/severity indication, active incident feed.

Incident feed rows: class, severity, confidence or score, current status, key metric, last update.

Evidence drawer: actual feature values, baseline, detector threshold, evidence interpretation, observability state, model and intel version, capture-loss information.

### Performance rules

- Batched WebSocket pushes at approximately 250 ms.
- Client ring buffer of 500 incidents.
- Virtualised incident list.
- `requestAnimationFrame` counters.
- A single CSS severity accent variable.

Load-tested with a synthetic 50 000-alert burst; the page must remain interactive and memory must remain bounded.

### Threat map

**Optional.** Built only if the hour-16 gate is completely green, and the first item on the kill ladder. If retained: offline GeoLite2, offline TopoJSON, no live lookup, demo fixtures for private/documentation addresses, an explicit `demo_fixture` badge, and the statement that geolocation is not attribution. If it threatens core functionality, it is cut.

---

## 21. Scenario Console

Plane A. Scenario menu; randomiser with seed logging; PCAP generation during the authorised build phase only; deterministic replay; scenario manifests; replay speed; GENERATE/REPLAY mode.

**Generation stops at the Hour-6 gate**, where the PCAP set is complete, hashed and manifested. After that the lab is replay-only. During hours 16–19 the console is switched to REPLAY mode and GENERATE is made unreachable outside the build machine.

Attack generation runs only inside Linux network namespaces, veth pairs, or a host-only virtual network with no bridge to a physical interface. Before every generation run, two checks: the output interface is a veth or host-only adapter and never a physical NIC, and the target is inside the declared lab subnet.

Malware-capture datasets are treated as hostile packet data. Binaries inside them are never executed.

### Canonical campaign

One deterministic scenario serves as integration test, main demo, backup recording and expected-alert contract:

```text
T+00:00   reconnaissance / scan
T+00:30   beaconing
T+01:30   DGA burst
T+03:00   DNS tunnel
T+04:00   exfiltration
T+05:00   suspicious TLS/QUIC session
T+06:00   DDoS/flood
```

Exact timing may be adjusted to the generated PCAPs. Deterministic ordering and seed/hash recording are the requirements.

A `BENIGN_STRESS` scenario is maintained alongside it — high-volume legitimate DNS, long/large legitimate transfers, TLS-heavy traffic, legitimate periodic polling, many short-lived connections, legitimate port/destination diversity, and long or machine-generated but benign domain names. It is mandatory for the false-alerts-per-hour measurement.

**Ground truth never reaches the dashboard.** Scenario manifests and expected alerts feed the offline evaluation harness only; the live dashboard receives actual detector output only.

---

## 22. Offline Intel Bundle

Versioned and bundled: allowlists; SSLBL JA3 data if used; DGA family data; Tranco list; baseline snapshot; explainer text; recommendations; GeoLite2 if the map is retained; version manifest.

Every relevant alert and report carries the bundle and model version.

**No runtime LLM and no internet service is permitted.** Retraining in an air-gapped environment happens through a versioned offline bundle cycle; drift is monitored passively for the next cycle.

Vendored offline before the window: Python wheels, Node dependencies, the Suricata package/build, GeoLite2 and TopoJSON if the map is retained, the intel bundle, the model artifact, all test PCAPs and flow-record fixtures, and scenario manifests. An offline asset audit runs before the demo.

---

## 23. Capability Negotiation

Two independent axes. They are frequently conflated and must not be.

### 23.1 Evidence-visibility axis (per detector)

```text
OBSERVABLE | DEGRADED | NOT_OBSERVABLE
```

### 23.2 Component-health axis (per component)

```text
HEALTHY | DEGRADED | UNAVAILABLE
```

`UNAVAILABLE` describes a component that is down — sensor, normalizer, detector process, API, WebSocket. It is not an evidence state and never appears in a detector capability declaration.

### 23.3 Serialized capability state

```text
input_mode
ipv4                dns_names           tls_handshake       ja3
ipv6                dns_responses       quic_metadata       ja3s
                                                            ja4
flow_records        flow_sampling       geo
capture_loss        bidirectional_visibility
```

Enum values are frozen by the contract.

### 23.4 Detector-specific visibility

| Detector | Full evidence | Partial → `DEGRADED` | Missing → `NOT_OBSERVABLE` |
|---|---|---|---|
| DDoS | Packet/flow rate + headers/timing | Flow records without TCP flags; sampled rate with sampling metadata | No usable packet/flow rate |
| Reflection | Flow/header rate + UDP service/source semantics | Flow records with incomplete source-port/service detail | No usable source/destination/protocol evidence |
| Scan | Source + destination + port spread | IPFIX/NetFlow with sampled or partial spread | No source/port spread |
| Slowloris | Half-open/long-lived connection state + low-rate bytes | Flow records with duration/bytes but no TCP-state detail | No duration or connection-state evidence |
| DGA | DNS names + query context + NXDOMAIN | Names visible but missing response context | No DNS names |
| DNS tunnel | DNS names + qtype + timing + response context | Names/timing but missing qtype or responses | No DNS names |
| C2 | Repeated flow timing + entity persistence | Sampled flow timing with uncertainty | Insufficient repeated flow observations |
| Exfiltration | Directional bytes + destination/entity | One-direction source volume only, no reply side | No usable byte/direction evidence |
| TLS/QUIC | Handshake + JA3/JA3S/JA4 + packet shape | Partial handshake or fingerprint visibility | No relevant TLS/QUIC metadata |

Slowloris appears as its own row because it is a distinct evidence path, though it lives inside `ddos.py` and maps to the same PS class.

For plain NetFlow/IPFIX: DDoS and scan generally remain flow-observable; C2 and exfiltration may remain usable depending on timing and direction fields; DNS names and TLS/QUIC fingerprints are normally `NOT_OBSERVABLE`. For sFlow, sampling state is always surfaced and packet-order-sensitive detectors degrade accordingly.

Worked examples:

```text
DNS unavailable                     → DGA = NOT_OBSERVABLE
sampled flow input                  → packet-order detector = DEGRADED / NOT_OBSERVABLE
v4-only detector on v6 traffic      → NOT_OBSERVABLE
ECH hides SNI                       → SNI-dependent evidence = NOT_OBSERVABLE
IPFIX record omits DNS/TLS fields   → name/fingerprint detector = NOT_OBSERVABLE
```

**Missing evidence never silently becomes a benign result.** The dashboard renders these states and the alert records the visibility limitation.

### 23.5 Input-mode limitations

NetFlow v9/IPFIX support is intentionally limited to the fields present in the exported records. The adapter does not reconstruct packets, DNS names, TLS fingerprints or TCP state the exporter did not export. Those capabilities become `DEGRADED` or `NOT_OBSERVABLE`. This is a capability boundary, not a claim that the underlying threat is absent.

---

## 24. Latency Budget

Frozen. Every track codes against these numbers.

```text
watermark / out-of-order grace        300 ms
window close + feature emit          ~1.0 s     (1 s tumbling window)
detector scoring + dedup             ~100 ms
API + WebSocket batch push            250 ms
------------------------------------------------
structural floor                     ~1.6 s
SLO                                   p95 < 2.0 s
```

`latency_ms` measures `t_observed` to `t_websocket_emit`. **Measured, never estimated.**

If p95 exceeds the SLO, fix in this order: batch push interval, then window size, then detector cost.

**Never shrink the watermark.** The 300 ms grace period is a floor accepted deliberately; shrinking it drops late packets silently and trades a visible latency number for invisible missed detections.

These values live in `config/thresholds.yaml`.

---

## 25. Failure Modes and Fallbacks

| Failure | Behaviour |
|---|---|
| Sensor / EVE input down | Component health → `DEGRADED` or `UNAVAILABLE`; no false healthy state; buffered and persisted incidents remain consistent |
| Normalizer, detector process, API or WebSocket down | Same; WebSocket clients can reconnect; `GET` endpoints remain authoritative after reconnect |
| Restart during or after replay | SQLite history readable; incident sequence and hash-chain state resume correctly; no duplicate incident created by restart alone; capability state recomputed; UI indicates session restart |
| Capture loss | Surfaced, never hidden. Kernel drops, ring counters, TCP sequence gaps, packet-count comparison. Where only one estimator exists, report the raw `kernel_drops` ratio and label it a lower bound. **No more precise number is invented** |
| DGA artifact unusable | Rule fallback with `calibrated: false`, `model_version: "rules-fallback"`; no Brier score or reliability diagram |
| Kalman clock servo not ready | Fixed 300 ms watermark |
| Capture-loss Kalman not ready | Raw `kernel_drops` lower bound |
| Lomb-Scargle not ready | CV + MAD |
| Fusion not ready | Separate detector alerts + deduplication (dedup is mandatory) |
| SHAP not ready | LightGBM `pred_contrib` or evidence templates |
| Real PCAP replay unavailable | Synthetic generator |

The full ordered kill ladder is in `implementation_plan.md`.

---

## 26. Architecture Decisions

| Decision | Final choice |
|---|---|
| Sensor | Suricata (7.0.3 or later) + header-only fast path |
| Input | Passive copied traffic / deterministic replay / offline NetFlow v9–IPFIX fixtures; sFlow capability mode |
| TLS | Metadata and fingerprints only: JA3/JA3S/JA4 where visible |
| QUIC | Metadata only |
| ML | One LightGBM DGA model |
| Statistical detection | Robust z-score, median/MAD, windowed behaviour |
| State | Bounded |
| Flow summary | Local bounded flow tracker; IPFIX/NetFlow records normalised when supplied |
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

### Positioning

> **This system is an intelligence layer on top of passive sensor data, not a replacement for Suricata.**

| Capability | Suricata / signatures | This intelligence layer |
|---|---|---|
| Known signatures | Strong | Consumes and augments sensor output |
| Behavioural baselines | Limited | Core feature |
| Beacon periodicity | Limited | Core detector |
| DGA lexical ML | Not the primary role | Core detector |
| Evidence correlation | Sensor-centric | Incident-centric |
| Passive / read-only | Yes | Yes |
