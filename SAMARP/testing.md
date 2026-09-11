# Testing Strategy

**Project:** Cyber Sentinel — PS26145
**Derived from:** `FINAL_DEVELOPMENT_PLAN_V6.3.md` sections 23, 26, 26A, 26B, 27, 28 and `ps26145_traceability_matrix.md` sections 1 and 8

This file defines **how the project proves that it works**. Architecture is in `design.md`; build order and gate hours are in `implementation_plan.md`; requirements are in `PRD.md`.

---

## 1. Testing Philosophy

Five rules govern every test in this repository.

1. **Evidence before assertion.** A claim of "working" is backed by a command and its actual output, never by inspection or intent.
2. **Every published number is reproducible.** Dataset or scenario, command, configuration and output artifact are preserved together. A number without its artifact does not reach the deck, the README or Q&A.
3. **Contracts are tested, not trusted.** Schema drift, feature-order drift and route drift each have a test that fails loudly.
4. **Missing evidence is a test case.** A detector that cannot see something must produce `DEGRADED` or `NOT_OBSERVABLE` — never a benign result. That behaviour is asserted, not assumed.
5. **Never weaken a test to make it pass.** If a test is wrong, fix the test deliberately and record why in `memory.md`.

Tests are organised by what they prove, not by which file they live next to:

```text
tests/schema/          contract conformance
tests/parity/          offline == streaming
tests/replay/          one fixture per detector class
tests/detectors/       per-detector acceptance
tests/latency/         p50/p95 against the SLO
tests/throughput/      measured rate + resource envelope
tests/boundary/        negative connectivity
tests/capture_loss/    loss visibility
tests/hash_chain/      tamper evidence
tests/ui_load/         render survivability
```

---

## 2. Unit Tests

Cover the deterministic pieces that everything else assumes:

- Feature extractors — entropy, lexical features, n-gram language-model scoring, qtype ratios, packet-size and inter-arrival statistics.
- Bounded sketches — Space-Saving, HyperLogLog, Count-Min, reservoir sampling — including behaviour at their caps.
- Window and watermark mechanics, including out-of-order arrival inside and outside the 300 ms grace.
- The replay clock rebasing formula.
- Canonical serialisation used by the hash chain, including rejection of NaN and Inf.
- `flow_id` and incident-identity derivation for all three `flow_ref_type` values, asserting the frozen form `sha256(canonical_value).hexdigest()[:16]` — exactly 16 lowercase hex characters, matching `^[0-9a-f]{16}$`.
- Deduplication-key canonicalisation with the `NOT_OBSERVABLE` sentinel substituted for unavailable components.
- Address-plan direction inference, including the bogon-set exclusion for declared lab prefixes.

---

## 3. Contract Tests

`tests/schema/` — these fail the build on drift.

Must cover:

- Normalized event schema conformance.
- Alert schema v1.3 conformance.
- `FEATURE_ORDER` — exact tuple, exact order.
- All enum values.
- Required evidence per detector.
- `not_observable` representation.
- **`input_mode` enum:** exactly `pcap_replay | live_tap | ipfix | netflow_v9 | sflow`.
- **Non-null `flow_id` on every emitted alert**, and a valid `flow_ref_type`.
- **Six PS classes to eight detector modules** — every `detector` value maps to exactly one `ps_class`, and the six external class strings match the frozen wording verbatim.
- **qtype features and TLS/QUIC shape features are present** in the feature and evidence contracts.
- Deduplication keys match `config/dedup_keys.yaml`.
- **No non-`GET` route is registered on the Plane B application.**

---

## 4. Feature-Parity Tests

`tests/parity/` — given the same packet fixture:

```text
offline feature extraction == streaming feature extraction
```

Also asserted:

- **Training and inference import the same `FEATURE_ORDER` object.** No component constructs its own ordering.
- **Packet-to-flow normalized-event contract parity** — a PCAP and the flow records exported from that same PCAP produce events on the same contract, differing only in capability state and the fields the exporter did not export.

This is the test that catches the single most expensive class of failure: a model trained on one feature order scoring against another.

---

## 5. Replay / Integration Tests

`tests/replay/` — at least one replay fixture per detector class. Expected alert contracts are stored with the scenario.

Acceptance:

- The same replay produces the same observations (deterministic, seeded).
- Both consumers — Suricata and the fast header counter — see the same replay within declared loss.
- **Packet-count agreement** between what was replayed and what was observed.
- **Alerts stream during the run.** End-of-run-only output fails the test; streaming operation is a graded PS constraint.
- `latency_ms` is populated and measured.
- Ground truth never reaches the dashboard — the live path receives detector output only.

Two scenarios are mandatory:

| Scenario | Purpose |
|---|---|
| Canonical campaign | Integration test, main demo, backup recording, expected-alert contract |
| `BENIGN_STRESS` | False-alerts-per-hour measurement on pure-benign traffic |

---

## 6. Detector Tests

`tests/detectors/` — one acceptance test per module, plus the two PS-named paths that are easy to lose.

| Test | Proves |
|---|---|
| `test_ddos.py` | Rate, baseline delta, SYN behaviour, source count and entropy; a 50 000 pps flood produces **one evolving incident**, not an alert storm |
| `test_reflection.py` | Fan-in, amplifier-port evidence, source entropy; the reserved-source share is computed against external space only and does **not** fire continuously on a private-address lab |
| `test_slowloris.py` | **Low-rate, long-duration fixtures.** Concurrency, duration percentile and bytes/connection detect it; a pps threshold alone does not. The incident fires only when concurrency and duration gates agree |
| `test_scan.py` | Destination and port spread, fan-out, bounded state |
| `test_dga.py` | Lexical and **bigram/trigram** features, NXDOMAIN context, calibration status, model version; hard negatives are not flagged |
| `test_dns_tunnel.py` | Query length and entropy, encoded-character indicators, frequency, **qtype distribution including TXT/NULL/CNAME shares** present in evidence |
| `test_c2.py` | Repeated destination, inter-arrival CV, robust timing statistic, persistence, novelty |
| `test_exfil.py` | Directional bytes, ratio, duration, destination novelty, baseline |
| `test_tls_quic.py` | **JA3, JA3S and JA4 where visible**, destination novelty, and concrete shape fields — `packet_size_first_n`, `direction_first_n`, `iat_median`, `iat_p95`, `iat_cv`, upstream/downstream ratios. **Asserts no decrypted or payload-content field exists anywhere in the alert** |

Each detector test also asserts its **minimum evidence contract**: an alert missing a required evidence field must not be emitted as a normal detection.

---

## 7. Model Evaluation

DGA is the only trained model, and it is evaluated as a model, not as "AI".

Required:

- Time-based holdout.
- Entity-based holdout.
- DGA-family holdout.
- Deduplication **before** splitting.
- TLD stripping where specified.
- Wordlist families represented in evaluation.
- **Hard negatives included** — CDN names, UUID-like identifiers, long API subdomains, telemetry names, software update infrastructure. The objective is to prevent the model learning `random-looking == malicious`.
- Platt calibration, reliability diagram, Brier score.
- Model card.

Never claim generic "AI accuracy". State explicitly that confidence represents evidence strength, not attacker intent.

**Fallback evaluation rule:** if the artifact is unusable and the rule fallback ships, it carries `calibrated: false` and `model_version: "rules-fallback"`, and **no Brier score or reliability diagram is published for it**. A rule score is not a probability.

### Evaluation units

Detector-level and incident-level evaluation are kept separate and reported separately.

- **Detector-level:** a prediction is matched against the ground-truth behaviour interval and entity/context — DGA by domain/query entity and query interval; scan by source plus target/port spread interval; DDoS by source/destination context and flood interval; C2 by source, destination and repeated-flow interval.
- **Incident-level:** after hysteresis and deduplication, the resulting incident is evaluated as one operational detection.

```text
1,842 anomalous windows
        ↓
17 candidate alerts
        ↓
1 deduplicated incident      counts as ONE predicted incident
```

The evaluation report must state the matching key/entity, the time-overlap rule, the minimum overlap or tolerance, how duplicates are collapsed, and how simultaneous classes are handled. This prevents inflated recall from repeated windows and inflated false-positive counts from alert storms.

### Baseline comparison

Compare three things: the implemented system, static thresholds, and stock signature rules where the comparison is meaningful. **Concede where rules perform better.** The statistical and ML layer exists to cover behaviour where signatures do not.

---

## 8. False-Positive Tests

Run the `BENIGN_STRESS` replay and measure **false alerts per hour**.

The scenario deliberately resembles suspicious behaviour without being malicious: high-volume legitimate DNS, long and large legitimate transfers, TLS-heavy traffic, legitimate periodic polling, many short-lived connections, legitimate port and destination diversity, and long or machine-generated but benign domain names.

Acceptance:

```text
BENIGN_STRESS
     ↓
low/acceptable false-alert rate
     ↓
no critical incident unless the evidence contract is genuinely met
```

This measurement is mandatory. The false-alert number reported in Q&A is this number, not an estimate.

---

## 9. Latency Tests

`tests/latency/` — measure, never estimate.

- `latency_ms` measures `t_observed` to `t_websocket_emit`.
- Report **p50 and p95** against the declared SLO of **p95 < 2.0 s**.
- Show the budget alongside: 300 ms watermark, ~1.0 s window, ~100 ms scoring and dedup, 250 ms batch push, structural floor ~1.6 s.

If p95 exceeds the SLO, the fix order is batch push interval, then window size, then detector cost. **A test run that "improves" latency by shrinking the watermark is a failed run** — it trades a visible number for silently dropped late packets.

---

## 10. Throughput Tests

`tests/throughput/` — sustained over a 60 s replay.

Publish in PS order: **flows/sec first**, then Mbps, then pps.

| Metric | Target | Role |
|---|---|---|
| Sustained normalized flows/sec | **at least 1 000**, sustained 60 s | **Primary PS KPI — publish first** |
| pps | at least 50 000, sustained 60 s | Secondary system metric |
| Mbps | at least 400, sustained 60 s | Secondary system metric |
| Capture loss at every target above | below 1 % | Acceptance ceiling |

**Metric-separation rule.** Flows/sec, pps and Mbps are three independent measurements, each measured and published on its own. **Never derive one from another** — a flows/sec figure computed from a pps figure is not a measurement and must not be published.

Rules:

- **Always publish the box specification beside the number** — CPU, RAM, NIC, kernel version. The figure is meaningless without it.
- **Never extrapolate** toward 10 Gbps or any unmeasured rate. Report the measured rate and where the prototype breaks.
- If the target is not met, publish the number actually achieved together with the loss at that rate.
- **WSL2 is not acceptable** for the published number — the capture path differs and the figure will be challenged.
- Optimise until the target is met, then stop. Throughput work is a known time sink.

### Resource and operating-envelope measurement

Captured alongside every throughput result: packets/sec, flows/sec, events/sec, Mbps, p50/p95 latency, CPU utilisation, RAM utilisation, active flow-state count, detector-state memory, WebSocket queue depth, SQLite write/commit rate, capture-loss percentage, kernel and ring drops.

Optional if time permits — a throughput-vs-loss sweep across multiple replay rates, producing a **measured operating envelope**. Do not extrapolate beyond the measured hardware and configuration.

---

## 11. Boundary / Negative Connectivity Tests

`tests/boundary/` — scripted and repeatable. Assert **all three**:

```text
monitor -> external internet      blocked
monitor -> attacker-side veth     blocked
monitor -> monitored enclave      no route present
```

While the test runs, **alerts must continue to flow** through the monitoring pipeline — that is what makes it a proof rather than a disconnection.

Archive the output as `artifacts/boundary_test_<timestamp>.txt` and include it in the export bundle. The proof must survive outside the live demo moment; if venue networking misbehaves during the run, the artifact still exists.

### No-decryption test

Assert that no decrypted or payload-content field exists in the sensor field allowlist, the normalized event contract, or the alert schema. The constraint is enforced structurally — there is no field capable of carrying payload content — so the test asserts absence, not restraint.

---

## 12. Capture-Loss Tests

`tests/capture_loss/` — loss is surfaced as evidence, never hidden.

Assert:

- `stats.kernel_drops` is present (the sensor probe requires it).
- `sensor_drop_pct` is computed and reaches the alert and the evidence drawer.
- Ring-buffer counters, TCP sequence gaps and packet-count comparison are recorded.
- Where only one estimator is available, the value is **labelled a lower bound**. No more precise number is invented.

---

## 13. Hash-Chain Verification

`tests/hash_chain/verify_hash_chain.py`.

- Runs **in a clean process against the exported JSON only**, with no import of writer runtime state.
- Must not reimplement the concatenation rule — it imports it from `alerts/hash_chain.py`.
- Verifies `seq` monotonicity across the whole store, `prev_hash` linkage, and `entry_hash` for every entry, from the genesis `"0" * 64`.

**Tamper demonstration** (also a demo beat): export incidents, modify one exported record, run the verifier.

```text
verify_hash_chain
      ↓
FAIL
      ↓
entry N modified
```

The claim tested is precise: post-hoc modification is **detectable**. The chain is tamper-evident; it is not a claim that storage is immutable.

---

## 14. UI Load Tests

`tests/ui_load/` — a synthetic **50 000-alert burst**.

**This harness deliberately bypasses deduplication.** It stresses the render path only.

It does **not** contradict the demo claim that a 50 000 pps flood produces one incident — that claim concerns the detector path, which sits upstream of this injection point. State the distinction if a judge watches the test run.

Acceptance:

- The page remains interactive.
- Memory remains bounded.
- The incident feed does not grow without limit (500-item client ring buffer holds).

### Flood survivability

Replay a flood with concurrent SYN, DNS and TLS handshake events. Confirm **all expected event categories survive** — a flood must not starve the DNS or TLS paths that other detectors depend on.

---

## 15. Export Tests

- JSON and CSV export succeed **mid-run**, while replay is still in progress. The report is a view over a continuously written store, not a batch job.
- CSV is one row per **incident**, not per evidence item: `evidence.<key>` scalar columns plus a single `evidence_json` column.
- JSON is lossless and canonical; where JSON and CSV disagree, JSON wins.
- The hash chain is computed over the **JSON form only**, and export carries `seq`, `prev_hash` and `entry_hash` for every entry.

---

## 16. Cold-Boot Test

Boot the complete stack on a **second machine that has never run the project**, with **networking disabled**.

Acceptance:

- Every dependency resolves from the vendored offline bundle — Python wheels, Node dependencies, Suricata, GeoLite2 and TopoJSON if the map is retained, intel bundle, model artifact, PCAPs, flow-record fixtures, scenario manifests.
- The offline asset audit passes — an explicit grep for any runtime network or internet dependency returns nothing.
- The system reaches a working dashboard with no internet access at any point.

---

## 17. Flow-Record Tests

At least one known-good **NetFlow v9** fixture and one **IPFIX** fixture.

Acceptance:

- Templates decode correctly.
- Records normalise to the common event contract.
- **Template handling and refresh** work for both protocols.
- **Malformed, missing or expired templates do not exhaust state** — the shared cache stays bounded under an attacker-controlled template stream.
- `input_mode` is set to `ipfix` or `netflow_v9`; exporter/template identity and sampling metadata are preserved.
- **Capability degradation is correct** — DNS-name and TLS-fingerprint detectors report `NOT_OBSERVABLE`, while flow-based detectors continue where their required fields are present.
- sFlow input surfaces sampling state, and packet-order-sensitive detectors degrade accordingly.

---

## 18. Sensor Failure, Restart and Recovery Tests

### Controlled failure

Fail each of: Suricata/EVE input, normalizer, detector process, API, WebSocket connection.

Acceptance:

- Health state changes to `DEGRADED` or `UNAVAILABLE`.
- **No false healthy state is shown.**
- Buffered and persisted incidents remain consistent.
- WebSocket clients can reconnect.
- API `GET` endpoints remain authoritative after reconnect.
- Restart does not silently erase persisted incident history.

### Restart / state recovery

Restart the stack during or immediately after replay.

Acceptance:

- SQLite history remains readable.
- Incident sequence and hash-chain state resume correctly.
- **No duplicate incident is created solely by restart.**
- Capability state is recomputed.
- The UI clearly indicates replay or session restart where relevant.

---

## 19. Demo Acceptance Test

The canonical campaign replay, run end to end, is itself an acceptance test. It must produce, in order: scan, beaconing, DGA burst, DNS tunnel, exfiltration, suspicious TLS/QUIC session, DDoS/flood — with evidence, capability state and a verifiable hash chain, and with an IPFIX input-mode switch that visibly degrades the packet-dependent capabilities.

If the campaign replay is not green, the demo is not ready, regardless of what individual tests say.

---

## 20. Test Commands

Commands are recorded here as they are implemented, so that every published number can be regenerated by copying a line. Each entry carries its dataset, configuration and output artifact path.

```text
# Contract tests
# Feature parity
# Replay per class
# Canonical campaign
# BENIGN_STRESS false-alert rate
# Latency p50/p95
# Throughput + resource envelope
# Boundary / negative connectivity
# Flow-record fixtures (NetFlow v9, IPFIX)
# Hash-chain verify
# UI load burst
# Cold boot
```

**Status: not yet populated — no implementation exists.** Every line is filled in as its phase lands, and a number that cannot be regenerated from a line here is not published.

---

## 21. Definition of Done

The verification layer is complete when all of the following pass and their artifacts exist. Owners and gate hours are in `implementation_plan.md`.

- [ ] Schema compatibility, `FEATURE_ORDER` parity, enum and route contract tests pass.
- [ ] Replay runs through the same interface for both consumers, with packet-count agreement.
- [ ] Alerts stream during the run rather than at end-of-run only.
- [ ] `latency_ms` is populated; p50 and p95 measured against the 2.0 s SLO.
- [ ] Throughput meets at least 1 000 normalized flows/sec sustained 60 s at below 1 % loss, with pps and Mbps measured separately against their own targets, and the box specification published beside all three.
- [ ] No connectivity across the monitored boundary; output archived as an artifact.
- [ ] No payload decryption — asserted structurally across allowlist, event contract and alert schema.
- [ ] Bounded memory under sustained flood, including template and flow state.
- [ ] 50 000-alert UI burst survived; feed and memory bounded.
- [ ] Hash-chain integrity verified from a clean process; tamper demonstration produces a detectable failure.
- [ ] JSON and CSV export succeed during replay.
- [ ] Cold boot passes on a second machine with networking disabled; offline asset audit passes.
- [ ] NetFlow v9 and IPFIX template handling and refresh verified; malformed and expired templates stay bounded.
- [ ] Packet-to-flow normalized-event contract parity verified.
- [ ] Every emitted alert carries a non-null `flow_id` and a correct `flow_ref_type` for flow, aggregate and entity incidents.
- [ ] DNS qtype distribution and TXT/NULL/CNAME evidence present where visible.
- [ ] Slowloris detected on low-rate, long-duration fixtures via concurrency, duration and bytes-per-connection.
- [ ] JA3S extraction and evidence verified.
- [ ] DGA bigram/trigram feature parity verified; hard-negative evaluation included.
- [ ] Concrete TLS/QUIC packet-size, direction and IAT features extracted and present in evidence.
- [ ] Capability degradation correct for IPFIX, NetFlow v9 and sFlow inputs.
- [ ] Detector-level and incident-level evaluation rules documented and reproducible.
- [ ] `BENIGN_STRESS` false-alert rate measured.
- [ ] Sensor failure, restart and recovery tests pass with no false healthy state.
- [ ] Every published number has a recorded dataset, command, configuration and artifact.
