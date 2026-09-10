# Implementation Plan

**Project:** Cyber Sentinel — PS26145
**Derived from:** `FINAL_DEVELOPMENT_PLAN_V6.3.md` sections 29–40, 45–46
**Architecture:** `design.md` · **Requirements:** `PRD.md` · **Verification:** `testing.md`

This is the long-lived execution roadmap: **what gets built, in what order, and what proves each phase is done.** It is not a scratchpad. Immediate work lives in `task_today.md`; current completion state lives in `STATUS.md`.

Ownership codes: **P1** = Sensor / Infrastructure, **P2** = Detection / ML, **P3** = UI / UX, **P4** = Backend / API / Integration. Ownership detail is in `agents.md`.

Legacy codes in `FINAL_DEVELOPMENT_PLAN_V6.3.md` section 39 map as `A → P1`, `B → P2`, `C → P3 + P4`. V6.3 is the implementation source of truth and is not edited to match the split.

---

## 1. Build Strategy

> **Build the spine before the brains.**

The first development action is not a detector. It is the contracts and the first end-to-end replay:

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

When that path works, the project has a spine. Then add the brains.

Three strategy rules govern the whole build:

- **Gate-driven.** Each gate has a binary exit criterion. A failed gate stops new feature work until it is green.
- **Tiered.** Tier 0 must work before serious Tier 1 work begins. Tier 2 is cut before any Tier 0 or Tier 1 capability.
- **Fallback-first.** Every risky component ships with a documented fallback before it is attempted, so a failure is a downgrade rather than a hole.

### Tier definitions

**Tier 0 — must work:** isolated lab → PCAP replay → veth/passive capture → fast header counter + Suricata → EVE normalizer → capability state → window features/bounded state → DDoS + scan + DGA → frozen alert schema → deduplication/lifecycle → FastAPI/WebSocket → dashboard.

**Tier 1 — strong differentiators:** DNS tunnel detector; C2 beaconing; exfiltration; TLS/QUIC metadata detector; evidence drawer; baseline comparison; calibration; hash chain; capability/health banner; read-only proof.

**Tier 2 — stretch, first to cut:** threat map; PDF export; clock-servo Kalman; Lomb-Scargle; sophisticated fusion/correlation; Scenario Console visual polish; additional model training.

**Never sacrifice Tier 0 for Tier 2.**

---

## 2. Dependencies

### Decided before the window opens

- **OS/box.** Native Linux preferred, full VM acceptable. **WSL2 is not acceptable for the published throughput number** — the capture path differs and the figure will be challenged. The box used for the published number is chosen in advance and its specification recorded.
- **DGA model artifact** pre-built and vendored into `models/artifact`. In-window training is a refresh, not a dependency.
- **Offline asset bundle** staged: Python wheels, Node dependencies, Suricata package/build, GeoLite2 and TopoJSON if the map is retained, intel bundle, model artifact, all test PCAPs, flow-record fixtures, scenario manifests.

### Build-order dependencies

```text
Contracts (schemas + FEATURE_ORDER)      FROZEN — Phase 0 complete
        ↓ blocks everything
Replay harness + veth lab                P1
        ↓ blocks P1 and P2
Normalizer + capability state            P1
        ↓ blocks detectors and dashboard evidence
Feature service                          P1 windows / P2 features
        ↓ blocks detectors and model inference
Detectors                                P2
        ↓ blocks dedup/lifecycle
Dedup (P2) / lifecycle integration (P4)
        ↓ blocks persistence, export, hash chain
```

**The sensor spine is blocking until the Hour-6 gate.**

Two tracks are deliberately decoupled from it and must never be idle waiting:

- **P3 develops against mock fixtures generated from the frozen schemas** — never against a running backend. See `agents.md` section 8. Swapping fixtures for the live WebSocket must be a transport change only.
- **P2 develops against the deterministic synthetic event generator** before P1's live capture lands.

All six shared contracts are already frozen, so no track is blocked on contract negotiation.

---

## 3. Phase 0 — Foundation

### Phase 0 — Hours 0–1, all four together
**Status:** NOT_STARTED
**Owner:** P1 + P2 + P3 + P4 together

**Objective:** Freeze every shared contract and prove the environment before any track diverges.

**Dependencies:** OS/box decision made before the window opens.

**Tasks:**
- Freeze the normalized event schema.
- Freeze alert schema v1.3.
- Freeze `FEATURE_ORDER`.
- Create the repository skeleton.
- Seed `config/thresholds.yaml` with starting values (see section 12).
- Freeze `config/dedup_keys.yaml` and `config/address_plan.yaml`.
- Agree branch rules (`git.md`).
- Suricata build and capability check; JA3/JA3S/JA4 verdict recorded.
- Build the isolated veth lab; set egress DROP.
- Apply the four frozen Phase 0 decisions recorded in section 13 (throughput target, identifier form, dedup sentinel, test directories).
- Create `tests/detectors/` and `tests/throughput/` alongside the existing test subtree.

**Output:** `schemas/`, `features/feature_order.py`, `config/*.yaml`, `tests/schema/`, capability probe report, lab with no egress.

**Exit criterion (Hour-1 gate):** Contract tests exist and pass. The JA3/JA3S/JA4 capability result is recorded. The lab interface has no route and no egress.

**Fallback:** None. This gate is not optional; a slipped Phase 0 costs more later than it saves now.

---

## 4. P1 — Sensor / Infrastructure

### P1-1 Transport and Clock — Hours 1–6
**Status:** NOT_STARTED
**Owner:** P1

**Objective:** One PCAP becomes normalized events through both capture paths on a single clock.

**Dependencies:** Phase 0 contracts; veth lab.

**Tasks:**
- tcpreplay driver with replay speed control.
- veth pair / one-way enclave.
- **Unified replay clock** — `t_replay_start` captured once, written to the manifest.
- Header-only packet counter.
- Suricata EVE tail with partial-line handling.
- Normalizer producing contract-valid events.
- Bounded flow tracker producing `flow_summary`.
- Capture-loss fields.
- Load `config/address_plan.yaml`; populate `direction` on real events.

**Output:** `ingest/` transport, clock, header counter, EVE tail, normalizer, flow tracker, capture loss.

**Exit criterion:** Both consumers see the same replay within declared loss; one real PCAP becomes contract-valid normalized events; `direction` is populated.

**Fallback:** Synthetic generator in place of real PCAP replay (kill ladder 11).

---

### P1-2 Windowing and State — Hours 6–10
**Status:** NOT_STARTED
**Owner:** P1

**Objective:** Bounded streaming state that detectors can rely on.

**Dependencies:** P1-1.

**Tasks:**
- Rolling tumbling/sliding windows with the 300 ms watermark.
- Bounded sketches — Space-Saving, HyperLogLog, Count-Min, reservoir sampling.
- Entropy estimators.
- Baseline snapshot **loading** at boot — so there is no cold start and detection is live from the first window. **Generation of the snapshot is P2's** (P2-1); P1 loads what P2 produces.
- `latency_ms` field populated end to end.

**Output:** `features/rolling.py`, `features/sketches.py`, `features/entropy.py`, baseline snapshot loader.

**Exit criterion:** Windows close on schedule, state stays bounded under flood, `latency_ms` is measured rather than estimated.

**Fallback:** Fixed 300 ms watermark if the clock servo is not ready (kill ladder 4).

---

### P1-3 Integrity and Measurement — Hours 10–16
**Status:** NOT_STARTED
**Owner:** P1

**Objective:** Every claim the demo makes about throughput, loss and integrity is measured and reproducible.

**Dependencies:** P1-2; alert emission from P2.

**Tasks:**
- Throughput harness and measurement.
- Threshold sweep harness.
- Read-only negative-connectivity test, output archived as an artifact.
- Sequence-gap and capture-loss reporting.
- Provenance recording — dataset, command, configuration, artifact.

> **Hash chain is P4's** (confirmed ownership, `agents.md` section 7). Writer and verifier are built together in P4-2. P1 supplies the measurement provenance the chain records; it does not implement the chain.

**Output:** benchmark report, `artifacts/boundary_test_<timestamp>.txt`, threshold sweep artifacts.

**Exit criterion:** Throughput measured with the box specification beside it (at least 1 000 normalized flows/sec sustained 60 s at below 1 % loss); boundary test passes and is archived.

**Fallback:** Raw `kernel_drops` lower bound if capture-loss Kalman is not ready (kill ladder 5).

---

### P1-4 Hardening — Hours 16–19
**Status:** NOT_STARTED
**Owner:** P1

**Objective:** The system survives a cold machine, a disabled network and an audit.

**Dependencies:** P1-3.

**Tasks:**
- Switch Scenario Console to REPLAY mode; make GENERATE unreachable outside the build machine.
- PCAP hash audit.
- **Cold boot on a second machine with networking disabled**, and the **offline asset audit** — confirmed P1 ownership. Every dependency must resolve from the vendored bundle.

> The **hash-chain tamper demonstration artifact** is P4's, produced in P4-4 from the chain P4 owns. P1 provides the cold-boot environment it is demonstrated on.

**Output:** cold-boot result, offline asset-audit result, PCAP hash audit.

**Exit criterion:** Second-machine cold boot passes with networking disabled; every asset resolves offline.

**Fallback:** None — this is the insurance policy for the demo itself.

---

### P1-5 Flow Record Ingestion — Hours 6–13
**Status:** NOT_STARTED
**Owner:** P1

**Objective:** NetFlow v9 and IPFIX are a real passive input path, not a slide.

**Dependencies:** P1-1 normalizer and event contract.

**This phase is not optional.** It must be complete and tested by the Hour-13 gate, and the normalisation contract with capability degradation is on the never-cut list.

**Tasks:**
- NetFlow v9 parser.
- IPFIX v10 parser.
- **One shared template cache** used by both — not two independent parsers.
- Bounded template state with expiry, resistant to malformed or attacker-controlled template streams.
- Normalized flow events on the same contract as PCAP/EVE.
- `input_mode` set to `ipfix` or `netflow_v9`; exporter/template identity and sampling metadata preserved.
- Flow-record fixtures — one known-good per protocol — exported at build time from project PCAPs using `yaf`, `nfpcapd` or `softflowd`, then vendored offline.
- Detector-specific capability degradation.
- Packet-vs-flow feature parity tests.

**Output:** `ingest/flow_record_adapter.py`, `scenarios/flow_records/ipfix/`, `scenarios/flow_records/netflow_v9/`, capability report.

**Exit criterion:** Both fixture types produce contract-valid normalized events; malformed and expired templates remain bounded; an IPFIX replay visibly degrades DNS/TLS-specific capabilities while flow-based detectors continue where required fields are present.

**Fallback:** None. This is a never-cut item.

---

## 5. P2 — Detection / ML

### P2-1 Ground Truth — Hours 1–6
**Status:** NOT_STARTED
**Owner:** P2

**Objective:** Reproducible corpora and manifests exist before any detector is tuned against them.

**Dependencies:** Phase 0 contracts.

**Tasks:**
- Deterministic synthetic event generator.
- Attack and benign corpora.
- Scenario manifests with logged seeds.
- DGA corpus **including hard negatives** — CDN names, UUID-like identifiers, long API subdomains, telemetry names, software update infrastructure.
- Holdout definitions: time, entity, DGA family.
- **Ticket 0 — PCAP generation**, run in the background during hours 1–6 inside the veth lab, mapped to the PS-named generation sources:

| PS-named source | Project fixture use |
|---|---|
| `iperf3` | Benign throughput and large-transfer traffic |
| Ostinato | Benign packet/port-diversity fixtures where available |
| TRex | Optional high-rate benign stress generation |
| `hping3` | Isolated SYN/UDP flood fixtures |
| Slowloris | Isolated low-rate HTTP exhaustion fixture |
| `dnscat2` / `iodine` | DNS-tunnel fixture coverage |
| DGArchive | **Not** a runtime or download dependency; published DGA families reimplemented locally for deterministic positives |
| Sandboxed C2 emulator | Deterministic beacon fixture |

Where a PS-named source is not used directly, the substitution is recorded in `README.md` and the scenario manifest.

Also owned here (confirmed ownership, `agents.md` section 7):

- **Baseline snapshot generation** from the benign corpus. P1 loads it at boot in P1-2; capped updates and an immutable long-term reference snapshot live in the offline intel bundle.
- **Offline intelligence bundle and version manifest** — allowlists, SSLBL JA3 data if used, DGA family data, Tranco list, baseline snapshot, explainer text, recommendations, GeoLite2 if the map is retained, and `intel/version_manifest.json`. Every relevant alert and report carries the bundle and model version. P1 stages it into the offline asset bundle; P2 owns its contents.

**Output:** corpora, manifests, seed log, hashed PCAP set, `BENIGN_STRESS` scenario, canonical campaign scenario, `intel/baseline_snapshot.json`, `intel/version_manifest.json`.

**Exit criterion:** The attack PCAP set is complete, hashed and manifested at the Hour-6 gate. **Generation stops there** — after Hour 6 the lab is replay-only.

**Fallback:** Synthetic generator coverage for any fixture that cannot be produced in time.

---

### P2-2 First Detectors — Hours 1–10
**Status:** NOT_STARTED
**Owner:** P2

**Objective:** The three Tier 0 detectors produce real alerts with real evidence.

**Dependencies:** P2-1 corpora; P1-1 normalizer; P1-2 windows.

**Tasks:**
- Initial DDoS logic — robust z-score, median/MAD, hysteresis `N=2`, hard gates.
- Reflection / spoofed-source detector, with the reserved-source share computed against **external** space only.
- Scan detector — unique destination/port spread, windowed source behaviour, bounded state.
- DNS feature extraction.
- DGA model integration and Platt calibration.

**Output:** `detectors/ddos.py`, `detectors/reflection.py`, `detectors/scan.py`, `detectors/dga.py`, calibrated model.

**Exit criterion (Hour-10 gate):** At least one real alert from a real PCAP, with populated evidence, correct `latency_ms`, concurrency test passed, and a UI that stays responsive under flood.

**Fallback:** DGA lexical + entropy + NXDOMAIN rule fallback with `calibrated: false` (kill ladder 12).

---

### P2-3 Temporal and Correlation Detectors — Hours 10–16
**Status:** NOT_STARTED
**Owner:** P2

**Objective:** The remaining Tier 1 detector families.

**Dependencies:** P2-2; Hour-12 integration checkpoint green.

**Tasks:**
- Beaconing — CV plus median/MAD.
- Exfiltration — per-entity outbound behaviour and baseline comparison.
- Deduplication against the frozen keys.
- Incident lifecycle `NEW → ACTIVE → UPDATED → RESOLVED`.

**Output:** `detectors/c2.py`, `detectors/exfil.py`, `alerts/deduplicator`, `alerts/lifecycle`.

**Exit criterion:** A 50 000 pps flood produces one evolving incident, not an alert storm.

**Fallback:** Lomb-Scargle dropped in favour of CV + MAD (kill ladder 6); fusion dropped in favour of separate alerts plus dedup (kill ladder 7) — **dedup itself is never dropped**.

---

### P2-4 Evidence and Evaluation — Hours 10–16
**Status:** NOT_STARTED
**Owner:** P2

**Objective:** Every published number is reproducible and every alert explains itself.

**Dependencies:** P2-2, P2-3.

**Tasks:**
- Minimum-evidence enforcement per detector.
- Detector-level and incident-level evaluation units with matching, overlap and deduplication rules.
- Benign stress replay and false-alerts-per-hour measurement.
- DGA hard-negative evaluation, reliability diagram, Brier score.
- Threshold sweeps with artifacts.
- Baseline comparison: implemented system vs static thresholds vs stock signature rules.
- **Model card** (`models/model_card.md`) and the **evaluation report** — confirmed P2 ownership. The model card states exactly one trained ML model and identifies every non-ML detector.

**Output:** evaluation harness, evaluation report, `docs/threshold_sweep/`, `models/model_card.md`.

**Exit criterion:** One command evaluates the canonical campaign and `BENIGN_STRESS` and emits reproducible metrics.

**Fallback:** LightGBM `pred_contrib` or evidence templates if SHAP is not ready (kill ladder 8).

---

### P2-5 PS Alignment Detectors — Hours 10–16
**Status:** NOT_STARTED
**Owner:** P2

**Objective:** The PS-named features that V6.3 restored are real code paths, not documentation claims.

**Dependencies:** P2-2; feature service.

**Tasks:**
- **Slowloris** low-rate exhaustion path inside `ddos.py` — half-open concurrency, connection-duration percentile, bytes per connection, low-rate evidence, destination/service baseline. Fires only when the concurrency and duration gates agree.
- **DNS qtype distribution and anomaly features** — TXT / NULL / CNAME shares and qtype entropy, exposed in the evidence drawer.
- **DGA bigram/trigram language-model features** trained from the benign Tranco-derived corpus, with explicit provenance.
- **JA3S** carried through the normalized event, evidence, capability and alert contracts.
- **TLS/QUIC packet-size, direction and timing shape** — `packet_size_first_n`, `direction_first_n`, `iat_median`, `iat_p95`, `iat_cv`, `upstream_packet_ratio`, `downstream_packet_ratio`.

**Output:** `detectors/dns.py`, `detectors/tls_quic.py`, Slowloris path inside `detectors/ddos.py`, extended `FEATURE_ORDER` coverage.

**Exit criterion:** Slowloris is independently exercised with low-rate, long-duration fixtures; DNS tunnel evidence carries the qtype distribution; TLS/QUIC evidence carries JA3S and concrete shape fields where visible.

**Fallback:** Slowloris duration/shape refinement dropped, concurrency + duration + bytes-per-connection detector retained (kill ladder 9). TLS/QUIC shape refinement dropped, JA3 + JA3S + intel + destination novelty retained (kill ladder 10). **Neither detector is removed.**

---

## 6. P3 — UI / UX

**P3 never waits for P4.** Every phase below is reachable with mock fixtures generated from the frozen schemas.

### P3-1 Mock-Driven Shell — Hours 1–6
**Status:** NOT_STARTED
**Owner:** P3

**Objective:** The dashboard renders incidents end to end with no backend running.

**Dependencies:** the frozen `schemas/alert.schema.json`. **Not P4.**

**Tasks:**
- React/Vite skeleton.
- **Generate mock fixtures from the frozen alert schema** into `scenarios/mock_fixtures/` — covering all six `ps_class` values, all three `flow_ref_type` values, all four `score_type` values with `calibrated` both true and false, `confidence: null`, all three capability states, a `DEGRADED` IPFIX input mode, and a `dedup_key` carrying the `NOT_OBSERVABLE` sentinel.
- Fixture schema-validity check, so P3 cannot build against a shape the backend will never send.
- Incident feed.
- LIVE/REPLAY badge.
- Fixture-driven local dev loop.

**Output:** `dashboard/` skeleton, `scenarios/mock_fixtures/`.

**Exit criterion:** The UI renders a contract-valid incident end to end from fixtures alone, with no API process running.

**Fallback:** None — this is Tier 0.

---

### P3-2 Render Survivability — Hours 6–10
**Status:** NOT_STARTED
**Owner:** P3

**Objective:** The interface does not become the bottleneck the demo trips over.

**Dependencies:** P3-1. Push cadence is P4's (see P4-1); everything after arrival is P3's.

**Tasks:**
- 500-item client ring buffer.
- List virtualisation.
- `requestAnimationFrame` counters.
- Evidence drawer.
- Single CSS severity accent variable.

**Output:** hardened dashboard render path.

**Exit criterion (part of Hour-10 gate):** The UI remains responsive under flood; memory stays bounded.

**Fallback:** None — Tier 0.

---

### P3-3 Operator Surfaces — Hours 10–16
**Status:** NOT_STARTED
**Owner:** P3

**Objective:** Everything an operator and a judge need to see is on screen.

**Dependencies:** P3-2; fixtures cover every state, so this does not block on live alerts.

**Tasks:**
- Capability and health banner; visibility/limitations panel.
- **PS-required alert fields rendered:** timestamp, `flow_id`, threat class, confidence, evidence.
- **Confidence presentation** — a percent sign only where `calibrated: true`; uncalibrated output labelled a risk/anomaly score, never a probability.
- **`NOT_OBSERVABLE` presentation** — visibly distinct from "nothing suspicious".
- Threat-class views using the six PS class strings verbatim.
- Counters and charts.
- History view; low-confidence tab; top talkers.
- Export operator surface (endpoints are P4's).
- Advisory panel — advisory text only, no action path.
- Replay controls.
- TLS/QUIC suspicion/anomaly wording, never malware identification.

**Output:** complete operator dashboard.

**Exit criterion:** Evidence drawer contains real observed values; baseline comparison is visible; `NOT_OBSERVABLE` renders visibly.

**Fallback:** PDF export dropped in favour of JSON/CSV (kill ladder 2).

---

### P3-4 Polish and Proof — Hours 16–19
**Status:** NOT_STARTED
**Owner:** P3

**Objective:** The demo is legible and the backup exists.

**Dependencies:** P3-3; Hour-16 gate pass.

**Tasks:**
- Campaign-mode demo sequence.
- Severity palette review.
- **Screenshots** — confirmed P3 ownership.
- UI load test (50 000-alert synthetic burst — deliberately bypasses deduplication; stresses the render path only).
- **Backup recording, made immediately on Hour-16 gate pass** — confirmed P3 ownership. Re-record after H19 if the run improved; keep both files.
- Threat map **only if all core gates are green**.

**Output:** backup video, screenshots, load-test result.

**Exit criterion:** A complete run exists on video and the page survives the burst.

**Fallback:** Threat map cut entirely (kill ladder 1).

---

## 6A. P4 — Backend / API / Integration

**P4 owns the seam.** Its primary product is that the other three tracks fit together.

### P4-1 API and Transport — Hours 1–6
**Status:** NOT_STARTED
**Owner:** P4

**Objective:** A read-only Plane B surface exists that P3 can point at the moment it is ready.

**Dependencies:** the frozen `schemas/alert.schema.json`.

**Tasks:**
- FastAPI application — **`GET` and WebSocket only**.
- Route contract test asserting **no non-`GET` route is registered** on Plane B.
- WebSocket transport with **250 ms batched pushes**.
- Route contract frozen before P3 switches off fixtures.
- Confirm P3's fixture set for contract fidelity (one review, then P3 regenerates freely).

**Output:** `api/main.py`, `api/websocket`, route contract test.

**Exit criterion:** `GET /health` and `GET /capabilities` respond; the route contract test passes; the WebSocket delivers a batched fixture stream.

**Fallback:** None — Tier 0.

---

### P4-2 Persistence and Lifecycle Integration — Hours 6–12
**Status:** NOT_STARTED
**Owner:** P4

**Objective:** Alerts become durable, deduplicated incidents with a verifiable chain.

**Dependencies:** P4-1; P2's dedup keys and alert emission.

**Tasks:**
- SQLite persistence — incidents, updates, evidence, timestamps, chain metadata, scenario/replay metadata.
- Alert persistence, written **continuously** — the report is a view over the store, never a batch job.
- **Incident lifecycle integration** — `NEW → ACTIVE → UPDATED → RESOLVED`, monotonic `seq` across the whole store.
- Hash-chain writer **and** verifier, built in the same ticket against the frozen spec; the verifier imports the concatenation rule rather than reimplementing it.
- `GET /incidents`, `GET /incidents/{id}`, `GET /export/json`, `GET /export/csv`.

**Output:** `api/persistence`, `alerts/lifecycle`, `alerts/hash_chain.py`, `tests/hash_chain/verify_hash_chain.py`.

**Exit criterion:** Incidents persist and survive a restart with no duplicate created by restart alone; the chain verifies from a clean process.

**Fallback:** PDF export dropped; JSON/CSV retained (kill ladder 2).

---

### P4-3 End-to-End Integration — Hours 10–16
**Status:** NOT_STARTED
**Owner:** P4

**Objective:** Sensor, detection and backend run as one pipeline. **P4 owns the Hour-12 checkpoint.**

**Dependencies:** P1-1/P1-2, P2-2, P4-2.

**Tasks:**
- Wire P1's normalized events through P2's detectors into P4's store.
- Backend orchestration and process supervision.
- Measure `latency_ms` end to end — `t_observed` to `t_websocket_emit`, **measured, never estimated**.
- Surface P1's capability state and capture-loss data through the API.
- Cut P3 over from fixtures to the live WebSocket — a transport change only.
- API and integration tests.

**Output:** running end-to-end pipeline, `tests/latency/`, integration test suite.

**Exit criterion (Hour-12 checkpoint):** replay → sensor → normalizer → features → DDoS/scan/DGA → lifecycle → SQLite → WebSocket → dashboard evidence, all green. **If not green, detector expansion stops.**

**Fallback:** None — this is the checkpoint the rest of the build depends on.

---

### P4-4 Integration Hardening — Hours 16–19
**Status:** NOT_STARTED
**Owner:** P4

**Objective:** The pipeline degrades honestly and recovers cleanly.

**Dependencies:** P4-3.

**Tasks:**
- Sensor / normalizer / detector / API / WebSocket failure simulation — health moves to `DEGRADED` or `UNAVAILABLE`, **never a false healthy state**.
- Restart and state recovery — history readable, chain resumes, no duplicate incident from restart alone, capability state recomputed.
- WebSocket reconnect; `GET` endpoints authoritative after reconnect.
- Export verified mid-run, during replay.
- **Hash-chain tamper demonstration artifact** — confirmed P4 ownership, following the chain itself. Export incidents, modify one exported record, run the verifier from a clean process, capture the failure on entry N. The claim is precise: post-hoc modification is *detectable*; the chain is tamper-evident, not a claim that storage is immutable.

**Output:** failure/recovery test results, hash-chain tamper demonstration artifact.

**Exit criterion:** Every failure mode surfaces to the operator, persisted history stays consistent, and the tamper demonstration produces a detectable, reproducible failure.

**Fallback:** None — this is Tier 1 proof the demo depends on.

---

## 7. Cross-Track Integration

Six shared contracts bind the four tracks. **All are already frozen** and change only through the contract-change procedure in `git.md` section 6.

| Interface | Contract owner | Consumers |
|---|---|---|
| Normalized event contract | P1 | P2, P4 |
| Alert schema v1.3 | P2 | P1, P3, P4 |
| `FEATURE_ORDER` | P2 | P2 training, P2 inference, P1 parity tests |
| `config/dedup_keys.yaml` | P2 | P2 dedup, P4 lifecycle |
| `config/address_plan.yaml` | P1 | P1 normalizer, P2 detectors, P3 map |
| `config/thresholds.yaml` | P2 | All. Latency block co-owned P1 + P4; throughput block P1 |

Integration obligations:

- **P3 never waits for P4.** It develops against mock fixtures generated from the frozen schemas, and the cut-over to the live WebSocket is a transport change only. If rendering breaks at cut-over, the fixtures were wrong — a contract-fidelity bug owned by P4, not a P3 rework.
- **P2 never waits for live capture.** It develops against the deterministic synthetic event generator.
- **P1 owns the clock.** Any component consuming replay time takes it from the single rebased clock; `t_replay_start` is captured once.
- **P4 owns the seam and the Hour-12 checkpoint.** In the three-track plan that gate had no single owner; here it does.
- **Neither P2 nor P4 may drop a PS-mandated alert field.** P2 emits `timestamp`, `flow_id`, threat class, `confidence`, `evidence`; P4 persists and serves all five; P3 renders all five.
- **Documentation is written incrementally from Hour 6** by whoever is gate-blocked. A track waiting on another track's gate writes docs. It does not idle and it does not start unplanned features.

Seam-by-seam ownership, including who owns the contract and who owns the integration for each, is in `agents.md` section 7.

---

## 8. Hourly Gates

| Gate | Hour | Must be true | If it fails |
|---|---|---|---|
| **Phase 0 exit** | H1 | Contract tests exist; JA3/JA3S/JA4 verdict recorded; lab has no route and no egress | Do not diverge into tracks |
### Gate ownership

Every gate has one **accountable owner** who calls it green or red, plus named contributors. A gate with no single owner is a gate nobody calls.

| Gate | Accountable owner | Contributors | Why this owner |
|---|---|---|---|
| **Phase 0 exit (H1)** | **All four** | — | Contracts are shared; no single track can freeze them alone |
| **Hour-6 gate (H6)** | **P1** | P2 (PCAP set hashed and manifested), P4 (dashboard receives events) | The gate is the sensor spine; P1 owns the spine |
| **Hour-10 gate (H10)** | **P2** | P1 (real PCAP, `flow_summary` bounded), P3 (UI responsive under flood, evidence drawer, `not_observable` visible), P4 (`latency_ms` measured end to end) | The headline criterion is *at least one real alert with populated evidence* — that is P2's output |
| **Hour-12 checkpoint (H12)** | **P4** | All three feed it | P4 owns the seam; the checkpoint is the whole integrated path |
| **Hour-13 optional gate (H13)** | **P1** | — | The non-optional item is the NetFlow v9/IPFIX adapter, which is P1's |
| **Hour-16 kill gate (H16)** | **P2** | P3 (backup recording immediately on gate pass), P1 (throughput, boundary, cold-boot prep), P4 (persistence, chain) | The gate decides detector coverage and executes the kill ladder |
| **Hour-19 feature freeze (H19)** | **P1** | All four enforce the freeze; P4 (recovery tests), P3 (load test, screenshots) | The H19 preconditions are hardening, cold boot and the offline asset audit — all P1's |
| **H19–H22** | **P2** | P3 (deck, rehearsals), all four (rehearsals) | The blocking deliverable is the evaluation report with final measured numbers |
| **H22–H24** | **All four** | — | Buffer, final cold boot, final rehearsal, backup verification |
| **Hour-6 gate** | H6 | Real PCAP → veth → both input paths → normalized event → dashboard. Attack PCAP set complete, hashed, manifested; generation stops. `address_plan.yaml` loaded and `direction` populated. Capability probe recorded, including every acceptance line. IPFIX and NetFlow v9 fixtures exist with known capability contracts | **All four people stop and fix the spine. No new detector work** |
| **Hour-10 gate** | H10 | At least one real alert from a real PCAP; populated evidence; correct `latency_ms`; concurrency test passed; UI responsive under flood | Stop and fix before Tier 1 expansion |
| **Hour-12 checkpoint** | H12 | Full integrated path green: replay, DDoS, scan, DGA, incident lifecycle, SQLite, WebSocket, evidence drawer, persistence, dedup, latency, capability state, dashboard responsiveness | **Stop detector expansion and fix integration** |
| **Hour-13 optional gate** | H13 | NetFlow v9/IPFIX adapter complete and tested — **not optional**. Only clock servo, Lomb-Scargle and unix-stream ingest remain optional | Skip the optional items; they are not demo-critical |
| **Hour-16 kill gate** | H16 | All six PS classes detect or have documented fallbacks. Execute the kill ladder | No new detector work after this point. **Record the backup video immediately on gate pass** |
| **Hour-19 feature freeze** | H19 | Hardening complete; cold boot passed; assets audited | Freeze regardless |
| **H19–H22** | H22 | Evaluation report with final numbers; deck and README numbers filled; **three full rehearsals** | Nothing else goes in this block |
| **H22–H24** | H24 | Final cold boot, final rehearsal, backup verified | Buffer only — do not touch working architecture |

### Why the backup recording moves to H16

Hour 16 is the earliest moment a complete run exists, and a recording is the only insurance that survives a dead laptop, a failed cold boot or a venue projector problem. Scheduled at H19–H22 it competes with three rehearsals for the same three hours and gets dropped. Re-record after H19 if the run improved; keep both files.

---

## 9. Kill Ladder

Executed at the Hour-16 gate. If a component is not working, take its fallback and move on.

| Priority | Component | Fallback |
|---|---|---|
| 1 | Threat map | Cut entirely |
| 2 | PDF export | JSON/CSV |
| 3 | Scenario Console UI | Shell script + menu |
| 4 | Clock-servo Kalman | Fixed 300 ms watermark |
| 5 | Capture-loss Kalman | Raw `kernel_drops` lower bound |
| 6 | Lomb-Scargle | CV + MAD |
| 7 | Fusion / correlation | Separate detector alerts + dedup |
| 8 | SHAP | LightGBM `pred_contrib` / evidence templates |
| 9 | Slowloris duration/shape refinement | Keep concurrency + duration + bytes/connection detector |
| 10 | TLS/QUIC shape refinement | JA3 + JA3S + intel + destination novelty |
| 11 | Real PCAP replay | Synthetic generator |
| 12 | LightGBM DGA artifact | Lexical + entropy + NXDOMAIN rules, `calibrated: false` |

Row 12 is a **fallback inside a never-cut item**, not a cut. DGA still ships; only the model is downgraded, and the downgrade is stated in the evidence drawer.

### Never cut

1. Incident feed
2. Evidence drawer
3. DGA model
4. DDoS statistics
5. Scan statistics
6. Capability banner
7. Read-only negative test
8. Measured throughput
9. NetFlow v9/IPFIX normalization contract and capability degradation

---

## 10. Feature Freeze

**Effective Hour 19.**

Allowed after freeze: documentation; rehearsal; bug fixes; evidence corrections; demo stability fixes.

Not allowed after freeze: new detectors; new models; architecture changes; new dependencies; new major UI features.

### Rest rotation

Four people, twenty-four hours and zero scheduled rest puts everyone at their worst during hours 16–22 — exactly where the kill gate, cold boot, hardening and all three rehearsals live.

```text
Hours 10-19    each person takes 2 x 90 min off, staggered
               P1 rests first — its blocking work ends at the hour-10 gate
               P3 and P4 rest last — their work sits on the demo critical path
               P3 and P4 never rest simultaneously — one must cover the seam
```

Rest is a scheduled item with an owner and a time, not something that happens if convenient.

---

## 11. Final Demo Preparation

### Drafted and substantially complete by Hour 16
README; architecture diagram; packet-to-alert flow diagram; incident lifecycle diagram; `LIMITATIONS.md`; model card; seven-slide deck with numbers left as placeholders.

### Hours 19–22 contain only
- Evaluation report — it needs the final measured numbers, so it lands here.
- Filling final numbers into the deck and README.
- **Three full rehearsals.**
- Re-recording the backup video if the run improved.

Three rehearsals in three hours is already tight. Nothing else goes in this block.

### Demo structure — 7 minutes

| Time | Beat |
|---|---|
| 0:00–0:30 | Problem: read-only, no decryption, streaming. Point at the LIVE/REPLAY badge; state the replay speed |
| 0:30–1:15 | Prove read-only: capability banner, negative-connectivity test, egress failure, alerts still flowing |
| 1:15–3:00 | Scenario: DDoS, evidence drawer, pps vs baseline, SYN/ACK ratio, source entropy, scan, DGA, NXDOMAIN context. Say **"advisory"** when showing recommendations |
| 3:00–4:00 | Incident lifecycle: one evolving incident vs 50 000 naive alerts; bounded flow state |
| 3:45–4:00 | Input-mode capability beat: switch to the IPFIX fixture; `input_mode: ipfix`; packet/DNS/TLS detectors degrade; flow-level detectors remain |
| 4:00–5:00 | Advanced detections: beacon, encrypted-session suspicion, exfiltration. State fingerprint and behaviour-based suspicion, never payload identification |
| 5:00–6:15 | Measurements: throughput, p95 latency, false alerts/hour, per-class PR-AUC, calibration, threshold sweep, baseline comparison. Export mid-run. Verify the hash chain |
| 6:15–7:00 | Limitations: QUIC, ECH, DoH/DoT, sampled flows, NAT, slow scans, concept drift, geolocation caveat, encrypted-session limitation, `not_observable` |

> **Timeline note — V6.3 timestamps preserved verbatim.** `FINAL_DEVELOPMENT_PLAN_V6.3.md` section 41 lists the incident-lifecycle beat as **3:00–4:00** and the input-mode capability beat as **3:45–4:00**. Those two intervals overlap inside a fixed 7-minute budget, and both are reproduced above exactly as the technical plan states them.
>
> **Stated interpretation for delivery:** the 3:45–4:00 input-mode beat is a **carve-out from the tail of the 3:00–4:00 lifecycle block**, not an additional fifteen seconds of budget. In practice the lifecycle narration runs to roughly 3:45 and hands over to the input-mode beat, which closes the block at 4:00.
>
> This is an interpretation recorded to make the demo runnable. **The technical-plan timeline has not been rewritten**, and any future correction belongs in `FINAL_DEVELOPMENT_PLAN_V6.3.md` section 41 first. Tracked as `DOC-012` in `bugs.md`.

Two fast proof moments to keep ready: the **hash-chain tamper demonstration** (export, modify one record, run the verifier, watch it fail on entry N) and the **Suricata-vs-intelligence-layer comparison** table from `design.md` section 26.

---

## 12. Seeded Configuration

`config/thresholds.yaml` ships populated on day one. An empty file costs hours of guessing at hour 7, when nobody has spare hours.

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

**These are starting points, not published values.** Every threshold that reaches the deck or the evaluation report must first be replaced by a sweep result with its artifact.

---

## 13. Phase 0 Decisions — Frozen

These were gaps in `FINAL_DEVELOPMENT_PLAN_V6.3.md` that the documentation layer was not entitled to fill. The project owner decided all four at Phase 0. They are now frozen contract facts; rationale is in `memory.md`, defect history in `bugs.md`.

| # | Decision | Frozen value | Owner |
|---|---|---|---|
| `DOC-004` | Throughput acceptance target | **Primary:** at least **1 000 normalized flows/sec** sustained 60 s at **below 1 %** loss. **Secondary (V6.3, retained unchanged):** at least **50 000 pps**, at least **400 Mbps**, each sustained 60 s at below 1 % loss. The three metrics are never conflated | P1 |
| `DOC-006` | Canonical identifier representation | `sha256(canonical_value).hexdigest()[:16]` — exactly **16 lowercase hex characters**, a 64-bit truncated SHA-256. Applies to `flow_id` and `incident_id`. **Not** 16 bytes. Chain hashes stay full 64-character digests. One shared canonicalisation and hashing helper for writers **and** verifiers | P2 contract / P4 helper |
| `DOC-007` | Unavailable dedup-key components | The exact canonical sentinel string **`NOT_OBSERVABLE`**. Never null, empty string, zero or `unknown`. Deduplication operates on the canonical serialized key containing the sentinel | P2 |
| `DOC-009` | Test subtree | `tests/detectors/` and `tests/throughput/` created; all other V6.3 test directories and repository structure preserved unchanged | P1 + P2 |

**Consistency note on `DOC-007`.** `NOT_OBSERVABLE` now carries two distinct meanings that deliberately share one string: a **detector capability state** (evidence-visibility axis, `design.md` section 23) and a **dedup-key component placeholder** (identity rule, `design.md` section 17). They are different mechanisms at different stages. The capability and minimum-evidence checks still run first — the sentinel governs how an incident is *identified*, never whether one may be *raised* on absent evidence.

### Remaining open item

| # | Item | State |
|---|---|---|
| `DOC-012` | Demo-script timeline overlap in `FINAL_DEVELOPMENT_PLAN_V6.3.md` section 41 (3:00–4:00 and 3:45–4:00 inside a 7-minute budget) | **Documented, not rewritten.** V6.3 timestamps preserved verbatim; the carve-out reading is recorded as a stated interpretation in section 11 |
