# Agents and Ownership

**Project:** Cyber Sentinel — PS26145
**Split:** four people, four tracks
**Derived from:** `FINAL_DEVELOPMENT_PLAN_V6.3.md` sections 39, 39.1, adapted to the four-person split

This file defines **who owns what**, so four people and multiple AI agents can work in parallel without producing conflicts. Behavioural rules for AI agents are in `CLAUDE.md`; the build sequence is in `implementation_plan.md`; git mechanics are in `git.md`.

**No architecture change.** The four tracks build the same V6.3 system, against the same already-frozen contracts. This is an ownership split, not a redesign.

---

## 1. Team Structure

```text
P1 — Sensor / Infrastructure     the spine; blocking until the Hour-6 gate
P2 — Detection / ML              the brains; consumes P1's event contract
P3 — UI / UX                     the surface; mock-driven, never blocked on P4
P4 — Backend / API / Integration the seam; owns end-to-end wiring
```

**Do not allow ownership to become ambiguous.** Every file, contract and gate item has exactly one owning person. Where two people both touch a thing, one owns the **contract** and the other owns the **integration** — section 7 names both for every seam.

AI agents inherit the ownership of the track they are working for. An agent working a P2 ticket does not modify P1 ingestion code; it raises a handoff.

### Legacy track codes

`FINAL_DEVELOPMENT_PLAN_V6.3.md` section 39 and any document still carrying `A` / `B` / `C` owner codes map as follows:

```text
Track A  →  P1
Track B  →  P2
Track C  →  P3 + P4      (split: dashboard to P3, API/persistence/integration to P4)
```

V6.3 is the implementation source of truth and is **not** edited to match this split. Read its `A`/`B`/`C` through the mapping above.

---

## 2. P1 — Sensor / Infrastructure

**Owns the spine.** Its work blocks P2 and P4 until the Hour-6 gate, and it rests first because that blocking work ends at the Hour-10 gate.

Owns:

- Suricata — build, version pin, the five mandatory configuration items, capability probe
- PCAP replay and live capture
- **NetFlow v9 / IPFIX ingestion** and the shared template cache
- **sFlow capability handling**
- Input adapters
- Normalization
- Header-only fast path and the bounded flow tracker producing `flow_summary`
- Capture-loss measurement
- Throughput measurement
- Lab / replay infrastructure, including the Scenario Console
- Read-only boundary verification

Directories: `sensor/`, `ingest/`, `lab_console/`, `features/rolling.py`, `features/sketches.py`, `features/entropy.py`, `config/address_plan.yaml`, `tests/boundary/`, `tests/capture_loss/`, `tests/throughput/`.

**Owns the contract:** `schemas/normalized_event.schema.json`.

---

## 3. P2 — Detection / ML

**Owns the brains.** Works against the deterministic synthetic event generator until P1's normalizer lands, so it is never idle waiting for capture.

Owns:

- Feature extraction
- **`features/feature_order.py`**
- DGA model — the single trained model in the system
- **DGA bigram/trigram features**
- DNS and **qtype** analysis
- DDoS detection
- Reflection detection
- C2 detection
- **Slowloris detection** (a low-rate path inside `ddos.py`, not a ninth module)
- TLS/QUIC metadata detection
- Reconnaissance / scan detection
- Exfiltration detection
- Fusion
- Deduplication
- Detector evaluation

Directories: `detectors/`, `models/`, `intel/`, `features/feature_order.py`, `features/stateless.py`, `alerts/scorer`, `alerts/deduplicator`, `scenarios/`, `config/thresholds.yaml`, `config/dedup_keys.yaml`, `tests/detectors/`, `tests/parity/`, `tests/replay/`.

**Owns the contracts:** `schemas/alert.schema.json`, `features/feature_order.py`, `config/dedup_keys.yaml`.

---

## 4. P3 — UI / UX

**Owns the surface.** Its work sits on the demo critical path, so it rests last.

**P3 is mock-driven and must never be blocked on P4.** See section 8.

Owns:

- React / Vite dashboard
- Incident feed
- Evidence drawer
- **Confidence presentation** — a percent sign only where `calibrated: true`; uncalibrated output labelled a risk/anomaly score
- Threat-class views — the six PS class strings, verbatim
- Counters and charts
- **Capability / visibility panel**
- **LIVE / REPLAY presentation**
- **`NOT_OBSERVABLE` presentation**
- Frontend performance — client ring buffer, virtualisation, `requestAnimationFrame` counters
- Export and operator experience
- Threat map, if the Hour-16 gate is green
- Demo screenshots, severity palette, backup recording

Directories: `dashboard/`, `tests/ui_load/`, `scenarios/mock_fixtures/` (generated, see section 8).

**Owns no frozen contract.** P3 consumes `schemas/alert.schema.json` and must not modify it.

---

## 5. P4 — Backend / API / Integration

**Owns the seam.** The only track whose primary product is that the other three fit together.

Owns:

- FastAPI
- WebSocket
- SQLite
- Alert persistence
- Incident lifecycle integration
- API contracts
- Backend orchestration
- Sensor / detection / backend integration
- End-to-end integration
- API and integration tests

Directories: `api/`, `alerts/lifecycle`, `alerts/hash_chain`, `tests/schema/` (route contract), `tests/hash_chain/`, `tests/latency/`.

**Owns the API contract:** the Plane B route surface.

> **Plane B is read-only: `GET` and WebSocket only. No `POST`, `PUT` or `DELETE`.** A contract test asserts no non-`GET` route is registered. `POST /simulate/scenario/{id}` was removed in V6.3 and must never return — scenario control lives only in P1's Scenario Console, on the other side of the boundary.

**Owns the Hour-12 integration checkpoint.** In the three-track split this gate had no single owner; in the four-person split it is P4's.

---

## 6. Shared Contracts

All six are **already frozen**. The four tracks build against them; they are not renegotiated during implementation.

| Contract | File | Owner | Consumers |
|---|---|---|---|
| Normalized event contract | `schemas/normalized_event.schema.json` | **P1** | P2, P4 |
| Alert schema v1.3 | `schemas/alert.schema.json` | **P2** | P1, P3, P4 |
| Feature order | `features/feature_order.py` | **P2** | P2 training, P2 inference, P1 parity tests |
| Deduplication keys | `config/dedup_keys.yaml` | **P2** | P2 dedup, P4 lifecycle, contract tests |
| Lab address plan | `config/address_plan.yaml` | **P1** | P1 normalizer, P2 reflection/exfil/novelty, P3 map |
| Thresholds and budgets | `config/thresholds.yaml` | **P2** | All. Latency block co-owned P1 (watermark, window) + P4 (batch push); throughput block P1 |

**A contract is not changed by whoever notices the problem.** Changes follow the procedure in `git.md` section 6: coordinate, update the schema, update the contract test, update every consumer, verify. A contract change lands as one reviewed merge.

Three frozen facts every track codes against:

- **Identifiers:** `sha256(canonical_value).hexdigest()[:16]` — exactly 16 lowercase hex characters. Chain hashes stay full 64-character digests.
- **Unavailable dedup-key components:** the exact sentinel string `NOT_OBSERVABLE`.
- **Throughput:** at least 1 000 normalized flows/sec sustained 60 s at below 1 % loss (primary); 50 000 pps and 400 Mbps secondary; never conflated.

---

## 7. Seams — where two people touch one thing

Every row names a **contract owner** and an **integration owner**. Neither may act alone.

| Seam | Contract owner | Integration owner | Rule |
|---|---|---|---|
| Normalized event → detectors | P1 | P2 | P1 publishes the schema before P2 codes against it |
| Detector output → alert schema | P2 | P4 | P2 emits; P4 persists and serves. Neither drops a PS-mandated field |
| Deduplication → incident lifecycle | P2 (dedup logic + keys) | P4 (lifecycle integration, persistence, sequence) | Dedup decides *identity*; P4 decides *storage and transitions*. `NEW → ACTIVE → UPDATED → RESOLVED` is defined in the frozen alert schema |
| Alert delivery → dashboard | P4 (WebSocket batching, ~250 ms) | P3 (client ring, virtualisation, render) | P4 owns the push cadence; P3 owns everything after it arrives |
| Export | P4 (`GET /export/json`, `/export/csv`) | P3 (operator surface) | CSV is one row per incident; JSON is canonical and the chain is computed over JSON only |
| Hash chain | P4 (writer + `alerts/hash_chain.py`) | P4 (verifier) | Writer and verifier built in the **same ticket** against the frozen spec. The verifier imports the concatenation rule, never reimplements it |
| Latency budget | P1 (watermark, window) + P4 (batch push) | P4 (measures `latency_ms` end to end) | Fix order: batch push, then window, then detector cost. **Never shrink the watermark** |
| JA3S | P1 (sensor extraction + probe) | P2 (evidence) | P1 confirms the probe records it before P2 relies on it |
| Capability state | P1 (computes) | P2 (per-detector declaration) → P3 (renders) | All three must agree on the vocabulary; the three evidence states never mix with the component-health states |
| Ground truth / PCAP corpus | P1 (lab, generation run, hashing, manifests) | P2 (corpora content, DGA data, holdouts, expected alerts) | Generation stops at the Hour-6 gate. Ground truth never reaches the dashboard |
| Throughput and capture loss | P1 (measures) | P4 (surfaces via API) → P3 (renders) | Never published without the machine specification |

### Supplementary ownership — CONFIRMED

Six responsibilities were not covered by the four primary ownership lists. They are now **confirmed assignments, not inferences**.

| # | Responsibility | Owner | Phase | Boundary with other tracks |
|---|---|---|---|---|
| 1 | `alerts/hash_chain.py` writer **and** verifier | **P4** | P4-2 | Writer and verifier are built in the **same ticket** against the frozen spec. The verifier imports the concatenation rule; it never reimplements it. P1 supplies the measurement provenance the chain records but does not implement the chain |
| 2 | Offline intelligence bundle and `intel/version_manifest.json` | **P2** | P2-1 | P2 owns the bundle's **contents** — allowlists, SSLBL JA3 data, DGA family data, Tranco list, explainer text, recommendations, GeoLite2 if retained. P1 owns its **offline staging** into the asset bundle. Every alert carries the bundle version |
| 3 | Baseline snapshot generation | **P2** | P2-1 | P2 **generates** from the benign corpus; P1 **loads** it at boot in P1-2. Capped updates prevent slow poisoning; the immutable long-term reference snapshot lives in the intel bundle |
| 4 | Model card and evaluation report | **P2** | P2-4 | The model card states exactly one trained ML model (DGA LightGBM) and identifies every non-ML detector. No Brier score or reliability diagram is published for the rule fallback |
| 5 | Cold boot and offline asset audit | **P1** | P1-4 | Second machine, networking disabled, every dependency resolving from the vendored bundle. P1 provides the environment other tracks' proofs are demonstrated on |
| 6 | Backup recording and screenshots | **P3** | P3-4 | Recording made **immediately on the Hour-16 gate pass** — the earliest moment a complete run exists. Re-record after H19 if the run improved; keep both files |

**Consequence recorded:** the hash-chain tamper demonstration artifact follows the chain to **P4** (P4-4), and is no longer a P1 hardening task. P1 still owns the cold-boot environment the demonstration runs on.

**No responsibility in the four-person split is now unowned.** The coverage sweep is in section 12.

---

## 8. Parallel Work Rules

- **Work inside your track's directories.** If a fix belongs elsewhere, raise it rather than reaching across.
- **Freeze first, build second.** All six contracts are already frozen; nothing is coded against an unfrozen interface.
- **A gate-blocked track writes documentation.** It does not idle, and it does not start unplanned features.
- **P1's spine is blocking until Hour 6.** If the Hour-6 gate fails, all four people stop and fix the spine. No new detector work.
- **If the Hour-12 integration checkpoint is not green, detector expansion stops** until P4 has it fixed.
- **After the Hour-16 kill gate, no new detector work.** After the Hour-19 feature freeze, no new detectors, models, architecture changes, dependencies or major UI features.

### P3 develops mock-driven, never blocked on P4

**This is a hard rule, not a convenience.** P3 must reach a fully rendered dashboard without a running backend.

1. **Mock fixtures are generated from the frozen schemas** — `schemas/alert.schema.json` for incidents, `schemas/normalized_event.schema.json` where event shape is needed. They are generated artifacts, not hand-written JSON that can drift.
2. Fixtures live in `scenarios/mock_fixtures/` and cover, at minimum: every one of the six `ps_class` values; all three `flow_ref_type` values; all four `score_type` values with `calibrated` both true and false; `confidence: null`; all three capability states including `NOT_OBSERVABLE`; a `DEGRADED` IPFIX input mode; a `dedup_key` carrying the `NOT_OBSERVABLE` sentinel; and a 50 000-alert burst for the load test.
3. **P3 renders from fixtures first, live WebSocket second.** The swap must be a transport change only — if rendering breaks when the real backend arrives, the fixtures were wrong and that is a contract-fidelity bug, owned by P4.
4. **A schema-validity test guards the fixtures.** Every fixture validates against the frozen schema in CI, so P3 cannot build against a shape the backend will never send.
5. P4 reviews the fixture set once for contract fidelity. After that P3 regenerates freely.

The same principle applies upstream: **P2 develops against the deterministic synthetic event generator** rather than waiting for P1's live capture.

### Rest rotation

```text
Hours 10-19    each person takes 2 x 90 min off, staggered
               P1 rests first — its blocking work ends at the hour-10 gate
               P3 and P4 rest last — their work sits on the demo critical path
               P3 and P4 never rest simultaneously — one must cover the seam
```

Rest is a scheduled item with an owner and a time, not something that happens if convenient. Hours 16–22 hold the kill gate, cold boot, hardening and all three rehearsals; that is the worst possible place to be exhausted.

---

## 9. Handoff Rules

1. **The producing track declares the contract first.** All six are already frozen, so this now means: publish the *implementation* against the frozen contract before a consumer builds on it.
2. **Consumers build against mocks, not promises.** P3 uses generated fixtures; P2 uses the synthetic event generator; P4 uses both.
3. **A handoff is complete when the consumer's test passes against the producer's real output**, not when the producer says it is done.
4. **Record the handoff** in `STATUS.md` when it changes what other tracks can rely on.

---

## 10. Conflict Rules

| Conflict | Resolution |
|---|---|
| Two tracks disagree on a contract field | The contract owner decides; the change goes through the full procedure in `git.md` section 6 |
| A document contradicts `FINAL_DEVELOPMENT_PLAN_V6.3.md` | The plan wins; correct the document |
| Two source documents contradict each other | Prefer the higher authority: PS26145, then the traceability matrix, then V6.3, then the documentation spec. **Never invent a new requirement to resolve it** |
| A defect exists in a higher-authority document | Document the interpretation; **do not silently rewrite the source** |
| Merge conflict in a shared contract | Do not resolve unilaterally. Both owners review together |
| A test fails after someone else's merge | The person whose change broke it fixes it; do not weaken the test |
| P3 and P4 disagree on payload shape | The frozen alert schema decides. If the schema is genuinely wrong, it is a contract change, not a negotiation |
| Two people want the same file | The owning track wins; the other raises a handoff |
| A cut is proposed | Only the kill ladder decides cuts, and only at the Hour-16 gate. Nothing on the never-cut list is cut |

---

## 11. Escalation Rules

Escalate immediately — do not absorb the delay quietly — when any of these happen:

1. **A gate is at risk.** Raise it before the gate hour, not at it.
2. **A frozen contract needs to change.** Stop and coordinate; do not code around it.
3. **A never-cut item is failing.** Incident feed, evidence drawer, DGA, DDoS statistics, scan statistics, capability banner, read-only negative test, measured throughput, NetFlow v9/IPFIX normalisation contract.
4. **A measurement cannot be reproduced.** An unreproducible number does not get published.
5. **A constraint is under pressure.** Anything that would weaken read-only, no-decryption, offline operation, bounded state or the two-plane separation is an immediate stop, regardless of schedule cost.
6. **P3 finds a fixture that the real backend contradicts.** That is a contract-fidelity failure at the P3/P4 seam and it invalidates whatever P3 built on it.

Escalation goes to the whole team, not to one person, because every one of these changes what the other tracks can rely on.

---

## 12. Coverage Sweep — no unowned responsibilities

Verified against `FINAL_DEVELOPMENT_PLAN_V6.3.md` section 21 (repository structure) and section 46 (Definition of Done). Every directory and every Definition-of-Done item has exactly one accountable owner.

### Repository directories — all 15 owned

| Directory | Owner |
|---|---|
| `sensor/` | P1 |
| `ingest/` | P1 |
| `lab_console/` | P1 |
| `features/` | P1 (`rolling`, `sketches`, `entropy`) · P2 (`feature_order`, `stateless`) |
| `detectors/` | P2 |
| `models/` | P2 |
| `intel/` | P2 (contents) · P1 (offline staging) |
| `scenarios/` | P2 (corpora, manifests) · P1 (PCAP generation run, hashing) · P3 (`mock_fixtures/`) |
| `schemas/` | P1 (event) · P2 (alert) — **frozen** |
| `config/` | P1 (`address_plan`) · P2 (`thresholds`, `dedup_keys`) — **frozen** |
| `alerts/` | P2 (`scorer`, `deduplicator`) · P4 (`lifecycle`, `hash_chain`) |
| `api/` | P4 |
| `dashboard/` | P3 |
| `tests/` | P1 (`boundary`, `capture_loss`, `throughput`) · P2 (`detectors`, `parity`, `replay`) · P3 (`ui_load`) · P4 (`schema`, `latency`, `hash_chain`) |
| `docs/` | P2 (`feature_dictionary`, `evaluation`, `model_card`, `threshold_sweep`) · P1 (`architecture`) · all (`qna`) |

### Definition-of-Done items — V6.3 owner codes resolved

V6.3 section 46 assigns 46 items across `A`, `B`, `C`, `A+B`, `A+C` and `all`. Under the four-person split:

| V6.3 code | Resolves to | Notes |
|---|---|---|
| `A` | **P1** | Direct |
| `B` | **P2** | Direct |
| `A+B` | **P1 + P2** | Canonical campaign replay |
| `A+C` | **P1 + P3** | Capability state works — P1 computes, P3 renders |
| `C` | **P3 or P4** | Split below |
| `all` | **all four** | Feature freeze, README, LIMITATIONS.md, H12 checkpoint, non-null `flow_id` |

The `C` items split as follows — the only place the three-track Definition of Done was ambiguous under a four-person team:

| V6.3 item | Owner |
|---|---|
| `not_observable` is visible | **P3** |
| Evidence drawer contains real values | **P3** |
| Baseline comparison is visible | **P3** |
| UI survives flood load | **P3** |
| Visibility/limitations panel is visible | **P3** |
| TLS/QUIC UI uses suspicion/anomaly wording | **P3** |
| Backup recording exists | **P3** |
| Seven-slide deck is complete | **P3** |

Every remaining `C`-adjacent obligation — FastAPI, WebSocket, SQLite, persistence, export endpoints, lifecycle integration, API and integration tests — is **P4**, per section 5.

Two `all` items now have a named driver so they do not fall between tracks:

- **`all / H12` integration checkpoint** — driven by **P4**, who owns the seam.
- **`all / H10` non-null `flow_id` and valid `flow_ref_type`** — **P2** emits, **P4** persists and serves, **P3** renders. All three verify; none may drop it silently.

### Result

**No responsibility in the four-person split is unowned.** Where two tracks touch one thing, section 7 names the contract owner and the integration owner separately.
