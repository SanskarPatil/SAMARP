# Task Today

**Updated:** 2026-09-10
**Timebox:** Phase 1 P2 implementation
**Current Phase:** P2-1 — Ground Truth
**Current Gate:** P2-1 corpus and offline-intelligence milestone
**Overall Status:** GREEN

> Keep this file small and short-lived. It holds only the current focused work period — roughly the next two hours. Project state is in `STATUS.md`; the roadmap is in `implementation_plan.md`.

---

## Current Objective

Build deterministic Detection / ML inputs and reusable passive-metadata features without waiting for P1 live capture.

---

## Priority Tasks

### 1. Stateless feature foundation — DONE

- [x] Implement deterministic entropy, median/MAD, robust z-score, inter-arrival and qtype primitives.
- [x] Implement lexical DGA, DNS qtype, and TLS/QUIC metadata-shape extraction using only frozen normalised-event fields.
- [x] Preserve the frozen `FEATURE_ORDER` with deterministic vector encoding.
- [x] Add and pass five deterministic feature tests.

### 2. Ground truth and offline intelligence — DONE

- [x] Deterministic synthetic benign/attack corpus and seed manifest.
- [x] Time, entity and DGA-family holdout definitions with leakage tests.
- [x] Immutable baseline snapshot generation.
- [x] Offline allowlist, DGA-family and Tranco-derived sample assets plus version manifest.

### 3. Statistical detector modules — DONE

- [x] DDoS/Slowloris/reflection and reconnaissance.
- [x] C2, DNS tunnel, TLS/QUIC metadata and exfiltration.
- [x] Schema-valid alert/evidence factory and detector acceptance tests.

### 4. Single LightGBM DGA model — NEXT

- [ ] Train only the DGA LightGBM classifier from the deterministic corpus.
- [ ] Add Platt calibration, reliability/Brier evaluation and model card.
- [ ] Implement DGA inference and fallback behavior.

### 1. Resolve the four open contract decisions — DONE

Decided by the project owner and applied across the documentation layer and the frozen artifacts.

- [x] Throughput target: at least **1 000 normalized flows/sec** sustained 60 s at below 1 % loss (primary); V6.3 pps and Mbps retained unchanged as secondary; the three are never conflated.
- [x] Canonical identifier: `sha256(canonical_value).hexdigest()[:16]` — exactly 16 lowercase hex characters, 64-bit truncated SHA-256; one shared helper for writers and verifiers; chain hashes stay full length.
- [x] Unavailable dedup-key components take the exact sentinel `NOT_OBSERVABLE`; dedup operates on the canonical serialized key containing it.
- [x] `tests/detectors/` and `tests/throughput/` created; all other V6.3 test directories preserved.

Rationale recorded in `memory.md`; `bugs.md` `DOC-004`, `DOC-006`, `DOC-007`, `DOC-009` closed.

### 2. Freeze the shared contracts — DONE

- [x] `schemas/normalized_event.schema.json`.
- [x] `schemas/alert.schema.json` (v1.3) with the five PS-mandated fields, `flow_ref_type`, `score_type`, `calibrated`, capability state and chain fields.
- [x] `features/feature_order.py` with the frozen `FEATURE_ORDER` tuple.
- [x] `config/thresholds.yaml` (seeded, plus the decided `throughput:` block), `config/address_plan.yaml`, `config/dedup_keys.yaml`.
- [ ] **Remaining:** contract tests in `tests/schema/` — enum values, non-null `flow_id`, identifier pattern `^[0-9a-f]{16}$`, dedup sentinel, six-classes-to-eight-modules mapping, `input_mode` enum, no non-`GET` route on Plane B (**P4**).

**Done when:** contract tests exist and pass, and all four tracks can build against mocks.

### 4. Ownership split applied — DONE

- [x] Four-person split documented: **P1** Sensor/Infrastructure, **P2** Detection/ML, **P3** UI/UX, **P4** Backend/API/Integration.
- [x] `agents.md` rewritten; `implementation_plan.md` phases renamed `P1-*`/`P2-*` and Track C split into `P3-*` and new `P4-*`.
- [x] Legacy mapping recorded: `A → P1`, `B → P2`, `C → P3 + P4`. V6.3 itself is **not** edited.
- [x] P3 mock-fixture independence made a hard rule; P4 owns the Hour-12 integration checkpoint.
- [x] **Six supplementary responsibilities confirmed** — hash chain → P4; offline intel bundle and version manifest → P2; baseline snapshot generation → P2; model card and evaluation report → P2; cold boot and offline asset audit → P1; backup recording and screenshots → P3. Recorded in `agents.md` section 7 as confirmed assignments.
- [x] **Coverage sweep passed** — all 15 V6.3 repository directories and all 46 Definition-of-Done items have a named owner (`agents.md` section 12). No unowned responsibility remains.

### 3. Prove the environment

- [ ] Confirm the OS/box decision is made and its specification recorded. **WSL2 is not acceptable** for the published throughput number.
- [ ] Build and version-check Suricata (7.0.3 or later for JA4).
- [ ] Run the capability probe against a known fixture PCAP; record every acceptance line, including the JA3/JA3S/JA4 verdict and `flow events == 0`.
- [ ] Build the isolated veth lab; set egress DROP.

**Done when:** the probe output is recorded in the capability state and the lab interface has no route and no egress.

---

## Current Blocker

None for P2. The repository has no P1 normalizer yet, so P2 uses deterministic synthetic events until the declared handoff.

---

## Do Not Work On

- Threat map, PDF export, clock servo, Lomb-Scargle, fusion, SHAP — all Tier 2.
- Unrelated refactors.
- Documentation beyond what a decision requires (the documentation layer already exists).
- Anything past the Phase 0 exit gate.

---

## Next Task — four tracks in parallel

| Track | Phase | Hours 1–6 |
|---|---|---|
| **P1 — Sensor / Infrastructure** | P1-1 Transport and Clock | tcpreplay driver, veth, the single rebased replay clock, header-only counter, Suricata EVE tail, normalizer, bounded flow tracker, capture-loss fields |
| **P2 — Detection / ML** | P2-1 Ground Truth | Synthetic event generator, corpora, manifests, DGA corpus with hard negatives, holdouts, background PCAP generation (**stops at the Hour-6 gate**) |
| **P3 — UI / UX** | P3-1 Mock-Driven Shell | Generate mock fixtures from the frozen alert schema, fixture validity check, React/Vite skeleton, incident feed, LIVE/REPLAY badge. **Does not wait for P4** |
| **P4 — Backend / API / Integration** | P4-1 API and Transport | FastAPI `GET`+WebSocket only, route contract test asserting no non-`GET` route, 250 ms batched pushes, review P3's fixtures for contract fidelity |

Ownership detail is in `agents.md`; phase detail in `implementation_plan.md`.

---

## End-of-Session Update

- **Completed:** documentation layer generated and cross-checked; four Phase 0 decisions applied; `schemas/`, `features/feature_order.py` and the three config files frozen; test subtree created.
- **Blocked:** nothing.
- **New bug:** `DOC-012` recorded — the V6.3 section 41 demo-beat overlap, documented rather than rewritten.
- **New decision:** throughput target, canonical identifier form, dedup sentinel and test subtree frozen — rationale in `memory.md`. Where source documents conflicted, the higher authority was preferred and the resolution recorded rather than a new requirement invented.

---

## Rule

**Never let this file become project history.** When the timebox ends: move durable discoveries to `memory.md`, bugs to `bugs.md`, completed roadmap items to `implementation_plan.md`, update `STATUS.md`, then replace the contents above with the next focused task set.
