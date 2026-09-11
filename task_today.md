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

- [ ] Replay, then chain verification, then the live API with the dashboard, then the 405 boundary proof.
- [ ] Confirm the machine is offline for at least one full rehearsal.
- [ ] Keep the frozen exports in `export/` untouched; the replay reproduces them byte for byte, which is itself a claim worth showing.

### 2. Fix the wording, not the code

- [ ] Say **seven detector modules across six PS classes**. `PRD.md`, `design.md` and V6.3 describe eight internal modules; `reflection.py` is deferred.
- [ ] Present `score`, `score_type` and `calibrated: false`. Never append a percent sign, and never call an uncalibrated score a probability.
- [ ] State that the DGA path runs its documented rule fallback with `model_version: "rules-fallback"`. Publish no Brier score and no reliability diagram.
- [ ] Quote no latency number. `latency_ms` is null on live alerts.
- [ ] Quote no throughput number without the machine specification beside it.

### 3. Prove the environment — still outstanding, still Linux-gated

- [ ] Confirm the OS/box decision is made and its specification recorded. **WSL2 is not acceptable** for the published throughput number.
- [ ] Build and version-check Suricata (7.0.3 or later for JA4).
- [ ] Run the capability probe against a known fixture PCAP; record every acceptance line, including the JA3/JA3S/JA4 verdict and `flow events == 0`.
- [ ] Build the isolated veth lab; set egress DROP.

---

## Current Blocker

None for P2. The repository has no P1 normalizer yet, so P2 uses deterministic synthetic events until the declared handoff.

---

## Do Not Work On

- Threat map, PDF export, clock servo, Lomb-Scargle, fusion, SHAP — all Tier 2.
- Unrelated refactors.
- Documentation beyond what a decision requires.

---

## End-of-Session Update

- **Completed:** read-only demo audit at `5f62f42` — 321 tests pass, frontend build passes, canonical replay is deterministic and byte-reproducible, hash chain verifies standalone, Plane B exposes only `GET` routes plus the WebSocket with mutating methods returning 405, no CDN runtime dependency in the dashboard, no secret or database tracked.
- **Corrected:** `STATUS.md` and `task_today.md` had fallen four commits behind the repository and described P2, P3 and P4 as not started. Both now describe the shipped system.
- **Recorded:** `reflection.py` is deferred, is not a Definition-of-Done item, and external material must say seven detector modules.

---

## Rule

**Never let this file become project history.** When the timebox ends: move durable discoveries to `memory.md`, bugs to `bugs.md`, completed roadmap items to `implementation_plan.md`, update `STATUS.md`, then replace the contents above with the next focused task set.
