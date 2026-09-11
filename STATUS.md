# Project Status

**Last Updated:** 2026-09-10
**Current Hour:** Phase 1
**Current Phase:** P2-1 — Ground Truth (in progress)
**Current Gate:** P2-1 corpus and offline-intelligence milestone
**Overall Status:** GREEN

> This file is the project's current state in under a minute. Immediate work is in `task_today.md`; the full roadmap is in `implementation_plan.md`.

**HEAD at last verification:** `5f62f42` — `test(hardening): verify throughput KPI and freeze clean canonical replay exports`.

---

## Completed

- Source documents reviewed in full: `ps26145_traceability_matrix.md`, `FINAL_DEVELOPMENT_PLAN_V6.3.md`, `create_project_md_files_V2.md`.
- Cross-document consistency analysis completed; contradictions and omissions recorded in `bugs.md` as `DOC-001` through `DOC-012`.
- Documentation layer generated: `PRD.md`, `design.md`, `implementation_plan.md`, `CLAUDE.md`, `agents.md`, `testing.md`, `git.md`, `STATUS.md`, `task_today.md`, `memory.md`, `bugs.md`.
- **Phase 0 decisions taken and applied** — throughput acceptance target, canonical identifier form, dedup sentinel, test subtree. Rationale in `memory.md`; defect history in `bugs.md`.
- **Frozen contracts written:** `schemas/normalized_event.schema.json`, `schemas/alert.schema.json`, `features/feature_order.py`, `config/thresholds.yaml`, `config/address_plan.yaml`, `config/dedup_keys.yaml`.
- **Four-person ownership split applied** — P1 Sensor/Infrastructure, P2 Detection/ML, P3 UI/UX, P4 Backend/API/Integration.
- **Six supplementary responsibilities confirmed and recorded**; hash-chain duplication between P1-3 and P4-2 removed, and the tamper-demonstration artifact moved with the chain to P4-4.
- **P2, P3 and P4 delivered and integrated.** The full vertical path runs end to end: Normalized Events → Features → Detectors → Deduplication/Scoring → SQLite / Hash Chain → FastAPI / WebSocket → Dashboard.

---

## Track Status

- Phase 0 exit is recorded as passed by the project owner. P2 is implementing against deterministic synthetic events while P1's live normalizer remains a future handoff.
- P2 feature foundation: deterministic passive-metadata primitives, lexical/DNS/qtype extraction, and frozen-order vectorization are implemented and test-green.
- P2 ground truth: deterministic DGA corpus with hard negatives, mutually exclusive time/entity/family holdouts, immutable baseline generation, and an offline intelligence manifest/assets are implemented and test-green.
- P2 non-ML detection: DDoS/Slowloris/reflection, scan, C2, DNS tunnelling, TLS/QUIC metadata and exfiltration paths now emit schema-valid alerts or explicit capability outcomes; 13 P2 tests pass.

---

## Blocked

- Nothing blocking the demo. All four Phase 0 contract decisions have been made and applied; `DOC-004`, `DOC-006`, `DOC-007` and `DOC-009` are closed.

## Open Finding — P1

**`external.*` in `config/address_plan.yaml` is still empty, and how it is filled matters.**

Python's `ipaddress` treats RFC 5737 documentation ranges as private. If `external.benign`, `external.synthetic_malicious` or `external.amplifier_hosts` are populated with documentation space, the reflection reserved-source share returns to ~100 % on benign traffic — **the exact trap section 2A.3 exists to prevent, reintroduced one level down** — and the false-alerts-per-hour figure is destroyed again.

The plan already requires *"curated public ranges, GeoLite2-resolvable"*. This finding records **why** that wording is load-bearing rather than stylistic. Owner: P1 (plan) with P2 (reflection detector). Pinned by `tests/ingest/test_address_plan.py::test_documentation_ranges_count_as_reserved_not_public`.

## Open Finding — detector module count

**`detectors/reflection.py` is deferred and is not implemented.** Seven detector modules ship: `c2.py`, `ddos.py`, `dga.py`, `dns.py`, `exfil.py`, `scan.py`, `tls_quic.py`.

`reflection.py` is **not** a Definition-of-Done item in `FINAL_DEVELOPMENT_PLAN_V6.3.md` section 46, is not on the never-cut list (section 40), and is not a kill-ladder row. The V6.3 traceability rule requires every externally presented PS class to have **at least one** implementation module; *Volumetric DDoS / flooding* is served by `ddos.py`, which emits real incidents in the canonical campaign. The `reflection` value remains in the frozen `detector` enum in `schemas/alert.schema.json` and its deduplication key remains defined in `config/dedup_keys.yaml`; neither obliges emission.

`PRD.md`, `design.md` and V6.3 describe eight internal modules. **External material must say seven detector modules across six PS classes** until `reflection.py` exists. Do not implement it — new detector work is closed.

## Ownership Coverage

**Complete.** All six previously unnamed responsibilities are confirmed: hash chain → **P4**; offline intel bundle and version manifest → **P2**; baseline snapshot generation → **P2**; model card and evaluation report → **P2**; cold boot and offline asset audit → **P1**; backup recording and screenshots → **P3**.

Coverage sweep against `FINAL_DEVELOPMENT_PLAN_V6.3.md` sections 21 and 46: all 15 repository directories and all 46 Definition-of-Done items have a named owner — `agents.md` section 12. **No unowned responsibility remains.**

---

## Working Systems

- P2 stateless feature extraction: entropy, robust statistics, inter-arrival features, DNS qtype distribution including TXT/NULL/CNAME, TLS/QUIC metadata shape extraction, and deterministic `FEATURE_ORDER` vectorization.
- P2 deterministic training inputs: locally generated DGA families, hard-negative domains, holdout definitions, allowlist/Tranco samples, and baseline snapshot generator.
- P2 non-ML detectors: all seven rule/statistical detector modules, with standard-alert construction confined to detector output (no P4 persistence/API change).

---

## Known Failures

- None from execution. Documentation-level defects are recorded in `bugs.md`. `DOC-012`, the demo-script timeline overlap, is deliberately documented rather than resolved so the V6.3 source timestamps stay intact. **No defect remains OPEN.**

---

## Latest Verification

- **Test:** `python -m unittest discover -s tests/detectors -p test_features.py -v`
- **Result:** PASS — 13 P2 tests passed, including DDoS, Slowloris, reflection, scan, C2, DNS tunnel, TLS/QUIC metadata, exfiltration, alert-schema conformance and `NOT_OBSERVABLE` behavior.
- **Time:** 2026-09-10.

---

## Next Gate

**P2-1 ground-truth milestone.** Deterministic synthetic corpus, holdout definitions, baseline snapshot and versioned offline-intelligence assets must be test-green before model training and detector tuning.

---

## Immediate Next Action

Build P2's deterministic synthetic corpus and holdout definitions, then generate the immutable baseline snapshot and offline intelligence bundle assets. The DGA LightGBM model follows only after those inputs and leakage tests exist.

### Track readiness at Phase 1 start

| Track | Blocked on | Can start immediately with |
|---|---|---|
| P1 | Lab machine, Suricata build | Nothing until the box exists |
| P2 | Nothing | Synthetic event generator, corpora, DGA data |
| P3 | Nothing | **Mock fixtures generated from the frozen alert schema** — explicitly not blocked on P4 |
| P4 | Nothing | FastAPI shell, route contract test, `tests/schema/` |

---

## Feature Freeze Status

**IN EFFECT.** P1/P2/P3/P4 are frozen and accepted. No new detector work, no architecture change, no schema change.

---

## Demo Readiness

| Area | Owner | State |
|---|---|---|
| Sensor / ingestion | P1 | **Ready** — PCAP replay, NetFlow v9 / IPFIX, bounded flow tracking |
| Detection | P2 | **Ready** — seven detector modules, six PS classes demonstrated |
| Dashboard | P3 | **Ready** — build green, feed, drawer and capability banner |
| Backend / API | P4 | **Ready** — seven `GET` routes plus WebSocket, mutating methods 405 |
| Evidence | P2 emits, P3 renders | **Ready** |
| Export | P4 endpoint, P3 surface | **Ready** — JSON and CSV, byte-reproducible |
| End-to-end integration | P4 | **Ready** — canonical campaign replay |
| Boundary proof | P1 | **Ready** — static ingest check plus the live 405 |
| Rehearsal | All | Outstanding |

### Known presentation limits

- `latency_ms` is null on live alerts, so the p95 latency figure is not demonstrable from alert data. Do not quote a latency number that was not measured.
- `model_version` and `intel_version` are populated only on the `dga` alert.
- `confidence` is null on every alert because no detector is calibrated. This is correct: present `score`, `score_type` and `calibrated: false`, and never append a percent sign.
- No LightGBM artifact ships. The documented rule fallback is in use, so publish no Brier score and no reliability diagram.
- The published throughput figure still needs the declared Linux box.

---

## Scope Reminder

Six PS threat classes, seven implemented detector modules (`reflection.py` deferred — see the open finding above), one trained model planned and currently running its documented rule fallback. Passive and read-only; no TLS/QUIC payload decryption; streaming rather than batch; measured throughput published in flows/sec first; every alert carries `timestamp`, non-null `flow_id`, threat class, `confidence` and `evidence`.
