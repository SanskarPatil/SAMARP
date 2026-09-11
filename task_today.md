# Task Today

**Updated:** 2026-09-11
**Timebox:** demo rehearsal
**Current Phase:** Integration complete — demo readiness
**Current Gate:** Final demo rehearsal
**Overall Status:** GREEN

> Keep this file small and short-lived. It holds only the current focused work period — roughly the next two hours. Project state is in `STATUS.md`; the roadmap is in `implementation_plan.md`.

---

## Current Objective

**Rehearse the demo. Change no code.** P1/P2/P3/P4 are frozen and accepted at commit `5f62f42`.

### Delivered

- [x] **P1 — Sensor / Infrastructure, frozen at STEP 7.** Normalized-event foundation, PCAP reader, header-only decode, unified replay clock with `t_replay_start` captured exactly once, deterministic replay driver, header-only counters, bounded flow tracker, capture-loss accounting, and the shared NetFlow v9 / IPFIX template adapter.
- [x] **P2 — Detection / ML, complete.** `features/rolling.py` and `features/entropy.py` against the frozen `FEATURE_ORDER`; seven detector modules — `ddos.py` (flood plus the distinct Slowloris low-rate path), `scan.py`, `c2.py`, `dga.py`, `dns.py`, `tls_quic.py`, `exfil.py` — wired by `detectors/pipeline.py`; `alerts/deduplicator.py` and `alerts/scorer.py`.
- [x] **P4 — Backend / API / Integration, complete.** Read-only FastAPI Plane B with seven `GET` routes and the `/ws/incidents` WebSocket, 250 ms batched pushes, SQLite persistence with JSON and CSV export, `alerts/hash_chain.py`, `scenarios/canonical_campaign.py` and `scripts/run_demo.py`.
- [x] **P3 — UI / UX, complete.** React/Vite operator dashboard — incident feed, incident row, evidence drawer, capability banner, header, demo tour modal, `useIncidents` hook, API and WebSocket services.
- [x] **321 tests pass** (`python -m pytest tests/ -q`).
- [x] **Frontend production build passes** (`cd dashboard && npm run build`) — 1 602 modules, 0 TypeScript errors.
- [x] **Canonical campaign replay verified:** 12 137 events → 13 raw alerts → 10 distinct incidents, chain sequence 13, hash chain verified, exports byte-identical across independent runs.
- [x] **Six PS 26145 threat classes verified** in a single replay: Botnet C2 beaconing, DGA / DNS tunnelling, Data exfiltration, Malware in encrypted sessions, Port scanning / reconnaissance, Volumetric DDoS / flooding.

### Not delivered, and not required today

- [ ] Suricata EVE tail with partial-line handling *(STEP 6 — Linux box required)*.
- [ ] sFlow capability handling *(STEP 8 — deferred by decision, not by dependency)*.
- [ ] Published throughput figure *(STEP 9 — needs the declared Linux box; WSL2 is not acceptable)*.
- [ ] veth pair / one-way enclave *(STEP 10 — Linux box required)*.
- [ ] `detectors/reflection.py` — **deferred. Not a Definition-of-Done item.** See the open finding in `STATUS.md`.

---

## Demo Commands

```bash
# Full suite
python -m pytest tests/ -q

# Canonical campaign replay, exports and chain verification in one run
python scripts/run_demo.py --replay-only

# Standalone hash-chain verification, clean process, no writer state
python tests/hash_chain/verify_hash_chain.py export/canonical_campaign_export.json
python scripts/run_demo.py --verify-only export/canonical_campaign_export.json

# Live read-only Plane B API, then the dashboard in a second terminal
python scripts/run_demo.py --serve
cd dashboard && npm run dev            # http://localhost:5173

# Read-only boundary proof
curl -s -o /dev/null -w "POST=%{http_code}\n" -X POST http://127.0.0.1:8000/incidents   # 405
```

Serve the dashboard with `npm run dev`, not `npm run preview`: the API proxy lives under `server.proxy` in `dashboard/vite.config.ts` and `vite preview` does not apply it.

**`/docs` and `/redoc` are not part of the offline demo path.** Those pages load Swagger UI and ReDoc from a CDN and will not render without internet access. Show the API through the `curl` commands above and through the dashboard.

---

## Priority Tasks

### 1. Rehearse the run order

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

**None on the demo path.** Tests, build, replay, chain verification and the boundary proof are all green at `5f62f42` with a clean working tree.

**Environment (unchanged).** The development box is Windows. Suricata, `veth`, `tcpreplay` and live tap are Linux-only, and V6.3 rules WSL2 unacceptable for the published throughput number.

---

## Do Not Work On

- Any new detector, `reflection.py` included. New detector work is closed.
- Any schema change, any frozen-contract change, any architecture change.
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
