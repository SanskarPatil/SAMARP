# Project Status

**Last Updated:** 2026-09-11
**Current Phase:** Integration complete — demo readiness
**Current Gate:** Final demo rehearsal
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

| Track | State | Detail |
|---|---|---|
| **P1 — Sensor / Infrastructure** | **FROZEN at STEP 7** | Ingest spine complete on this box. STEP 6, STEP 9 (published figure) and STEP 10 remain Linux-gated; STEP 8 deferred by decision. |
| **P2 — Detection / ML** | **COMPLETE** | Window features, entropy, seven detector modules, deduplication and scoring. |
| **P3 — UI / UX** | **COMPLETE** | React/Vite operator dashboard, incident feed, evidence drawer, capability banner. |
| **P4 — Backend / API / Integration** | **COMPLETE** | Read-only FastAPI Plane B, SQLite persistence, hash chain, WebSocket, canonical campaign integration. |

### P1 step status

| Step | State | Blocker |
|---|---|---|
| STEP 3 normalized-event foundation | **DONE** | — |
| STEP 4 PCAP replay + unified clock | **DONE** | — |
| STEP 5 counters, bounded flow tracker, capture loss | **DONE** | — |
| STEP 7 NetFlow v9 / IPFIX adapter (phase P1-5) | **DONE** — satisfies H13 gate item | — |
| STEP 6 Suricata integration | **NOT STARTED** | Needs Linux box. Suricata is Linux-only. Adapter can be written blind here; probe and EVE tail must run on the lab machine |
| STEP 8 sFlow capability handling | **NOT STARTED** | No blocker — pure Python, buildable here. Deferred by decision, not by dependency. `sflow` already a valid frozen `input_mode`; capability baseline already defined in `ingest/capability.py` |
| STEP 9 throughput / capture-loss instrumentation | **PARTIAL** | Loss accounting done in STEP 5. Published throughput number needs the declared Linux box — V6.3 rules WSL2 unacceptable for that figure |
| STEP 10 veth / lab integration | **NOT STARTED** | Needs Linux box. `veth` and `tcpreplay` are Linux-only |

Phase 0 remainder (Suricata build, capability probe, veth lab with egress DROP) is all P1 and all Linux-gated.

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

- **`ingest/` normalized-event foundation (P1).** `identity.py` (canonical serialisation, frozen 16-hex identifiers, `NOT_OBSERVABLE` sentinel), `capability.py` (two-axis capability, per-input-mode baselines), `address_plan.py` (direction inference, bogon exclusion), `normalized_event.py` (single normalizer for all five input modes).
- **`ingest/` PCAP replay path (P1).** `pcap.py` (classic libpcap reader, all four magics, both endiannesses, PCAPNG rejected), `headers.py` (header-only Ethernet/VLAN/IPv4/IPv6/TCP/UDP/ICMP decode), `clock.py` (unified replay clock, start-once), `replay.py` (deterministic driver, speed control).
- **`ingest/` counters, bounded flow tracking and capture loss (P1).** `counters.py` (header-only `PacketCounter`, `CaptureLossAccount` reporting an explicit lower bound), `flow_tracker.py` (LRU-bounded flow table producing `flow_summary` per V6.3 §6.2 — from the in-process tracker, never Suricata EVE flow output).
- **`ingest/flow_record_adapter.py` — NetFlow v9 / IPFIX (P1).** One shared template-based decoder for both protocols per V6.3 §2.4, not two parsers. Bounded LRU template cache with idle expiry, scoped by exporter and observation domain. Emits the same normalized event contract as the packet path.
- **`features/` window and lexical features (P2).** `feature_order.py` (frozen `FEATURE_ORDER`, imported by every producer), `rolling.py` (tumbling window aggregator), `entropy.py`.
- **`detectors/` seven modules (P2).** `ddos.py` (flood and the distinct Slowloris low-rate path), `scan.py`, `c2.py`, `dga.py` (rule fallback, `model_version: "rules-fallback"`, `calibrated: false`), `dns.py`, `tls_quic.py`, `exfil.py`, wired by `pipeline.py`.
- **`alerts/` deduplication, scoring and chain (P2 emits, P4 chains).** `deduplicator.py` (keys frozen in `config/dedup_keys.yaml`), `scorer.py`, `hash_chain.py` (single home for the canonicalisation helper, the concatenation rule and the truncation rule; full 64-character `payload_hash`, `entry_hash`, `prev_hash`).
- **`api/` read-only Plane B (P4).** `main.py`, `routes.py` (seven `GET` paths), `state.py` (250 ms batched pushes), `websocket.py` (`/ws/incidents`), `persistence.py` (SQLite store, JSON and CSV export).
- **`dashboard/` operator console (P3).** React/Vite; `IncidentFeed.tsx`, `IncidentRow.tsx`, `EvidenceDrawer.tsx`, `CapabilityBanner.tsx`, `Header.tsx`, `DemoTourModal.tsx`; `useIncidents.ts`; `api.ts`, `websocket.ts`, `mockFixtures.ts`.
- **`scenarios/canonical_campaign.py` (P4).** Deterministic seven-beat campaign driving the whole pipeline.
- **`scripts/run_demo.py` (P4).** Replay launcher, export writer, chain verifier and API server entry point.

---

## Known Failures

- None from execution. Documentation-level defects are recorded in `bugs.md`. `DOC-012`, the demo-script timeline overlap, is deliberately documented rather than resolved so the V6.3 source timestamps stay intact. **No defect remains OPEN.**

---

## Latest Verification

**Date:** 2026-09-11. **Commit:** `5f62f42`. **Working tree:** clean.

- **Test:** `python -m pytest tests/ -q`
- **Result:** **321 passed**, 0 failed, 17.73 s. By directory: 248 `ingest`, 30 `detectors`, 17 `alerts`, 10 `hash_chain`, 9 `api`, 4 `parity`, 1 each `integration`, `throughput`, `ui_load`. The two warnings are Starlette/anyio deprecations raised inside `starlette.testclient`, not project code.
- **Frontend build:** `cd dashboard && npm run build` (`tsc && vite build`) → 1 602 modules transformed, 0 TypeScript errors. `index.html` 0.66 kB, CSS 17.47 kB (gzip 3.70 kB), JS 194.09 kB (gzip 60.33 kB). Asset hashes reproduce across builds.
- **Canonical campaign replay:** **12 137 events → 13 raw alerts → 10 distinct incidents**, chain sequence 13, hash chain verified, 0.90 s. Two independent runs from a clean state produced exports **byte-identical** to the committed `export/canonical_campaign_export.json` and `export/canonical_campaign_export.csv`.
- **Six PS 26145 threat classes verified** in one replay: Botnet C2 beaconing 3, DGA / DNS tunnelling 2, Data exfiltration 1, Malware in encrypted sessions 1, Port scanning / reconnaissance 1, Volumetric DDoS / flooding 2.
- **Hash chain verified standalone**, in a clean process with no writer runtime state, by both entry points — `python tests/hash_chain/verify_hash_chain.py export/canonical_campaign_export.json` and `python scripts/run_demo.py --verify-only export/canonical_campaign_export.json`.
- **Plane B route surface:** seven `GET` paths — `/health`, `/capabilities`, `/incidents`, `/incidents/{incident_id}`, `/incidents/{incident_id}/history`, `/export/json`, `/export/csv` — plus the WebSocket `/ws/incidents`, which delivers a snapshot frame and answers `ping` with `pong`. `POST`, `PUT`, `DELETE` and `PATCH` on `/incidents` all return **405**. `POST /simulate/scenario/1` returns **404**; the route was removed and has not returned.
- **Offline:** no CDN script, stylesheet or web font in the dashboard. Frontend dependencies are `react`, `react-dom` and `lucide-react`, all bundled. The only external strings in the build output are W3C XML namespaces and a React error-decoder URL, neither of which is fetched. No network import in `alerts/`, `api/`, `detectors/`, `features/`, `ingest/` or `scenarios/`.
- **Repository hygiene:** 123 tracked files; no database, log, environment file, key, certificate, credential or temporary file is tracked.

### Retained ingest verification

- **STEP 7 measured:** NetFlow v9 fixture decodes 3 records, IPFIX fixture decodes 2; both validate against the frozen schema. The same five-tuple yields the same `flow_id` `4242dae276b9f525` across **both protocols and the packet path** — one identity rule, three input modes. Template register → replace → decode-with-new-layout → expire all demonstrated. 2 000 template IDs against a 32 cap → active 32, peak 32, 1 968 evictions, **cap never exceeded**.
- **`NOT_OBSERVABLE` preserved:** `dns_names`, `dns_responses`, `tls_handshake`, `quic_metadata`, `ja3`, `ja3s`, `ja4` all `NOT_OBSERVABLE` on flow-record input; `flow_records` `OBSERVABLE`; `bidirectional_visibility` `DEGRADED`.
- **Bounded state proven:** 10 000 distinct 5-tuples against a 100-flow cap → active 100, peak 100, 9 900 evictions counted, **cap never exceeded at any point**.
- **Capture loss:** `sensor_drop_pct 16.67`, `estimator "pcap_parse_and_snaplen"`, `is_lower_bound true`, `kernel_drops`/`ring_drops` **null**; `capture_loss` capability `DEGRADED`.
- **`t_replay_start` captured exactly once**, written to the manifest; starting twice is refused by contract.
- **Static boundary check across all `ingest/` modules:** no egress-capable import, no `connect`/`sendto`/`bind`/`listen`, no file writes, no payload-capable field.

---

## Demo Commands

```bash
# 1. Full suite
python -m pytest tests/ -q

# 2. Canonical campaign replay, exports and chain verification in one run
python scripts/run_demo.py --replay-only

# 3. Standalone hash-chain verification, clean process, no writer state
python tests/hash_chain/verify_hash_chain.py export/canonical_campaign_export.json
python scripts/run_demo.py --verify-only export/canonical_campaign_export.json

# 4. Live read-only Plane B API, then the dashboard in a second terminal
python scripts/run_demo.py --serve
cd dashboard && npm run dev            # http://localhost:5173

# 5. Read-only boundary proof, in front of the audience
curl -s -o /dev/null -w "POST=%{http_code}\n" -X POST http://127.0.0.1:8000/incidents   # 405
```

Serve the dashboard with `npm run dev`, not `npm run preview`: the API proxy is configured under `server.proxy` in `dashboard/vite.config.ts` and `vite preview` does not apply it.

**`/docs` and `/redoc` are not part of the offline demo path.** FastAPI's generated documentation pages load Swagger UI and ReDoc from a CDN and will not render without internet access. Demonstrate the API with the `curl` commands above and with the dashboard.

---

## Next Gate

**Final demo rehearsal.** The build path, replay path, chain verification and boundary proof are all green and reproducible.

---

## Immediate Next Action

Rehearsal and demo hygiene only. The remaining Phase 0 environment work is Linux-gated and is not on the demo path:

1. Confirm the OS/box decision and record the machine specification. **WSL2 is not acceptable** for the published throughput number.
2. Build and version-check Suricata (7.0.3 or later for JA4).
3. Run the capability probe against a known fixture PCAP; record every acceptance line, including the JA3/JA3S/JA4 verdict and `flow events == 0`.
4. Build the isolated veth lab; set egress DROP.

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
