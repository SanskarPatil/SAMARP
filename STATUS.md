# Project Status

**Last Updated:** 2026-09-10
**Current Hour:** Pre-window (build window not opened)
**Current Phase:** Phase 0 — Foundation (not started)
**Current Gate:** Phase 0 exit gate (H1)
**Overall Status:** GREEN

> This file is the project's current state in under a minute. Immediate work is in `task_today.md`; the full roadmap is in `implementation_plan.md`.

---

## Completed

- Source documents reviewed in full: `ps26145_traceability_matrix.md`, `FINAL_DEVELOPMENT_PLAN_V6.3.md`, `create_project_md_files_V2.md`.
- Cross-document consistency analysis completed; contradictions and omissions recorded in `bugs.md` as `DOC-001` through `DOC-011`.
- Documentation layer generated: `PRD.md`, `design.md`, `implementation_plan.md`, `CLAUDE.md`, `agents.md`, `testing.md`, `git.md`, `STATUS.md`, `task_today.md`, `memory.md`, `bugs.md`.
- **Phase 0 decisions taken and applied** — throughput acceptance target, canonical identifier form, dedup sentinel, test subtree. Rationale in `memory.md`; defect history in `bugs.md`.
- **Frozen contracts written:** `schemas/normalized_event.schema.json`, `schemas/alert.schema.json`, `features/feature_order.py`, `config/thresholds.yaml`, `config/address_plan.yaml`, `config/dedup_keys.yaml`.
- Test subtree created, including the two previously missing directories.
- **Four-person ownership split applied** — P1 Sensor/Infrastructure, P2 Detection/ML, P3 UI/UX, P4 Backend/API/Integration. `agents.md` rewritten; `implementation_plan.md` phases renamed and Track C split into P3 and P4.
- **Six supplementary responsibilities confirmed and recorded**; hash-chain duplication between P1-3 and P4-2 removed, and the tamper-demonstration artifact moved with the chain to P4-4.

---

## In Progress

- Phase 0 remainder: Suricata build and capability probe, isolated veth lab with egress DROP, and contract tests in `tests/schema/`. No feature implementation has begun.

---

## Blocked

- Nothing. All four Phase 0 contract decisions have been made and applied; `DOC-004`, `DOC-006`, `DOC-007` and `DOC-009` are closed.

## Open Finding — P1, needs a decision before the H6 gate

**`external.*` in `config/address_plan.yaml` is still empty, and how it is filled matters.**

Python's `ipaddress` treats RFC 5737 documentation ranges as private. If `external.benign`, `external.synthetic_malicious` or `external.amplifier_hosts` are populated with documentation space, the reflection reserved-source share returns to ~100 % on benign traffic — **the exact trap section 2A.3 exists to prevent, reintroduced one level down**, and the false-alerts-per-hour figure is destroyed again.

The plan already requires *"curated public ranges, GeoLite2-resolvable"*. This finding records **why** that wording is load-bearing rather than stylistic. Owner: P1 (plan) with P2 (reflection detector). Pinned by `tests/ingest/test_address_plan.py::test_documentation_ranges_count_as_reserved_not_public`.

## Open Finding — P1, needs a decision before the H6 gate

**`external.*` in `config/address_plan.yaml` is still empty, and how it is filled matters.**

Python's `ipaddress` treats RFC 5737 documentation ranges as private. If `external.benign`, `external.synthetic_malicious` or `external.amplifier_hosts` are populated with documentation space, the reflection reserved-source share returns to ~100 % on benign traffic — **the exact trap section 2A.3 exists to prevent, reintroduced one level down** — and the false-alerts-per-hour figure is destroyed again.

The plan already requires *"curated public ranges, GeoLite2-resolvable"*. This finding records **why** that wording is load-bearing rather than stylistic. Owner: P1 (plan) with P2 (reflection detector). Pinned by `tests/ingest/test_address_plan.py::test_documentation_ranges_count_as_reserved_not_public`.

## Ownership Coverage

**Complete.** All six previously unnamed responsibilities are confirmed: hash chain → **P4**; offline intel bundle and version manifest → **P2**; baseline snapshot generation → **P2**; model card and evaluation report → **P2**; cold boot and offline asset audit → **P1**; backup recording and screenshots → **P3**.

Coverage sweep against `FINAL_DEVELOPMENT_PLAN_V6.3.md` sections 21 and 46: all 15 repository directories and all 46 Definition-of-Done items have a named owner. **No unowned responsibility remains** — `agents.md` section 12.

---

## Working Systems

- **`ingest/` normalized-event foundation (P1).** `identity.py` (canonical serialisation, frozen 16-hex identifiers, `NOT_OBSERVABLE` sentinel), `capability.py` (two-axis capability, per-input-mode baselines), `address_plan.py` (direction inference, bogon exclusion), `normalized_event.py` (single normalizer for all five input modes).
- **`ingest/` PCAP replay path (P1).** `pcap.py` (classic libpcap reader, all four magics, both endiannesses, PCAPNG rejected), `headers.py` (header-only Ethernet/VLAN/IPv4/IPv6/TCP/UDP/ICMP decode), `clock.py` (unified replay clock, start-once), `replay.py` (deterministic driver, speed control).
- **`ingest/` counters, bounded flow tracking and capture loss (P1).** `counters.py` (header-only `PacketCounter`, `CaptureLossAccount` reporting an explicit lower bound), `flow_tracker.py` (LRU-bounded flow table producing `flow_summary` per V6.3 §6.2 — from the in-process tracker, never Suricata EVE flow output).
- **`ingest/flow_record_adapter.py` — NetFlow v9 / IPFIX (P1).** One shared template-based decoder for both protocols per V6.3 §2.4, not two parsers. Bounded LRU template cache with idle expiry, scoped by exporter and observation domain. Emits the same normalized event contract as the packet path. 3 455 lines across twelve modules.
- No other runtime component exists. No detector, API, persistence or dashboard code.

---

## Known Failures

- None from execution. Twelve documentation-level defects are recorded in `bugs.md`. Seven were resolved by authority precedence, four by explicit Phase 0 decision, and one (`DOC-012`, the demo-script timeline overlap) is deliberately documented rather than resolved so the V6.3 source timestamps stay intact. **No defect remains OPEN.**

---

## Latest Verification

- **Test:** `python -m pytest tests/ -q`
- **Result:** **248 passed**, 0 failed, 4.26 s. (72 foundation + 91 replay + 46 STEP 5 + 39 STEP 7.)
- **STEP 7 measured:** NetFlow v9 fixture decodes 3 records, IPFIX fixture decodes 2; both validate against the frozen schema. Same five-tuple yields the same `flow_id` `4242dae276b9f525` across **both protocols and the packet path** — one identity rule, three input modes. Template register → replace → decode-with-new-layout → expire all demonstrated. Data-before-template deferred (not guessed) then decoded once the template arrives. 2 000 template IDs against a 32 cap → active 32, peak 32, 1 968 evictions, **cap never exceeded**.
- **`NOT_OBSERVABLE` preserved:** `dns_names`, `dns_responses`, `tls_handshake`, `quic_metadata`, `ja3`, `ja3s`, `ja4` all `NOT_OBSERVABLE` on flow-record input; `flow_records` `OBSERVABLE`; `bidirectional_visibility` `DEGRADED`. No `dns`/`tls`/`quic`/`shape` block is emitted — flow records cannot supply them and none is invented.
- **STEP 5 measured on the deterministic fixture:** 5 packets / 298 wire bytes / 278 captured; `by_protocol {TCP: 3, UDP: 2}`; all four directions counted; 4 flows created from 5 packets (the two directions of one conversation share a flow).
- **Bounded state proven:** 10 000 distinct 5-tuples against a 100-flow cap → active 100, peak 100, 9 900 evictions counted, **cap never exceeded at any point**. Idle expiry, absolute-lifetime rotation and LRU capacity eviction each demonstrated and accounted separately.
- **Capture loss:** `sensor_drop_pct 16.67`, `estimator "pcap_parse_and_snaplen"`, `is_lower_bound true`, `kernel_drops`/`ring_drops` **null** (no sensor on this path — NOT_OBSERVABLE, not zero); `capture_loss` capability `DEGRADED`.
- **Replay demonstrated:** representative event validates against the frozen schema; three independent replays are byte-identical; display spacing mirrors capture spacing exactly (5 s capture span → 5 s display span, no drift); speed control scales display span 5 s → 2.5 s → 0.5 s at 1×/2×/10×; counters account for every packet (6 read = 5 parsed + 1 unparseable, 1 truncated, measured parse loss 16.67 %).
- **`t_replay_start` captured exactly once**, written to the manifest; starting twice is refused by contract.
- **Static boundary check across all nine `ingest/` modules:** no egress-capable import, no `connect`/`sendto`/`bind`/`listen`, **no file writes at all** (read-only), no payload-capable field.

### Milestone 1 verification (retained)

- 72 ingest-foundation tests: canonical serialisation, the frozen `sha256(...).hexdigest()[:16]` identifier, bidirectional flow identity, sentinel substitution, direction inference, the RFC 1918 bogon trap, schema conformance for all five input modes.
- **Coverage:** canonical serialisation and the frozen `sha256(...).hexdigest()[:16]` identifier (incl. an explicit assertion that the 16-*byte* misreading is not produced); bidirectional flow identity; `NOT_OBSERVABLE` sentinel substitution; direction inference for all four enum values; the RFC 1918 bogon-exclusion trap; schema conformance for all five input modes; capability two-axis separation; sFlow not claiming packet-level visibility.
- **Static boundary check:** `ingest/` imports no `socket`, `http`, `urllib`, `subprocess` or crypto module; contains no `connect`/`send`/`bind` call, no file write, and no payload access. Passive by construction.
- **Time:** 2026-09-10.

### Defects found and fixed by the tests

**Milestone 1**
1. `display_time` is typed `string` (**not** nullable) by the frozen schema, unlike every other optional field. The normalizer emitted an explicit null under `drop_none=False` and failed validation. Fixed in code — the schema was not touched.
2. Python's `ipaddress` classifies RFC 5737 documentation ranges as **private**. A fixture used one as "external and routable" and correctly failed. See the open finding below.

**STEP 4**
3. **Big-endian PCAP writer bug (real).** The fixture builder wrote the byte-swapped magic `0xd4c3b2a1` in big-endian order, producing a file that read back as *little-endian*. A big-endian capture stores the canonical `0xa1b2c3d4` in big-endian byte order. Caught by the parametrised magic test.
4. **`capture_loss` capability semantics.** A snapped capture gives *partial* loss visibility — truncation is observable from `caplen` vs `wirelen`, but kernel/ring drops are not. `DEGRADED` is the honest state; `OBSERVABLE` would claim precision we lack and `NOT_OBSERVABLE` would hide evidence we have.
5. **A test asserted the wrong invariant.** It required a constant 1 s display gap, but the canonical fixture contains an ARP frame that yields no event, so one legitimate gap is 2 s. The real invariant — display spacing *mirrors* capture spacing — is now asserted per-pair and on the total span, which is a strictly stronger check.

**STEP 5**
6. **`flow_id` divergence between tracker and normalizer (real, and the most serious so far).** The flow tracker hashed the raw numeric IP protocol (`6`) while the normalizer hashed the canonical name (`"TCP"`), so the same flow produced **two different `flow_id`s** — an event's `flow_summary.flow_id` disagreed with its own `flow_id`. Caught by the integration test. Fixed by canonicalising protocol once, in the same helper both paths use; pinned by `test_tracker_and_normalizer_agree_on_flow_id`. This is the same class of failure DOC-006 exists to prevent, one level down.
7. **Counter protocol keys** had the same root cause — `by_protocol` was keyed `{'6', '17'}` rather than `{TCP, UDP}`. Cosmetic (internal telemetry, not a schema field) but fixed alongside so counter output cannot disagree with event output.

---

## Next Gate

**Phase 0 exit (H1).** Contract tests exist and pass; the JA3/JA3S/JA4 capability result is recorded; the lab interface has no route and no egress.

---

## Immediate Next Action

Complete the remaining Phase 0 environment work, in this order:

1. Confirm the OS/box decision and record the machine specification. **WSL2 is not acceptable** for the published throughput number.
2. Build and version-check Suricata (7.0.3 or later for JA4).
3. Run the capability probe against a known fixture PCAP; record every acceptance line, including the JA3/JA3S/JA4 verdict and `flow events == 0`.
4. Build the isolated veth lab; set egress DROP.
5. Write the contract tests in `tests/schema/` against the now-frozen schemas (**P4**).

Items 1–4 are P1's and need the Linux lab machine. Item 5 is P4's and needs nothing but the frozen schemas.

Then the Phase 0 exit gate can be assessed. **Feature implementation does not begin until that gate is green.**

### Track readiness at Phase 1 start

| Track | Blocked on | Can start immediately with |
|---|---|---|
| P1 | Lab machine, Suricata build | Nothing until the box exists |
| P2 | Nothing | Synthetic event generator, corpora, DGA data |
| P3 | Nothing | **Mock fixtures generated from the frozen alert schema** — explicitly not blocked on P4 |
| P4 | Nothing | FastAPI shell, route contract test, `tests/schema/` |

---

## Feature Freeze Status

**NOT REACHED** (freeze begins at H19).

---

## Demo Readiness

| Area | Owner | State |
|---|---|---|
| Sensor / ingestion | P1 | Not started |
| Detection | P2 | Not started |
| Dashboard | P3 | Not started |
| Backend / API | P4 | Not started |
| Evidence | P2 emits, P3 renders | Not started |
| Export | P4 endpoint, P3 surface | Not started |
| End-to-end integration | P4 | Not started |
| Boundary proof | P1 | Not started |
| Rehearsal | All | Not started |

---

## Scope Reminder

Six PS threat classes, eight detector modules, one trained model (DGA LightGBM). Passive and read-only; no TLS/QUIC payload decryption; streaming rather than batch; measured throughput published in flows/sec first; every alert carries `timestamp`, non-null `flow_id`, threat class, `confidence` and `evidence`.
