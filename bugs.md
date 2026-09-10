# Bugs

Structured record of failures — what is broken, what was broken, and why. Never delete an important resolved entry; its root cause is what prevents the regression.

**Numbering:** `DOC-NNN` entries are defects found in the source documentation by cross-document review. `BUG-NNN` is reserved for runtime and implementation failures once code exists.

---

## Active Bugs

No runtime bugs. No implementation exists yet.

---

## Documentation Defects

Found by reviewing `ps26145_traceability_matrix.md`, `FINAL_DEVELOPMENT_PLAN_V6.3.md` and `create_project_md_files_V2.md` against one another on 2026-09-10. Each was resolved by preferring the higher authority, never by inventing a requirement.

**Status as of Phase 0:** `DOC-001`, `DOC-002`, `DOC-003`, `DOC-005`, `DOC-008`, `DOC-010`, `DOC-011` resolved by authority precedence during documentation generation. `DOC-004`, `DOC-006`, `DOC-007`, `DOC-009` resolved by explicit project-owner decision at Phase 0. `DOC-012` is documented rather than resolved — the V6.3 source timestamps are deliberately preserved. **No item remains OPEN.**

---

### DOC-001 — Six PS class label strings are not verbatim-consistent

**Status:** RESOLVED
**Severity:** HIGH
**Owner:** B
**Area:** Terminology / alert schema

#### Symptom
The six external PS class strings are spelled three different ways across the source documents, while `FINAL_DEVELOPMENT_PLAN_V6.3.md` section 1.1 declares its own left column to be the verbatim external wording and section 23.1 mandates a contract test on the `detector`-to-`ps_class` mapping.

#### Reproduction
Compare class 1, 2 and 4 across V6.3 section 1.1, V6.3 section 1.2, traceability matrix section 3, and the documentation spec's PRD include-list.

#### Expected
One frozen string per class, used verbatim everywhere external.

#### Actual
`Volumetric DDoS / flooding` vs `Volumetric / protocol DDoS`; `Port scanning / reconnaissance` vs `Reconnaissance / port scanning`; `DGA / DNS tunnelling` vs `DGA domains / DNS tunnelling` vs `DGA domains and DNS tunnelling`.

#### Root Cause
Section 1.2 and the traceability matrix restate the class names in prose without treating section 1.1 as authoritative, so three variants propagated.

#### Fix
The section 1.1 left column is the frozen `ps_class` enum, because section 1.1 is the section that declares the terminology rule. All generated documents use it verbatim. Other spellings remain acceptable in prose but must never reach the schema.

#### Regression Test
Contract test asserting the six `ps_class` values match the frozen strings exactly, and that every `detector` maps to exactly one of them.

---

### DOC-002 — Ticket 0 contradicts the Hour-6 gate on the PCAP generation deadline

**Status:** RESOLVED
**Severity:** HIGH
**Owner:** B
**Area:** Execution plan / scenario generation

#### Symptom
Two different deadlines are given for when attack PCAP generation stops.

#### Reproduction
Compare V6.3 section 30 (Hour-6 gate items), section 45 Ticket 0 opening narrative, and section 45 Ticket 0 "Done when".

#### Expected
One deadline.

#### Actual
Hour-6 gate: *"Generation stops here; after hour 6 the lab is replay-only."* Ticket 0 narrative: *"before the console switches to replay-only at hour 16."* Ticket 0 done-when: *"complete, hashed and manifested at the hour-6 gate. Generation stops there."*

#### Root Cause
The hour-16 phrase is stale narrative carried forward from V6.2, where the console mode switch and the generation deadline were the same event.

#### Fix
Generation stops at **hour 6** — two of three binding statements say so, including Ticket 0's own exit criterion. The hours 16–19 "switch Scenario Console to REPLAY mode" is console hardening (making GENERATE unreachable), not the generation deadline. No third date was invented.

#### Regression Test
Hour-6 gate checklist item: the attack PCAP set is complete, hashed and manifested.

---

### DOC-003 — sFlow is described three incompatible ways

**Status:** RESOLVED
**Severity:** HIGH
**Owner:** A
**Area:** Capability model / input modes

#### Symptom
The documentation spec instructs agents to "recognize sFlow as `NOT_OBSERVABLE`", which treats an input mode as if it were a detector capability state.

#### Reproduction
Compare the documentation spec's CLAUDE rule 17 and its design.md section, against V6.3 section 2.4 and section 49.

#### Expected
`NOT_OBSERVABLE` applies per detector; an input mode is either supported or not.

#### Actual
Spec: sFlow is `NOT_OBSERVABLE`. V6.3 section 2.4: sampling-aware volumetric statistics may remain usable; only order-, name- and fingerprint-dependent detectors degrade. V6.3 section 49: recognised as a sampled input mode, not implemented as a packet-equivalent detector source.

#### Root Cause
Conflation of two distinct axes — input-mode support and per-detector evidence visibility.

#### Fix
V6.3 wins. `sflow` is a **valid, frozen `input_mode` value**; sampling state is always surfaced; per-detector capability degrades to `DEGRADED` or `NOT_OBSERVABLE`. "sFlow is `NOT_OBSERVABLE`" is not a valid statement in this system, and no generated document makes it.

#### Regression Test
`input_mode` enum contract test; capability-degradation test for sampled input.

---

### DOC-004 — The primary throughput KPI has no declared target

**Status:** RESOLVED — Phase 0 decision
**Severity:** HIGH
**Owner:** A
**Area:** Measurement / NFR-2

#### Symptom
Section 14.1 names sustained **flows/sec** the primary PS-aligned KPI and instructs that it be published first, but declares numeric targets only for pps and Mbps.

#### Reproduction
Read V6.3 section 14.1; note `Target >= 50 000 pps sustained, >= 400 Mbps` alongside `Primary PS KPI sustained flows/sec (publish first)`.

#### Expected
The primary metric has a target, so optimisation has a stopping condition.

#### Actual
No flows/sec number exists anywhere in the three documents.

#### Root Cause
The PS-alignment change reordered the published metrics without moving the target with them. This is precisely the defect section 14.1 says it exists to fix — *"a measured number with no target has no stopping condition"* — reintroduced one metric up.

#### Fix
Decided by the project owner at Phase 0 and frozen:

```text
Primary PS KPI      >= 1 000 normalized flows/sec, sustained 60 s, < 1 % measured loss
Secondary (V6.3)    >= 50 000 pps,  sustained 60 s, < 1 % loss
                    >= 400 Mbps,    sustained 60 s, < 1 % loss
```

The V6.3 secondary figures are retained **unchanged**. A metric-separation rule was added alongside: flows/sec, pps and Mbps are three independent measurements and are never conflated or derived from one another.

Applied to `PRD.md` NFR-2/NFR-3/NFR-4 plus the metric-separation note, `PRD.md` section 15 acceptance criteria, `testing.md` section 10 target table and Definition of Done, `CLAUDE.md` performance rules, `implementation_plan.md` section 13, and `config/thresholds.yaml` (`throughput:` block).

#### Regression Test
`tests/throughput/` asserts sustained normalized flows/sec against the 1 000 target over a 60 s replay with loss below 1 %, and asserts pps and Mbps separately against their own targets. The box specification is emitted with the result.

---

### DOC-005 — `UNAVAILABLE` is declared but appears in no capability table

**Status:** RESOLVED
**Severity:** MEDIUM
**Owner:** A
**Area:** Capability model

#### Symptom
Four capability states are declared, but only three are ever used.

#### Reproduction
Compare V6.3 section 7 and traceability matrix section 7 (four states) against V6.3 sections 7.2 and 7C (three states) and section 23.10 (`DEGRADED` or `UNAVAILABLE` for health).

#### Expected
Every declared state has a defined usage.

#### Actual
`UNAVAILABLE` is used only for component health in section 23.10, and the two axes are never distinguished.

#### Root Cause
Two different concepts share one vocabulary list.

#### Fix
Documented as two axes: evidence visibility per detector (`OBSERVABLE | DEGRADED | NOT_OBSERVABLE`) and component health per component (`HEALTHY | DEGRADED | UNAVAILABLE`). No new state was invented; the distinction is derived from V6.3 section 7 plus section 23.10.

#### Regression Test
Sensor failure/recovery test asserts health transitions; capability contract test asserts detector states.

---

### DOC-006 — `sha256(...)[:16]` is ambiguous

**Status:** RESOLVED — Phase 0 decision
**Severity:** HIGH
**Owner:** B
**Area:** Frozen contracts / identity

#### Symptom
The truncation is unspecified between 16 hex characters and 16 bytes.

#### Reproduction
Read V6.3 section 6.3 (`flow_id`) and section 13.1 (incident identity). Both use `[:16]` without stating the representation.

#### Expected
One unambiguous definition, imported by every producer.

#### Actual
In Python, `[:16]` on a hexdigest yields 16 hex characters (64 bits); on `digest()` it yields 16 bytes (128 bits). Two developers will pick differently, and the identities will not match across restarts or between writer and verifier.

#### Root Cause
Shorthand carried from prose into a frozen contract without expansion.

#### Fix
Decided by the project owner at Phase 0 and frozen:

```text
identifier = sha256(canonical_value).hexdigest()[:16]
```

- Exactly **16 lowercase hexadecimal characters** — a 64-bit truncated SHA-256. Schema pattern `^[0-9a-f]{16}$`.
- Truncation is applied to the **hex digest**, never to `digest()`. `[:16]` is not 16 bytes.
- Applies to `flow_id` and `incident_id`.
- **Does not apply to the hash chain.** `payload_hash`, `entry_hash` and `prev_hash` remain full 64-character SHA-256 digests, consistent with the genesis `"0" * 64`.
- The canonicalisation helper and the truncation live **once** in `alerts/hash_chain.py`; every producer and every verifier imports them.

Applied to `design.md` section 9.4 (new "Canonical identifier representation — frozen" block, plus the `flow_id` derivation), `design.md` section 17 (incident identity), `design.md` section 18 (explicit no-truncation note for chain fields), `CLAUDE.md` coding rules, `testing.md` section 2, and `schemas/alert.schema.json`.

#### Regression Test
Contract test asserting `flow_id` and `incident_id` match `^[0-9a-f]{16}$`, that identity is stable across a restart, and that writer and verifier produce byte-identical output from the shared helper.

---

### DOC-007 — Frozen dedup keys depend on evidence that may be absent

**Status:** RESOLVED — Phase 0 decision
**Severity:** HIGH
**Owner:** B
**Area:** Deduplication / capability interaction

#### Symptom
Three deduplication keys reference fields the capability model says are normally `NOT_OBSERVABLE` under flow-record input.

#### Reproduction
Compare V6.3 section 13.1 keys against sections 7.2, 7C and 49.

#### Expected
Defined behaviour when a key component is null.

#### Actual
`tls_quic` keys on `ja3`; `dns_tunnel` keys on `registered_domain`; `reflection` keys on `amplifier_port`. Under NetFlow/IPFIX all three are normally unavailable, and V6.3 does not say what the key becomes.

#### Root Cause
The dedup keys were frozen in the same version that formalised capability degradation, but the two sections were not cross-checked.

#### Fix
Decided by the project owner at Phase 0 and frozen: an unavailable key component takes the **exact canonical sentinel string `NOT_OBSERVABLE`**. Never null, empty string, zero, `unknown`, or any other placeholder. Deduplication operates on the canonical serialized key containing the sentinel.

```text
tls_quic      (ps_class, src_ip, NOT_OBSERVABLE, dst_ip)      ja3 absent under IPFIX
dns_tunnel    (ps_class, src_ip, NOT_OBSERVABLE)              registered_domain absent
reflection    (ps_class, dst_ip, NOT_OBSERVABLE)              amplifier_port absent
```

Because an `aggregate` `flow_id` is derived from the canonical dedup key, the sentinel propagates into `flow_id` deterministically. That is intended and keeps identity stable across input modes.

**Deliberate string reuse, checked for contradiction.** `NOT_OBSERVABLE` now serves two distinct mechanisms: a detector **capability state** on the evidence-visibility axis, and a dedup-key **component placeholder** on the identity axis. They operate at different pipeline stages and do not conflict. The capability check and minimum-evidence check still run first, so this sentinel governs how an incident is *identified*, never whether one may be *raised* on absent evidence. Both `design.md` section 17 and `implementation_plan.md` section 13 state this explicitly so the two uses are not later collapsed.

Applied to `design.md` section 17 (new "Unavailable key components — frozen sentinel" block), `CLAUDE.md` coding rules, `testing.md` section 2, and `config/dedup_keys.yaml`.

#### Regression Test
Dedup contract test exercised against an IPFIX fixture with `ja3`, `registered_domain` and `amplifier_port` absent — asserting the sentinel appears in the canonical key, that identity is stable across restarts, and that no null, empty or `unknown` placeholder is ever produced.

---

### DOC-008 — Documentation spec nests two phases under the wrong tracks

**Status:** RESOLVED
**Severity:** MEDIUM
**Owner:** All
**Area:** Documentation spec

#### Symptom
The suggested `implementation_plan.md` structure places a Track A phase inside Track B, and a Track B phase inside Track C.

#### Reproduction
Read `create_project_md_files_V2.md` section 6: `A-P5 Flow Record Ingestion` appears between `B-P3` and `B-P4`; `B-P5 PS Alignment Detectors` appears between `C-P3` and `C-P4`.

#### Expected
Phases sit under their owning track.

#### Actual
Ownership is visually contradicted by the outline, which would assign flow-record ingestion to the detection track.

#### Root Cause
Copy-paste ordering defect when the V6.3 PS-alignment phases were appended.

#### Fix
`A-P5` placed under Track A, `B-P5` under Track B in `implementation_plan.md`. **No phase content was changed, merged or dropped** — only the position corrected.

#### Regression Test
None automatable. Reviewed at Phase 0 alongside `agents.md` ownership.

---

### DOC-009 — Repository tree omits referenced test directories

**Status:** RESOLVED — Phase 0 decision
**Severity:** LOW
**Owner:** A + B
**Area:** Repository structure

#### Symptom
Test paths referenced by the plan and the matrix do not exist in the declared repository tree.

#### Reproduction
Compare V6.3 section 21 `tests/` subtree against V6.3 section 1.2 (`test_ddos.py`, `test_reflection.py`, `test_slowloris.py`, and the rest) and traceability matrix section 1 (`tests/throughput/`).

#### Expected
Every referenced test path exists in the tree.

#### Actual
Section 21 lists `schema`, `parity`, `replay`, `latency`, `boundary`, `capture_loss`, `hash_chain`, `ui_load` — with no `detectors/` and no `throughput/`.

#### Root Cause
The tree was written before the per-detector tests and the throughput harness were enumerated elsewhere.

#### Fix
Decided by the project owner at Phase 0. `tests/detectors/` and `tests/throughput/` created. **All other V6.3 test directories and the rest of the repository structure are preserved unchanged** — `schema`, `parity`, `replay`, `latency`, `boundary`, `capture_loss`, `hash_chain`, `ui_load`.

#### Regression Test
Test collection discovers every named test file across all ten directories.

---

### DOC-010 — File-set mismatch between the plan and the documentation spec

**Status:** RESOLVED
**Severity:** LOW
**Owner:** All
**Area:** Documentation layer

#### Symptom
The two documents disagree about which Markdown files the project has.

#### Reproduction
Compare V6.3 section 21 repo tree against `create_project_md_files_V2.md` sections 1 and 15.

#### Expected
One file set.

#### Actual
V6.3 lists `README.md` and `LIMITATIONS.md` but omits `task_today.md`, `memory.md` and `bugs.md`. The spec requires those three but omits `README.md` and `LIMITATIONS.md`, and also omits `schemas/` from its repository layout.

#### Root Cause
The two documents were written for different purposes and neither was reconciled against the other.

#### Fix
Union. The eleven spec'd files were generated; `README.md` and `LIMITATIONS.md` remain V6.3 deliverables, referenced from `PRD.md`, `agents.md` and `CLAUDE.md` but outside the documentation-generation scope. `schemas/` is authoritative per V6.3 section 6.3 and is retained.

#### Regression Test
None. Reviewed at the H22 documentation checkpoint.

---

### DOC-011 — Minor citation and numbering defects in V6.3

**Status:** RESOLVED
**Severity:** LOW
**Owner:** All
**Area:** Source document hygiene

#### Symptom
Three cosmetic defects that could mislead a reader chasing a cross-reference.

#### Reproduction
Read V6.3 section 0.0 changelog and traceability matrix section 2.

#### Expected
Unique item numbers and correct section citations.

#### Actual
1. Changelog item number `36` is used twice — once ending the V6.2-carried list, once opening the V6.3 list.
2. Changelog item 16 cites section 23.5 for the "UI load-test versus demo-narrative conflict"; that content is in section 23.6 (section 23.5 is the boundary test).
3. Traceability matrix section 2 uses "Implemented" as a **scope** word for PCAP, NetFlow v9 and IPFIX, describing what is in scope rather than what is built.

#### Root Cause
Editorial drift across versions.

#### Fix
Numbering and citation defects noted, not propagated. Defect 3 matters operationally: "Implemented" is deliberately **not** carried into `STATUS.md`, which records every area as not started, so the matrix's scope language cannot be mistaken for a completion claim.

#### Regression Test
None.

---

### DOC-012 — Demo-script beats overlap inside a fixed 7-minute budget

**Status:** DOCUMENTED — interpretation recorded, source not rewritten
**Severity:** LOW
**Owner:** C
**Area:** Demo script

#### Symptom
Two demo beats claim overlapping time inside a fixed total.

#### Reproduction
Read `FINAL_DEVELOPMENT_PLAN_V6.3.md` section 41: the incident-lifecycle beat is headed **3:00–4:00** and the input-mode capability beat **3:45–4:00**, within a 7-minute script.

#### Expected
Beats that sum to the stated total.

#### Actual
The 3:45–4:00 interval falls inside 3:00–4:00, so fifteen seconds are claimed twice.

#### Root Cause
The input-mode capability beat was inserted during V6.3 PS-alignment hardening without re-cutting the surrounding block's heading.

#### Fix
**The V6.3 timestamps are preserved verbatim** in `implementation_plan.md` section 11 — both `3:00–4:00` and `3:45–4:00` appear exactly as the technical plan states them. Alongside them is a recorded interpretation: the input-mode beat is a **carve-out from the tail** of the lifecycle block, not additional budget, so lifecycle narration runs to roughly 3:45 and hands over.

This is a delivery interpretation, not a correction. **The technical-plan timeline has not been rewritten.** Any authoritative fix belongs in `FINAL_DEVELOPMENT_PLAN_V6.3.md` section 41 first, after which this entry and `implementation_plan.md` section 11 follow it.

#### Regression Test
None automatable. Verified against the clock during each of the three H19–H22 rehearsals.

---

## Resolved Bugs

None yet — no implementation exists. Resolved documentation defects are recorded above and are retained permanently; their root causes are what prevent the same drift on the next regeneration.

---

## Known Limitations

These are accepted properties of the design, not defects. Full treatment belongs in `LIMITATIONS.md`.

- **QUIC, ECH, DoH and DoT** reduce or remove visible metadata. SNI-dependent evidence becomes `NOT_OBSERVABLE`.
- **Sampled flow input** loses packet ordering and complete port spread; order-sensitive detectors degrade.
- **NAT** obscures per-host attribution behind a shared address.
- **Slow scans and jittered beacons** can fall below the windowed thresholds. An honest limitation is preferable to a false claim.
- **Wordlist DGAs** are the hardest lexical case; the n-gram language model exists specifically for them but does not eliminate the gap.
- **Concept drift** is monitored passively for the next offline bundle cycle; there is no online learning.
- **Geolocation is not attribution**, and does not resolve for private lab addressing at all.
- **Baseline poisoning** is possible in principle; mitigated by capped update rate, an immutable reference snapshot and bundle versioning.
- **Encrypted-session detection is suspicion only** — never payload identification or malware-family attribution.
- **NetFlow/IPFIX support is limited to exported fields.** The adapter does not reconstruct packets, DNS names, TLS fingerprints or TCP state the exporter did not export.
- **No runtime anonymisation** in this build; all capture is lab-synthetic.

---

## Deferred Issues

- **sFlow as a first-class detector source.** Recognised as a sampled input mode in this build; not implemented as packet-equivalent. Deferred deliberately, and stated as a capability boundary rather than an absence of threat.
- **Threat map**, PDF export, clock-servo Kalman, capture-loss Kalman, Lomb-Scargle, cross-detector fusion and SHAP — all Tier 2, all with documented fallbacks on the kill ladder, all cut before any core capability.
- **Real-enclave anonymisation path** (CryptoPAn after geolocation, before persistence) — designed, documented, not implemented.
- **Throughput-vs-loss sweep** for a measured operating envelope — optional, only if time permits after the target is met.
