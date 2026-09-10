# Master Specification — Project Markdown Documentation Files

## Purpose

This file is the master specification for creating and maintaining the project's Markdown documentation layer for **Cyber Sentinel — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic**, SIH 2026 Problem Statement 26145.

Create the following Markdown files:

1. `PRD.md`
2. `CLAUDE.md`
3. `design.md`
4. `agents.md`
5. `implementation_plan.md`
6. `task_today.md`
7. `memory.md`
8. `bugs.md`
9. `testing.md`
10. `git.md`
11. `STATUS.md`

The files must be complementary. Do **not** copy the same information into every file.

---

# 1. Documentation Architecture

Use this hierarchy:

```text
PRD.md
  ↓
design.md
  ↓
implementation_plan.md
  ↓
task_today.md

CLAUDE.md   → rules for AI-assisted development
agents.md   → ownership and coordination
STATUS.md   → current project state
memory.md   → durable project knowledge
bugs.md     → known failures and fixes
testing.md  → verification strategy
git.md      → version-control workflow
```

## Source-of-Truth Hierarchy

The documentation layer must preserve the distinction between the external requirement authority and the internal implementation authority:

```text
NTRO PS26145
    ↓
FINAL_DEVELOPMENT_PLAN_V6.3.md
    ↓
PRD.md / design.md / implementation_plan.md / testing.md
    ↓
CLAUDE.md / agents.md
    ↓
STATUS.md / task_today.md / memory.md / bugs.md
```

- **PS26145** = external requirement and constraint authority.
- **`FINAL_DEVELOPMENT_PLAN_V6.3.md`** = current development source of truth for implementation scope, architecture, detectors, gates, tests and demo.
- The individual Markdown files must derive from those sources and must not silently contradict them.
- `ps26145_traceability_matrix.md` is a compliance checklist linking PS requirements to implementation, evidence and tests; it is not a competing architecture source of truth.

### Core distinction

- `PRD.md` = **WHAT and WHY**
- `design.md` = **HOW**
- `implementation_plan.md` = **WHAT TO BUILD AND IN WHAT ORDER**
- `task_today.md` = **WHAT TO DO RIGHT NOW**
- `STATUS.md` = **WHERE THE PROJECT IS RIGHT NOW**
- `CLAUDE.md` = **HOW THE AI MUST BEHAVE**
- `agents.md` = **WHO OWNS WHAT**
- `memory.md` = **WHAT WE HAVE LEARNED**
- `bugs.md` = **WHAT IS BROKEN / WAS BROKEN**
- `testing.md` = **HOW WE VERIFY IT**
- `git.md` = **HOW WE COLLABORATE SAFELY**

---

# 2. `PRD.md`

## Purpose

Define the product requirements without becoming an implementation manual.

## Suggested structure

```markdown
# Product Requirements Document

## 1. Product Overview
## 2. Problem Statement
## 3. Objective
## 4. Target Users
## 5. Core User Outcomes
## 6. Core Features
## 7. Threat Classes
## 8. Hard Constraints
## 9. Functional Requirements
## 10. Non-Functional Requirements
## 11. Dashboard Requirements
## 12. Scenario Console Requirements
## 13. Evidence and Alert Requirements
## 14. Reporting Requirements
## 15. Acceptance Criteria
## 16. Explicitly Out of Scope
## 17. Stretch Features
```

## Include

- The system detects, classifies and scores cyber threats from passively observed traffic.
- The output is intelligence, not a control surface.
- The six PS threat classes:
  - Volumetric / protocol DDoS
  - Botnet C2 beaconing
  - DGA domains and DNS tunnelling
  - Malware in encrypted sessions
  - Reconnaissance / port scanning
  - Data exfiltration
- Internal detector implementation remains eight modules:
  - `ddos.py`
  - `reflection.py`
  - `c2.py`
  - `dga.py`
  - `dns.py`
  - `tls_quic.py`
  - `scan.py`
  - `exfil.py`
- The five graded constraints:
  - Read-only ingest
  - No payload decryption
  - Streaming rather than batch-only operation
  - Stated throughput
  - Standard alert schema
- User-visible requirements such as incident feed, evidence, confidence/risk, capability state, history and export.

## Must not contain

- Detailed Python implementation.
- Class-by-class source-code instructions.
- Git commands.
- Temporary task lists.
- Bug histories.

---

# 3. `CLAUDE.md`

## Purpose

Provide strict operating instructions to Claude and other coding agents.

This should be the first file an AI reads before modifying the repository.

## Suggested structure

```markdown
# Claude Instructions

## Project Context
## Source-of-Truth Files
## Non-Negotiable Architecture Rules
## Coding Rules
## Security Rules
## Data / Schema Rules
## AI/ML Rules
## Performance Rules
## Testing Rules
## Git Rules
## File Ownership
## Workflow Before Coding
## Workflow After Coding
## Forbidden Actions
## Definition of Done
```

## Important rules

The AI must:

1. Preserve the one-way monitored boundary.
2. Never add a route, probe, handshake, mitigation command or other control path across the monitored boundary.
3. Never decrypt TLS/QUIC payloads.
4. Keep runtime threat intelligence offline.
5. Keep the DGA LightGBM model as the only trained model unless the project plan is explicitly changed.
6. Treat the frozen JSON schemas as contracts.
7. Never introduce JSON files as routine inter-stage transport.
8. Preserve the single-clock replay architecture.
9. Avoid payload parsing when header/metadata-only information is sufficient.
10. Respect bounded-memory requirements.
11. Run relevant tests before declaring work complete.
12. Read `task_today.md` before beginning a focused work session.
13. Update `STATUS.md`, `memory.md`, or `bugs.md` when durable state changes.
14. Never silently change architecture because it is convenient.
15. Treat `FINAL_DEVELOPMENT_PLAN_V6.3.md` as the current development source of truth.
16. Preserve the six external PS threat classes and eight internal detector modules.
17. Preserve passive PCAP and NetFlow v9/IPFIX input support; recognize sFlow as `NOT_OBSERVABLE` unless explicitly implemented.
18. Preserve the frozen `input_mode` enum: `pcap_replay | live_tap | ipfix | netflow_v9 | sflow`.
19. Never make a PS-mandated alert field nullable: timestamp, `flow_id`, threat class, confidence score and supporting evidence must be represented.
20. Preserve `flow_ref_type` and deterministic `flow_id` semantics for both ordinary flows and aggregate/entity incidents.
21. Preserve DNS qtype distribution/anomaly features, including TXT/NULL/CNAME evidence where observable.
22. Preserve Slowloris-specific features; do not silently replace Slowloris with only high-rate DDoS logic.
23. Preserve JA3, JA3S and JA4 where available.
24. Preserve explicit DGA character bigram/trigram language-model features.
25. Preserve concrete TLS/QUIC packet-size, direction and inter-arrival shape features.
26. Report throughput using flows/sec and Mbps, with pps as an additional system metric.
27. Do not add a second trained ML model without an explicit plan change.

## Must not contain

- A complete copy of `design.md`.
- Current temporary task details.
- Long bug reports.

---

# 4. `design.md`

## Purpose

Technical source of truth for the system architecture.

## Suggested structure

```markdown
# System Design

## 1. Architecture Overview
## 2. Deployment / Network Boundary
## 3. Two-Plane UI Architecture
## 4. Ingestion Layer
## 5. Replay and Clock Model
## 6. Fast Header Counter
## 7. Suricata Metadata Path
## 8. Normalization
## 9. Event Contract
## 10. Feature Service
## 11. Rolling Windows and Bounded State
## 12. Detection Architecture
## 13. DGA Model
## 14. Statistical Detectors
## 15. TLS/QUIC Metadata Detection
## 16. Fusion and Risk Scoring
## 17. Deduplication and Incident Lifecycle
## 18. Persistence and Hash Chain
## 19. API and WebSocket
## 20. Monitoring Dashboard
## 21. Scenario Console
## 22. Offline Intel Bundle
## 23. Capability Negotiation
## 24. Latency Budget
## 25. Failure Modes and Fallbacks
## 26. Architecture Decisions
```

## Architecture principles to preserve

The technical plan uses a dual passive-input architecture:

### Packet input path

```text
PCAP / live tap
      ↓
tcpreplay / passive capture
      ↓
veth / monitored boundary
      ↓
Fast header counter + Suricata metadata
      ↓
Normalizer
```

### Flow-record input path

```text
NetFlow v9 / IPFIX
      ↓
Shared template cache
      ↓
Common flow-record decoder
      ↓
Normalizer
```

`sFlow` is a recognized input mode but remains `NOT_OBSERVABLE` in the 24-hour implementation unless explicitly implemented.

Both paths converge on the same normalized event contract:

```text
                 Packet path
                     │
                     ├──────────┐
                     │          │
                 Flow path      │
                     │          │
                     └────┬─────┘
                          ↓
                   Normalized Event
                          ↓
                   Capability State
                          ↓
                     Features
                          ↓
                     Detectors
                          ↓
                 Fusion / Dedup / Lifecycle
                          ↓
                       SQLite
                          ↓
                  FastAPI/WebSocket
                          ↓
                   Monitoring UI
```

The Scenario Console must remain separate from the Monitoring Dashboard.

### PS-aligned feature requirements

The technical design documentation must explicitly cover:
- DNS qtype distribution/anomalies;
- character bigram/trigram DGA language-model features;
- JA3/JA3S/JA4;
- concrete encrypted-session packet-size/direction/inter-arrival features;
- Slowloris concurrency, duration and bytes/connection features;
- `flow_id` and `flow_ref_type`;
- capability degradation for flow-only/sampled inputs.

### Existing packet-path detail

The technical plan uses:

```text
PCAP corpus
    ↓
tcpreplay
    ↓
veth pair / one-way enclave
    ↓
 ┌───────────────────────┐
 │ Fast header counter   │
 │ Suricata metadata     │
 └───────────┬───────────┘
             ↓
        Normalizer
             ↓
      Feature service
             ↓
      Detector bank
             ↓
   Fusion / Dedup / Lifecycle
             ↓
          SQLite
             ↓
      FastAPI/WebSocket
             ↓
       Monitoring UI
```

The Scenario Console must remain separate from the Monitoring Dashboard.

---

# 5. `agents.md`

## Purpose

Define human and AI-agent ownership so parallel development does not create conflicts.

## Suggested structure

```markdown
# Agents and Ownership

## 1. Team Structure
## 2. Track A — Ingestion
## 3. Track B — AI/ML & Detection
## 4. Track C — UI/UX
## 5. Shared Contracts
## 6. File Ownership
## 7. Handoff Rules
## 8. Parallel Work Rules
## 9. Conflict Rules
## 10. Escalation Rules
```

## Ownership model

### Track A — Ingestion

Owns:

- Lab/replay
- Clock
- Capture paths
- Header counter
- Suricata integration
- Normalizer
- Windowing
- Bounded state
- Capture-loss estimation
- Throughput
- Read-only proof
- NetFlow v9 / IPFIX adapter
- Shared template cache
- Flow-record fixtures
- `input_mode` and capability handling

### Track B — AI/ML & Detection

Owns:

- Ground-truth generation
- Feature engineering
- DGA model
- Statistical detectors
- Fusion
- Deduplication
- Incident lifecycle
- Evaluation
- Slowloris features/detection
- DNS qtype features
- DGA bigram/trigram features
- JA3S evidence
- TLS/QUIC shape features

### Track C — UI/UX

Owns:

- FastAPI
- WebSocket
- SQLite integration
- Monitoring Dashboard
- Export
- Operator experience

The Scenario Console belongs with the lab/ingestion side and must not be merged into the Monitoring Dashboard.

---

# 6. `implementation_plan.md`

## Purpose

Long-lived execution roadmap.

Do not turn this into a live scratchpad.

## Suggested structure

```markdown
# Implementation Plan

## 1. Build Strategy
## 2. Dependencies
## 3. Phase 0 — Foundation
## 4. Track A — Ingestion
### A-P1 Transport and Clock
### A-P2 Windowing and State
### A-P3 Integrity and Measurement
### A-P4 Hardening
## 5. Track B — AI/ML & Detection
### B-P1 Ground Truth
### B-P2 First Detectors
### B-P3 Temporal and Correlation Detectors
### A-P5 Flow Record Ingestion
- NetFlow v9 parser
- IPFIX parser
- Shared template cache
- Normalized flow events
- Flow-record fixtures
- Capability degradation
- Packet-vs-flow feature parity tests

### B-P4 Evidence and Evaluation
## 6. Track C — UI/UX
### C-P1 Shell and Transport
### C-P2 Flood Survivability
### C-P3 Operator Surfaces
### B-P5 PS Alignment Detectors
- Slowloris
- DNS qtype distribution/anomaly
- DGA bigram/trigram LM features
- JA3S
- TLS/QUIC packet-size/direction/timing shape

### C-P4 Polish and Proof
## 7. Cross-Track Integration
## 8. Hourly Gates
## 9. Kill Ladder
## 10. Feature Freeze
## 11. Final Demo Preparation
```

Each phase should use:

```markdown
### Phase
**Status:** NOT_STARTED | IN_PROGRESS | BLOCKED | COMPLETE

**Objective:**

**Dependencies:**

**Tasks:**

**Output:**

**Exit Criterion:**

**Fallback:**
```

The plan should preserve the project's gate-driven philosophy.

Important gates include:

- Hour 6 — real replay, normalized events and dashboard activity.
- Hour 10 — at least one real alert with evidence and latency.
- Hour 12 — full end-to-end integration checkpoint before detector expansion.
- Hour 13 — optional-work gate.
- Hour 16 — all six classes or their fallbacks.
- Hour 19 — feature freeze.
- Hours 19–24 — documentation, rehearsal, backup demo and buffer.

---

# 7. `task_today.md`

## Purpose

A deliberately small, short-lived execution file.

It should contain only the current focused work period, ideally approximately the next two hours.

## Suggested structure

```markdown
# Task Today

**Updated:** YYYY-MM-DD HH:MM
**Timebox:** HH:MM–HH:MM
**Current Phase:**
**Current Gate:**
**Overall Status:** GREEN | YELLOW | RED

## Current Objective

One sentence.

## Priority Tasks

### 1. Task
- [ ] Concrete action
- [ ] Concrete action

**Done when:** ...

### 2. Task
- [ ] Concrete action

**Done when:** ...

## Current Blocker

None / describe blocker.

## Do Not Work On

- Future features
- Stretch features
- Unrelated refactors

## Next Task

...

## End-of-Session Update

- Completed:
- Blocked:
- New bug:
- New decision:
```

## Critical rule

Never allow `task_today.md` to become project history.

When the timebox ends:

- Move durable discoveries to `memory.md`.
- Move bugs to `bugs.md`.
- Move completed roadmap items to `implementation_plan.md`.
- Update `STATUS.md`.
- Replace the contents with the next focused task set.

---

# 8. `memory.md`

## Purpose

Store durable project knowledge that an AI would otherwise need to rediscover.

## Suggested structure

```markdown
# Project Memory

## Architecture Decisions
## Important Discoveries
## Environment Facts
## Known Gotchas
## Performance Discoveries
## Dataset / Scenario Knowledge
## Detection Knowledge
## UI Knowledge
## Judge / Demo Insights
## Rejected Approaches
## Future Work
```

## Good memory entries

```markdown
### One-clock replay

Suricata and the fast counter must consume the same tcpreplay-driven interface.
Running them independently against the PCAP creates divergent clocks and breaks correlation.

### JSON boundary rule

JSON exists at the EVE input boundary, SQLite evidence storage and WebSocket output.
It is not an inter-stage transport format.

### DGA model

DGA is the only trained model in the current scope.
Other detectors use statistical, rule-based or offline-intel approaches.
```

## Rule

Only record information that will remain useful beyond the current task.

---

# 9. `bugs.md`

## Purpose

Centralized structured bug tracking.

## Suggested structure

```markdown
# Bugs

## Active Bugs

### BUG-001 — Short title

**Status:** OPEN
**Severity:** CRITICAL | HIGH | MEDIUM | LOW
**Owner:**
**Area:**

#### Symptom

#### Reproduction

#### Expected

#### Actual

#### Root Cause

#### Fix

#### Regression Test

#### Notes
```

Also include:

```markdown
## Resolved Bugs
## Known Limitations
## Deferred Issues
```

Never delete important resolved bugs. Their root causes can prevent regressions.

---

# 10. `testing.md`

## Purpose

Define how the project proves that it works.

## Suggested structure

```markdown
# Testing Strategy

## 1. Testing Philosophy
## 2. Unit Tests
## 3. Contract Tests
## 4. Feature-Parity Tests
## 5. Replay / Integration Tests
## 6. Detector Tests
## 7. Model Evaluation
## 8. False-Positive Tests
## 9. Latency Tests
## 10. Throughput Tests
## 11. Boundary / Negative Connectivity Tests
## 12. Capture-Loss Tests
## 13. Hash-Chain Verification
## 14. UI Load Tests
## 15. Export Tests
## 16. Cold-Boot Test
## 17. Demo Acceptance Test
## 18. Test Commands
## 19. Definition of Done
```

## Critical tests

The project should explicitly verify:

- Schema compatibility.
- Frozen `FEATURE_ORDER` parity between training and inference.
- Replay through the same interface.
- Packet-count agreement.
- Streaming alerts rather than end-of-run-only output.
- `latency_ms`.
- p50/p95 latency.
- Stated throughput.
- No connectivity across the monitored boundary.
- No payload decryption.
- Bounded memory.
- 50,000-alert UI survivability.
- Hash-chain integrity.
- JSON/CSV export during replay.
- Cold boot with networking disabled.
- NetFlow v9 template handling and refresh.
- IPFIX template handling and refresh.
- Malformed/missing flow-record handling.
- Packet-to-flow normalized-event contract parity.
- Non-null PS-mandated `flow_id`.
- `flow_ref_type` correctness for flow/aggregate/entity incidents.
- DNS qtype distribution and TXT/NULL/CNAME evidence.
- Slowloris concurrency/duration/bytes-per-connection detection.
- JA3S extraction and evidence.
- DGA bigram/trigram feature parity.
- Concrete TLS/QUIC packet-size/direction/IAT feature extraction.
- Capability degradation for IPFIX/NetFlow/sFlow inputs.

---

# 11. `git.md`

## Purpose

Define safe collaboration for four people and potentially multiple AI agents.

## Suggested structure

```markdown
# Git Workflow

## 1. Repository Rules
## 2. Branch Strategy
## 3. Ownership
## 4. Commit Convention
## 5. Pull / Rebase Rules
## 6. Shared Contract Changes
## 7. Conflict Resolution
## 8. Testing Before Commit
## 9. Emergency Fixes
## 10. Feature Freeze Rules
## 11. Useful Commands
```

## Recommended conventions

Branch examples:

```text
main
develop
feature/ingestion-replay
feature/detection-ddos
feature/detection-dga
feature/dashboard
fix/replay-clock
fix/schema-parity
```

Commit examples:

```text
feat(ingest): add tcpreplay harness
feat(detection): add DGA feature extractor
feat(ui): add incident evidence drawer
fix(ingest): handle partial EVE lines
test(schema): add alert contract tests
docs: update architecture
```

## Hard rules

- Never force-push shared branches.
- Never reset another developer's work.
- Do not silently rewrite shared contracts.
- Run relevant tests before committing.
- Keep commits logically focused.
- Coordinate changes to frozen schemas and `FEATURE_ORDER`.

---

# 12. `STATUS.md`

## Purpose

Provide a compact current-state snapshot.

This is different from `task_today.md`.

- `STATUS.md` = project state.
- `task_today.md` = immediate work.

## Suggested structure

```markdown
# Project Status

**Last Updated:** YYYY-MM-DD HH:MM
**Current Hour:**
**Current Phase:**
**Current Gate:**
**Overall Status:** GREEN | YELLOW | RED

## Completed

- ...

## In Progress

- ...

## Blocked

- ...

## Working Systems

- ...

## Known Failures

- ...

## Latest Verification

- Test:
- Result:
- Time:

## Next Gate

...

## Immediate Next Action

...

## Feature Freeze Status

NOT REACHED | ACTIVE

## Demo Readiness

- Ingestion:
- Detection:
- Dashboard:
- Evidence:
- Export:
- Boundary proof:
- Rehearsal:
```

Keep this file short enough that a team member can understand the project's state in under one minute.

---

# 13. Cross-File Rules

## Rule 1 — No duplicated truth

If a fact belongs to one file, reference that file rather than copying a second authoritative version.

Examples:

- Architecture → `design.md`
- Requirements → `PRD.md`
- Roadmap → `implementation_plan.md`
- Current task → `task_today.md`
- Current state → `STATUS.md`
- AI rules → `CLAUDE.md`
- Bug details → `bugs.md`
- Test methodology → `testing.md`

## Rule 2 — `CLAUDE.md` has behavioral authority

Agents should read:

```text
CLAUDE.md
↓
STATUS.md
↓
task_today.md
↓
relevant design / implementation / testing files
```

before starting a substantial task.

## Rule 3 — Contracts are shared interfaces

The normalized event contract, alert schema and `FEATURE_ORDER` must be treated as explicit interfaces between tracks.

Contract changes require:

1. Discussion/coordination.
2. Schema update.
3. Contract-test update.
4. Consumer update.
5. Verification.

## Rule 4 — Current state must stay current

After meaningful work:

```text
implementation_plan.md → update completion
STATUS.md              → update current state
task_today.md          → update immediate work
memory.md              → record durable discovery
bugs.md                → record failures
testing.md             → record new verification requirements
```

Do not update every file mechanically if nothing relevant changed.

---

# 14. Recommended Creation Order

Create the files in this order:

```text
1. PRD.md
2. design.md
3. implementation_plan.md
4. CLAUDE.md
5. agents.md
6. testing.md
7. git.md
8. STATUS.md
9. task_today.md
10. memory.md
11. bugs.md
```

### Why this order?

The first three establish the product, architecture and roadmap.

`CLAUDE.md` then converts the architecture into enforceable AI behavior.

`agents.md`, `testing.md` and `git.md` establish collaboration and verification.

`STATUS.md`, `task_today.md`, `memory.md` and `bugs.md` are operational files that evolve during implementation.

---

# 15. Initial Repository Documentation Layout

Use:

```text
cyber-sentinel/
│
├── PRD.md
├── CLAUDE.md
├── design.md
├── agents.md
├── implementation_plan.md
├── task_today.md
├── STATUS.md
├── memory.md
├── bugs.md
├── testing.md
├── git.md
│
├── sensor/
├── ingest/
├── features/
├── detectors/
├── models/
├── intel/
├── alerts/
├── lab_console/
├── api/
├── dashboard/
├── scenarios/
├── tests/
├── config/
└── docs/
```

---

# 16. Final Quality Check

Before considering the documentation layer complete, verify:

```text
[ ] PRD explains what and why.
[ ] design explains how.
[ ] implementation_plan explains what gets built in what order.
[ ] CLAUDE contains enforceable AI rules.
[ ] agents defines ownership and handoffs.
[ ] task_today contains only immediate work.
[ ] memory contains durable knowledge.
[ ] bugs contains structured failures.
[ ] testing defines objective verification.
[ ] git defines safe collaboration.
[ ] STATUS reflects current project state.
[ ] No file contains a competing source of truth.
[ ] Frozen contracts are clearly identified.
[ ] Read-only boundary is explicitly protected.
[ ] No-decryption rule is explicit.
[ ] Offline-intel requirement is explicit.
[ ] One-trained-model scope is explicit.
[ ] Feature freeze is explicit.
[ ] V6.3 is identified as the current development source of truth.
[ ] Six PS classes / eight detector modules are consistently represented.
[ ] NetFlow v9 / IPFIX support is represented.
[ ] sFlow capability state is represented.
[ ] `input_mode` enum is frozen.
[ ] `flow_id` and `flow_ref_type` are explicit and non-null by contract.
[ ] DNS qtype anomalies are represented.
[ ] Slowloris capability is represented.
[ ] JA3S is represented.
[ ] DGA n-gram features are represented.
[ ] TLS/QUIC shape features are concrete.
[ ] Throughput includes flows/sec and Mbps.
[ ] One-trained-model scope is explicitly documented.
[ ] PS traceability matrix exists as a compliance checklist.
```

# 17. Source Alignment

This documentation structure is designed around the current technical plan's architecture and execution model:

- The system is a read-only, metadata-based, streaming intelligence layer.
- The build uses a single replay clock and two ingestion paths.
- The current scope intentionally uses one trained DGA model while other detection families use statistical, rule-based or offline-intelligence methods.
- The Scenario Console and Monitoring Dashboard are separate planes.
- The project is divided into Ingestion, AI/ML & Detection, and UI/UX workstreams.
- Work is organized into phases with explicit outputs and binary exit criteria.
- Feature freeze occurs before the final documentation/rehearsal period.
- V6.3 explicitly aligns the documentation layer with PS-named passive inputs, alert fields, DNS features, Slowloris, JA3S, n-grams, encrypted-session shape analysis and PS-aligned throughput metrics.

This master file should guide creation of the individual Markdown files without turning any one file into a duplicate of the complete technical plan.


---

# 18. V2 Update Notes

This master specification was updated to align the documentation-generation process with `FINAL_DEVELOPMENT_PLAN_V6.3.md` and the PS26145 requirements.

The update specifically protects:
- six official PS classes vs eight internal detector modules;
- PCAP plus NetFlow v9/IPFIX input handling;
- sFlow `NOT_OBSERVABLE` capability;
- PS-mandated alert fields and non-null flow identity;
- DNS qtype anomalies;
- Slowloris-specific detection;
- JA3/JA3S/JA4;
- DGA bigram/trigram features;
- concrete TLS/QUIC packet-size and timing shape;
- flows/sec + Mbps throughput reporting;
- PS-named dataset/generator traceability;
- V6.3 as the implementation source of truth.

This file remains a **documentation-generation specification**, not a replacement for the technical development plan.
