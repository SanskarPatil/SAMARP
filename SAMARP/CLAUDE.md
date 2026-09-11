# Claude Instructions

**Read this file before modifying anything in this repository.** It is the behavioural authority for Claude and every other coding agent working on this project.

This file tells you **how to behave**. It does not restate the architecture — that is `design.md` — and it does not restate the roadmap — that is `implementation_plan.md`.

---

## Project Context

Cyber Sentinel is a passive, streaming cyber-intelligence layer for a monitored enclave behind a one-way boundary, built for SIH 2026 Problem Statement **PS26145**.

It observes copied traffic, sensor metadata and exported flow records; it never sends anything back across the boundary; it never decrypts payload; and it turns observations into evidence-rich, deduplicated incidents with explicit statements of what it could not see.

The project is a **24-hour gate-driven build** by four people across three tracks. Time is the binding constraint. A stable, explainable system that survives scrutiny beats a larger one that does not.

---

## Source-of-Truth Files

```text
PS26145 (official problem statement)
    ↓
ps26145_traceability_matrix.md      external requirement / compliance authority
    ↓
FINAL_DEVELOPMENT_PLAN_V6.3.md      current implementation source of truth
    ↓
PRD.md / design.md / implementation_plan.md / testing.md
    ↓
CLAUDE.md / agents.md
    ↓
STATUS.md / task_today.md / memory.md / bugs.md
```

**Treat `FINAL_DEVELOPMENT_PLAN_V6.3.md` as the current implementation source of truth.** When a generated document disagrees with it, the plan wins and the document is corrected — never the other way around.

`ps26145_traceability_matrix.md` is the requirement-to-implementation compliance map. It is an authority on *what must be satisfied*, not a competing architecture source.

**When two sources conflict, prefer the higher authority. Never resolve a contradiction by inventing a new requirement.**

Frozen contracts live in code, not prose:

| Contract | File |
|---|---|
| Normalized event schema | `schemas/normalized_event.schema.json` |
| Alert schema v1.3 | `schemas/alert.schema.json` |
| Feature order | `features/feature_order.py` |
| Deduplication keys | `config/dedup_keys.yaml` |
| Lab address plan | `config/address_plan.yaml` |
| Thresholds and latency budget | `config/thresholds.yaml` |

---

## Non-Negotiable Architecture Rules

1. **Preserve the one-way monitored boundary.** Nothing in the monitoring plane may write toward the packet source.
2. **Never add a route, probe, handshake, mitigation command or other control path across the monitored boundary.** Recommendations are advisory text only.
3. **Never decrypt TLS or QUIC payloads**, and never claim payload identification, malware-family attribution or decrypted-content inspection.
4. **Keep runtime threat intelligence offline.** No live feed, no external geolocation service, no runtime LLM inference, no internet dependency at run time.
5. **The DGA LightGBM model is the only trained model.** Every other detector is statistical, rule-based or offline-intelligence driven. Do not add a second trained model without an explicit plan change.
6. **Treat the frozen JSON schemas as contracts.** Change them only through the procedure in `git.md`.
7. **Never introduce JSON files as routine inter-stage transport.** JSON exists at exactly three boundaries: the Suricata EVE input, the SQLite/storage boundary, and the WebSocket output. Post-normalisation processing is in-process.
8. **Preserve the single-clock replay architecture.** `t_replay_start` is captured once, never re-evaluated per packet.
9. **Avoid payload parsing when header or metadata information is sufficient.**
10. **Respect bounded-memory requirements.** No unbounded structure keyed on attacker-controlled values — flow state, template caches and detector state all have caps and eviction.
11. **Preserve the six external PS threat classes and the eight internal detector modules.** Six classes, eight modules. Never improvise or collapse the count.
12. **Preserve passive PCAP and NetFlow v9 / IPFIX input support.** The shared template-based adapter and its capability degradation are on the never-cut list.
13. **`sflow` is a valid frozen `input_mode` value.** sFlow is recognised as a sampled input mode; per-detector capability degrades to `DEGRADED` or `NOT_OBSERVABLE` per `design.md` section 23. **`NOT_OBSERVABLE` is a per-detector evidence state, never a property of an input mode** — do not write "sFlow is NOT_OBSERVABLE".
14. **Preserve the frozen `input_mode` enum:** `pcap_replay | live_tap | ipfix | netflow_v9 | sflow`.
15. **Never make a PS-mandated alert field nullable.** `timestamp`, `flow_id`, threat class, confidence score and supporting evidence must all be represented on every alert.
16. **Preserve `flow_ref_type` and deterministic `flow_id` semantics** for ordinary flows and for aggregate and entity incidents alike. `flow_id` is never null.
17. **Preserve DNS qtype distribution and anomaly features**, including TXT/NULL/CNAME evidence where observable.
18. **Preserve Slowloris-specific features.** Do not silently replace Slowloris with high-rate DDoS logic; it is a distinct low-rate exhaustion path inside `ddos.py`.
19. **Preserve JA3, JA3S and JA4** wherever the installed sensor exposes them.
20. **Preserve explicit DGA character bigram and trigram language-model features.**
21. **Preserve concrete TLS/QUIC packet-size, direction and inter-arrival shape features.** "Shape" means named, concrete features — never a generic anomaly label.
22. **Preserve the two-plane separation.** The Scenario Console never notifies the Monitoring Dashboard that an attack occurred. No convenience routing between planes, for any reason.
23. **Never silently change architecture because it is convenient.**
24. **Do not add detector families or architectural components** unless `FINAL_DEVELOPMENT_PLAN_V6.3.md` explicitly requires them.

---

## Coding Rules

- Read the relevant section of `design.md` before writing code for a component.
- Match the surrounding code's conventions, naming and comment density.
- Keep detectors simple enough to explain in the evidence drawer. An unexplainable detector is worse than a simpler one that works.
- Do not scatter thresholds through detector code — they belong in `config/thresholds.yaml`.
- Do not hardcode address prefixes — read `config/address_plan.yaml`.
- Define shared primitives once and import them. The canonicalisation helper, the hash-chain concatenation rule and the identifier truncation rule each live in exactly one place in `alerts/hash_chain.py`, and every producer **and every verifier** imports them rather than reimplementing.
- **Canonical identifier form is frozen:** `sha256(canonical_value).hexdigest()[:16]` — exactly 16 lowercase hex characters, a 64-bit truncated SHA-256. This applies to `flow_id` and `incident_id`. **Never read `[:16]` as 16 bytes.** Hash-chain fields `payload_hash`, `entry_hash` and `prev_hash` are **full** 64-character digests and are never truncated.
- **Unavailable deduplication-key components use the exact canonical sentinel string `NOT_OBSERVABLE`.** Never substitute null, an empty string, zero, `unknown`, or any other placeholder.
- Prefer the smallest change that satisfies the requirement. Do not refactor adjacent code opportunistically during a gate-driven build.

---

## Security Rules

- **Attack generation is lab-only** — Linux network namespaces, veth pairs, or a host-only virtual network with no bridge to a physical interface. Before any generation run, verify the output interface is a veth or host-only adapter and never a physical NIC, and that the target is inside the declared lab subnet.
- **Never run attack tooling against** college networks, hostel Wi-Fi, venue networks, cloud VMs, third-party IPs, or any system not personally owned or authorised.
- **Treat malware-capture datasets as hostile packet data.** Never execute a binary contained inside one.
- **Generation stops at the Hour-6 gate.** After that the lab is replay-only.
- Never add an endpoint, script or convenience path that could be read as a return route across the boundary. `POST /simulate/scenario/{id}` was removed and must never return.
- Do not commit credentials, keys or venue network details.

---

## Data / Schema Rules

- The schema files are the source of truth for required fields, types, enums, evidence structure, observability state, detector metadata, incident identity and chain fields. This document is not.
- Contract tests must fail on schema drift. If you change a schema, update the contract test in the same change.
- Never use commented JSON as a canonical schema. If an example needs comments, label it JSONC.
- `flow_summary` comes from the bounded in-process flow tracker, **not** from Suricata EVE flow output. Do not re-enable EVE flow events to populate it.
- Deduplication keys are frozen in `config/dedup_keys.yaml` and asserted by a contract test. `ddos` never keys on source; `dga` never keys on domain.
- Every alert carries the model and intel bundle version.

---

## AI/ML Rules

- **One trained model: the DGA LightGBM classifier.** State this explicitly in the README and model card.
- Training and inference import the same `FEATURE_ORDER` object. No component builds its own ordering.
- Maintain time-based, entity-based and DGA-family holdouts; deduplicate before splitting; strip TLDs where specified.
- Keep the DGA hard-negative corpus. The model must not learn `random-looking == malicious`.
- Report calibration honestly: reliability diagram and Brier score for the calibrated model only.
- **Never present a robust z-score or a rule score as a probability.** `score_type` and `calibrated` govern presentation; the UI appends a percent sign only when `calibrated: true`.
- If the DGA artifact is unusable, ship the documented rule fallback with `calibrated: false` and `model_version: "rules-fallback"` — and do **not** publish a Brier score or reliability diagram for it.
- Never claim generic "AI accuracy". Never claim zero-day detection; the accepted wording is "previously unseen patterns".

---

## Performance Rules

- Code against the frozen latency budget: 300 ms watermark, ~1.0 s window, ~100 ms scoring and dedup, 250 ms batch push, structural floor ~1.6 s, **SLO p95 < 2.0 s**.
- `latency_ms` is **measured**, never estimated.
- If p95 exceeds the SLO, fix in this order: batch push interval, then window size, then detector cost. **Never shrink the watermark** — that trades a visible latency number for invisible missed detections.
- **Report throughput as normalized flows/sec first** — the primary PS KPI, target at least 1 000 flows/sec sustained 60 s at below 1 % loss — then pps (at least 50 000) and Mbps (at least 400) as secondary system metrics.
- **Never conflate flows/sec, pps and Mbps.** They are three independent measurements; deriving one from another is not a measurement.
- Never publish a throughput number without the machine specification beside it, and never extrapolate beyond the measured hardware.
- Surface capture loss rather than hiding it. Where only one estimator exists, report the raw `kernel_drops` ratio and label it a lower bound. Do not invent a more precise number.
- Keep UI performance rules intact: 250 ms batched pushes, 500-item client ring buffer, virtualised list, `requestAnimationFrame` counters.

---

## Testing Rules

- **Run the relevant tests before declaring work complete.** State the command and the actual result; if tests fail, say so with the output.
- Contract tests, feature-parity tests and the boundary test are not optional.
- A new detector requires a replay fixture and an acceptance test in the same change.
- Never weaken a test to make it pass. If a test is wrong, fix the test deliberately and say why.
- Test methodology lives in `testing.md`. Do not duplicate it here or invent a parallel strategy.

---

## Git Rules

Full workflow is in `git.md`. The rules that bind an agent:

- Never force-push a shared branch. Never reset another developer's work.
- Do not silently rewrite a shared contract.
- Keep commits logically focused and run relevant tests before committing.
- Coordinate any change to a frozen schema or to `FEATURE_ORDER` before making it.
- Commit or push only when asked.

---

## File Ownership

Track ownership is defined in `agents.md`. Before editing a file outside your assigned track, check that file's owner and coordinate.

Documentation ownership:

| File | Owns |
|---|---|
| `PRD.md` | Requirements and scope |
| `design.md` | Architecture and contracts |
| `implementation_plan.md` | Build order and gates |
| `testing.md` | Verification methodology |
| `agents.md` | Ownership and handoffs |
| `git.md` | Collaboration workflow |
| `STATUS.md` | Current project state |
| `task_today.md` | Immediate work only |
| `memory.md` | Durable knowledge |
| `bugs.md` | Failures and fixes |
| `LIMITATIONS.md` | Known visibility and engineering limits |

**No file may contain a competing source of truth.** If a fact belongs to another file, reference it rather than copying a second authoritative version.

---

## Workflow Before Coding

1. Read `CLAUDE.md` (this file).
2. Read `STATUS.md` — where the project actually is.
3. Read `task_today.md` — what the current focused work period is.
4. Read the relevant sections of `design.md`, `implementation_plan.md` and `testing.md`.
5. Confirm the work belongs to the current gate. If it is future or stretch work, do not start it.
6. Confirm the change does not touch a frozen contract. If it does, stop and coordinate first.

---

## Workflow After Coding

1. Run the relevant tests and report the actual output.
2. Update `implementation_plan.md` phase status if a phase advanced.
3. Update `STATUS.md` if the project state changed.
4. Update `task_today.md` if the immediate work changed.
5. Record a durable discovery in `memory.md`; record a failure in `bugs.md`.
6. Do not update every file mechanically. Update what actually changed.

---

## Forbidden Actions

- Adding any `POST`, `PUT` or `DELETE` route to the Plane B monitoring application.
- Adding any path, endpoint or script that lets the Scenario Console inform the dashboard of ground truth.
- Decrypting, or adding a schema field capable of carrying, TLS/QUIC payload content.
- Adding a second trained ML model.
- Adding a new detector family or architectural component not required by `FINAL_DEVELOPMENT_PLAN_V6.3.md`.
- Introducing a runtime network or internet dependency.
- Re-enabling Suricata EVE flow events to populate `flow_summary`.
- Re-evaluating `now` per packet in the replay clock.
- Shrinking the 300 ms watermark to improve a latency figure.
- Keying `ddos` deduplication on source IP, or `dga` deduplication on domain.
- Presenting an uncalibrated score as a percentage or a probability.
- Converting missing evidence into a benign result.
- Publishing a throughput number without its machine specification, or extrapolating one.
- Starting new detector work after the Hour-16 kill gate, or any architecture change after the Hour-19 feature freeze.
- Inventing a measurement, a threshold or a requirement. If a number is undecided, say so and leave it open.

---

## Definition of Done

A change is done when **all** of the following are true:

- [ ] It satisfies the requirement in `PRD.md` and matches the architecture in `design.md`.
- [ ] It touches no frozen contract, or the contract change went through the full procedure: coordination, schema update, contract-test update, consumer update, verification.
- [ ] Relevant tests were run and their **actual output** is reported.
- [ ] Any new detector ships with a replay fixture, a minimum-evidence contract and an acceptance test.
- [ ] Any new alert path emits a non-null `flow_id` and a valid `flow_ref_type`.
- [ ] Capability state is declared correctly, and missing evidence produces `DEGRADED` or `NOT_OBSERVABLE` rather than a benign result.
- [ ] Any published number carries its dataset, command, configuration and output artifact.
- [ ] The operating documents that actually changed were updated: `implementation_plan.md`, `STATUS.md`, `task_today.md`, `memory.md`, `bugs.md`.
- [ ] Nothing on the forbidden-actions list was done.

If any item cannot be satisfied, say so plainly rather than declaring the work complete.
