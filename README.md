# Cyber Sentinel

**AI-Based Detection of Cyber Threats in Unidirectional IP Traffic — SIH 2026, Problem Statement PS26145.**

Cyber Sentinel is a passive, streaming cyber-intelligence layer for a monitored enclave sitting behind a one-way boundary. It observes copied traffic, sensor metadata and exported flow records, and turns those observations into evidence-rich, deduplicated incidents — including an explicit statement of what it could **not** see.

It never sends anything back across the boundary, never decrypts payload, and never depends on the internet at run time.

---

## Design Constraints

These are architectural invariants, not preferences. Every one of them is enforced by code, by a contract test, or by both.

| Constraint | What it means in practice |
|---|---|
| **One-way boundary** | The monitoring plane has no actionable return route. The API exposes `GET` routes and a WebSocket only; mutating methods return `405`. |
| **No payload decryption** | TLS/QUIC are characterised by fingerprints (JA3/JA3S/JA4) and traffic shape — packet sizes, direction sequence, inter-arrival statistics. No decrypted-content claim is ever made. |
| **Offline at run time** | No live threat feed, no external geolocation service, no runtime LLM inference. Intelligence ships as a versioned offline bundle under `intel/`. |
| **Streaming, not batch** | Bounded tumbling windows behind a fixed watermark, pushed to the dashboard over a WebSocket. |
| **Bounded memory** | No unbounded structure is keyed on an attacker-controlled value. Flow state, template caches and detector state all have caps and eviction. |
| **Missing evidence is never benign** | Absent observability produces `DEGRADED` or `NOT_OBSERVABLE`, never a clean result. |
| **One trained model** | The DGA LightGBM classifier is the only trained model in the system. Every other detector is statistical, rule-based or offline-intelligence driven. |

---

## Pipeline

```text
Passive input                 PCAP replay | live tap | IPFIX | NetFlow v9 | sFlow
      |
      v
ingest/       normalization, single-clock replay, bounded flow tracking,
              capability declaration, deterministic flow identity
      |
      v
features/     entropy, robust statistics (median/MAD, robust z), inter-arrival
              shape, DNS qtype distribution, lexical/DGA features, TLS/QUIC shape
              — emitted in a single frozen FEATURE_ORDER
      |
      v
detectors/    seven active modules covering the six PS threat classes
      |
      v
alerts/       deduplication (frozen keys), scoring, SHA-256 hash chain
      |
      v
persistence   SQLite
      |
      v
api/          FastAPI read-only routes + /ws/incidents WebSocket
      |
      v
dashboard/    React + TypeScript + Vite monitoring dashboard
```

JSON appears at exactly three boundaries — the Suricata EVE input, the storage boundary and the WebSocket output. Everything between normalization and persistence is in-process.

---

## Threat Coverage

Six externally presented PS threat classes, served by seven active detector modules:

| PS class | Module | Primary evidence |
|---|---|---|
| Volumetric DDoS / flooding | `detectors/ddos.py` | pps and byte rate against baseline, SYN behaviour, source entropy; **Slowloris is a distinct low-rate exhaustion path in the same module** (concurrency, duration percentile, bytes per connection) |
| Botnet C2 beaconing | `detectors/c2.py` | repeated destination, inter-arrival coefficient of variation and MAD, persistence, destination novelty |
| DGA domains | `detectors/dga.py` | lexical entropy, character bigram and trigram language-model scores, NXDOMAIN rate |
| DNS tunnelling | `detectors/dns.py` | query length and entropy, qtype distribution including TXT/NULL/CNAME share, queries per second per registered domain |
| Malware in encrypted sessions | `detectors/tls_quic.py` | JA3, JA3S, JA4 where the sensor exposes them; destination novelty; first-N packet sizes, direction ratios, inter-arrival statistics |
| Reconnaissance / port scanning | `detectors/scan.py` | distinct destination hosts and ports, fan-out, address spread |
| Data exfiltration | `detectors/exfil.py` | directional byte volume and ratio, session duration, destination novelty, baseline deviation |

`detectors/reflection.py` defines UDP reflection/amplification evidence and its deduplication key is frozen, but it is **not** wired into `detectors/pipeline.py`. Volumetric flooding is served by `ddos.py`. Describe the system externally as **seven active detector modules across six PS classes**.

---

## Frozen Contracts

These files are contracts. Changing one requires coordination, a schema update, a contract-test update, a consumer update and verification — see `git.md`.

| Contract | File |
|---|---|
| Normalized event schema | `schemas/normalized_event.schema.json` |
| Alert / incident schema v1.3 | `schemas/alert.schema.json` |
| Feature order | `features/feature_order.py` |
| Deduplication keys | `config/dedup_keys.yaml` |
| Lab address plan | `config/address_plan.yaml` |
| Thresholds and latency budget | `config/thresholds.yaml` |

### Alert identity

Every alert carries a non-null `flow_id` and a valid `flow_ref_type`:

```text
flow_ref_type = flow_5tuple | aggregate | entity

flow_id     = sha256(canonical(5-tuple))[:16]
            | sha256(canonical(dedup_key))[:16]
            | sha256(canonical(entity))[:16]
```

The canonical identifier form is exactly 16 lowercase hex characters — a 64-bit truncated SHA-256. Hash-chain fields (`payload_hash`, `entry_hash`, `prev_hash`) are full 64-character digests and are never truncated. Both the producer and every verifier import these helpers from `alerts/hash_chain.py` rather than reimplementing them.

Where a deduplication-key component is unavailable under the current observation mode, it takes the exact sentinel string `NOT_OBSERVABLE` — never null, never an empty string, never zero.

Two deduplication keys are deliberately counter-intuitive: `ddos` **never** keys on source (sources are spoofed, and a source key produces one incident per packet), and `dga` **never** keys on domain (a DGA burst is hundreds of distinct domains, which are evidence rows inside one incident).

---

## Quick Start

Requirements: Python 3.13, Node.js 18+.

```bash
pip install fastapi uvicorn jsonschema pyyaml lightgbm scikit-learn scipy
```

### Run the canonical campaign replay and the read-only API

```bash
python scripts/run_demo.py --serve --host 127.0.0.1 --port 8000
```

Other launcher modes:

```bash
python scripts/run_demo.py --replay-only              # replay the campaign and exit
python scripts/run_demo.py --verify-only export/canonical_campaign_export.json
```

The replay is deterministic: it regenerates the frozen artifacts in `export/` byte for byte, which is itself a verifiable claim.

### Run the dashboard

```bash
cd dashboard
npm install
npm run dev     # http://127.0.0.1:5173, proxied to the API on 127.0.0.1:8000
npm run build   # type-check and production build
```

### Read-only API surface

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | System health and read-only verification |
| `GET` | `/capabilities` | Capability and visibility declaration |
| `GET` | `/incidents` | Query latest incidents |
| `GET` | `/incidents/{incident_id}` | Single incident |
| `GET` | `/incidents/{incident_id}/history` | Incident update history |
| `GET` | `/export/json` | Complete signed hash chain, canonical JSON |
| `GET` | `/export/csv` | Flattened incident export |
| `WS` | `/ws/incidents` | Batched live incident stream |

There are no `POST`, `PUT` or `DELETE` routes, and there never will be. That absence is the boundary proof.

---

## Tests

```bash
python -m pytest -q
```

The suite covers the frozen schemas, feature parity, the one-way boundary, hash-chain verification, replay determinism, latency, capture loss, throughput and the detector acceptance fixtures.

Contract tests, feature-parity tests and the boundary test are not optional. A new detector requires a replay fixture and an acceptance test in the same change. Never weaken a test to make it pass.

---

## Evidence Integrity

Incidents are appended to a SHA-256 hash chain. Each entry binds the canonicalised alert payload to the previous entry, so any edit to a stored incident breaks verification from that point forward. `GET /export/json` returns the full chain, and the launcher can verify an exported file standalone with `--verify-only`.

---

## Machine Learning

- **One trained model: the DGA LightGBM classifier.** Training and inference import the same `FEATURE_ORDER` object; no component builds its own ordering.
- Time-based, entity-based and DGA-family holdouts are maintained, deduplicated before splitting, with TLDs stripped where specified.
- A hard-negative corpus of legitimately random-looking domains is kept so the model does not learn `random-looking == malicious`.
- `score_type` and `calibrated` govern presentation. A robust z-score or a rule score is **never** shown as a probability, and the UI appends a percent sign only when `calibrated: true`.
- If the DGA artifact is unusable, the documented rule fallback ships with `calibrated: false` and `model_version: "rules-fallback"` — and no Brier score or reliability diagram is published for it.

The accepted wording for novel activity is "previously unseen patterns". Cyber Sentinel does not claim zero-day detection, malware-family attribution or generic "AI accuracy".

---

## Performance Budget

The latency budget in `config/thresholds.yaml` is frozen: 300 ms watermark, ~1.0 s window, ~100 ms scoring and deduplication, 250 ms batch push, giving a structural floor of roughly 1.6 s against an SLO of **p95 < 2.0 s**. `latency_ms` is measured, never estimated.

If p95 exceeds the SLO, the fix order is batch push interval, then window size, then detector cost. **The watermark is never shrunk** — that trades a visible latency number for invisible missed detections.

Throughput acceptance targets are at least 1 000 normalized flows/sec sustained for 60 s below 1 % loss (the primary PS KPI), with at least 50 000 pps and 400 Mbps as independent secondary system metrics. Flows/sec, pps and Mbps are three separate measurements; deriving one from another is not a measurement. No throughput figure is published without the machine specification beside it, and none is extrapolated beyond the measured hardware.

---

## Repository Layout

```text
ingest/        normalization, replay clock, flow tracking, capability, identity
features/      stateless primitives, rolling windows, frozen FEATURE_ORDER
detectors/     seven active detector modules plus the pipeline coordinator
alerts/        deduplication, scoring, hash chain
models/        DGA dataset, training and inference
intel/         offline allowlist, DGA families, Tranco sample, baseline, version manifest
scenarios/     canonical campaign generator and mock fixtures
api/           FastAPI application, routes, WebSocket, persistence, state
dashboard/     React + TypeScript + Vite monitoring dashboard
schemas/       frozen JSON Schemas
config/        thresholds, deduplication keys, address plan
scripts/       run_demo.py launcher
export/        frozen canonical campaign artifacts
tests/         contract, boundary, replay, latency, throughput and detector tests
```

`SAMARP/` is a parallel snapshot of the project carrying its own copy of the detector modules and their tests, and `UI/` holds an earlier standalone HTML/JS interface. Neither is part of the live pipeline; the shipped dashboard is `dashboard/`.

---

## Security and Lab Policy

- Attack generation is **lab-only** — Linux network namespaces, veth pairs, or a host-only virtual network with no bridge to a physical interface. Before any run, verify the output interface is a veth or host-only adapter and that the target is inside the declared lab subnet.
- Never run attack tooling against college networks, hostel Wi-Fi, venue networks, cloud VMs, third-party IPs, or any system not personally owned or authorised.
- Treat malware-capture datasets as hostile packet data. Never execute a binary contained inside one.
- No credentials, keys or venue network details are committed.

---

## Documentation Map

Each file owns exactly one subject. No file carries a competing source of truth.

| File | Owns |
|---|---|
| `FINAL_DEVELOPMENT_PLAN_V6.3.md` | Current implementation source of truth |
| `ps26145_traceability_matrix.md` | Requirement-to-implementation compliance map |
| `PRD.md` | Requirements and scope |
| `design.md` | Architecture and contracts |
| `implementation_plan.md` | Build order and gates |
| `testing.md` | Verification methodology |
| `agents.md` | Ownership and handoffs |
| `git.md` | Collaboration workflow |
| `CLAUDE.md` | Behavioural rules for coding agents |
| `STATUS.md` | Current project state |
| `task_today.md` | Immediate work only |
| `memory.md` | Durable knowledge |
| `bugs.md` | Failures and fixes |

When two sources conflict, the higher authority wins. A contradiction is never resolved by inventing a new requirement.

---

## License

MIT — see `LICENSE`.
