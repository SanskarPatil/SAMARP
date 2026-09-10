# Project Memory

Durable knowledge an engineer or AI agent would otherwise have to rediscover. **Only record what remains useful beyond the current task.** Transient state belongs in `task_today.md`; current state belongs in `STATUS.md`; failures belong in `bugs.md`.

Seeded 2026-09-10 from `FINAL_DEVELOPMENT_PLAN_V6.3.md` and the cross-document analysis of the three source documents.

---

## Architecture Decisions

### Phase 0 frozen decisions (project owner, 2026-09-10)

Four gaps in `FINAL_DEVELOPMENT_PLAN_V6.3.md` that the documentation layer was not entitled to fill. Decided explicitly; now frozen contract facts.

#### Throughput acceptance target

```text
Primary PS KPI      >= 1 000 normalized flows/sec, sustained 60 s, < 1 % measured loss
Secondary (V6.3)    >= 50 000 pps,  sustained 60 s, < 1 % loss
                    >= 400 Mbps,    sustained 60 s, < 1 % loss
```

**Rationale:** V6.3 section 14.1 promoted flows/sec to primary PS KPI but left its target behind with pps and Mbps, so the headline metric had no stopping condition — the exact defect that section exists to prevent, reintroduced one metric up. The V6.3 secondary figures are retained unchanged so nothing already argued for is lost.

**The three metrics are never conflated.** Flows/sec is not derived from pps, and neither is derived from Mbps. A derived figure is not a measurement and does not get published. This matters because a flow-record input and a packet input produce wildly different flows-per-packet ratios, so a conversion factor from one replay would be meaningless on another.

#### Canonical identifier representation

```text
identifier = sha256(canonical_value).hexdigest()[:16]
```

Exactly 16 lowercase hexadecimal characters — a 64-bit truncated SHA-256, matching `^[0-9a-f]{16}$`.

**Rationale:** `[:16]` in V6.3 was ambiguous between 16 hex characters (64-bit) and 16 bytes (128-bit). In Python the same expression yields either, depending on whether it is applied to `hexdigest()` or `digest()`. Two developers would have picked differently, and the failure would surface as a verifier that cannot reproduce the writer's identities — at hour 17, on a scripted demo beat.

- Applies to `flow_id` and `incident_id` only.
- **Chain hashes are never truncated.** `payload_hash`, `entry_hash` and `prev_hash` stay full 64-character digests, consistent with the genesis `"0" * 64`.
- One canonicalisation and hashing helper in `alerts/hash_chain.py`, imported by **both** writers and verifiers. Neither reimplements it.

#### Unavailable deduplication-key components

Unavailable components take the exact canonical sentinel string **`NOT_OBSERVABLE`** — never null, empty string, zero, `unknown`, or another placeholder. Deduplication operates on the canonical serialized key containing the sentinel.

```text
tls_quic      (ps_class, src_ip, NOT_OBSERVABLE, dst_ip)      ja3 absent under IPFIX
dns_tunnel    (ps_class, src_ip, NOT_OBSERVABLE)              registered_domain absent
reflection    (ps_class, dst_ip, NOT_OBSERVABLE)              amplifier_port absent
```

**Rationale:** the dedup keys were frozen in the same version that formalised capability degradation, and the two sections were never cross-checked. Three keys depend on evidence that is normally invisible under flow-record input. A single explicit sentinel keeps identity deterministic and stable across input modes; a null or empty string would collide with legitimately empty values and would serialise differently in different languages.

**The string is deliberately reused, and the two meanings must not be collapsed.** `NOT_OBSERVABLE` is both a detector capability state (evidence-visibility axis) and a dedup-key component placeholder (identity axis). They act at different pipeline stages. The capability and minimum-evidence checks still run first — **the sentinel governs how an incident is identified, never whether one may be raised on absent evidence.**

#### Test subtree

`tests/detectors/` and `tests/throughput/` created; every other V6.3 test directory and the rest of the repository structure preserved unchanged.

#### Demo timeline — documented, not rewritten

V6.3 section 41 heads the incident-lifecycle beat **3:00–4:00** and the input-mode beat **3:45–4:00**, which overlap inside a fixed 7-minute budget. **Both timestamps are preserved verbatim.** The recorded interpretation is that the input-mode beat is a carve-out from the tail of the lifecycle block rather than extra budget.

This is deliberately *not* a correction. Rewriting a source timeline inside a derived document is how the two drift apart; the authoritative fix belongs in V6.3 section 41 first, and the derived documents follow it.

---

### One-clock replay

Suricata and the fast header counter must consume the **same** tcpreplay-driven interface. Running them independently against the PCAP creates divergent clocks and breaks correlation.

Display time is rebased once:

```text
t_display = t_replay_start + (t_packet - t_pcap_start) / replay_speed
```

`t_replay_start` is captured once when replay begins and written into the scenario manifest. Writing `now` here and evaluating it per packet adds wall-clock elapsed on top of PCAP-relative elapsed, so the displayed clock drifts at roughly 2x. This is the dual-clock correlation failure — do not reintroduce it.

### JSON boundary rule

JSON exists at exactly three boundaries: the Suricata EVE input, SQLite evidence storage, and WebSocket output. **It is not an inter-stage transport format.** Post-normalisation processing is in-process. The only runtime file on the input path is `eve.json`, which is tailed.

### One trained model

DGA (LightGBM) is the only trained model in scope. Every other detector is statistical, rule-based or offline-intelligence driven. This is a deliberate scope decision, not an accident of time — it keeps latency low, keeps the system interpretable, and gives one honest calibration story instead of several weak ones.

### Six classes, eight modules

The PS defines **six** threat classes; the implementation contains **eight** detector modules. The counts differ deliberately: *Volumetric DDoS / flooding* is served by `ddos.py` and `reflection.py`, and *DGA / DNS tunnelling* by `dga.py` and `dns.py`. An earlier plan version said "seven classes" while listing eight modules — that drift is the exact failure the terminology rule exists to prevent. External material uses the six class names verbatim; module names are internal only.

### Two planes, no return path

The Scenario Console (Plane A) and Monitoring Dashboard (Plane B) are separate applications on opposite sides of the boundary. `POST /simulate/scenario/{id}` was removed from Plane B because an attack-starting endpoint on the monitoring side reads as a return path, and the entire read-only argument collapses in one question. A contract test asserts no non-`GET` route is registered.

### `flow_summary` ownership

Suricata EVE flow events are intentionally disabled to reduce output pressure. `flow_summary` therefore comes from the bounded in-process flow tracker on the header path. **Do not re-enable EVE flow events to populate it** — the capability probe asserts `flow events == 0`.

### Baseline loads at boot; warm-up applies only to the adaptive delta

An earlier version said both "baseline available at startup" and "baseline warm-up gate", which read as contradictory. The resolution: the snapshot loads at boot so there is no cold start and detection is live from the first window. The `warmup_windows` gate applies **only** to the adaptive delta layered on top of the snapshot, never to detection itself.

---

## Important Discoveries

### Capability state has two axes, not one

`FINAL_DEVELOPMENT_PLAN_V6.3.md` lists four states but its tables only ever use three. The two axes are distinct and were being conflated:

- **Evidence visibility, per detector:** `OBSERVABLE | DEGRADED | NOT_OBSERVABLE`
- **Component health, per component:** `HEALTHY | DEGRADED | UNAVAILABLE`

`UNAVAILABLE` describes a component that is down — sensor, normalizer, detector process, API, WebSocket. It never appears in a detector capability declaration.

### `NOT_OBSERVABLE` is not a property of an input mode

`sflow` is a valid frozen `input_mode` value. sFlow is a recognised sampled input; sampling-aware volumetric statistics may remain usable, and only detectors depending on unsampled packet order, complete port spread, DNS names or TLS fingerprints degrade. The phrase "sFlow is `NOT_OBSERVABLE`" appears in the documentation specification but is not a valid statement in this system — capability is declared per detector, not per input mode.

### Deduplication keys are counter-intuitive in two places

- **`ddos` never keys on source.** Sources are spoofed, so a source key produces one incident per packet — the precise failure the incident model exists to prevent.
- **`dga` never keys on domain.** A DGA burst is hundreds of distinct domains; domains are evidence rows *inside* one incident, not incident identities.
- `dns_tunnel` keys on the registered domain (eTLD+1 after TLD stripping), because the full query name is the thing that varies.

---

## Environment Facts

- **Suricata 7.0.3 or later** is required for JA4. Record the exact version in capability state and in every alert's sensor metadata.
- **WSL2 is not acceptable** for the published throughput number — the capture path differs and the figure will be challenged. Native Linux preferred; a full VM is acceptable.
- The OS and box decision is made **before** the window opens, not at hour 0, and the box specification is recorded because a throughput number without it is meaningless.
- Everything runs offline. Vendor Python wheels, Node dependencies, the Suricata build, GeoLite2 and TopoJSON if the map is retained, the intel bundle, the model artifact, all PCAPs and flow fixtures, and scenario manifests.

---

## Known Gotchas

### Suricata's five silent defaults

Each one disables a detector without producing an error. A detector with no input does not fail — it simply never alerts, and the team debugs the detector for four hours instead of the sensor.

1. **EVE log types** — missing `dns.responses` removes NXDOMAIN context, which is minimum evidence for DGA *and* a required feature for the DNS-tunnel ensemble.
2. **Fingerprints off by default** — no JA3, JA3S or JA4.
3. **Stats disabled** — no `kernel_drops`, so no `sensor_drop_pct`, so the entire capture-loss story does not exist.
4. **Capture ring too small** — drops during the flood get wrongly attributed to the detection pipeline rather than the capture layer.
5. **Stream reassembly depth** — truncated reassembly silently shortens the flows exfiltration and beaconing depend on.

### The private-address lab traps

Two failures in the same family, both fixed by `config/address_plan.yaml`:

- **Reflection reserved-source share** is 100 % on benign traffic in a pure RFC 1918 lab, so the detector fires continuously and destroys the false-alerts-per-hour figure. The feature must be computed against the **external** address space only, with declared lab prefixes excluded from the bogon set — and the exclusion stated in the evidence drawer text.
- **Geolocation** does not work for private addresses. The external side is assigned GeoLite2-resolvable ranges; anything unresolvable renders with a visible `demo_fixture` badge. Geolocation is not attribution.

`direction` was never defined anywhere before the address plan existed, yet `exfil.py` cannot exist without it.

### The UI load test does not contradict the demo claim

`tests/ui_load/` deliberately bypasses deduplication to stress the render path. The demo claim that a 50 000 pps flood produces one incident concerns the **detector** path, which sits upstream of the injection point. State the distinction if a judge watches the test run.

---

## Performance Discoveries

- **Never shrink the watermark to improve latency.** The 300 ms out-of-order grace is a floor accepted deliberately; shrinking it drops late packets silently and trades a visible latency number for invisible missed detections. Fix order is batch push interval, then window size, then detector cost.
- The structural latency floor is ~1.6 s (300 ms watermark + ~1.0 s window + ~100 ms scoring + 250 ms push), against an SLO of p95 < 2.0 s. There is not much headroom; design accordingly.
- Throughput work is a known time sink. Optimise until the target is met, then stop and move to hardening.
- **Never extrapolate** a throughput number toward 10 Gbps or any unmeasured rate.

---

## Dataset / Scenario Knowledge

- **PCAP generation stops at the Hour-6 gate**, where the set is complete, hashed and manifested. After that the lab is replay-only. (An earlier narrative line said hour 16; the binding statements — the Hour-6 gate item and Ticket 0's own done-when — both say hour 6.)
- **DGArchive is not a runtime or download dependency.** Published DGA families are reimplemented locally so evaluation is reproducible offline. Every substitution for a PS-named source is documented in `README.md` and the scenario manifest.
- **CIC-IDS2017 is not used** — port-label leakage and mislabeling concerns, large download, reproducibility concerns. Ground truth is generated reproducibly in the repository instead.
- **`BENIGN_STRESS` is mandatory**, not optional. It is the only source of the false-alerts-per-hour number.
- Malware-capture datasets are hostile packet data. Never execute a binary from one.

---

## Detection Knowledge

- **Slowloris cannot be a pps threshold.** It is a low-rate exhaustion path: concurrent half-open/long-lived connections, connection-duration percentile, bytes per connection, low rate, destination-specific baseline. The incident fires only when the concurrency and duration gates agree, and the evidence drawer shows the low-rate nature rather than hiding it behind the generic flood detector.
- **The n-gram language-model score is a feature, not a verdict.** It is what defeats wordlist-style DGAs that raw entropy cannot separate.
- **DGA hard negatives matter more than more positives.** CDN names, UUID-like identifiers, long API subdomains, telemetry names and update infrastructure stop the model learning `random-looking == malicious`.
- **"Shape" must mean named features**, not a generic anomaly label: `packet_size_first_n`, `direction_first_n`, `iat_median`, `iat_p95`, `iat_cv`, upstream/downstream ratios.
- **Missing fingerprints are capability state, not evidence of benign traffic.**
- A robust z-score or rule score is **never** a probability. `score_type` and `calibrated` govern presentation; a percent sign appears only when `calibrated: true`.

---

## UI Knowledge

- Batched WebSocket pushes at ~250 ms, a 500-item client ring buffer, list virtualisation, `requestAnimationFrame` counters, and a single CSS severity accent variable. These four together are what keeps the page interactive under a burst.
- TLS/QUIC wording is `Suspicious Encrypted Session` / `Encrypted Session Anomaly`. Never malware identification.
- Recommendations are advisory text. Say "advisory" out loud when demonstrating them.

---

## Judge / Demo Insights

- **Record the backup video immediately on the Hour-16 gate pass.** It is the earliest moment a complete run exists, and it is the only insurance that survives a dead laptop, a failed cold boot or a broken projector. Scheduled later it competes with three rehearsals and gets dropped.
- **Archive the boundary test output as an artifact.** If venue networking misbehaves during the run, the proof still exists.
- The tamper claim must be phrased precisely: the chain makes post-hoc modification **detectable**. It is tamper-evident, not a claim that storage is immutable.
- Positioning: *this system is an intelligence layer on top of passive sensor data, not a replacement for Suricata.* Concede where signatures perform better.
- Say "previously unseen patterns", never "zero-day".
- Never improvise a number in Q&A. If it is not measured with an artifact, it does not get said.

---

## Rejected Approaches

- **A scalar Kalman filter as a detector baseline** — it can absorb the attack into its own state. If Kalman is used at all, it belongs in ingest and loss estimation, not in detection.
- **Two independent NetFlow and IPFIX parsers** — both use template-defined records, so one shared template cache and decoder is correct. Two parsers means two sets of bugs and two places to forget bounded state.
- **Re-enabling EVE flow events** to populate `flow_summary`.
- **A `POST` route on the monitoring API** for demo convenience.
- **Runtime address anonymisation in this build** — all capture is lab-synthetic, so there is nothing to protect. For real enclave traffic, CryptoPAn applies *after* geolocation and *before* persistence; applying it first destroys the geo lookup. Documented in `LIMITATIONS.md`.

---

## Documentation Conflicts and How They Were Resolved

Recorded because the same conflicts will resurface whenever a document is regenerated. Full detail is in `bugs.md` (`DOC-001` to `DOC-011`).

The governing rule, stated by the project owner: **when two sources conflict, prefer the higher authority — PS26145, then `ps26145_traceability_matrix.md`, then `FINAL_DEVELOPMENT_PLAN_V6.3.md`, then `create_project_md_files_V2.md`. Never resolve a contradiction by inventing a new requirement.**

| Conflict | Resolution |
|---|---|
| Six PS class label strings spelled three different ways across the documents | The `FINAL_DEVELOPMENT_PLAN_V6.3.md` section 1.1 left column is the frozen `ps_class` wording, because 1.1 is the section that declares the terminology rule |
| PCAP generation deadline: hour 6 vs hour 16 | Hour 6 — two of three binding statements say so; the hour-16 phrase is stale narrative. The hours 16–19 "switch to REPLAY mode" is console hardening, not the generation deadline |
| sFlow described three incompatible ways | V6.3 wins: `sflow` is a valid input mode; capability degrades per detector |
| `UNAVAILABLE` declared but never used in a capability table | Documented as the component-health axis, distinct from evidence visibility |
| `A-P5` and `B-P5` nested under the wrong tracks in the documentation spec | Moved to their owning tracks; no phase content changed or dropped |
| Four items genuinely undecided in V6.3 | Left open and escalated to a Phase 0 decision. **No values were invented** |

---

## Future Work

- Real-enclave anonymisation path (CryptoPAn after geo, before persistence).
- sFlow as a first-class sampled detector source rather than a recognised capability mode.
- Retraining cadence for the DGA model through a versioned offline bundle cycle, with passive drift monitoring feeding the next bundle.
- The optional throughput-vs-loss sweep, to publish a measured operating envelope rather than a single point.
