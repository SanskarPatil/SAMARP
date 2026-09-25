# Security controls: built vs roadmap

Status as of branch `fix/ps-compliance`. BUILT = in code and tested; NOT BUILT = design only.

## Built
| Control | Evidence |
|---|---|
| Read-only application interface: GET + WebSocket only, POST / PUT / DELETE -> 405 | `api/routes.py`; `tests/api/test_api_and_persistence.py::test_plane_b_strictly_read_only`; `scripts/verify_all.py` static route scan |
| No payload fields; metadata only | `schemas/normalized_event.schema.json`; `test_schema_has_no_payload_or_content_field` |
| Tamper-evident hash-chained incident ledger (SHA-256; one edit breaks verification) | `alerts/hash_chain.py`; `run_demo.py --verify-only` |
| Offline operation: no internet, feed or LLM at run time | `intel/version_manifest.json` |
| Missing evidence reported as DEGRADED / NOT_OBSERVABLE, never "benign" | `ingest/capability.py`; `test_statistical_detectors.py::test_missing_evidence_is_not_benign` |
| Model artifact without pickle (text booster + JSON), SHA-256 recorded | `models/dga_model.py`; `benchmarks/dga_eval_*.json` |

## Software read-only vs physical one-way
The API proves only that SAMARP exposes no write path. The **physical** guarantee - that no packet can travel
back to the production network - comes from deployment: a hardware data diode or a passive network TAP feeding
the sensor. SAMARP assumes that and never needs a return path (no probing, no handshakes, no blocking). The
diode itself is infrastructure, not demonstrated by this software.

## NOT BUILT (roadmap)
| Control | Plan |
|---|---|
| Authentication | Local accounts or the site's SSO in front of the dashboard / API |
| Role-based access | viewer (read incidents) - analyst (+ export evidence, change status) - admin (+ thresholds, retention); least privilege by default |
| Configuration audit | Hash-chain threshold / config changes like incidents: who, when, old -> new value |
| Signed configuration | Detached signature on `config/*.yaml`, checked at start-up |
| Database protection | OS file permissions, encryption at rest (e.g. BitLocker / LUKS) where required, backups, retention policy |
| ML security | Training data only from curated, hashed sources (Tranco list SHA-256 already recorded); shadow mode doubles as drift monitoring; model promotion requires beating rules on a held-out real set, with a human sign-off |
