"""End-to-end integration test for the PS26145 canonical campaign replay.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 17, 18, 19, 24, testing.md section 19.
Traceability: PS26145 all 6 mandatory threat classes, passive ingest, hash chain, read-only API.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from starlette.testclient import TestClient

from alerts.hash_chain import verify_hash_chain
from api.main import create_app
from api.state import AppState
from detectors.pipeline import DetectionPipeline
from scenarios.canonical_campaign import generate_canonical_campaign_events

ALERT_SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "alert.schema.json"

MANDATORY_PS_CLASSES = {
    "Volumetric DDoS / flooding",
    "Port scanning / reconnaissance",
    "Botnet C2 beaconing",
    "DGA / DNS tunnelling",
    "Malware in encrypted sessions",
    "Data exfiltration",
}


@pytest.fixture(scope="module")
def alert_schema() -> dict[str, Any]:
    with open(ALERT_SCHEMA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def test_canonical_campaign_end_to_end_pipeline(tmp_path: Path, alert_schema: dict[str, Any]):
    """Execute the full canonical campaign and verify end-to-end integration.

    Normalized Events -> Features -> Detectors -> Deduplicator -> SQLite -> API/WS.
    """
    db_file = tmp_path / "test_campaign.db"
    app_state = AppState(db_path=db_file)
    pipeline = DetectionPipeline()

    # 1. Generate canonical campaign events
    events = generate_canonical_campaign_events()
    assert len(events) >= 1000

    # 2. Ingest through detection pipeline
    for ev in events:
        alerts = pipeline.process_event(ev)
        for a in alerts:
            app_state.ingest_alert(a)

    flushed = pipeline.flush()
    for a in flushed:
        app_state.ingest_alert(a)

    # 3. Verify that all 6 mandatory PS threat classes were detected and persisted
    incidents = app_state.store.list_incidents(limit=1000)
    detected_classes = {inc["ps_class"] for inc in incidents}
    missing_classes = MANDATORY_PS_CLASSES - detected_classes
    assert not missing_classes, f"Missing mandatory PS threat classes: {missing_classes}"

    # 4. Verify all persisted incidents comply with schemas/alert.schema.json
    for inc in incidents:
        jsonschema.validate(instance=inc, schema=alert_schema)
        assert len(inc["incident_id"]) == 16
        assert len(inc["flow_id"]) == 16
        assert inc["flow_ref_type"] in ("flow_5tuple", "aggregate", "entity")
        assert inc["severity"] in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert inc["status"] in ("NEW", "ACTIVE", "UPDATED", "RESOLVED")

    # 5. Verify cryptographic hash chain integrity
    all_chain_entries = app_state.store.get_all_signed_entries()
    assert len(all_chain_entries) >= len(incidents)
    valid_chain, chain_err = verify_hash_chain(all_chain_entries)
    assert valid_chain is True, f"Hash chain verification failed: {chain_err}"

    # 6. Test FastAPI Plane B endpoints
    app = create_app(service_state=app_state)
    client = TestClient(app)

    # GET /health
    r_health = client.get("/health")
    assert r_health.status_code == 200
    h_data = r_health.json()
    assert h_data["status"] == "healthy"
    assert h_data["read_only"] is True
    assert h_data["total_incidents"] == len(incidents)

    # GET /capabilities
    r_cap = client.get("/capabilities")
    assert r_cap.status_code == 200
    c_data = r_cap.json()
    assert "input_mode" in c_data

    # GET /incidents
    r_inc = client.get("/incidents")
    assert r_inc.status_code == 200
    api_incidents = r_inc.json()
    assert len(api_incidents) == len(incidents)

    # GET /export/json
    r_export_json = client.get("/export/json")
    assert r_export_json.status_code == 200
    exported_entries = r_export_json.json()
    ok_exp, err_exp = verify_hash_chain(exported_entries)
    assert ok_exp is True

    # GET /export/csv
    r_export_csv = client.get("/export/csv")
    assert r_export_csv.status_code == 200
    csv_rows = list(csv.DictReader(io.StringIO(r_export_csv.text)))
    assert len(csv_rows) == len(incidents)
    csv_classes = {r["ps_class"] for r in csv_rows}
    assert csv_classes == MANDATORY_PS_CLASSES

    # WS /ws/incidents snapshot
    with client.websocket_connect("/ws/incidents") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "snapshot"
        assert msg["count"] == len(incidents)
        assert len(msg["incidents"]) == len(incidents)
