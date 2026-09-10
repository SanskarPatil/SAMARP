"""Contract, persistence, and endpoint tests for PS26145 Plane B monitoring API.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 17, 18, 19, design.md sections 18, 19.
Schema: schemas/alert.schema.json.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from starlette.routing import Route, WebSocketRoute
from starlette.testclient import TestClient

from alerts.hash_chain import HashChainWriter, verify_hash_chain
from api.main import create_app
from api.persistence import SQLiteIncidentStore
from api.state import AppState

ALERT_SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "alert.schema.json"


@pytest.fixture(scope="module")
def alert_schema() -> dict[str, Any]:
    with open(ALERT_SCHEMA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def sample_alert() -> dict[str, Any]:
    return {
        "schema_version": "1.3",
        "timestamp": "2026-09-11T00:00:00.000000+00:00",
        "flow_id": "0123456789abcdef",
        "flow_ref_type": "aggregate",
        "ps_class": "Volumetric DDoS / flooding",
        "threat_class": "syn_flood",
        "detector": "ddos",
        "confidence": None,
        "score": 14.2,
        "score_type": "robust_z",
        "calibrated": False,
        "evidence": {
            "interpretation": "SYN flood detected exceeding 1000 pps",
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "packet_rate": 5400,
        },
        "incident_id": "0123456789abcdef",
        "status": "NEW",
        "severity": "HIGH",
        "first_observed": "2026-09-11T00:00:00.000000+00:00",
        "last_observed": "2026-09-11T00:00:01.000000+00:00",
        "event_count": 1,
        "capability": {
            "detector_state": "OBSERVABLE",
            "input_mode": "pcap_replay",
        },
    }


def test_plane_b_strictly_read_only():
    """Route contract test: Plane B exposes GET and WebSocket ONLY.

    Asserts that no POST, PUT, PATCH, or DELETE route is registered on the Plane B application.
    """
    app = create_app()

    allowed_http_methods = {"GET", "HEAD", "OPTIONS"}

    for route in app.routes:
        if isinstance(route, Route):
            for method in route.methods:
                assert method in allowed_http_methods, (
                    f"Forbidden mutating HTTP method '{method}' registered on route '{route.path}'. "
                    f"Plane B must be strictly read-only."
                )
        elif isinstance(route, WebSocketRoute):
            continue
        else:
            # Mounts or static routes
            pass

    client = TestClient(app)

    # Assert forbidden methods return 405 Method Not Allowed
    r_post_health = client.post("/health", json={})
    assert r_post_health.status_code == 405

    r_post_incidents = client.post("/incidents", json={})
    assert r_post_incidents.status_code == 405

    r_put_incidents = client.put("/incidents/1", json={})
    assert r_put_incidents.status_code == 405

    r_del_incidents = client.delete("/incidents/1")
    assert r_del_incidents.status_code == 405

    # Assert attack simulation endpoint was permanently removed in V6.3
    r_sim = client.post("/simulate/scenario/1", json={})
    assert r_sim.status_code in (404, 405)


def test_health_endpoint():
    """Verify GET /health returns operational and read-only status."""
    app = create_app()
    client = TestClient(app)

    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "healthy"
    assert data["read_only"] is True
    assert "uptime_seconds" in data
    assert "total_incidents" in data
    assert "chain_seq" in data


def test_capabilities_endpoint():
    """Verify GET /capabilities returns capability state conforming to frozen contract."""
    app = create_app()
    client = TestClient(app)

    response = client.get("/capabilities")
    assert response.status_code == 200
    data = response.json()

    assert "input_mode" in data
    assert data["input_mode"] == "pcap_replay"
    assert "ipv4" in data
    assert "ja3" in data


def test_incidents_crud_and_schema_validation(sample_alert: dict[str, Any], alert_schema: dict[str, Any]):
    """Verify incidents query, single get, filtering, and alert.schema.json validation."""
    app_state = AppState(db_path=":memory:")
    app = create_app(service_state=app_state)
    client = TestClient(app)

    # Empty store
    r_empty = client.get("/incidents")
    assert r_empty.status_code == 200
    assert r_empty.json() == []

    # Ingest 1 alert
    signed_inc = app_state.ingest_alert(sample_alert)
    inc_id = signed_inc["incident_id"]

    # Ingest 2nd alert with a DIFFERENT class
    scan_alert = dict(sample_alert)
    scan_alert["incident_id"] = "fedcba9876543210"
    scan_alert["flow_id"] = "fedcba9876543210"
    scan_alert["ps_class"] = "Port scanning / reconnaissance"
    scan_alert["threat_class"] = "syn_scan"
    scan_alert["detector"] = "scan"
    scan_alert["severity"] = "MEDIUM"
    app_state.ingest_alert(scan_alert)

    # List all
    r_list = client.get("/incidents")
    assert r_list.status_code == 200
    incidents = r_list.json()
    assert len(incidents) == 2

    # Validate schema of each returned incident
    for inc in incidents:
        jsonschema.validate(instance=inc, schema=alert_schema)

    # Filter by ps_class
    r_filter_class = client.get("/incidents", params={"ps_class": "Volumetric DDoS / flooding"})
    assert r_filter_class.status_code == 200
    assert len(r_filter_class.json()) == 1
    assert r_filter_class.json()[0]["incident_id"] == inc_id

    # Filter by severity
    r_filter_sev = client.get("/incidents", params={"severity": "MEDIUM"})
    assert r_filter_sev.status_code == 200
    assert len(r_filter_sev.json()) == 1
    assert r_filter_sev.json()[0]["ps_class"] == "Port scanning / reconnaissance"

    # Get single existing
    r_single = client.get(f"/incidents/{inc_id}")
    assert r_single.status_code == 200
    single_data = r_single.json()
    assert single_data["incident_id"] == inc_id
    jsonschema.validate(instance=single_data, schema=alert_schema)

    # Get single nonexistent
    r_404 = client.get("/incidents/0000000000000000")
    assert r_404.status_code == 404


def test_incident_history_endpoint(sample_alert: dict[str, Any]):
    """Verify GET /incidents/{id}/history tracks lifecycle progression."""
    app_state = AppState(db_path=":memory:")
    app = create_app(service_state=app_state)
    client = TestClient(app)

    # Ingest first observation -> NEW
    inc1 = app_state.ingest_alert(sample_alert)
    inc_id = inc1["incident_id"]

    # Ingest second observation -> ACTIVE
    app_state.ingest_alert(sample_alert)

    # Ingest third observation -> UPDATED
    app_state.ingest_alert(sample_alert)

    r_hist = client.get(f"/incidents/{inc_id}/history")
    assert r_hist.status_code == 200
    history = r_hist.json()

    assert len(history) == 3
    assert history[0]["status"] == "NEW"
    assert history[1]["status"] == "ACTIVE"
    assert history[2]["status"] == "UPDATED"

    # Monotonic seq across history
    assert history[0]["seq"] == 1
    assert history[1]["seq"] == 2
    assert history[2]["seq"] == 3


def test_export_json_verifies_hash_chain(sample_alert: dict[str, Any], alert_schema: dict[str, Any]):
    """Verify GET /export/json outputs a valid continuous hash chain."""
    app_state = AppState(db_path=":memory:")
    app = create_app(service_state=app_state)
    client = TestClient(app)

    for _ in range(5):
        app_state.ingest_alert(sample_alert)

    r_export = client.get("/export/json")
    assert r_export.status_code == 200
    assert r_export.headers["content-type"].startswith("application/json")

    entries = r_export.json()
    assert len(entries) == 5

    for entry in entries:
        jsonschema.validate(instance=entry, schema=alert_schema)

    valid, err = verify_hash_chain(entries)
    assert valid is True
    assert err is None


def test_export_csv_flattening(sample_alert: dict[str, Any]):
    """Verify GET /export/csv flattens scalar evidence columns and includes evidence_json."""
    app_state = AppState(db_path=":memory:")
    app = create_app(service_state=app_state)
    client = TestClient(app)

    signed_inc = app_state.ingest_alert(sample_alert)

    r_csv = client.get("/export/csv")
    assert r_csv.status_code == 200
    assert r_csv.headers["content-type"].startswith("text/csv")

    csv_text = r_csv.text
    reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(reader)

    assert len(rows) == 1
    row = rows[0]

    assert row["incident_id"] == signed_inc["incident_id"]
    assert row["ps_class"] == "Volumetric DDoS / flooding"
    assert "evidence_json" in row
    assert row["evidence.dst_ip"] == "10.0.0.1"
    assert row["evidence.dst_port"] == "80"
    assert row["evidence.packet_rate"] == "5400"


def test_sqlite_persistence_reload_and_chain_continuity(sample_alert: dict[str, Any], tmp_path: Path):
    """Verify SQLite persistence retains state and resumes hash-chain state seamlessly across restarts."""
    db_file = tmp_path / "sentinel.db"

    # Session 1: write 3 entries
    store1 = SQLiteIncidentStore(db_file)
    writer1 = HashChainWriter()

    for i in range(3):
        rec = dict(sample_alert)
        rec["last_observed"] = f"2026-09-11T00:00:0{i}.000000+00:00"
        store1.save_incident(rec, chain_writer=writer1)

    assert store1.count_incidents() == 1
    assert store1.count_updates() == 3
    store1.close()

    # Session 2: reopen store and resume hash chain
    store2 = SQLiteIncidentStore(db_file)
    last_seq, last_hash = store2.get_latest_chain_state()
    assert last_seq == 3

    writer2 = HashChainWriter(initial_seq=last_seq, initial_prev_hash=last_hash)
    rec4 = dict(sample_alert)
    rec4["last_observed"] = "2026-09-11T00:00:04.000000+00:00"
    store2.save_incident(rec4, chain_writer=writer2)

    assert store2.count_updates() == 4

    # Full export across both sessions must verify completely
    all_entries = store2.get_all_signed_entries()
    assert len(all_entries) == 4
    assert [e["seq"] for e in all_entries] == [1, 2, 3, 4]

    valid, err = verify_hash_chain(all_entries)
    assert valid is True
    assert err is None
    store2.close()


def test_websocket_incidents_snapshot_and_broadcast(sample_alert: dict[str, Any]):
    """Verify WebSocket connection receives initial snapshot and real-time incident batches."""
    app_state = AppState(db_path=":memory:")
    # Seed an incident
    app_state.ingest_alert(sample_alert)

    app = create_app(service_state=app_state)
    client = TestClient(app)

    with client.websocket_connect("/ws/incidents") as websocket:
        # Initial snapshot
        initial_msg = websocket.receive_json()
        assert initial_msg["type"] == "snapshot"
        assert initial_msg["count"] == 1
        assert len(initial_msg["incidents"]) == 1
        assert "capabilities" in initial_msg

        # Client ping-pong
        websocket.send_text("ping")
        resp = websocket.receive_text()
        assert resp == "pong"
