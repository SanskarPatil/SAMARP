"""Acceptance tests for Alert Deduplication and Incident Lifecycle Engine.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 13.1, 17, design.md section 17.
Keys: config/dedup_keys.yaml (FROZEN).
Schema: schemas/alert.schema.json (v1.3).

Verifies:
- new incident creation
- duplicate collapse
- incident update
- resolution timeout sweep
- separate incidents
- NOT_OBSERVABLE dedup components
- bounded state with deterministic eviction
- deterministic identity across restarts
- schema validation against schemas/alert.schema.json
- cross-detector dedup behavior across all detector modules
- high-rate alert collapse (50,000 alerts -> 1 evolving incident)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from alerts.deduplicator import Deduplicator, extract_dedup_key
from ingest.identity import NOT_OBSERVABLE, canonical, identifier

REPO = Path(__file__).resolve().parents[2]
ALERT_SCHEMA_PATH = REPO / "schemas" / "alert.schema.json"


def _iso_utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="microseconds")


@pytest.fixture(scope="module")
def alert_schema() -> dict:
    return json.loads(ALERT_SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def alert_validator(alert_schema: dict) -> jsonschema.Draft202012Validator:
    jsonschema.Draft202012Validator.check_schema(alert_schema)
    return jsonschema.Draft202012Validator(alert_schema)


def _base_alert(
    detector: str,
    ps_class: str,
    threat_class: str,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    dst_port: int | None = None,
    registered_domain: str | None = None,
    ja3: str | None = None,
    ts: float = 1000.0,
    count: int = 1,
    severity: str = "MEDIUM",
) -> dict[str, Any]:
    iso_time = _iso_utc(ts)
    evidence: dict[str, Any] = {
        "interpretation": f"Alert from {detector} for test",
    }
    if src_ip:
        evidence["src_ip"] = src_ip
    if dst_ip:
        evidence["dst_ip"] = dst_ip
    if dst_port is not None:
        evidence["dst_port"] = dst_port
    if registered_domain:
        evidence["registered_domain"] = registered_domain
    if ja3:
        evidence["ja3"] = ja3

    raw: dict[str, Any] = {
        "schema_version": "1.3",
        "timestamp": iso_time,
        "flow_id": identifier([src_ip or "0.0.0.0", dst_ip or "0.0.0.0", dst_port or 0]),
        "flow_ref_type": "aggregate",
        "ps_class": ps_class,
        "threat_class": threat_class,
        "detector": detector,
        "confidence": None,
        "score": 0.85,
        "score_type": "anomaly_score",
        "calibrated": False,
        "evidence": evidence,
        "capability": {"detector_state": "OBSERVABLE", "input_mode": "pcap_replay"},
        "status": "NEW",
        "severity": severity,
        "first_observed": iso_time,
        "last_observed": iso_time,
        "event_count": count,
    }

    key_comps = extract_dedup_key(raw)
    raw["dedup_key"] = canonical(key_comps)
    raw["incident_id"] = identifier(key_comps)
    return raw


def test_new_incident_creation(alert_validator: jsonschema.Draft202012Validator) -> None:
    """1. Test new incident: first alert creates an incident with status NEW."""
    dedup = Deduplicator()
    alert = _base_alert("ddos", "Volumetric DDoS / flooding", "syn_flood", dst_ip="192.0.2.10", dst_port=80)

    incident = dedup.process_alert(alert)

    assert incident["status"] == "NEW"
    assert incident["event_count"] == 1
    assert incident["incident_id"] == alert["incident_id"]
    alert_validator.validate(incident)


def test_duplicate_collapse(alert_validator: jsonschema.Draft202012Validator) -> None:
    """2. Test duplicate collapse: duplicate alerts collapse into one tracked incident."""
    dedup = Deduplicator()
    alert1 = _base_alert("ddos", "Volumetric DDoS / flooding", "syn_flood", dst_ip="192.0.2.15", dst_port=443, ts=100.0)
    alert2 = _base_alert("ddos", "Volumetric DDoS / flooding", "syn_flood", dst_ip="192.0.2.15", dst_port=443, ts=105.0)

    inc1 = dedup.process_alert(alert1)
    inc2 = dedup.process_alert(alert2)

    assert inc1["incident_id"] == inc2["incident_id"]
    assert len(dedup.get_all_incidents()) == 1
    assert inc2["event_count"] == 2
    assert inc2["status"] == "ACTIVE"
    alert_validator.validate(inc2)


def test_incident_update_and_lifecycle() -> None:
    """3. Test incident update: transitions from NEW -> ACTIVE -> UPDATED."""
    dedup = Deduplicator()

    # Event 1 -> NEW
    i1 = dedup.process_alert(_base_alert("scan", "Port scanning / reconnaissance", "host_sweep", src_ip="10.10.0.1", ts=100.0))
    assert i1["status"] == "NEW"

    # Event 2 -> ACTIVE
    i2 = dedup.process_alert(_base_alert("scan", "Port scanning / reconnaissance", "host_sweep", src_ip="10.10.0.1", ts=102.0))
    assert i2["status"] == "ACTIVE"

    # Event 3 -> UPDATED
    i3 = dedup.process_alert(_base_alert("scan", "Port scanning / reconnaissance", "host_sweep", src_ip="10.10.0.1", ts=104.0))
    assert i3["status"] == "UPDATED"
    assert i3["event_count"] == 3


def test_incident_resolution() -> None:
    """4. Test resolution: inactive incident beyond resolve_timeout_s transitions to RESOLVED."""
    dedup = Deduplicator(resolve_timeout_s=30.0)
    a = _base_alert("c2", "Botnet C2 beaconing", "c2_beacon", src_ip="10.10.0.5", dst_ip="198.51.100.1", dst_port=8443, ts=1000.0)

    inc = dedup.process_alert(a)
    assert inc["status"] == "NEW"

    # No resolution before timeout (20s < 30s)
    resolved_early = dedup.sweep_resolved(current_time=1020.0)
    assert len(resolved_early) == 0

    # Resolution triggered after timeout (35s > 30s)
    resolved = dedup.sweep_resolved(current_time=1035.0)
    assert len(resolved) == 1
    assert resolved[0]["status"] == "RESOLVED"
    assert dedup.get_incident(inc["incident_id"])["status"] == "RESOLVED"


def test_separate_incidents() -> None:
    """5. Test separate incidents: different dedup keys produce separate incidents."""
    dedup = Deduplicator()
    a1 = _base_alert("ddos", "Volumetric DDoS / flooding", "syn_flood", dst_ip="192.0.2.1", dst_port=80)
    a2 = _base_alert("ddos", "Volumetric DDoS / flooding", "syn_flood", dst_ip="192.0.2.2", dst_port=80)
    a3 = _base_alert("ddos", "Volumetric DDoS / flooding", "syn_flood", dst_ip="192.0.2.1", dst_port=443)

    inc1 = dedup.process_alert(a1)
    inc2 = dedup.process_alert(a2)
    inc3 = dedup.process_alert(a3)

    assert len(dedup.get_all_incidents()) == 3
    assert inc1["incident_id"] != inc2["incident_id"]
    assert inc1["incident_id"] != inc3["incident_id"]
    assert inc2["incident_id"] != inc3["incident_id"]


def test_not_observable_dedup_components(alert_validator: jsonschema.Draft202012Validator) -> None:
    """6. Test NOT_OBSERVABLE dedup components: missing values take exact sentinel string."""
    dedup = Deduplicator()
    # tls_quic uses [ps_class, src_ip, ja3, dst_ip]
    alert = _base_alert(
        "tls_quic",
        "Malware in encrypted sessions",
        "suspicious_encrypted_session",
        src_ip="10.10.0.10",
        dst_ip="198.51.100.22",
        ja3=None,  # Unavailable
    )
    inc = dedup.process_alert(alert)

    assert inc["dedup_key"] == canonical(["Malware in encrypted sessions", "10.10.0.10", NOT_OBSERVABLE, "198.51.100.22"])
    expected_id = identifier(["Malware in encrypted sessions", "10.10.0.10", NOT_OBSERVABLE, "198.51.100.22"])
    assert inc["incident_id"] == expected_id
    alert_validator.validate(inc)


def test_bounded_state_eviction() -> None:
    """7. Test bounded state: total incidents never exceed max_incidents."""
    max_cap = 10
    dedup = Deduplicator(max_incidents=max_cap)

    # Ingest 50 distinct incidents
    for i in range(50):
        a = _base_alert("scan", "Port scanning / reconnaissance", "host_sweep", src_ip=f"10.10.0.{i}", ts=100.0 + i)
        dedup.process_alert(a)

    assert len(dedup.get_all_incidents()) <= max_cap


def test_deterministic_identity() -> None:
    """8. Test deterministic identity: incident_id is strictly reproducible across instances."""
    d1 = Deduplicator()
    d2 = Deduplicator()

    a1 = _base_alert("exfil", "Data exfiltration", "data_exfil", src_ip="10.10.0.8", dst_ip="198.51.100.50")
    a2 = _base_alert("exfil", "Data exfiltration", "data_exfil", src_ip="10.10.0.8", dst_ip="198.51.100.50")

    inc1 = d1.process_alert(a1)
    inc2 = d2.process_alert(a2)

    assert inc1["incident_id"] == inc2["incident_id"]
    assert len(inc1["incident_id"]) == 16
    assert inc1["incident_id"] == identifier(["Data exfiltration", "10.10.0.8", "198.51.100.50"])


def test_schema_validation(alert_validator: jsonschema.Draft202012Validator) -> None:
    """9. Test schema validation: resulting incident conforms to schemas/alert.schema.json."""
    dedup = Deduplicator()
    a = _base_alert("dns", "DGA / DNS tunnelling", "dns_tunnel", src_ip="10.10.0.30", registered_domain="tunnel.biz")
    inc = dedup.process_alert(a)

    alert_validator.validate(inc)
    assert inc["schema_version"] == "1.3"
    assert "status" in inc
    assert "evidence" in inc


def test_cross_detector_dedup_behavior() -> None:
    """10. Test cross-detector dedup behavior across all detector modules."""
    dedup = Deduplicator()

    detectors_and_classes = [
        ("ddos", "Volumetric DDoS / flooding", "syn_flood", {"dst_ip": "192.0.2.1", "dst_port": 80}),
        ("scan", "Port scanning / reconnaissance", "port_scan", {"src_ip": "10.10.0.1"}),
        ("dga", "DGA / DNS tunnelling", "dga_burst", {"src_ip": "10.10.0.2"}),
        ("dns", "DGA / DNS tunnelling", "dns_tunnel", {"src_ip": "10.10.0.3", "registered_domain": "ex.com"}),
        ("c2", "Botnet C2 beaconing", "c2_beacon", {"src_ip": "10.10.0.4", "dst_ip": "198.51.100.1", "dst_port": 443}),
        ("exfil", "Data exfiltration", "data_exfil", {"src_ip": "10.10.0.5", "dst_ip": "198.51.100.2"}),
        ("tls_quic", "Malware in encrypted sessions", "suspicious_encrypted_session", {"src_ip": "10.10.0.6", "dst_ip": "198.51.100.3", "ja3": "abc123"}),
    ]

    for det, ps_cls, th_cls, kwargs in detectors_and_classes:
        a1 = _base_alert(det, ps_cls, th_cls, **kwargs, count=1)
        a2 = _base_alert(det, ps_cls, th_cls, **kwargs, count=2)

        i1 = dedup.process_alert(a1)
        i2 = dedup.process_alert(a2)

        assert i1["incident_id"] == i2["incident_id"]
        assert i2["event_count"] == 3


def test_high_rate_alert_collapse(alert_validator: jsonschema.Draft202012Validator) -> None:
    """11. Test high-rate alert collapse: 50,000 alerts with same key collapse to 1 incident."""
    dedup = Deduplicator()
    total = 50_000
    final_inc = None

    for i in range(total):
        alert = _base_alert("ddos", "Volumetric DDoS / flooding", "syn_flood", dst_ip="192.0.2.100", dst_port=80, count=1)
        final_inc = dedup.process_alert(alert)

    assert final_inc is not None
    assert len(dedup.get_all_incidents()) == 1
    assert final_inc["event_count"] == total
    assert final_inc["status"] == "UPDATED"
    alert_validator.validate(final_inc)
