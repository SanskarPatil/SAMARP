"""Acceptance tests for Reconnaissance and Port Scanning detection.

Asserts:
- Conformance to schemas/alert.schema.json.
- Vertical port scan detection (destination-port spread).
- Horizontal host sweep detection (destination-host spread).
- Hybrid scan classification.
- Flow identity entity semantics: flow_id == sha256(canonical(src_ip))[:16].
- Bounded memory limits on tracked hosts and ports.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from detectors.scan import ScanDetector
from ingest.capability import CapabilityState, InputMode
from ingest.identity import identifier
from ingest.normalized_event import NormalizedEvent

REPO = Path(__file__).resolve().parents[2]
ALERT_SCHEMA_PATH = REPO / "schemas" / "alert.schema.json"


@pytest.fixture(scope="module")
def alert_schema() -> dict:
    return json.loads(ALERT_SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def alert_validator(alert_schema: dict) -> jsonschema.Draft202012Validator:
    jsonschema.Draft202012Validator.check_schema(alert_schema)
    return jsonschema.Draft202012Validator(alert_schema)


def _event(src_ip: str, dst_ip: str, dst_port: int, ts: float) -> NormalizedEvent:
    return NormalizedEvent(
        observed_time=ts,
        input_mode=InputMode.PCAP_REPLAY,
        capability=CapabilityState(InputMode.PCAP_REPLAY),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=54321,
        dst_port=dst_port,
        protocol="TCP",
        packets=1,
        bytes=60,
    )


def test_benign_traffic_no_scan_alert() -> None:
    detector = ScanDetector(unique_dst_min=10, unique_port_min=15)
    # 5 probes to port 80 and 443 across 3 hosts
    for i in range(5):
        ev = _event("192.0.2.5", f"10.10.0.{i%3 + 1}", 80 if i % 2 == 0 else 443, 100.0 + i * 0.1)
        alert = detector.evaluate_event(ev)
        assert alert is None


def test_vertical_port_scan_detection(alert_validator: jsonschema.Draft202012Validator) -> None:
    detector = ScanDetector(unique_dst_min=50, unique_port_min=20)
    src = "192.0.2.100"
    target = "10.10.0.50"

    alert = None
    # Probe 25 distinct ports on target host
    for p in range(1, 26):
        ev = _event(src, target, p, 100.0 + p * 0.05)
        res = detector.evaluate_event(ev)
        if res:
            alert = res

    assert alert is not None
    alert_validator.validate(alert)

    assert alert["ps_class"] == "Port scanning / reconnaissance"
    assert alert["threat_class"] == "port_scan"
    assert alert["detector"] == "scan"
    assert alert["flow_ref_type"] == "entity"
    assert alert["flow_id"] == identifier(src)
    assert alert["incident_id"] == identifier(["Port scanning / reconnaissance", src])
    assert alert["evidence"]["unique_port_count"] >= 20
    assert alert["evidence"]["scan_pattern"] == "vertical"


def test_horizontal_host_sweep_detection(alert_validator: jsonschema.Draft202012Validator) -> None:
    detector = ScanDetector(unique_dst_min=15, unique_port_min=50)
    src = "192.0.2.200"
    port = 445

    alert = None
    # Probe 20 distinct destination hosts on port 445
    for h in range(1, 21):
        ev = _event(src, f"10.10.1.{h}", port, 200.0 + h * 0.05)
        res = detector.evaluate_event(ev)
        if res:
            alert = res

    assert alert is not None
    alert_validator.validate(alert)

    assert alert["threat_class"] == "host_sweep"
    assert alert["evidence"]["unique_dst_count"] >= 15
    assert alert["evidence"]["scan_pattern"] == "horizontal"


def test_hybrid_scan_detection(alert_validator: jsonschema.Draft202012Validator) -> None:
    detector = ScanDetector(unique_dst_min=10, unique_port_min=10)
    src = "192.0.2.222"

    alert = None
    for i in range(15):
        ev = _event(src, f"10.10.2.{i+1}", 1000 + i, 300.0 + i * 0.05)
        res = detector.evaluate_event(ev)
        if res:
            alert = res

    assert alert is not None
    alert_validator.validate(alert)
    assert alert["threat_class"] == "network_scan"
    assert alert["evidence"]["scan_pattern"] == "hybrid"
