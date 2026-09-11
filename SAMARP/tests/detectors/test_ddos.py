"""Acceptance tests for DDoS and Slowloris detection.

Asserts:
- Conformance to schemas/alert.schema.json.
- Volumetric flood detection with hysteresis and source entropy.
- SYN flood and UDP flood threat classification.
- Slowloris low-rate exhaustion path: concurrency + duration + bytes/connection.
- Non-null 16-hex flow_id with flow_ref_type="aggregate".
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from detectors.ddos import DDoSDetector
from features.rolling import WindowSummary
from ingest.capability import CapabilityState, InputMode

REPO = Path(__file__).resolve().parents[2]
ALERT_SCHEMA_PATH = REPO / "schemas" / "alert.schema.json"


@pytest.fixture(scope="module")
def alert_schema() -> dict:
    return json.loads(ALERT_SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def alert_validator(alert_schema: dict) -> jsonschema.Draft202012Validator:
    jsonschema.Draft202012Validator.check_schema(alert_schema)
    return jsonschema.Draft202012Validator(alert_schema)


def _make_window(
    start: float,
    duration: float = 1.0,
    packet_count: int = 100,
    byte_count: int = 10000,
    tcp_flags: dict[str, int] | None = None,
    protocols: dict[str, int] | None = None,
    src_ip_counts: dict[str, int] | None = None,
    dst_ip_counts: dict[str, int] | None = None,
    dst_port_counts: dict[int, int] | None = None,
    src_entropy: float = 1.0,
    flow_summaries: list[dict] | None = None,
) -> WindowSummary:
    tcp_f = tcp_flags or {"S": 10, "A": 90}
    proto_f = protocols or {"TCP": packet_count}
    src_c = src_ip_counts or {"192.0.2.1": packet_count}
    dst_c = dst_ip_counts or {"10.10.0.10": packet_count}
    dst_p = dst_port_counts or {80: packet_count}

    return WindowSummary(
        start_time=start,
        end_time=start + duration,
        duration_s=duration,
        event_count=packet_count,
        packet_count=packet_count,
        byte_count=byte_count,
        tcp_flags=tcp_f,
        protocols=proto_f,
        src_ip_counts=src_c,
        dst_ip_counts=dst_c,
        dst_port_counts=dst_p,
        src_entropy=src_entropy,
        dst_entropy=0.5,
        unique_src_count=len(src_c),
        unique_dst_count=len(dst_c),
        unique_dst_ports_count=len(dst_p),
        flow_summaries=flow_summaries or [],
        latest_capability=CapabilityState(InputMode.PCAP_REPLAY),
        latest_input_mode="pcap_replay",
    )


def test_benign_traffic_no_alert(alert_validator: jsonschema.Draft202012Validator) -> None:
    detector = DDoSDetector(min_pps=5000, hysteresis_windows=2)
    # Window with 200 pps
    w1 = _make_window(start=100.0, packet_count=200)
    alerts = detector.evaluate_window(w1)
    assert len(alerts) == 0


def test_volumetric_flood_detection(alert_validator: jsonschema.Draft202012Validator) -> None:
    detector = DDoSDetector(min_pps=5000, hysteresis_windows=2)

    # Window 1: flood starts (5000 packets) -> held by hysteresis (N=2)
    w1 = _make_window(start=100.0, packet_count=6000, src_entropy=4.5)
    alerts1 = detector.evaluate_window(w1)
    assert len(alerts1) == 0

    # Window 2: flood continues -> alert emitted
    w2 = _make_window(start=101.0, packet_count=6500, src_entropy=4.8)
    alerts2 = detector.evaluate_window(w2)
    assert len(alerts2) == 1
    alert = alerts2[0]

    # Validate against frozen schema
    alert_validator.validate(alert)

    assert alert["ps_class"] == "Volumetric DDoS / flooding"
    assert alert["detector"] == "ddos"
    assert alert["flow_ref_type"] == "aggregate"
    assert len(alert["flow_id"]) == 16
    assert len(alert["incident_id"]) == 16
    assert alert["calibrated"] is False
    assert alert["score_type"] in ("robust_z", "anomaly_score")
    assert alert["evidence"]["packet_rate_pps"] == 6500.0
    assert alert["evidence"]["source_entropy"] == 4.8


def test_syn_flood_threat_class(alert_validator: jsonschema.Draft202012Validator) -> None:
    detector = DDoSDetector(min_pps=1000, hysteresis_windows=1)
    w = _make_window(
        start=200.0,
        packet_count=2000,
        tcp_flags={"S": 1900, "A": 10},
    )
    alerts = detector.evaluate_window(w)
    assert len(alerts) == 1
    alert = alerts[0]
    alert_validator.validate(alert)
    assert alert["threat_class"] == "syn_flood"


def test_udp_flood_threat_class(alert_validator: jsonschema.Draft202012Validator) -> None:
    detector = DDoSDetector(min_pps=1000, hysteresis_windows=1)
    w = _make_window(
        start=200.0,
        packet_count=2000,
        protocols={"UDP": 1900, "TCP": 100},
    )
    alerts = detector.evaluate_window(w)
    assert len(alerts) == 1
    alert = alerts[0]
    alert_validator.validate(alert)
    assert alert["threat_class"] == "udp_flood"


def test_slowloris_concurrency_and_duration_gates(alert_validator: jsonschema.Draft202012Validator) -> None:
    detector = DDoSDetector(
        slowloris_min_concurrency=5,
        slowloris_min_duration_s=10.0,
        slowloris_max_bytes_per_conn=1500,
        slowloris_max_pps=100.0,
    )

    # 1. Concurrency met but duration short -> NO alert
    short_flows = [
        {"dst_ip": "10.10.0.5", "dst_port": 80, "duration_s": 2.0, "bytes": 400, "packets": 4}
        for _ in range(8)
    ]
    w1 = _make_window(start=300.0, packet_count=32, flow_summaries=short_flows)
    alerts1 = detector.evaluate_window(w1)
    assert len(alerts1) == 0

    # 2. Both concurrency AND duration gates met with low rate & low bytes -> SLOWLORIS ALERT
    long_flows = [
        {"dst_ip": "10.10.0.5", "dst_port": 80, "duration_s": 18.5, "bytes": 350, "packets": 3}
        for _ in range(8)
    ]
    w2 = _make_window(start=301.0, packet_count=24, flow_summaries=long_flows)
    alerts2 = detector.evaluate_window(w2)
    assert len(alerts2) == 1
    alert = alerts2[0]

    alert_validator.validate(alert)
    assert alert["ps_class"] == "Volumetric DDoS / flooding"
    assert alert["threat_class"] == "slowloris"
    assert alert["detector"] == "ddos"
    assert alert["flow_ref_type"] == "aggregate"
    assert alert["evidence"]["half_open_concurrency"] >= 5
    assert alert["evidence"]["connection_duration_p95"] >= 10.0
    assert alert["evidence"]["bytes_per_connection"] <= 1500
