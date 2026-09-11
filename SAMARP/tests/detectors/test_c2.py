"""Acceptance tests for Botnet C2 beaconing detection.

Asserts:
- Conformance to schemas/alert.schema.json.
- Low-jitter periodic beaconing triggers alert with CV <= 0.15.
- Random irregular browsing intervals do not trigger alert.
- Dedup key is [ps_class, src_ip, dst_ip, dst_port].
- Required evidence: iat_mean, iat_median, iat_cv, duration_s.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from detectors.c2 import C2Detector
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


def _beacon_event(src_ip: str, dst_ip: str, dst_port: int, ts: float) -> NormalizedEvent:
    return NormalizedEvent(
        observed_time=ts,
        input_mode=InputMode.PCAP_REPLAY,
        capability=CapabilityState(InputMode.PCAP_REPLAY),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=49152,
        dst_port=dst_port,
        protocol="TCP",
        packets=2,
        bytes=120,
    )


def test_benign_random_traffic_no_c2_alert() -> None:
    detector = C2Detector(cv_max=0.15, min_events=8)
    src = "10.10.0.12"
    dst = "198.51.100.4"
    port = 443

    # Irregular intervals with high jitter (1s, 15s, 3s, 40s, 2s, 80s, etc.)
    intervals = [1.2, 15.4, 3.1, 42.0, 2.5, 78.1, 9.4, 33.2, 5.0, 60.0]
    t = 100.0
    for interval in intervals:
        t += interval
        alert = detector.evaluate_event(_beacon_event(src, dst, port, t))
        assert alert is None


def test_periodic_c2_beacon_detection(alert_validator: jsonschema.Draft202012Validator) -> None:
    detector = C2Detector(cv_max=0.15, min_events=8)
    src = "10.10.0.15"
    dst = "203.0.113.88"
    port = 8443

    # Highly periodic beaconing every 10.0 seconds with +/- 0.2s jitter (CV ~ 0.02 << 0.15)
    intervals = [10.1, 9.9, 10.0, 10.2, 9.8, 10.1, 10.0, 9.9, 10.0]
    t = 1000.0
    alert = None

    for interval in intervals:
        t += interval
        res = detector.evaluate_event(_beacon_event(src, dst, port, t))
        if res:
            alert = res

    assert alert is not None
    alert_validator.validate(alert)

    assert alert["ps_class"] == "Botnet C2 beaconing"
    assert alert["threat_class"] == "c2_beacon"
    assert alert["detector"] == "c2"
    assert alert["flow_ref_type"] == "aggregate"
    assert alert["incident_id"] == identifier(["Botnet C2 beaconing", src, dst, port])
    assert alert["evidence"]["iat_cv"] <= 0.15
    assert 9.0 <= alert["evidence"]["iat_mean"] <= 11.0
    assert alert["evidence"]["event_count"] >= 8


def test_c2_burst_filtering_not_beaconing() -> None:
    detector = C2Detector(cv_max=0.15, min_events=8)
    src = "10.10.0.18"
    dst = "198.51.100.20"
    port = 80

    # Rapid burst (e.g. 10ms intervals): bulk download / port scan, mean IAT < 50ms
    t = 500.0
    for _ in range(12):
        t += 0.01
        res = detector.evaluate_event(_beacon_event(src, dst, port, t))
        assert res is None


def test_c2_bounded_state_eviction() -> None:
    # Set max_tracked=5 and ensure tracker doesn't grow unbounded
    detector = C2Detector(max_tracked=5, window_s=60.0)
    for i in range(20):
        detector.evaluate_event(_beacon_event(f"10.10.0.{i}", "198.51.100.1", 443, 100.0 + i))
    assert len(detector._conversations) <= 5

