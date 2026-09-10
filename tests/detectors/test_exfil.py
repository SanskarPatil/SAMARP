"""Acceptance tests for Data Exfiltration detection.

Asserts:
- Conformance to schemas/alert.schema.json.
- Outbound byte ratio >= 10.0 and high-volume burst detection.
- Balanced browsing traffic does not alert.
- Dedup key is [ps_class, src_ip, dst_ip].
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from detectors.exfil import ExfilDetector
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


def _flow_ev(src_ip: str, dst_ip: str, bytes_: int, direction: str, ts: float) -> NormalizedEvent:
    return NormalizedEvent(
        observed_time=ts,
        input_mode=InputMode.PCAP_REPLAY,
        capability=CapabilityState(InputMode.PCAP_REPLAY),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=49999,
        dst_port=443,
        protocol="TCP",
        packets=10,
        bytes=bytes_,
        direction=direction,
    )


def test_benign_browsing_no_exfil_alert() -> None:
    detector = ExfilDetector(outbound_ratio_min=10.0, min_outbound_bytes=100_000)
    src = "10.10.0.5"
    dst = "93.184.216.34"

    # Typical web browsing: small outbound request (1 KB), large inbound response (50 KB)
    ev_out = _flow_ev(src, dst, bytes_=1000, direction="outbound", ts=100.0)
    ev_in = _flow_ev(src, dst, bytes_=50000, direction="inbound", ts=100.5)

    assert detector.evaluate_event(ev_out) is None
    assert detector.evaluate_event(ev_in) is None


def test_data_exfiltration_detection(alert_validator: jsonschema.Draft202012Validator) -> None:
    detector = ExfilDetector(outbound_ratio_min=10.0, min_outbound_bytes=100_000)
    src = "10.10.0.10"
    dst = "198.51.100.77"

    # Initial handshake / small inbound ack (2 KB)
    detector.evaluate_event(_flow_ev(src, dst, bytes_=2000, direction="inbound", ts=200.0))

    # Massive outbound transfer: 300 KB outbound vs 2 KB inbound -> ratio = 150.0 >> 10.0
    ev_exfil = _flow_ev(src, dst, bytes_=300_000, direction="outbound", ts=201.0)
    alert = detector.evaluate_event(ev_exfil)

    assert alert is not None
    alert_validator.validate(alert)

    assert alert["ps_class"] == "Data exfiltration"
    assert alert["threat_class"] == "data_exfil"
    assert alert["detector"] == "exfil"
    assert alert["flow_ref_type"] == "aggregate"
    assert alert["incident_id"] == identifier(["Data exfiltration", src, dst])

    ev_data = alert["evidence"]
    assert ev_data["outbound_bytes"] >= 300_000
    assert ev_data["outbound_ratio"] >= 10.0
    assert ev_data["direction"] == "outbound"
    assert ev_data["burst_or_sustained"] in ("burst", "sustained")


def test_data_exfiltration_robust_z_with_baseline(alert_validator: jsonschema.Draft202012Validator) -> None:
    # Baseline median=10,000 bytes, MAD=2,000 bytes
    baseline = {"median_bytes": 10_000, "mad_bytes": 2_000}
    detector = ExfilDetector(
        outbound_ratio_min=10.0,
        robust_z=5.0,
        min_outbound_bytes=100_000,  # Even though volume < 100k, robust z >= 5.0 triggers
        baseline=baseline,
    )
    src = "10.10.0.12"
    dst = "198.51.100.80"

    # Outbound transfer of 30,000 bytes -> robust z = (30,000 - 10,000) / (1.4826 * 2,000) = 6.74 >= 5.0
    ev = _flow_ev(src, dst, bytes_=30_000, direction="outbound", ts=300.0)
    alert = detector.evaluate_event(ev)

    assert alert is not None
    alert_validator.validate(alert)
    assert alert["score_type"] == "robust_z"
    assert alert["calibrated"] is False
    assert alert["evidence"]["robust_z"] >= 5.0
    assert alert["baseline"] == baseline


def test_exfil_bounded_state() -> None:
    detector = ExfilDetector(max_conversations=5, window_s=60.0)
    for i in range(20):
        detector.evaluate_event(_flow_ev("10.10.0.1", f"198.51.100.{i}", bytes_=100, direction="outbound", ts=100.0 + i))
    assert len(detector._conversations) <= 5

