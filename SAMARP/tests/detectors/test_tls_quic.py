"""Acceptance tests for TLS/QUIC metadata and traffic shape anomaly detection.

Asserts:
- Conformance to schemas/alert.schema.json.
- No payload decryption: handshake metadata (JA3/JA3S/JA4) and shape only.
- Output threat wording: suspicious_encrypted_session.
- Dedup key semantics: [ps_class, src_ip, ja3, dst_ip] with NOT_OBSERVABLE sentinel.
- Evidence carries required fields: ja3, packet_size_first_n, iat_median, iat_cv.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from detectors.tls_quic import TLSQuicDetector
from ingest.capability import CapabilityState, InputMode
from ingest.identity import NOT_OBSERVABLE, identifier
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


def _tls_ev(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    ja3: str | None = None,
    ja3s: str | None = None,
    ja4: str | None = None,
    sni: str | None = None,
    bytes_: int = 200,
    ts: float = 100.0,
) -> NormalizedEvent:
    tls_meta = {}
    if ja3:
        tls_meta["ja3"] = ja3
    if ja3s:
        tls_meta["ja3s"] = ja3s
    if ja4:
        tls_meta["ja4"] = ja4
    if sni:
        tls_meta["sni"] = sni

    return NormalizedEvent(
        observed_time=ts,
        input_mode=InputMode.PCAP_REPLAY,
        capability=CapabilityState(InputMode.PCAP_REPLAY),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=52000,
        dst_port=dst_port,
        protocol="TCP",
        bytes=bytes_,
        tls=tls_meta if tls_meta else None,
        direction="outbound",
    )


def test_benign_tls_session_no_alert() -> None:
    detector = TLSQuicDetector()
    src = "10.10.0.5"
    dst = "142.250.190.46"

    # Standard browser TLS handshake to port 443 with valid SNI and benign JA3
    ev = _tls_ev(
        src,
        dst,
        443,
        ja3="cd08e31494f9531f560d64cfa3f2233c",  # Standard Chrome JA3
        ja3s="ec74a5c5110605f9592a37540609d6b0",
        sni="www.google.com",
    )
    assert detector.evaluate_event(ev) is None


def test_suspicious_ja3_session_detection(alert_validator: jsonschema.Draft202012Validator) -> None:
    detector = TLSQuicDetector()
    src = "10.10.0.40"
    dst = "198.51.100.99"
    cobalt_ja3 = "72a589da586844d7f0818ce684948eea"

    ev = _tls_ev(
        src,
        dst,
        443,
        ja3=cobalt_ja3,
        ja3s="ec74a5c5110605f9592a37540609d6b0",
        ja4="t13d1516h2_8daaf6152771_010c22d7c001",
        sni="badc2.example",
    )
    alert = detector.evaluate_event(ev)

    assert alert is not None
    alert_validator.validate(alert)

    assert alert["ps_class"] == "Malware in encrypted sessions"
    assert alert["threat_class"] == "suspicious_encrypted_session"
    assert alert["detector"] == "tls_quic"
    assert alert["incident_id"] == identifier(["Malware in encrypted sessions", src, cobalt_ja3, dst])

    ev_data = alert["evidence"]
    assert ev_data["ja3"] == cobalt_ja3
    assert ev_data["ja3s"] is not None
    assert "no decrypted payload bytes inspected" in ev_data["interpretation"]


def test_no_sni_direct_ip_tls_detection(alert_validator: jsonschema.Draft202012Validator) -> None:
    detector = TLSQuicDetector()
    src = "10.10.0.42"
    dst = "203.0.113.15"

    # Direct IP TLS handshake to unusual port 9443 with NO SNI and missing JA3
    ev = _tls_ev(src, dst, 9443, ja3=None, sni=None)
    alert = detector.evaluate_event(ev)

    assert alert is not None
    alert_validator.validate(alert)

    assert alert["incident_id"] == identifier(["Malware in encrypted sessions", src, NOT_OBSERVABLE, dst])
    assert alert["capability"]["detector_state"] == "DEGRADED"
    assert "ja3" in alert["capability"]["missing_evidence"]


def test_stealth_shape_detection(alert_validator: jsonschema.Draft202012Validator) -> None:
    detector = TLSQuicDetector()
    src = "10.10.0.50"
    dst = "198.51.100.111"

    # Stealth beaconing shape: repeated 180-byte packets with low jitter
    alert = None
    t = 1000.0
    for i in range(8):
        t += 5.0 + (0.05 if i % 2 == 0 else -0.05)
        ev = NormalizedEvent(
            observed_time=t,
            input_mode=InputMode.PCAP_REPLAY,
            capability=CapabilityState(InputMode.PCAP_REPLAY),
            src_ip=src,
            dst_ip=dst,
            src_port=49800,
            dst_port=443,
            protocol="TCP",
            bytes=180,
            direction="outbound" if i % 2 == 0 else "inbound",
            tls={"sni": "legit-looking.cdn"},
        )
        res = detector.evaluate_event(ev)
        if res:
            alert = res

    assert alert is not None
    alert_validator.validate(alert)
    ev_data = alert["evidence"]
    assert ev_data["packet_size_first_n"] is not None
    assert ev_data["direction_first_n"] is not None
    assert ev_data["packet_size_mean"] == 180.0
    assert ev_data["iat_median"] is not None
    assert ev_data["iat_cv"] < 0.20
    assert ev_data["upstream_packet_ratio"] is not None
    assert ev_data["downstream_packet_ratio"] is not None


def test_tls_quic_bounded_state() -> None:
    detector = TLSQuicDetector(max_sessions=5, window_s=60.0)
    for i in range(20):
        detector.evaluate_event(_tls_ev("10.10.0.1", f"198.51.100.{i}", 443, ts=100.0 + i))
    assert len(detector._sessions) <= 5

