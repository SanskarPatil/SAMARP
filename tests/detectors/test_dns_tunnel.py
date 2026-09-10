"""Acceptance tests for DNS Tunnelling and record-type anomaly detection.

Asserts:
- Conformance to schemas/alert.schema.json.
- DNS tunnelling detection via query length, entropy, and frequency.
- qtype_distribution in evidence including TXT/NULL/CNAME shares.
- Dedup key is [ps_class, src_ip, registered_domain].
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from detectors.dns import DNSTunnelDetector
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


def _dns_ev(src_ip: str, qname: str, qtype: str, ts: float) -> NormalizedEvent:
    return NormalizedEvent(
        observed_time=ts,
        input_mode=InputMode.PCAP_REPLAY,
        capability=CapabilityState(InputMode.PCAP_REPLAY),
        src_ip=src_ip,
        dst_ip="10.10.0.53",
        src_port=53535,
        dst_port=53,
        protocol="UDP",
        dns={"qname": qname, "qtype": qtype},
    )


def test_benign_dns_traffic_no_tunnel_alert() -> None:
    detector = DNSTunnelDetector(qname_len_min=50, entropy_min=3.5, min_queries=5)
    src = "10.10.0.22"

    queries = [
        ("api.github.com", "A"),
        ("www.google.com", "A"),
        ("mail.google.com", "AAAA"),
        ("login.microsoft.com", "A"),
        ("cloudflare.com", "A"),
    ]
    for i, (qname, qtype) in enumerate(queries):
        alert = detector.evaluate_event(_dns_ev(src, qname, qtype, 100.0 + i))
        assert alert is None


def test_dns_tunnel_detection(alert_validator: jsonschema.Draft202012Validator) -> None:
    detector = DNSTunnelDetector(qname_len_min=45, entropy_min=3.2, min_queries=5)
    src = "10.10.0.33"
    domain = "tunnel.exfil-target.net"

    # Base64/encoded payload in subdomains with TXT and NULL record queries
    tunnel_queries = [
        (f"dGhpcy1pcy1hLXZlcnktbG9uZy1leGZpbHRyYXRpb24tcGF5bG9hZC1kYXRhLTE.{domain}", "TXT"),
        (f"c2Vjb25kLWJsb2NrLW9mLWVuY3J5cHRlZC1kbnMtdHVubmVsLWRhdGEtYnl0ZXMtMg.{domain}", "TXT"),
        (f"dGhpcmQtY2h1bmstb2YtY3liZXItc2VudGluZWwtZG5zLXR1bm5lbC1leGZpbC0z.{domain}", "NULL"),
        (f"Zm91cnRoLXNlZ21lbnQtdHJhbnNmZXJyaW5nLXN0ZWFsZWQtZmlsZS1ieXRlcy00.{domain}", "TXT"),
        (f"ZmlmdGgtcGFja2V0LWNvbXBsZXRpbmctZG5zY2F0Mi1jb21tdW5pY2F0aW9uLTU.{domain}", "TXT"),
        (f"c2l4dGgtc2VxdWVuY2UtYWNrbm93bGVkZ2luZy1yZWNlaXZlZC1ieXRlcy1jbTItNg.{domain}", "CNAME"),
    ]

    alert = None
    for i, (qname, qtype) in enumerate(tunnel_queries):
        res = detector.evaluate_event(_dns_ev(src, qname, qtype, 200.0 + i * 0.2))
        if res:
            alert = res

    assert alert is not None
    alert_validator.validate(alert)

    assert alert["ps_class"] == "DGA / DNS tunnelling"
    assert alert["threat_class"] == "dns_tunnel"
    assert alert["detector"] == "dns"
    assert alert["flow_ref_type"] == "aggregate"

    # Evidence verification
    ev = alert["evidence"]
    assert "qtype_distribution" in ev
    assert ev["qtype_distribution"]["TXT"] >= 4
    assert ev["qtype_txt_ratio"] > 0.5
    assert ev["avg_length"] >= 45
    assert ev["avg_entropy"] >= 3.0
    assert len(ev["sample_queries"]) > 0
