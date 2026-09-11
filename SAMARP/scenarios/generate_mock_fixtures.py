"""Deterministic mock fixture generator adhering strictly to schemas/alert.schema.json.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 8, 15, implementation_plan.md P3-1.

Covers:
- All 6 PS threat classes verbatim
- All 3 flow_ref_type values (flow_5tuple, aggregate, entity)
- All 4 score_type values with calibrated both true and false
- confidence: null and confidence: float
- All 3 capability states (OBSERVABLE, DEGRADED, NOT_OBSERVABLE)
- DEGRADED IPFIX input mode
- dedup_key carrying the NOT_OBSERVABLE sentinel
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema

import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from alerts.hash_chain import HashChainWriter
SCHEMA_PATH = PROJECT_ROOT / "schemas" / "alert.schema.json"
FIXTURES_DIR = PROJECT_ROOT / "scenarios" / "mock_fixtures"


def generate_canonical_fixtures() -> list[dict[str, Any]]:
    """Generate the minimum required fixture set for P3 dashboard verification."""
    fixtures: list[dict[str, Any]] = [
        # 1. Volumetric DDoS / flooding - aggregate, uncalibrated robust_z, OBSERVABLE
        {
            "schema_version": "1.3",
            "timestamp": "2026-09-11T02:00:00.000000+00:00",
            "observed_time": "2026-09-11T02:00:00.000000+00:00",
            "flow_id": "a1b2c3d4e5f60718",
            "flow_ref_type": "aggregate",
            "ps_class": "Volumetric DDoS / flooding",
            "threat_class": "syn_flood",
            "detector": "ddos",
            "confidence": None,
            "score": 18.5,
            "score_type": "robust_z",
            "calibrated": False,
            "evidence": {
                "interpretation": "SYN flood exceeding volumetric threshold (12,400 pps)",
                "dst_ip": "10.0.0.5",
                "dst_port": 80,
                "packet_rate": 12400,
                "byte_rate": 7800000,
                "syn_ratio": 0.98,
            },
            "baseline": {"packet_rate_median": 450, "packet_rate_mad": 60},
            "threshold": {"syn_flood_pps": 1000},
            "window": {
                "start": "2026-09-11T01:59:59.000000+00:00",
                "end": "2026-09-11T02:00:00.000000+00:00",
                "duration_s": 1.0,
            },
            "incident_id": "a1b2c3d4e5f60718",
            "dedup_key": '["Volumetric DDoS / flooding","10.0.0.5",80]',
            "status": "ACTIVE",
            "severity": "CRITICAL",
            "first_observed": "2026-09-11T01:58:30.000000+00:00",
            "last_observed": "2026-09-11T02:00:00.000000+00:00",
            "event_count": 92,
            "capability": {
                "detector_state": "OBSERVABLE",
                "input_mode": "pcap_replay",
            },
            "latency_ms": 142.5,
            "recommendation": "ADVISORY TEXT ONLY. Upstream rate-limiting recommended. No active response path in system.",
        },
        # 2. Port scanning / reconnaissance - entity, uncalibrated anomaly_score, DEGRADED
        {
            "schema_version": "1.3",
            "timestamp": "2026-09-11T02:01:10.000000+00:00",
            "flow_id": "b2c3d4e5f6a10729",
            "flow_ref_type": "entity",
            "ps_class": "Port scanning / reconnaissance",
            "threat_class": "vertical_port_scan",
            "detector": "scan",
            "confidence": None,
            "score": 42.0,
            "score_type": "anomaly_score",
            "calibrated": False,
            "evidence": {
                "interpretation": "Vertical scan probed 42 ports on target in 1s window",
                "src_ip": "192.168.1.105",
                "dst_ip": "10.0.0.8",
                "ports_probed": 42,
                "scan_type": "SYN_STEALTH",
            },
            "incident_id": "b2c3d4e5f6a10729",
            "dedup_key": '["Port scanning / reconnaissance","192.168.1.105","NOT_OBSERVABLE"]',
            "status": "NEW",
            "severity": "MEDIUM",
            "first_observed": "2026-09-11T02:01:10.000000+00:00",
            "last_observed": "2026-09-11T02:01:10.000000+00:00",
            "event_count": 1,
            "capability": {
                "detector_state": "DEGRADED",
                "input_mode": "ipfix",
                "missing_evidence": ["tcp_flags"],
            },
            "latency_ms": 88.0,
            "recommendation": "ADVISORY TEXT ONLY. Investigate host 192.168.1.105 for credential discovery. No mitigation command.",
        },
        # 3. Botnet C2 beaconing - flow_5tuple, uncalibrated rule_score, OBSERVABLE
        {
            "schema_version": "1.3",
            "timestamp": "2026-09-11T02:02:15.000000+00:00",
            "flow_id": "c3d4e5f6a1b2073a",
            "flow_ref_type": "flow_5tuple",
            "ps_class": "Botnet C2 beaconing",
            "threat_class": "periodic_beacon",
            "detector": "c2",
            "confidence": None,
            "score": 9.4,
            "score_type": "rule_score",
            "calibrated": False,
            "evidence": {
                "interpretation": "High periodicity heartbeat detected with CV 0.04 (<=0.15 threshold)",
                "src_ip": "10.0.0.22",
                "dst_ip": "198.51.100.44",
                "dst_port": 443,
                "iat_median": 5.02,
                "iat_cv": 0.041,
                "intervals_observed": 28,
            },
            "incident_id": "c3d4e5f6a1b2073a",
            "dedup_key": '["Botnet C2 beaconing","10.0.0.22","198.51.100.44",443]',
            "status": "UPDATED",
            "severity": "HIGH",
            "first_observed": "2026-09-11T01:50:00.000000+00:00",
            "last_observed": "2026-09-11T02:02:15.000000+00:00",
            "event_count": 28,
            "capability": {
                "detector_state": "OBSERVABLE",
                "input_mode": "pcap_replay",
            },
            "latency_ms": 115.0,
            "recommendation": "ADVISORY TEXT ONLY. Review endpoint process tree on 10.0.0.22. System operates passively.",
        },
        # 4. DGA / DNS tunnelling - entity, calibrated model_probability, OBSERVABLE
        {
            "schema_version": "1.3",
            "timestamp": "2026-09-11T02:03:00.000000+00:00",
            "flow_id": "d4e5f6a1b2c3074b",
            "flow_ref_type": "entity",
            "ps_class": "DGA / DNS tunnelling",
            "threat_class": "dns_tunnel",
            "detector": "dns",
            "confidence": 0.94,
            "score": 0.94,
            "score_type": "model_probability",
            "calibrated": True,
            "evidence": {
                "interpretation": "High entropy TXT query volume consistent with DNS data tunnelling",
                "domain": "tunnel.exfil-corp.internal.attacker.com",
                "qtype_distribution": {"TXT": 0.88, "CNAME": 0.08, "A": 0.04},
                "query_length_mean": 82.4,
                "entropy_mean": 4.35,
            },
            "incident_id": "d4e5f6a1b2c3074b",
            "dedup_key": '["DGA / DNS tunnelling","tunnel.exfil-corp.internal.attacker.com"]',
            "status": "ACTIVE",
            "severity": "CRITICAL",
            "first_observed": "2026-09-11T02:00:00.000000+00:00",
            "last_observed": "2026-09-11T02:03:00.000000+00:00",
            "event_count": 64,
            "capability": {
                "detector_state": "OBSERVABLE",
                "input_mode": "pcap_replay",
            },
            "latency_ms": 95.0,
            "recommendation": "ADVISORY TEXT ONLY. Inspect authoritative DNS server forwarding logs. No automated blocking.",
        },
        # 5. Malware in encrypted sessions - flow_5tuple, uncalibrated anomaly_score, NOT_OBSERVABLE for payload
        {
            "schema_version": "1.3",
            "timestamp": "2026-09-11T02:04:12.000000+00:00",
            "flow_id": "e5f6a1b2c3d4075c",
            "flow_ref_type": "flow_5tuple",
            "ps_class": "Malware in encrypted sessions",
            "threat_class": "tls_fingerprint_anomaly",
            "detector": "tls_quic",
            "confidence": None,
            "score": 7.8,
            "score_type": "anomaly_score",
            "calibrated": False,
            "evidence": {
                "interpretation": "Known malicious JA3 hash observed without payload decryption",
                "ja3": "6734f37431670b3ab4292b8faea04307",
                "ja3s": "ec74a5c5110605f9f8eac84b7252e1fb",
                "ja4": "t13d1516h2_8daaf6152771_02711d04b684",
                "server_name": "unknown-cdn-edge.net",
                "packet_size_first_n": [240, 1420, 180, 520, 1420],
                "direction_first_n": ["c2s", "s2c", "c2s", "c2s", "s2c"],
            },
            "incident_id": "e5f6a1b2c3d4075c",
            "dedup_key": '["Malware in encrypted sessions","6734f37431670b3ab4292b8faea04307"]',
            "status": "NEW",
            "severity": "HIGH",
            "first_observed": "2026-09-11T02:04:12.000000+00:00",
            "last_observed": "2026-09-11T02:04:12.000000+00:00",
            "event_count": 1,
            "capability": {
                "detector_state": "OBSERVABLE",
                "input_mode": "pcap_replay",
            },
            "latency_ms": 130.0,
            "recommendation": "ADVISORY TEXT ONLY. Metadata analysis only — payload decryption is strictly out of scope.",
        },
        # 6. Data exfiltration - aggregate, uncalibrated robust_z, NOT_OBSERVABLE capability state
        {
            "schema_version": "1.3",
            "timestamp": "2026-09-11T02:05:30.000000+00:00",
            "flow_id": "f6a1b2c3d4e5076d",
            "flow_ref_type": "aggregate",
            "ps_class": "Data exfiltration",
            "threat_class": "outbound_volume_anomaly",
            "detector": "exfil",
            "confidence": None,
            "score": 11.2,
            "score_type": "robust_z",
            "calibrated": False,
            "evidence": {
                "interpretation": "Outbound/inbound byte ratio 34.2 (>=10) and robust z-score 11.2 (>=5)",
                "src_ip": "10.0.0.15",
                "dst_ip": "203.0.113.88",
                "bytes_out": 45000000,
                "bytes_in": 1315000,
                "byte_ratio": 34.2,
            },
            "incident_id": "f6a1b2c3d4e5076d",
            "dedup_key": '["Data exfiltration","10.0.0.15","203.0.113.88"]',
            "status": "RESOLVED",
            "severity": "HIGH",
            "first_observed": "2026-09-11T01:30:00.000000+00:00",
            "last_observed": "2026-09-11T02:05:30.000000+00:00",
            "event_count": 15,
            "capability": {
                "detector_state": "NOT_OBSERVABLE",
                "input_mode": "sflow",
                "missing_evidence": ["packet_payload", "tls_metadata"],
            },
            "latency_ms": 160.0,
            "recommendation": "ADVISORY TEXT ONLY. Verify destination 203.0.113.88 in data loss prevention logs.",
        },
    ]

    # Cryptographically sign all mock fixtures
    writer = HashChainWriter()
    signed_fixtures: list[dict[str, Any]] = []
    for f in fixtures:
        signed = writer.append(f)
        signed_fixtures.append(signed)

    return signed_fixtures


def main() -> None:
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema = json.load(f)

    fixtures = generate_canonical_fixtures()

    # Validate against schema
    for i, item in enumerate(fixtures):
        try:
            jsonschema.validate(instance=item, schema=schema)
        except Exception as e:
            raise ValueError(f"Mock fixture {i} failed schema validation: {e}")

    out_file = FIXTURES_DIR / "incidents.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(fixtures, f, indent=2)

    print(f"Generated and validated {len(fixtures)} mock fixtures at {out_file}")


if __name__ == "__main__":
    main()
