"""Acceptance tests for P2 non-ML detection paths and alert contract output."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from detectors import c2, ddos, dns, exfil, reflection, scan, tls_quic


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = Draft202012Validator(json.loads((ROOT / "schemas" / "alert.schema.json").read_text()), format_checker=FormatChecker())
TIME = "2026-09-10T00:00:00+00:00"


def assert_valid_alert(test: unittest.TestCase, outcome) -> None:
    test.assertIsNotNone(outcome.alert)
    errors = sorted(VALIDATOR.iter_errors(outcome.alert), key=lambda error: error.path)
    test.assertEqual(errors, [], errors)
    test.assertRegex(outcome.alert["flow_id"], r"^[0-9a-f]{16}$")


class StatisticalDetectorTests(unittest.TestCase):
    def test_ddos_and_slowloris_are_distinct_paths(self) -> None:
        flood = ddos.detect({"observed_time": TIME, "input_mode": "pcap_replay", "packets_per_second": 6000, "bytes_per_second": 900000, "dst_ip": "10.10.0.9", "dst_port": 443, "sources": [f"198.51.100.{item}" for item in range(30)], "syn_rate": 5000, "syn_ack_rate": 10})
        assert_valid_alert(self, flood)
        self.assertEqual(flood.alert["threat_class"], "SYN flood")
        slowloris = ddos.detect_slowloris({"observed_time": TIME, "input_mode": "pcap_replay", "dst_ip": "10.10.0.9", "dst_port": 80, "half_open_concurrency": 25, "connection_duration_p95": 90, "bytes_per_connection": 80, "packets_per_second": 5})
        assert_valid_alert(self, slowloris)
        self.assertIn("low-rate", slowloris.alert["threat_class"])

    def test_reflection_and_scan(self) -> None:
        reflected = reflection.detect({"observed_time": TIME, "input_mode": "pcap_replay", "dst_ip": "10.10.0.9", "amplifier_port": 53, "packets_per_second": 7000, "sources": [f"203.0.113.{item}" for item in range(12)], "reserved_source_share_external": 0.1})
        assert_valid_alert(self, reflected)
        scanned = scan.detect({"observed_time": TIME, "input_mode": "pcap_replay", "src_ip": "10.10.0.4", "destination_ports": list(range(100)), "destinations": [f"198.51.100.{item}" for item in range(10)], "connection_attempts": 100})
        assert_valid_alert(self, scanned)

    def test_c2_timing_and_exfiltration(self) -> None:
        beacon = c2.detect({"observed_time": TIME, "input_mode": "pcap_replay", "src_ip": "10.10.0.4", "dst_ip": "198.51.100.10", "dst_port": 443, "timestamps": [float(item * 60) for item in range(8)], "destination_novel": True})
        assert_valid_alert(self, beacon)
        self.assertLessEqual(beacon.alert["evidence"]["iat_cv"], 0.15)
        transfer = exfil.detect({"observed_time": TIME, "input_mode": "pcap_replay", "src_ip": "10.10.0.4", "dst_ip": "198.51.100.20", "outbound_bytes": 100000, "inbound_bytes": 100, "duration_s": 300, "bytes_per_packet": 1200, "destination_concentration": .9})
        assert_valid_alert(self, transfer)
        self.assertIn("does not infer data content", transfer.alert["evidence"]["interpretation"])

    def test_dns_tunnel_and_tls_metadata(self) -> None:
        qname = "a9f8e7d6c5b4a3f2e1d0qwertyuiopasdfghjklzxcvbnm1234567890.example.test"
        tunnel = dns.detect({"observed_time": TIME, "input_mode": "pcap_replay", "src_ip": "10.10.0.4", "registered_domain": "example.test", "queries_per_second": 11, "events": [{"dns": {"qname": qname, "qtype": item, "response_seen": True}} for item in ("TXT", "NULL", "CNAME", "TXT", "TXT")]})
        assert_valid_alert(self, tunnel)
        self.assertEqual(set(("TXT", "NULL", "CNAME")), set(tunnel.alert["evidence"]["qtype_distribution"]) & {"TXT", "NULL", "CNAME"})
        encrypted = tls_quic.detect({"observed_time": TIME, "input_mode": "pcap_replay", "src_ip": "10.10.0.4", "dst_ip": "198.51.100.30", "destination_novel": True, "capability": {"tls_handshake": "OBSERVABLE"}, "tls": {"ja3": "abc", "ja3s": "def", "ja4": "ghi"}, "shape": {"packet_size_first_n": [1300, 1500], "direction_first_n": ["outbound", "inbound"], "iat_median": .1, "iat_p95": .5, "iat_cv": .2, "upstream_packet_ratio": .5, "downstream_packet_ratio": .5}})
        assert_valid_alert(self, encrypted)
        self.assertIn("no payload was decrypted", encrypted.alert["evidence"]["interpretation"])

    def test_missing_evidence_is_not_benign(self) -> None:
        outcome = dns.detect({"input_mode": "ipfix", "src_ip": "10.10.0.4", "events": []})
        self.assertIsNone(outcome.alert)
        self.assertEqual(outcome.capability_state, "NOT_OBSERVABLE")
        self.assertIn("dns_names", outcome.missing_evidence)


if __name__ == "__main__":
    unittest.main()
