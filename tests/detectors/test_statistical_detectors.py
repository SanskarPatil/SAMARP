"""Acceptance tests for the non-ML detection paths and the alert contract.

Rewritten in task 9: the original file called module-level ``detect(dict)``
functions (c2, ddos, dns, scan) that the streaming detectors replaced, so 5
tests failed with AttributeError. The intents are kept and asserted through
the current APIs; paths already covered elsewhere are pointed to, not copied:
  * SYN flood vs Slowloris distinct paths -> tests/detectors/test_ddos.py
  * streaming UDP reflection              -> tests/detectors/test_reflection_stream.py
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from detectors import reflection
from detectors.c2 import C2Detector
from detectors.dns import DNSTunnelDetector
from detectors.exfil import ExfilDetector
from detectors.scan import ScanDetector
from detectors.tls_quic import TLSQuicDetector
from ingest.capability import Capability, CapabilityState, InputMode
from ingest.normalized_event import NormalizedEvent

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = Draft202012Validator(json.loads((ROOT / "schemas" / "alert.schema.json").read_text(encoding="utf-8")), format_checker=FormatChecker())
TIME = "2026-09-10T00:00:00+00:00"
T0 = 1773280000.0
CAP = CapabilityState(InputMode.PCAP_REPLAY)


def _flow(t, src, dst, sport, dport, proto="TCP", **kw):
    kw.setdefault("direction", "outbound")
    return NormalizedEvent.from_flow(observed_time=t, input_mode=InputMode.PCAP_REPLAY, capability=CAP, src_ip=src, dst_ip=dst,
                                     src_port=sport, dst_port=dport, protocol=proto, **kw)


def _first(detector, events):
    for ev in events:
        alert = detector.evaluate_event(ev)
        if alert is not None:
            return alert
    return None


class StatisticalDetectorTests(unittest.TestCase):
    def assert_valid_alert(self, alert) -> None:
        self.assertIsNotNone(alert)
        errors = sorted(VALIDATOR.iter_errors(alert), key=lambda error: list(error.path))
        self.assertEqual(errors, [], errors)
        self.assertRegex(alert["flow_id"], r"^[0-9a-f]{16}$")
        self.assertTrue(0.0 <= alert["confidence"] <= 1.0)

    def test_reflection_and_scan(self) -> None:
        # Legacy stateless reflection API is still supported.
        reflected = reflection.detect({"observed_time": TIME, "input_mode": "pcap_replay", "dst_ip": "10.10.0.9", "amplifier_port": 53,
                                       "packets_per_second": 7000, "sources": [f"203.0.113.{item}" for item in range(12)],
                                       "reserved_source_share_external": 0.1})
        self.assert_valid_alert(reflected.alert)
        scanned = _first(ScanDetector(), [_flow(T0 + i * 0.02, "10.10.0.4", f"198.51.100.{i % 10}", 40000 + i, 1 + i, tcp_flags="S",
                                                packets=1, bytes=60) for i in range(150)])
        self.assert_valid_alert(scanned)
        self.assertEqual(scanned["ps_class"], "Port scanning / reconnaissance")

    def test_c2_timing_and_exfiltration(self) -> None:
        beacon = _first(C2Detector(), [_flow(T0 + i * 60, "10.10.0.4", "198.51.100.10", 49152, 443, packets=2, bytes=220) for i in range(10)])
        self.assert_valid_alert(beacon)
        self.assertLessEqual(beacon["evidence"]["iat_cv"], 0.15)
        records = [_flow(T0 + i * 3, "10.10.0.4", "198.51.100.20", 55000, 443, packets=800, bytes=1_000_000,
                         flow_summary={"bytes_toserver": 1_000_000, "bytes_toclient": 2_000, "pkts_toserver": 800, "pkts_toclient": 6})
                   for i in range(5)]
        transfer = _first(ExfilDetector(), records)
        self.assert_valid_alert(transfer)
        self.assertIn("does not infer data content", transfer["evidence"]["interpretation"])

    def test_dns_tunnel_and_tls_metadata(self) -> None:
        events = [_flow(T0 + i * 0.08, "10.10.0.4", "10.10.0.53", 53000 + i, 53, "UDP", packets=2, bytes=200,
                        dns={"qname": f"a9f8e7d6c5b4a3f2e1d0qwertyuiop{i:04d}asdfghjklzxcvbnm1234567890.example.test",
                             "qtype": ("TXT", "NULL", "CNAME")[i % 3], "nxdomain": False, "rcode": 0}) for i in range(40)]
        tunnel = _first(DNSTunnelDetector(), events)
        self.assert_valid_alert(tunnel)
        self.assertEqual({"TXT", "NULL", "CNAME"}, set(tunnel["evidence"]["qtype_distribution"]) & {"TXT", "NULL", "CNAME"})
        encrypted = _first(TLSQuicDetector(), [_flow(T0, "10.10.0.4", "198.51.100.30", 50000, 4443, packets=5, bytes=1500,
                                                     tls={"ja3": "e7d705a3286e19ea42f587b344ee6865", "ja3s": "def", "ja4": "ghi"})])
        self.assert_valid_alert(encrypted)
        self.assertIn("no decrypted payload bytes inspected", encrypted["evidence"]["interpretation"])

    def test_missing_evidence_is_not_benign(self) -> None:
        # IPFIX carries no DNS names: the capability must say NOT_OBSERVABLE (unknown),
        # and the DNS detector must stay silent rather than issue a verdict.
        ipfix = CapabilityState(InputMode.IPFIX)
        self.assertIs(ipfix.get("dns_names"), Capability.NOT_OBSERVABLE)
        ev = NormalizedEvent.from_flow(observed_time=T0, input_mode=InputMode.IPFIX, capability=ipfix, src_ip="10.10.0.4",
                                       dst_ip="10.10.0.53", src_port=53000, dst_port=53, protocol="UDP", packets=2, bytes=120)
        self.assertIsNone(DNSTunnelDetector().evaluate_event(ev))


if __name__ == "__main__":
    unittest.main()
