import { Incident } from '../types';

// GENERATED from scenarios/mock_fixtures/incidents.json by scenarios/generate_mock_fixtures.py.
// Synthetic DEMO fixtures - shown only behind the 'Demo data' toggle, never mixed with live data.
export const CANONICAL_MOCK_FIXTURES: Incident[] = [
  {
    "schema_version": "1.3",
    "timestamp": "2026-09-11T02:00:00.000000+00:00",
    "observed_time": "2026-09-11T02:00:00.000000+00:00",
    "flow_id": "a1b2c3d4e5f60718",
    "flow_ref_type": "aggregate",
    "ps_class": "Volumetric DDoS / flooding",
    "threat_class": "syn_flood",
    "detector": "ddos",
    "confidence": 0.9542,
    "score": 18.5,
    "score_type": "robust_z",
    "calibrated": false,
    "evidence": {
      "interpretation": "SYN flood exceeding volumetric threshold (12,400 pps)",
      "dst_ip": "10.0.0.5",
      "dst_port": 80,
      "packet_rate": 12400,
      "byte_rate": 7800000,
      "syn_ratio": 0.98
    },
    "baseline": {
      "packet_rate_median": 450,
      "packet_rate_mad": 60
    },
    "threshold": {
      "syn_flood_pps": 1000
    },
    "window": {
      "start": "2026-09-11T01:59:59.000000+00:00",
      "end": "2026-09-11T02:00:00.000000+00:00",
      "duration_s": 1.0
    },
    "incident_id": "a1b2c3d4e5f60718",
    "dedup_key": "[\"Volumetric DDoS / flooding\",\"10.0.0.5\",80]",
    "status": "ACTIVE",
    "severity": "CRITICAL",
    "first_observed": "2026-09-11T01:58:30.000000+00:00",
    "last_observed": "2026-09-11T02:00:00.000000+00:00",
    "event_count": 92,
    "capability": {
      "detector_state": "OBSERVABLE",
      "input_mode": "pcap_replay"
    },
    "latency_ms": 142.5,
    "recommendation": "ADVISORY TEXT ONLY. Upstream rate-limiting recommended. No active response path in system.",
    "calibrated_on": "uncalibrated",
    "seq": 1,
    "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "payload_hash": "fc7874fd59e31f8b724318e5fd1746d30e7a88153f8094b81d877a5bd0e6bd06",
    "entry_hash": "131709276b4b7d1a87561c95cdd6c1e6f88c3938bf9f460357a1d888eb5d625b"
  },
  {
    "schema_version": "1.3",
    "timestamp": "2026-09-11T02:01:10.000000+00:00",
    "flow_id": "b2c3d4e5f6a10729",
    "flow_ref_type": "entity",
    "ps_class": "Port scanning / reconnaissance",
    "threat_class": "vertical_port_scan",
    "detector": "scan",
    "confidence": 1.0,
    "score": 42.0,
    "score_type": "anomaly_score",
    "calibrated": false,
    "evidence": {
      "interpretation": "Vertical scan probed 42 ports on target in 1s window",
      "src_ip": "192.168.1.105",
      "dst_ip": "10.0.0.8",
      "ports_probed": 42,
      "scan_type": "SYN_STEALTH"
    },
    "incident_id": "b2c3d4e5f6a10729",
    "dedup_key": "[\"Port scanning / reconnaissance\",\"192.168.1.105\",\"NOT_OBSERVABLE\"]",
    "status": "NEW",
    "severity": "MEDIUM",
    "first_observed": "2026-09-11T02:01:10.000000+00:00",
    "last_observed": "2026-09-11T02:01:10.000000+00:00",
    "event_count": 1,
    "capability": {
      "detector_state": "DEGRADED",
      "input_mode": "ipfix",
      "missing_evidence": [
        "tcp_flags"
      ]
    },
    "latency_ms": 88.0,
    "recommendation": "ADVISORY TEXT ONLY. Investigate host 192.168.1.105 for credential discovery. No mitigation command.",
    "calibrated_on": "uncalibrated",
    "seq": 2,
    "prev_hash": "131709276b4b7d1a87561c95cdd6c1e6f88c3938bf9f460357a1d888eb5d625b",
    "payload_hash": "82b7c0d562e54db3fd7a39bafd73bc0fb679de8ca86d8b4e3e0aeefa8789f7e1",
    "entry_hash": "15cee2dbcc7fbbd61cdeb3b2734aaabe14bbfe96bd9342e715d512fc6cb4020b"
  },
  {
    "schema_version": "1.3",
    "timestamp": "2026-09-11T02:02:15.000000+00:00",
    "flow_id": "c3d4e5f6a1b2073a",
    "flow_ref_type": "flow_5tuple",
    "ps_class": "Botnet C2 beaconing",
    "threat_class": "periodic_beacon",
    "detector": "c2",
    "confidence": 1.0,
    "score": 9.4,
    "score_type": "rule_score",
    "calibrated": false,
    "evidence": {
      "interpretation": "High periodicity heartbeat detected with CV 0.04 (<=0.15 threshold)",
      "src_ip": "10.0.0.22",
      "dst_ip": "198.51.100.44",
      "dst_port": 443,
      "iat_median": 5.02,
      "iat_cv": 0.041,
      "intervals_observed": 28
    },
    "incident_id": "c3d4e5f6a1b2073a",
    "dedup_key": "[\"Botnet C2 beaconing\",\"10.0.0.22\",\"198.51.100.44\",443]",
    "status": "UPDATED",
    "severity": "HIGH",
    "first_observed": "2026-09-11T01:50:00.000000+00:00",
    "last_observed": "2026-09-11T02:02:15.000000+00:00",
    "event_count": 28,
    "capability": {
      "detector_state": "OBSERVABLE",
      "input_mode": "pcap_replay"
    },
    "latency_ms": 115.0,
    "recommendation": "ADVISORY TEXT ONLY. Review endpoint process tree on 10.0.0.22. System operates passively.",
    "calibrated_on": "uncalibrated",
    "seq": 3,
    "prev_hash": "15cee2dbcc7fbbd61cdeb3b2734aaabe14bbfe96bd9342e715d512fc6cb4020b",
    "payload_hash": "73cbcd222139c12b8ed8b16fbc30df28916c13f93fcaa17075f0807ec34890ab",
    "entry_hash": "8789998c74e055c327b54dad05de4f101edc995ffc809339ebce8d625f68f802"
  },
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
    "calibrated": true,
    "evidence": {
      "interpretation": "High entropy TXT query volume consistent with DNS data tunnelling",
      "domain": "tunnel.exfil-corp.internal.attacker.com",
      "qtype_distribution": {
        "TXT": 0.88,
        "CNAME": 0.08,
        "A": 0.04
      },
      "query_length_mean": 82.4,
      "entropy_mean": 4.35
    },
    "incident_id": "d4e5f6a1b2c3074b",
    "dedup_key": "[\"DGA / DNS tunnelling\",\"tunnel.exfil-corp.internal.attacker.com\"]",
    "status": "ACTIVE",
    "severity": "CRITICAL",
    "first_observed": "2026-09-11T02:00:00.000000+00:00",
    "last_observed": "2026-09-11T02:03:00.000000+00:00",
    "event_count": 64,
    "capability": {
      "detector_state": "OBSERVABLE",
      "input_mode": "pcap_replay"
    },
    "latency_ms": 95.0,
    "recommendation": "ADVISORY TEXT ONLY. Inspect authoritative DNS server forwarding logs. No automated blocking.",
    "calibrated_on": "platt_dga",
    "seq": 4,
    "prev_hash": "8789998c74e055c327b54dad05de4f101edc995ffc809339ebce8d625f68f802",
    "payload_hash": "11e0069e3d09101376083a2f33b14b9069da9aa0512ab1884981a1498ca1b914",
    "entry_hash": "273e10eb9810a07754e760eda946f6a88523a95b34f007316656c197c19157e5"
  },
  {
    "schema_version": "1.3",
    "timestamp": "2026-09-11T02:04:12.000000+00:00",
    "flow_id": "e5f6a1b2c3d4075c",
    "flow_ref_type": "flow_5tuple",
    "ps_class": "Malware in encrypted sessions",
    "threat_class": "tls_fingerprint_anomaly",
    "detector": "tls_quic",
    "confidence": 1.0,
    "score": 7.8,
    "score_type": "anomaly_score",
    "calibrated": false,
    "evidence": {
      "interpretation": "Known malicious JA3 hash observed without payload decryption",
      "ja3": "6734f37431670b3ab4292b8faea04307",
      "ja3s": "ec74a5c5110605f9f8eac84b7252e1fb",
      "ja4": "t13d1516h2_8daaf6152771_02711d04b684",
      "server_name": "unknown-cdn-edge.net",
      "packet_size_first_n": [
        240,
        1420,
        180,
        520,
        1420
      ],
      "direction_first_n": [
        "c2s",
        "s2c",
        "c2s",
        "c2s",
        "s2c"
      ]
    },
    "incident_id": "e5f6a1b2c3d4075c",
    "dedup_key": "[\"Malware in encrypted sessions\",\"6734f37431670b3ab4292b8faea04307\"]",
    "status": "NEW",
    "severity": "HIGH",
    "first_observed": "2026-09-11T02:04:12.000000+00:00",
    "last_observed": "2026-09-11T02:04:12.000000+00:00",
    "event_count": 1,
    "capability": {
      "detector_state": "OBSERVABLE",
      "input_mode": "pcap_replay"
    },
    "latency_ms": 130.0,
    "recommendation": "ADVISORY TEXT ONLY. Metadata analysis only \u2014 payload decryption is strictly out of scope.",
    "calibrated_on": "uncalibrated",
    "seq": 5,
    "prev_hash": "273e10eb9810a07754e760eda946f6a88523a95b34f007316656c197c19157e5",
    "payload_hash": "867df0be10f1cd3cf6bc3057c2a77f121f0f60a7380b301ee2f88b31690851b3",
    "entry_hash": "0e4e712a7a95cc7a18060924b3adf961dc47f6ca985045bae67d97c3fcaa15cc"
  },
  {
    "schema_version": "1.3",
    "timestamp": "2026-09-11T02:05:30.000000+00:00",
    "flow_id": "f6a1b2c3d4e5076d",
    "flow_ref_type": "aggregate",
    "ps_class": "Data exfiltration",
    "threat_class": "outbound_volume_anomaly",
    "detector": "exfil",
    "confidence": 0.8935,
    "score": 11.2,
    "score_type": "robust_z",
    "calibrated": false,
    "evidence": {
      "interpretation": "Outbound/inbound byte ratio 34.2 (>=10) and robust z-score 11.2 (>=5)",
      "src_ip": "10.0.0.15",
      "dst_ip": "203.0.113.88",
      "bytes_out": 45000000,
      "bytes_in": 1315000,
      "byte_ratio": 34.2
    },
    "incident_id": "f6a1b2c3d4e5076d",
    "dedup_key": "[\"Data exfiltration\",\"10.0.0.15\",\"203.0.113.88\"]",
    "status": "RESOLVED",
    "severity": "HIGH",
    "first_observed": "2026-09-11T01:30:00.000000+00:00",
    "last_observed": "2026-09-11T02:05:30.000000+00:00",
    "event_count": 15,
    "capability": {
      "detector_state": "NOT_OBSERVABLE",
      "input_mode": "sflow",
      "missing_evidence": [
        "packet_payload",
        "tls_metadata"
      ]
    },
    "latency_ms": 160.0,
    "recommendation": "ADVISORY TEXT ONLY. Verify destination 203.0.113.88 in data loss prevention logs.",
    "calibrated_on": "uncalibrated",
    "seq": 6,
    "prev_hash": "0e4e712a7a95cc7a18060924b3adf961dc47f6ca985045bae67d97c3fcaa15cc",
    "payload_hash": "000a1699a1288a43e94eb64d682286d8ef9b17c82532f9acf6310c50c6f6cc83",
    "entry_hash": "cf609544fe7bf826ff5c554d37614d23f6c3097d373e3ea435794d6409bcc361"
  }
] as Incident[];
