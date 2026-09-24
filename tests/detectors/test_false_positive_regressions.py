"""Regression tests for the four false-positive / miss bugs found by scripts/evaluate.py (task 5).

Each test builds the benign shape that used to alert (or the attack shape that
used to be missed) and checks the fixed behaviour, plus that the matching
true-positive shape still alerts.
"""

from ingest.capability import CapabilityState, InputMode
from ingest.normalized_event import NormalizedEvent
from detectors.c2 import C2Detector
from detectors.ddos import DDoSDetector
from detectors.exfil import ExfilDetector
from detectors.tls_quic import TLSQuicDetector
from features.rolling import TumblingWindowAggregator

T0 = 1773280000.0
CAP = CapabilityState(InputMode.PCAP_REPLAY)


def _flow(t, src, dst, sport, dport, proto="TCP", **kw):
    kw.setdefault("direction", "outbound")
    return NormalizedEvent.from_flow(observed_time=t, input_mode=InputMode.PCAP_REPLAY, capability=CAP, src_ip=src, dst_ip=dst,
                                     src_port=sport, dst_port=dport, protocol=proto, **kw)


# ---------- exfil: bidirectional records are split, inbound packets count ----------

def _record(t, src, dst, out_b, in_b):
    return _flow(t, src, dst, 50000, 443, packets=(out_b + in_b) // 1200, bytes=out_b + in_b,
                 flow_summary={"bytes_toserver": out_b, "bytes_toclient": in_b, "pkts_toserver": out_b // 1200, "pkts_toclient": in_b // 1200})


def test_exfil_download_record_is_not_outbound():
    det = ExfilDetector()
    alerts = [det.evaluate_event(_record(T0 + i * 5, "10.0.1.10", "198.18.1.1", 20_000, 40_000_000)) for i in range(10)]
    assert not any(alerts), "a 400 MB download must not look like exfiltration"


def test_exfil_upload_record_still_alerts():
    det = ExfilDetector()
    alerts = [det.evaluate_event(_record(T0 + i * 3, "10.0.9.1", "203.0.113.30", 1_000_000, 4_000)) for i in range(5)]
    hits = [a for a in alerts if a]
    assert len(hits) == 1
    assert hits[0]["evidence"]["inbound_bytes"] > 0


def test_exfil_counts_inbound_packets_of_the_same_conversation():
    det = ExfilDetector()
    for i in range(300):   # per-packet replay: server -> client data, then small client ACKs
        det.evaluate_event(_flow(T0 + i * 0.01, "198.18.1.1", "10.0.1.10", 443, 50000, packets=1, bytes=1500, direction="inbound"))
    alerts = [det.evaluate_event(_flow(T0 + 4 + i * 0.01, "10.0.1.10", "198.18.1.1", 50000, 443, packets=1, bytes=1000)) for i in range(260)]
    assert not any(alerts), "replies must be counted, so 260 KB up vs 450 KB down is not asymmetric"


# ---------- C2: NTP exempt, fleet services suppressed, single implant still alerts ----------

def _beacons(det, src, dst, port, proto, period, n=12, t0=T0):
    return [det.evaluate_event(_flow(t0 + i * period, src, dst, 50000, port, proto, packets=2, bytes=200)) for i in range(n)]


def test_c2_ignores_ntp():
    det = C2Detector()
    assert not any(_beacons(det, "10.0.1.10", "192.0.2.123", 123, "UDP", 64.0))


def test_c2_suppresses_destination_used_by_fleet():
    det = C2Detector()
    alerts = []
    for i in range(12):
        for h in range(5):
            alerts.append(det.evaluate_event(_flow(T0 + i * 30 + h, f"10.0.1.{10 + h}", "192.0.2.90", 50000, 443, packets=2, bytes=600)))
    assert not any(alerts), "a telemetry endpoint contacted by 5 hosts is a shared service"


def test_c2_single_host_beacon_still_alerts():
    det = C2Detector()
    assert any(_beacons(det, "10.0.9.6", "203.0.113.10", 443, "TCP", 5.0))


# ---------- DDoS: one bulk flow is not a flood; a spread flood still is ----------

def _windows(events):
    agg = TumblingWindowAggregator()
    out = []
    for ev in events:
        out.extend(agg.add_event(ev))
    out.extend(agg.flush())
    return out


def test_ddos_single_bulk_flow_is_not_a_flood():
    det = DDoSDetector()
    events = []
    for s in range(60):   # quiet baseline: a few small flows per second
        for k in range(3):
            events.append(_flow(T0 + s + k * 0.3, f"10.0.1.{10 + k}", "198.18.2.2", 50000 + k, 443, packets=4, bytes=2000))
    for s in range(60, 66):   # one download: 5 s flow records of ~70k packets each
        events.append(_flow(T0 + s, "10.0.1.20", "198.18.3.3", 51000, 443, packets=70_000, bytes=84_000_000, tcp_flags="A"))
    alerts = [a for w in _windows(events) for a in det.evaluate_window(w)]
    assert not alerts


def test_ddos_spoofed_syn_flood_still_alerts():
    det = DDoSDetector()
    events = [_flow(T0 + i / 6000, f"45.{i % 200}.1.{1 + i % 250}", "10.0.1.250", 1024 + i % 60000, 80, tcp_flags="S",
                    packets=1, bytes=60, direction="inbound") for i in range(18_000)]
    alerts = [a for w in _windows(events) for a in det.evaluate_window(w)]
    assert alerts and alerts[0]["threat_class"] == "syn_flood"


# ---------- TLS: packet sizes come from shape, not the record total ----------

def test_tls_fixed_small_packet_shape_is_seen_on_flow_records():
    det = TLSQuicDetector()
    alerts = []
    for i in range(3):
        alerts.append(det.evaluate_event(_flow(T0 + i * 15, "10.0.9.20", "203.0.113.24", 50000, 443, packets=5, bytes=1550,
                                              tls={"ja3": "3b5074b1b5d032e5620f69f9f700ff0e", "sni": "api.example"},
                                              shape={"packet_size_first_n": [310] * 5})))
    assert any(alerts)


def test_tls_varied_benign_shape_does_not_alert():
    det = TLSQuicDetector()
    alerts = [det.evaluate_event(_flow(T0 + i * 20, "10.0.1.10", "198.18.4.4", 50000 + i, 443, packets=90, bytes=110_000,
                                       tls={"ja3": "cd08e31494f9531f560d64c695473da9", "sni": "news.example"},
                                       shape={"packet_size_first_n": [517, 1460, 880, 1460, 212]})) for i in range(6)]
    assert not any(alerts)


def test_c2_ignores_active_timeout_records_of_one_bulk_flow():
    det = C2Detector()
    alerts = [det.evaluate_event(_flow(T0 + i * 10, "10.0.1.30", "192.0.2.200", 51000, 443, packets=1750, bytes=2_109_000)) for i in range(20)]
    assert not any(alerts), "10 s export records of one 2 MB-per-slice upload are not beacons"
