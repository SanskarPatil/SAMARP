"""Declared internal resolvers (config/address_plan.yaml additional_dns_resolvers)."""

import detectors.scan as scan_mod
from detectors.ddos import DDoSDetector
from detectors.scan import ScanDetector
from features.rolling import TumblingWindowAggregator
from ingest.address_plan import AddressPlan
from ingest.capability import CapabilityState, InputMode
from ingest.normalized_event import NormalizedEvent

T0 = 1773280000.0
CAP = CapabilityState(InputMode.PCAP_REPLAY)
RESOLVER = "10.0.1.2"


def _udp(t, src, dst, sport, dport, size=100, direction="outbound"):
    return NormalizedEvent.from_flow(observed_time=t, input_mode=InputMode.PCAP_REPLAY, capability=CAP, src_ip=src, dst_ip=dst,
                                     src_port=sport, dst_port=dport, protocol="UDP", packets=1, bytes=size, direction=direction)


def _queries(src, n=200):
    return [_udp(T0 + i * 0.5, src, f"198.19.{i}.1", 30000 + i, 53) for i in range(n)]


def test_plan_loads_declared_resolvers():
    assert RESOLVER in AddressPlan.load().dns_resolvers


def test_scan_skips_declared_resolver_queries(monkeypatch):
    monkeypatch.setattr(scan_mod, "_DECLARED_RESOLVERS", frozenset({RESOLVER}))
    det = ScanDetector()
    assert not any(det.evaluate_event(e) for e in _queries(RESOLVER))


def test_scan_still_flags_undeclared_host_sweeping_53(monkeypatch):
    monkeypatch.setattr(scan_mod, "_DECLARED_RESOLVERS", frozenset({RESOLVER}))
    det = ScanDetector()
    assert any(det.evaluate_event(e) for e in _queries("10.0.1.77"))


def _ddos_alerts(events, resolvers):
    agg, det, out = TumblingWindowAggregator(resolvers=resolvers), DDoSDetector(), []
    for e in events:
        for w in agg.add_event(e):
            out.extend(det.evaluate_window(w))
    for w in agg.flush():
        out.extend(det.evaluate_window(w))
    return out


def _baseline():
    return [_udp(T0 + s + k * 0.2, f"10.0.1.{10 + k}", "198.18.1.1", 40000 + k, 443) for s in range(40) for k in range(5)]


def _refresh(start):
    ev = []
    for i in range(6000):                       # 6,000 q + 6,000 answers over 2 s
        t, sport = start + i / 3000, 20000 + i % 40000
        ev.append(_udp(t, RESOLVER, f"198.19.{i % 150}.1", sport, 53))
        ev.append(_udp(t + 0.01, f"198.19.{i % 150}.1", RESOLVER, 53, sport, 700, "inbound"))
    return ev


def test_ddos_skips_balanced_refresh_of_declared_resolver():
    events = sorted(_baseline() + _refresh(T0 + 40), key=lambda e: float(e.observed_time))
    assert _ddos_alerts(events, frozenset()) , "guard: without the declaration this window IS a UDP flood"
    assert not _ddos_alerts(events, frozenset({RESOLVER}))


def test_ddos_still_flags_query_flood_at_declared_resolver():
    flood = [_udp(T0 + 40 + i / 6000, f"45.{i % 200}.2.{1 + i % 250}", RESOLVER, 1024 + i % 60000, 53, 80, "inbound") for i in range(18000)]
    events = sorted(_baseline() + flood, key=lambda e: float(e.observed_time))
    assert _ddos_alerts(events, frozenset({RESOLVER})), "inbound query flood is not balanced resolver traffic"
