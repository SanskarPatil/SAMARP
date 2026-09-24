"""UDP reflection wired into the pipeline (task 7)."""

from random import Random

from detectors.pipeline import DetectionPipeline
from detectors.reflection import ReflectionDetector
from ingest.capability import CapabilityState, InputMode
from ingest.normalized_event import NormalizedEvent
from scenarios.attack_suite import _Builder, _reflection

T0 = 1773280000.0
CAP = CapabilityState(InputMode.PCAP_REPLAY)


def _udp(t, src, dst, sport, dport, size, direction):
    return NormalizedEvent.from_flow(observed_time=t, input_mode=InputMode.PCAP_REPLAY, capability=CAP, src_ip=src, dst_ip=dst,
                                     src_port=sport, dst_port=dport, protocol="UDP", packets=1, bytes=size, direction=direction)


def _attack(victim="10.0.1.245", port=53, amps=80, pps=6000, seconds=3, size=1200):
    b = _Builder(Random(3))
    _reflection(b, T0, victim, port, amps, pps, seconds, size)
    return sorted(b.events, key=lambda e: float(e.observed_time))


def test_dns_reflection_alerts_once_with_evidence():
    det = ReflectionDetector()
    alerts = [a for a in (det.evaluate_event(e) for e in _attack()) if a]
    assert len(alerts) == 1
    a = alerts[0]
    assert a["detector"] == "reflection" and a["ps_class"] == "Volumetric DDoS / flooding"
    assert a["threat_class"] == "udp_reflection"
    ev = a["evidence"]
    assert ev["amplifier_port"] == 53 and ev["fan_in"] >= 10 and ev["unsolicited_share"] == 1.0
    assert "Header metadata only" in ev["interpretation"]
    assert 0.0 <= a["confidence"] <= 1.0 and a["calibrated_on"]


def test_ntp_reflection_triggers_on_bit_rate():
    det = ReflectionDetector(min_pps=5000)          # pps gate out of reach; 2.5k x 468 B = 9.4 Mbps < 20 Mbps
    assert not any(det.evaluate_event(e) for e in _attack(port=123, amps=30, pps=2500, seconds=4, size=468))
    det = ReflectionDetector()                      # default 2,000 pps gate
    assert any(det.evaluate_event(e) for e in _attack(victim="10.0.1.246", port=123, amps=30, pps=2500, seconds=4, size=468))


def test_solicited_resolver_burst_is_not_reflection():
    det = ReflectionDetector()
    rng = Random(5)
    auths = [f"198.19.{i}.1" for i in range(150)]
    alerts = []
    for i in range(3000):                          # 3,000 answers/s from 150 servers: passes rate and fan-in gates
        t, sport = T0 + i / 3000, 20000 + i
        alerts.append(det.evaluate_event(_udp(t, "10.0.1.2", auths[i % 150], sport, 53, 90, "outbound")))
        alerts.append(det.evaluate_event(_udp(t + 0.01, auths[i % 150], "10.0.1.2", 53, sport, rng.randint(200, 1400), "inbound")))
    assert not any(alerts), "a resolver's own answers are solicited"


def test_below_fan_in_is_not_reflection():
    det = ReflectionDetector()
    assert not any(det.evaluate_event(e) for e in _attack(victim="10.0.1.247", port=11211, amps=6, pps=600, seconds=5, size=1400))


def test_non_amplifier_port_ignored():
    det = ReflectionDetector()
    assert not any(det.evaluate_event(e) for e in _attack(port=4444))


def test_pipeline_emits_reflection_alert():
    p = DetectionPipeline()
    alerts = [a for e in _attack() for a in p.process_event(e)] + p.flush()
    assert any(a["detector"] == "reflection" for a in alerts)


def test_resolver_burst_would_alert_without_the_unsolicited_gate():
    """Guards the test above: the burst must clear the rate and fan-in gates."""
    det = ReflectionDetector(min_unsolicited_share=0.0)
    auths = [f"198.19.{i}.1" for i in range(150)]
    hits = [det.evaluate_event(_udp(T0 + i / 3000 + 0.01, auths[i % 150], "10.0.1.2", 53, 20000 + i, 800, "inbound")) for i in range(3000)]
    assert any(hits)
