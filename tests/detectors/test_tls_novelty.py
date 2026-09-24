"""JA3/JA4 novelty (task 6): novel fires, known stays quiet, expiry, warm-up, canonical beat."""

import json

from detectors.tls_quic import TLSQuicDetector, load_fingerprint_baseline
from ingest.capability import CapabilityState, InputMode
from ingest.normalized_event import NormalizedEvent
from scenarios.canonical_campaign import generate_canonical_campaign_events

T0 = 1773280000.0
DAY = 86400.0
CAP = CapabilityState(InputMode.PCAP_REPLAY)
KNOWN_JA3, KNOWN_JA4 = "cd08e31494f9531f560d64c695473da9", "t13d1715h2_5b57614c22b0_3d5424432f57"
NEW_JA3, NEW_JA4 = "1d095e68489d3c535297cd8dffb06cb9", "t13d0909h1_aaaaaaaaaaaa_bbbbbbbbbbbb"
BASELINE = {"ja3": {KNOWN_JA3: T0}, "ja4": {KNOWN_JA4: T0}, "source": "unit-test baseline"}


def _tls(t, ja3, ja4, src="10.0.1.10", dst="198.18.4.4", sni="static.example"):
    return NormalizedEvent.from_flow(observed_time=t, input_mode=InputMode.PCAP_REPLAY, capability=CAP, src_ip=src, dst_ip=dst,
                                     src_port=50000, dst_port=443, protocol="TCP", packets=12, bytes=9000, direction="outbound",
                                     tls={"ja3": ja3, "ja4": ja4, "sni": sni},
                                     shape={"packet_size_first_n": [517, 1460, 880, 1460, 212]})


def test_novel_fingerprint_alerts_once_with_evidence():
    det = TLSQuicDetector(baseline=BASELINE)
    alert = det.evaluate_event(_tls(T0 + 60, NEW_JA3, NEW_JA4))
    assert alert is not None and alert["ps_class"] == "Malware in encrypted sessions"
    ev = alert["evidence"]
    assert ev["novel_fingerprints"] == [f"ja3:{NEW_JA3}", f"ja4:{NEW_JA4}"]
    assert ev["novelty_state"] == "active" and ev["novelty_days"] == 7
    assert "not seen on this network" in ev["interpretation"]
    assert 0.0 <= alert["confidence"] <= 1.0 and alert["calibrated_on"]
    # same fingerprint from another host a minute later is no longer novel
    assert det.evaluate_event(_tls(T0 + 120, NEW_JA3, NEW_JA4, src="10.0.1.11")) is None


def test_known_fingerprint_is_quiet():
    det = TLSQuicDetector(baseline=BASELINE)
    assert det.evaluate_event(_tls(T0 + 60, KNOWN_JA3, KNOWN_JA4)) is None


def test_fingerprint_expires_after_novelty_days():
    det = TLSQuicDetector(baseline=BASELINE, novelty_days=7)
    assert det.evaluate_event(_tls(T0 + 6 * DAY, KNOWN_JA3, KNOWN_JA4, dst="198.18.4.5")) is None
    alert = det.evaluate_event(_tls(T0 + 6 * DAY + 8 * DAY, KNOWN_JA3, KNOWN_JA4, dst="198.18.4.6"))
    assert alert is not None and f"ja3:{KNOWN_JA3}" in alert["evidence"]["novel_fingerprints"]


def test_no_baseline_means_warm_up_then_active():
    det = TLSQuicDetector(novelty_warmup_s=3600)
    assert det.evaluate_event(_tls(T0, KNOWN_JA3, KNOWN_JA4)) is None          # learning
    assert det.evaluate_event(_tls(T0 + 60, NEW_JA3, NEW_JA4)) is None         # learning: recorded, no alert
    assert det.novelty_state(T0 + 60) == "learning"
    late = det.evaluate_event(_tls(T0 + 4000, "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f", "t13d0000h2_cccccccccccc_dddddddddddd", dst="198.18.9.9"))
    assert late is not None and late["evidence"]["novelty_state"] == "active"
    assert det.evaluate_event(_tls(T0 + 4100, NEW_JA3, NEW_JA4, dst="198.18.9.10")) is None   # learned during warm-up


def test_canonical_tls_beat_raises_class_d():
    det = TLSQuicDetector(baseline=BASELINE)
    alerts = [a for a in (det.evaluate_event(e) for e in generate_canonical_campaign_events()) if a]
    beat6 = [a for a in alerts if "10.0.0.75" in a["dedup_key"]]
    assert len(beat6) == 1
    assert beat6[0]["ps_class"] == "Malware in encrypted sessions"
    assert "ja3:6734f37431670b3ab4292b8faea04307" in beat6[0]["evidence"]["novel_fingerprints"]


def test_load_fingerprint_baseline_roundtrip(tmp_path):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"source": "x", "ja3": {KNOWN_JA3: T0}, "ja4": {}}), encoding="utf-8")
    b = load_fingerprint_baseline(p)
    assert b["source"] == "x" and KNOWN_JA3 in b["ja3"]
    assert load_fingerprint_baseline(tmp_path / "missing.json") is None
