"""Feature parity tests.

Asserts:
- FEATURE_ORDER is the single authoritative contract (no duplicates, frozen length 20).
- Offline vs streaming entropy calculation parity.
- Windowing aggregation parity and 300 ms watermark behavior.
"""

from __future__ import annotations

from features.entropy import StreamingEntropy, shannon_entropy
from features.feature_order import FEATURE_COUNT, FEATURE_ORDER, FEATURE_ORDER_VERSION
from features.rolling import TumblingWindowAggregator
from ingest.capability import CapabilityState, InputMode
from ingest.normalized_event import NormalizedEvent


def test_feature_order_contract_parity() -> None:
    assert FEATURE_ORDER_VERSION == 1
    assert len(FEATURE_ORDER) == 20
    assert FEATURE_COUNT == 20
    assert len(set(FEATURE_ORDER)) == 20

    # Ensure key expected features are present in the exact tuple
    assert "length" in FEATURE_ORDER
    assert "entropy" in FEATURE_ORDER
    assert "lm_bigram" in FEATURE_ORDER
    assert "lm_trigram" in FEATURE_ORDER
    assert "nxdomain_rate" in FEATURE_ORDER
    assert "qtype_txt_ratio" in FEATURE_ORDER
    assert "packet_size_first_n" in FEATURE_ORDER


def test_entropy_streaming_vs_offline_parity() -> None:
    test_strings = [
        "example",
        "google",
        "xzkjqwyfp7931",
        "a" * 50,
        "abcdefghijklmnopqrstuvwxyz0123456789",
    ]

    for s in test_strings:
        # Offline computation
        offline_val = shannon_entropy(s)

        # Streaming computation
        streamer = StreamingEntropy(max_distinct=128)
        for ch in s:
            streamer.add(ch)
        streaming_val = streamer.entropy()

        assert abs(offline_val - streaming_val) < 1e-9


def test_windowing_300ms_watermark_closure() -> None:
    aggregator = TumblingWindowAggregator(window_duration_s=1.0, watermark_delay_s=0.3)

    # Event at t=100.1s (window [100.0, 101.0))
    ev1 = NormalizedEvent(
        observed_time=100.1,
        input_mode=InputMode.PCAP_REPLAY,
        capability=CapabilityState(InputMode.PCAP_REPLAY),
        src_ip="10.10.0.1",
        dst_ip="10.10.0.2",
    )
    closed1 = aggregator.add_event(ev1)
    # Watermark = 100.1 - 0.3 = 99.8. Window [100.0, 101.0) has end=101.0 > 99.8 -> remains OPEN
    assert len(closed1) == 0

    # Event at t=100.9s
    ev2 = NormalizedEvent(
        observed_time=100.9,
        input_mode=InputMode.PCAP_REPLAY,
        capability=CapabilityState(InputMode.PCAP_REPLAY),
        src_ip="10.10.0.3",
        dst_ip="10.10.0.2",
    )
    closed2 = aggregator.add_event(ev2)
    # Watermark = 100.9 - 0.3 = 100.6 < 101.0 -> remains OPEN
    assert len(closed2) == 0

    # Event at t=101.35s (watermark = 101.35 - 0.3 = 101.05 >= 101.0 -> window [100.0, 101.0) CLOSES!)
    ev3 = NormalizedEvent(
        observed_time=101.35,
        input_mode=InputMode.PCAP_REPLAY,
        capability=CapabilityState(InputMode.PCAP_REPLAY),
        src_ip="10.10.0.4",
        dst_ip="10.10.0.2",
    )
    closed3 = aggregator.add_event(ev3)
    assert len(closed3) == 1
    w = closed3[0]
    assert w.start_time == 100.0
    assert w.end_time == 101.0
    assert w.event_count == 2
    assert w.unique_src_count == 2
