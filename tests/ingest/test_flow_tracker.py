"""Bounded flow tracking: identity, direction split, expiry, eviction.

The invariant these tests defend (V6.3 section 11): an attacker presenting
millions of distinct 5-tuples must not be able to grow detector state without
limit, and every flow we drop must be counted rather than silently lost.
"""

from __future__ import annotations

import pytest

from ingest.flow_tracker import (
    DEFAULT_IDLE_TIMEOUT_S,
    DEFAULT_MAX_FLOWS,
    FlowTracker,
)
from ingest.headers import PacketHeaders

T0 = 1_757_500_000.0
LAB = "10.10.0.5"
EXT = "93.184.216.34"

SYN, ACK, FIN, RST = 0x02, 0x10, 0x01, 0x04


def hdr(
    src=LAB, dst=EXT, sport=44321, dport=443, proto="TCP", flags=None, wire=54
) -> PacketHeaders:
    return PacketHeaders(
        ip_version=4,
        src_ip=src,
        dst_ip=dst,
        protocol=proto,
        src_port=sport,
        dst_port=dport,
        tcp_flags=flags,
        wire_bytes=wire,
    )


# ------------------------------------------------------------- identity


def test_bidirectional_packets_share_one_flow_id():
    """Requirement 12: same flow_id both ways."""
    t = FlowTracker()
    fwd = t.observe(hdr(), T0)
    rev = t.observe(hdr(src=EXT, dst=LAB, sport=443, dport=44321), T0 + 0.1)
    assert fwd.flow_id == rev.flow_id
    assert len(t) == 1, "one conversation is one flow"


def test_direction_is_still_counted_separately():
    """Same identity, distinct directional counters."""
    t = FlowTracker()
    t.observe(hdr(wire=100), T0)
    t.observe(hdr(wire=100), T0 + 0.1)
    flow = t.observe(hdr(src=EXT, dst=LAB, sport=443, dport=44321, wire=200), T0 + 0.2)

    assert flow.packets == 3
    assert flow.fwd_packets == 2 and flow.fwd_bytes == 200
    assert flow.rev_packets == 1 and flow.rev_bytes == 200
    assert flow.bytes == 400


def test_different_ports_are_different_flows():
    t = FlowTracker()
    a = t.observe(hdr(sport=1000), T0)
    b = t.observe(hdr(sport=1001), T0)
    assert a.flow_id != b.flow_id
    assert len(t) == 2


def test_different_protocols_are_different_flows():
    t = FlowTracker()
    a = t.observe(hdr(proto="TCP"), T0)
    b = t.observe(hdr(proto="UDP"), T0)
    assert a.flow_id != b.flow_id


def test_flow_id_matches_the_frozen_identifier_form():
    t = FlowTracker()
    flow = t.observe(hdr(), T0)
    assert len(flow.flow_id) == 16
    assert all(c in "0123456789abcdef" for c in flow.flow_id)


def test_tracker_and_normalizer_agree_on_flow_id():
    """Regression: hashing 6 is not hashing "TCP".

    The tracker receives a numeric IP protocol from the header decoder while
    the normalizer stores the canonical name. If the tracker hashes the raw
    number, the same flow gets two different flow_ids - the flow_summary on
    an event would then disagree with that event's own flow_id.
    """
    from ingest.identity import flow_id_for_five_tuple

    numeric = hdr(proto=6)  # as the header decoder produces it
    flow = FlowTracker().observe(numeric, T0)

    expected = flow_id_for_five_tuple(LAB, EXT, 44321, 443, "TCP")
    assert flow.flow_id == expected
    assert flow.protocol == "TCP", "protocol is stored canonically, not as an int"


def test_numeric_and_named_protocol_land_on_one_flow():
    t = FlowTracker()
    a = t.observe(hdr(proto=6), T0)
    b = t.observe(hdr(proto="TCP"), T0 + 0.1)
    assert a.flow_id == b.flow_id
    assert len(t) == 1


# ------------------------------------------------------------ flow_summary


def test_summary_carries_the_required_counters():
    t = FlowTracker()
    t.observe(hdr(flags=SYN, wire=54), T0)
    flow = t.observe(
        hdr(src=EXT, dst=LAB, sport=443, dport=44321, flags=SYN | ACK, wire=60),
        T0 + 1.0,
    )
    s = flow.to_summary()

    assert s["packets"] == 2
    assert s["bytes"] == 114
    assert s["fwd_packets"] == 1 and s["rev_packets"] == 1
    assert s["duration_s"] == pytest.approx(1.0)
    assert s["first_seen"] == T0 and s["last_seen"] == T0 + 1.0
    assert set("SA").issubset(set(s["tcp_flags_seen"]))


def test_summary_holds_no_payload_field():
    """Header-only: there is nowhere for packet bytes to live."""
    t = FlowTracker()
    s = t.observe(hdr(), T0).to_summary()
    for banned in ("payload", "data", "body", "content", "raw"):
        assert banned not in s


def test_state_transitions_on_tcp_flags():
    t = FlowTracker()
    f = t.observe(hdr(flags=SYN), T0)
    assert f.state == "NEW"
    f = t.observe(hdr(flags=ACK), T0 + 0.1)
    assert f.state == "ACTIVE"
    f = t.observe(hdr(flags=FIN | ACK), T0 + 0.2)
    assert f.state == "CLOSING"


def test_reset_state_is_recorded():
    t = FlowTracker()
    t.observe(hdr(flags=SYN), T0)
    f = t.observe(hdr(flags=RST), T0 + 0.1)
    assert f.state == "RESET"


# -------------------------------------------------------- capacity bound


def test_table_never_exceeds_the_hard_cap():
    """THE bounded-state guarantee under a spoofed flood."""
    t = FlowTracker(max_flows=100)
    for i in range(10_000):
        t.observe(hdr(src=f"10.10.{i // 256}.{i % 256}", sport=1024 + (i % 40000)), T0)
        assert len(t) <= 100, f"table grew past the cap at packet {i}"

    assert len(t) == 100
    assert t.stats.peak_active_flows == 100
    assert t.stats.flows_created == 10_000


def test_capacity_evictions_are_counted_not_silent():
    t = FlowTracker(max_flows=10)
    for i in range(50):
        t.observe(hdr(sport=1024 + i), T0)
    assert t.stats.flows_evicted_capacity == 40
    assert t.stats.flows_dropped == 40, "eviction is visibility loss and is reported"


def test_eviction_is_least_recently_seen():
    t = FlowTracker(max_flows=3)
    a = t.observe(hdr(sport=1), T0)
    b = t.observe(hdr(sport=2), T0 + 1)
    c = t.observe(hdr(sport=3), T0 + 2)
    # Touch `a` so `b` becomes the least recently seen.
    t.observe(hdr(sport=1), T0 + 3)
    d = t.observe(hdr(sport=4), T0 + 4)

    assert b.flow_id not in t, "least-recently-seen flow should have been evicted"
    assert a.flow_id in t and c.flow_id in t and d.flow_id in t
    assert len(t) == 3


def test_max_flows_must_be_positive():
    with pytest.raises(ValueError, match="at least 1"):
        FlowTracker(max_flows=0)


def test_a_single_slot_table_still_works():
    t = FlowTracker(max_flows=1)
    for i in range(20):
        t.observe(hdr(sport=1024 + i), T0)
    assert len(t) == 1
    assert t.stats.flows_evicted_capacity == 19


# ----------------------------------------------------------- idle expiry


def test_idle_flows_expire():
    t = FlowTracker(max_flows=100, idle_timeout=60.0)
    old = t.observe(hdr(sport=1), T0)
    assert old.flow_id in t

    # A later packet on a different flow triggers the sweep.
    t.observe(hdr(sport=2), T0 + 120.0)

    assert old.flow_id not in t
    assert t.stats.flows_expired_idle == 1


def test_active_flows_are_not_expired():
    t = FlowTracker(max_flows=100, idle_timeout=60.0)
    kept = t.observe(hdr(sport=1), T0)
    for step in range(1, 6):
        t.observe(hdr(sport=1), T0 + step * 30.0)  # refreshed within the timeout
    assert kept.flow_id in t
    assert t.stats.flows_expired_idle == 0


def test_absolute_lifetime_rotates_a_kept_alive_flow():
    """A flow held open forever must still rotate out."""
    t = FlowTracker(max_flows=100, idle_timeout=1_000.0, max_lifetime=100.0)
    flow = t.observe(hdr(sport=1), T0)
    # Keep it warm past its lifetime.
    for step in range(1, 40):
        t.observe(hdr(sport=1), T0 + step * 10.0)
    t.observe(hdr(sport=2), T0 + 500.0)
    assert flow.flow_id not in t
    assert t.stats.flows_expired_lifetime >= 1


def test_expire_all_idle_flushes_everything_due():
    t = FlowTracker(max_flows=1000, idle_timeout=10.0)
    for i in range(100):
        t.observe(hdr(sport=1024 + i), T0)
    assert len(t) == 100
    removed = t.expire_all_idle(T0 + 60.0)
    assert removed == 100
    assert len(t) == 0
    assert t.stats.flows_expired_idle == 100


def test_sweep_cost_is_bounded_per_packet():
    """A flood must not trigger an unbounded scan on a single packet."""
    t = FlowTracker(max_flows=10_000, idle_timeout=1.0)
    for i in range(500):
        t.observe(hdr(sport=1024 + i), T0)
    # Everything is now idle. One packet may only sweep a bounded slice.
    t.observe(hdr(sport=60000), T0 + 100.0)
    assert t.stats.flows_expired_idle <= 65, "sweep budget must cap per-packet work"


def test_expiry_and_eviction_are_accounted_separately():
    """Expiry is lifecycle; capacity eviction is loss. They differ."""
    t = FlowTracker(max_flows=5, idle_timeout=10.0)
    for i in range(20):
        t.observe(hdr(sport=1024 + i), T0)
    assert t.stats.flows_evicted_capacity == 15
    assert t.stats.flows_expired_idle == 0
    assert t.stats.flows_dropped == t.stats.flows_evicted_capacity


# ------------------------------------------------------------- accessors


def test_tracker_reports_active_and_peak():
    t = FlowTracker(max_flows=50)
    for i in range(30):
        t.observe(hdr(sport=1024 + i), T0)
    assert t.stats.active_flows == 30
    assert t.stats.peak_active_flows == 30
    t.clear()
    assert t.stats.active_flows == 0
    assert t.stats.peak_active_flows == 30, "peak is a high-water mark"


def test_default_bounds_exist():
    t = FlowTracker()
    assert t.max_flows == DEFAULT_MAX_FLOWS
    assert t.idle_timeout == DEFAULT_IDLE_TIMEOUT_S
    assert t.max_flows < 10**7, "the cap must be a real bound, not a formality"


def test_iteration_is_safe_against_mutation():
    t = FlowTracker(max_flows=10)
    for i in range(5):
        t.observe(hdr(sport=1024 + i), T0)
    seen = [f.flow_id for f in t]
    assert len(seen) == 5
