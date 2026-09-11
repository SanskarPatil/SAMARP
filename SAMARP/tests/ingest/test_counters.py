"""Header-only counters and capture-loss accounting, end to end.

The rule under test (V6.3 section 14): loss is surfaced, never hidden, and
where only one estimator exists the figure is labelled a lower bound rather
than dressed up as precise.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from ingest.address_plan import AddressPlan
from ingest.capability import Capability
from ingest.counters import CaptureLossAccount, PacketCounter
from ingest.flow_tracker import FlowTracker
from ingest.headers import PacketHeaders
from ingest.replay import PcapReplay, replay_to_events

from pcap_builder import (  # noqa: E402  (tests/ingest is on sys.path via pytest)
    PROTO_TCP,
    SYN,
    PcapWriter,
    ethernet,
    ipv4,
    simple_capture,
    tcp,
)

REPO = Path(__file__).resolve().parents[2]
T0 = 1_757_500_000.0


def hdr(proto="TCP", flags=None, wire=54, ipv=4, frag=False, trunc=False):
    return PacketHeaders(
        ip_version=ipv,
        src_ip="10.10.0.5",
        dst_ip="93.184.216.34",
        protocol=proto,
        src_port=1234,
        dst_port=443,
        tcp_flags=flags,
        wire_bytes=wire,
        fragmented=frag,
        transport_truncated=trunc,
    )


@pytest.fixture(scope="module")
def validator():
    schema = json.loads(
        (REPO / "schemas" / "normalized_event.schema.json").read_text(encoding="utf-8")
    )
    return jsonschema.Draft202012Validator(schema)


@pytest.fixture(scope="module")
def plan():
    return AddressPlan.load()


# --------------------------------------------------------- packet counter


def test_counter_totals_packets_and_bytes():
    c = PacketCounter()
    for i in range(5):
        c.observe(hdr(wire=100), T0 + i, direction="outbound")
    assert c.packets == 5
    assert c.bytes == 500
    assert c.duration == pytest.approx(4.0)


def test_counter_breaks_down_by_closed_vocabularies_only():
    """Breakdowns must never be keyed by attacker-controlled values."""
    c = PacketCounter()
    c.observe(hdr(proto="TCP"), T0, direction="outbound")
    c.observe(hdr(proto="UDP"), T0, direction="inbound")
    c.observe(hdr(proto="TCP", ipv=6), T0, direction="external")

    assert dict(c.by_protocol) == {"TCP": 2, "UDP": 1}
    assert dict(c.by_direction) == {"outbound": 1, "inbound": 1, "external": 1}
    assert dict(c.by_ip_version) == {4: 2, 6: 1}


def test_unknown_direction_is_not_silently_bucketed():
    c = PacketCounter()
    c.observe(hdr(), T0, direction=None)
    assert c.packets == 1
    assert dict(c.by_direction) == {}, "unknown must stay unknown, not become a guess"


def test_tcp_flag_counters():
    c = PacketCounter()
    c.observe(hdr(flags=0x02), T0)  # SYN
    c.observe(hdr(flags=0x12), T0)  # SYN-ACK
    c.observe(hdr(flags=0x01), T0)  # FIN
    c.observe(hdr(flags=0x04), T0)  # RST
    assert (c.tcp_syn, c.tcp_syn_ack, c.tcp_fin, c.tcp_rst) == (1, 1, 1, 1)


def test_fragment_and_truncation_counters():
    c = PacketCounter()
    c.observe(hdr(frag=True), T0)
    c.observe(hdr(trunc=True), T0)
    assert c.fragmented == 1
    assert c.transport_truncated == 1


def test_rate_derivations():
    c = PacketCounter()
    for i in range(10):
        c.observe(hdr(wire=125), T0 + i)  # 1000 bits each
    assert c.duration == pytest.approx(9.0)
    assert c.packets_per_second == pytest.approx(10 / 9)
    assert c.bits_per_second == pytest.approx(10000 / 9)


def test_rates_are_zero_for_a_single_instant():
    c = PacketCounter()
    c.observe(hdr(), T0)
    assert c.packets_per_second == 0.0  # no elapsed time to divide by


# --------------------------------------------------------- capture loss


def test_loss_is_measured_not_assumed_zero():
    a = CaptureLossAccount()
    for _ in range(9):
        a.observe_packet(parsed=True)
    a.observe_packet(parsed=False)
    assert a.observed_loss_pct == pytest.approx(10.0)


def test_kernel_and_ring_drops_are_null_on_the_pcap_path():
    """There is no sensor here, so these are NOT_OBSERVABLE - not zero."""
    a = CaptureLossAccount()
    a.observe_packet(parsed=True)
    block = a.to_sensor_loss()
    assert block["kernel_drops"] is None
    assert block["ring_drops"] is None
    assert block["kernel_drops"] != 0, "null and zero mean different things"


def test_missing_sensor_counters_force_the_lower_bound_flag():
    a = CaptureLossAccount()
    a.observe_packet(parsed=True)
    assert a.is_lower_bound is True
    assert a.to_sensor_loss()["is_lower_bound"] is True


def test_supplying_sensor_counters_clears_the_lower_bound_flag():
    a = CaptureLossAccount(kernel_drops=12)
    a.observe_packet(parsed=True)
    assert a.has_sensor_counters is True
    assert a.is_lower_bound is False


def test_malformed_records_count_toward_loss():
    a = CaptureLossAccount()
    for _ in range(10):
        a.observe_packet(parsed=True)
    a.records_malformed = 5
    assert a.observed_loss_pct == pytest.approx(50.0)


def test_truncation_is_tracked_separately_from_loss():
    """A snapped packet is still observed - truncation is not a drop."""
    a = CaptureLossAccount()
    a.observe_packet(parsed=True, truncated=True)
    a.observe_packet(parsed=True)
    assert a.observed_loss_pct == 0.0
    assert a.truncated_pct == pytest.approx(50.0)


def test_estimator_name_travels_with_the_number():
    a = CaptureLossAccount()
    a.observe_packet(parsed=True)
    assert a.to_sensor_loss()["estimator"] == "pcap_parse_and_snaplen"


def test_empty_input_reports_zero_without_dividing_by_zero():
    a = CaptureLossAccount()
    assert a.observed_loss_pct == 0.0
    assert a.truncated_pct == 0.0


# ------------------------------------------------------- integrated path


def test_replayed_events_carry_flow_summary_and_validate(tmp_path, validator, plan):
    cap = simple_capture(tmp_path / "c.pcap")
    events, _ = replay_to_events(cap, address_plan=plan)
    assert events
    for ev in events:
        ev.validate()
        validator.validate(ev.to_dict())
        assert ev.flow_summary is not None
        assert ev.flow_summary["flow_id"] == ev.flow_id


def test_replayed_events_carry_sensor_loss(tmp_path, validator, plan):
    cap = simple_capture(tmp_path / "c.pcap")
    events, _ = replay_to_events(cap, address_plan=plan)
    block = events[-1].to_dict()["sensor_loss"]
    assert block["kernel_drops"] is None
    assert block["is_lower_bound"] is True
    assert block["sensor_drop_pct"] >= 0.0


def test_flow_summary_accumulates_across_the_replay(tmp_path, plan):
    cap = simple_capture(tmp_path / "c.pcap")
    events, _ = replay_to_events(cap, address_plan=plan)
    # Packets 0 and 1 are the two directions of one conversation.
    assert events[0].flow_id == events[1].flow_id
    assert events[0].flow_summary["packets"] == 1
    assert events[1].flow_summary["packets"] == 2
    assert events[1].flow_summary["fwd_packets"] == 1
    assert events[1].flow_summary["rev_packets"] == 1


def test_replay_exposes_counter_tracker_and_loss(tmp_path, plan):
    cap = simple_capture(tmp_path / "c.pcap")
    r = PcapReplay(cap, address_plan=plan)
    list(r.run())

    assert r.counter.packets == 5  # 6 read, ARP unparseable
    assert r.counter.bytes > 0
    assert r.flows.stats.flows_created == 4  # two directions share one flow
    assert r.loss.packets_read == 6
    assert r.loss.observed_loss_pct == pytest.approx(100 / 6)
    assert r.capability.get("capture_loss") is Capability.DEGRADED


def test_manifest_includes_counters_flows_and_loss(tmp_path, plan):
    cap = simple_capture(tmp_path / "c.pcap")
    r = PcapReplay(cap, address_plan=plan)
    list(r.run())
    m = r.manifest()
    assert "counters" in m and "flows" in m and "capture_loss" in m
    assert m["capture_loss"]["is_lower_bound"] is True
    assert m["flows"]["peak_active_flows"] >= 1


def test_bounded_tracker_holds_under_a_flood_through_replay(tmp_path, plan):
    """Integrated bounded-state proof: many flows, capped table."""
    w = PcapWriter()
    for i in range(2000):
        w.add(
            ethernet(
                ipv4(
                    f"10.10.{i // 256}.{i % 256}",
                    "93.184.216.34",
                    PROTO_TCP,
                    tcp(1024 + (i % 40000), 80, SYN),
                )
            ),
            T0 + i * 0.001,
        )
    cap = w.write(tmp_path / "flood.pcap")

    r = PcapReplay(cap, address_plan=plan, flow_tracker=FlowTracker(max_flows=64))
    events = list(r.run())

    assert len(events) == 2000
    assert len(r.flows) <= 64, "flow table must stay bounded under flood"
    assert r.flows.stats.flows_evicted_capacity > 0
    assert r.loss.flows_evicted == r.flows.stats.flows_evicted_capacity
