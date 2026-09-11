"""PCAP replay: determinism, the single clock, counters and loss.

Replay feeds the SAME normalizer every other input mode uses. These tests
assert that, and that the same capture yields byte-identical events on every
run.
"""

from __future__ import annotations

import json
import struct
from datetime import timedelta
from pathlib import Path

import jsonschema
import pytest

from ingest.address_plan import AddressPlan
from ingest.capability import Capability, InputMode
from ingest.clock import ReplayClock
from ingest.pcap import PcapError
from ingest.replay import PcapReplay, replay_to_events

from pcap_builder import (  # noqa: E402  (tests/ingest is on sys.path via pytest)
    CAPTURE_BASE_TS,
    PROTO_TCP,
    SIMPLE_CAPTURE_PACKETS,
    SIMPLE_CAPTURE_PARSEABLE,
    SIMPLE_CAPTURE_TRUNCATED,
    SYN,
    PcapWriter,
    ethernet,
    ipv4,
    simple_capture,
    tcp,
)

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def validator() -> jsonschema.Draft202012Validator:
    schema = json.loads(
        (REPO / "schemas" / "normalized_event.schema.json").read_text(encoding="utf-8")
    )
    return jsonschema.Draft202012Validator(schema)


@pytest.fixture(scope="module")
def plan() -> AddressPlan:
    return AddressPlan.load()


@pytest.fixture
def capture(tmp_path) -> Path:
    return simple_capture(tmp_path / "canonical.pcap")


# ------------------------------------------------- contract conformance


def test_every_replayed_event_validates_against_the_frozen_schema(
    capture, validator, plan
):
    events, _ = replay_to_events(capture, address_plan=plan)
    assert events, "replay produced no events"
    for ev in events:
        ev.validate()
        validator.validate(ev.to_dict())


def test_replay_uses_the_shared_normalizer_not_a_second_one(capture, plan):
    """Events must be NormalizedEvent instances with pcap_replay input mode."""
    from ingest.normalized_event import NormalizedEvent

    events, _ = replay_to_events(capture, address_plan=plan)
    for ev in events:
        assert isinstance(ev, NormalizedEvent)
        assert str(InputMode(ev.input_mode)) == "pcap_replay"


def test_flow_id_is_present_and_never_null(capture, plan):
    events, _ = replay_to_events(capture, address_plan=plan)
    for ev in events:
        assert ev.flow_id
        assert len(ev.flow_id) == 16
        assert ev.flow_ref_type == "flow_5tuple"


def test_direction_is_populated_from_the_address_plan(capture, plan):
    events, _ = replay_to_events(capture, address_plan=plan)
    directions = [ev.direction for ev in events]
    assert "outbound" in directions
    assert "inbound" in directions
    assert "internal" in directions  # enclave -> enclave resolver
    assert "external" in directions  # the IPv6 pair


def test_both_directions_of_one_conversation_share_a_flow_id(capture, plan):
    events, _ = replay_to_events(capture, address_plan=plan)
    outbound = next(e for e in events if e.direction == "outbound" and e.dst_port == 443)
    inbound = next(e for e in events if e.direction == "inbound")
    assert outbound.flow_id == inbound.flow_id
    # Direction is still recorded separately - no information is lost.
    assert outbound.direction != inbound.direction


# -------------------------------------------------------- determinism


def test_replaying_twice_yields_identical_events(capture, plan):
    first, _ = replay_to_events(capture, address_plan=plan)
    second, _ = replay_to_events(capture, address_plan=plan)

    a = [e.to_dict() for e in first]
    b = [e.to_dict() for e in second]

    # display_time depends on t_replay_start, which differs between runs by
    # design. Everything else must be byte-identical.
    for d in a + b:
        d.pop("display_time", None)

    assert a == b


def test_event_order_matches_capture_order(capture, plan):
    events, _ = replay_to_events(capture, address_plan=plan)
    times = [ev.observed_time for ev in events]
    assert times == sorted(times)


def test_flow_ids_are_stable_across_runs(capture, plan):
    first, _ = replay_to_events(capture, address_plan=plan)
    second, _ = replay_to_events(capture, address_plan=plan)
    assert [e.flow_id for e in first] == [e.flow_id for e in second]


def test_replay_speed_does_not_change_event_content(capture, plan):
    slow, _ = replay_to_events(capture, address_plan=plan, replay_speed=1.0)
    fast, _ = replay_to_events(capture, address_plan=plan, replay_speed=100.0)

    def strip(events):
        out = []
        for e in events:
            d = e.to_dict()
            d.pop("display_time", None)
            out.append(d)
        return out

    assert strip(slow) == strip(fast)


# ----------------------------------------------------- the single clock


def test_replay_starts_the_clock_exactly_once(capture, plan):
    replay = PcapReplay(capture, address_plan=plan)
    assert replay.clock.started is False
    list(replay.run())
    assert replay.clock.started is True
    assert replay.clock.origin.pcap_start == pytest.approx(CAPTURE_BASE_TS)


def test_display_times_preserve_capture_spacing(capture, plan):
    """The dual-clock guard, end to end.

    At speed 1.0 the gap between two display times must equal the gap between
    the corresponding capture timestamps - exactly, for every pair. A
    per-packet `now` would add wall-clock elapsed on top and roughly double
    the spacing.

    Compared against observed_time rather than a fixed 1 s: the canonical
    fixture contains an ARP frame that yields no event, so consecutive events
    are legitimately 2 s apart there. The invariant is that display spacing
    MIRRORS capture spacing, not that it is constant.
    """
    replay = PcapReplay(capture, address_plan=plan)
    events = list(replay.run())
    timed = [e for e in events if e.display_time is not None]
    assert len(timed) >= 2

    for a, b in zip(timed, timed[1:]):
        capture_gap = b.observed_time - a.observed_time
        display_gap = b.display_time - a.display_time
        assert display_gap == capture_gap, (
            f"clock drift: capture gap {capture_gap} became {display_gap}"
        )

    # And the total span is preserved, not inflated.
    assert (timed[-1].display_time - timed[0].display_time) == (
        timed[-1].observed_time - timed[0].observed_time
    )


def test_display_time_is_scaled_by_replay_speed(capture, plan):
    replay = PcapReplay(capture, address_plan=plan, replay_speed=2.0)
    events = list(replay.run())
    delta = events[1].display_time - events[0].display_time
    assert delta == timedelta(seconds=0.5)


def test_observed_time_is_the_original_capture_time(capture, plan):
    events, _ = replay_to_events(capture, address_plan=plan)
    assert events[0].observed_time.timestamp() == pytest.approx(CAPTURE_BASE_TS)


def test_an_injected_clock_is_shared_not_replaced(capture, plan):
    clock = ReplayClock(replay_speed=4.0)
    replay = PcapReplay(capture, address_plan=plan, clock=clock)
    list(replay.run())
    assert replay.clock is clock
    assert clock.origin.replay_speed == 4.0


# ---------------------------------------------------------- counters


def test_counters_account_for_every_packet(capture, plan):
    _, stats = replay_to_events(capture, address_plan=plan)
    assert stats.packets_read == SIMPLE_CAPTURE_PACKETS
    assert stats.packets_parsed == SIMPLE_CAPTURE_PARSEABLE
    assert stats.packets_unparseable == 1  # the ARP frame
    assert stats.events_emitted == stats.packets_parsed
    assert stats.packets_read == stats.packets_parsed + stats.packets_unparseable


def test_unparseable_reasons_are_recorded_not_swallowed(capture, plan):
    _, stats = replay_to_events(capture, address_plan=plan)
    assert stats.unparseable_reasons, "reasons must be attributed, not discarded"
    assert any("ethertype" in r for r in stats.unparseable_reasons)


def test_parse_loss_is_measured_not_assumed_zero(capture, plan):
    _, stats = replay_to_events(capture, address_plan=plan)
    assert stats.parse_loss_pct > 0.0
    assert stats.parse_loss_pct == pytest.approx(100.0 / SIMPLE_CAPTURE_PACKETS)


def test_truncated_packets_are_counted(capture, plan):
    _, stats = replay_to_events(capture, address_plan=plan)
    assert stats.packets_truncated == SIMPLE_CAPTURE_TRUNCATED


def test_snapped_capture_degrades_the_capture_loss_capability(capture, plan):
    """Loss is surfaced on the capability state, not hidden."""
    replay = PcapReplay(capture, address_plan=plan)
    list(replay.run())
    assert replay.capability.get("capture_loss") is Capability.DEGRADED


def test_byte_counters_track_wire_length(capture, plan):
    events, stats = replay_to_events(capture, address_plan=plan)
    assert stats.wire_bytes > stats.captured_bytes  # one snapped packet
    for ev in events:
        assert ev.packets == 1
        assert ev.bytes is not None and ev.bytes > 0


def test_capture_duration_is_derived_from_timestamps(capture, plan):
    _, stats = replay_to_events(capture, address_plan=plan)
    assert stats.capture_duration == pytest.approx(5.0)


# ------------------------------------------------------------ manifest


def test_manifest_records_replay_provenance(capture, plan):
    replay = PcapReplay(capture, address_plan=plan, replay_speed=2.0)
    list(replay.run())
    m = replay.manifest()
    assert m["input_mode"] == "pcap_replay"
    assert m["replay_speed"] == 2.0
    assert m["t_pcap_start"] == pytest.approx(CAPTURE_BASE_TS)
    assert "t_replay_start" in m
    assert m["stats"]["packets_read"] == SIMPLE_CAPTURE_PACKETS


# ------------------------------------------------------- error handling


def test_empty_capture_completes_gracefully(tmp_path, plan):
    p = PcapWriter().write(tmp_path / "empty.pcap")
    events, stats = replay_to_events(p, address_plan=plan)
    assert events == []
    assert stats.packets_read == 0


def test_unsupported_linktype_is_refused_with_a_clear_message(tmp_path, plan):
    pkt = ethernet(ipv4("10.10.0.5", "93.184.216.34", PROTO_TCP, tcp(1, 2, SYN)))
    p = PcapWriter(linktype=999).add(pkt, CAPTURE_BASE_TS).write(tmp_path / "lt.pcap")
    with pytest.raises(PcapError, match="unsupported linktype"):
        list(PcapReplay(p, address_plan=plan).run())


def test_malformed_records_do_not_abort_the_replay(tmp_path, plan):
    pkt = ethernet(ipv4("10.10.0.5", "93.184.216.34", PROTO_TCP, tcp(1, 2, SYN)))
    w = PcapWriter()
    w.add(pkt, CAPTURE_BASE_TS)
    w.add_raw_record(struct.pack("<IIII", 1, 0, 9999, 9999) + b"\x00" * 4)
    p = w.write(tmp_path / "bad.pcap")

    events, stats = replay_to_events(p, address_plan=plan)
    assert len(events) == 1, "the good packet before the bad record must survive"
    assert stats.records_malformed == 1


def test_replay_without_an_address_plan_leaves_direction_unset(capture):
    events, _ = replay_to_events(capture)
    assert all(ev.direction is None for ev in events)


# ------------------------------------------------------- passive boundary


def test_replay_module_has_no_network_surface():
    """Replay observes a recording; it never transmits."""
    import inspect

    import ingest.replay as mod

    source = inspect.getsource(mod)
    for banned in ("socket.", "urllib", "requests.", ".connect(", ".sendto(", ".bind("):
        assert banned not in source, banned
