"""The unified replay clock.

Pins the frozen V6.3 section 6.1 formula and the start-once contract::

    t_display = t_replay_start + (t_packet - t_pcap_start) / replay_speed

The dual-clock failure these tests exist to prevent: V6 wrote ``now`` in this
formula. Re-evaluated per packet, wall-clock elapsed is added on top of
PCAP-relative elapsed and the displayed clock drifts at roughly 2x.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ingest.clock import ClockOrigin, ReplayClock, ReplayClockError

T_START = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
PCAP_START = 1_757_500_000.0


def _clock(speed: float = 1.0, *, ticking: bool = False) -> ReplayClock:
    """A clock with a pinned origin.

    ``ticking=True`` returns a *different* time on every call, which is what
    a naive per-packet ``now`` would do. Used to prove the clock reads the
    current time at most once.
    """
    if ticking:
        state = {"n": 0}

        def now() -> datetime:
            state["n"] += 1
            return T_START + timedelta(seconds=state["n"])

        return ReplayClock(replay_speed=speed, now=now)
    return ReplayClock(replay_speed=speed, now=lambda: T_START)


# ------------------------------------------------------------ start-once


def test_start_captures_the_origin_once():
    c = _clock()
    origin = c.start(PCAP_START)
    assert isinstance(origin, ClockOrigin)
    assert origin.replay_start == T_START
    assert origin.pcap_start == PCAP_START
    assert c.started is True


def test_starting_twice_is_refused():
    c = _clock()
    c.start(PCAP_START)
    with pytest.raises(ReplayClockError, match="exactly once"):
        c.start(PCAP_START + 10)


def test_using_an_unstarted_clock_is_refused():
    c = _clock()
    assert c.started is False
    with pytest.raises(ReplayClockError, match="not started"):
        c.display_time(PCAP_START)


def test_origin_is_immutable():
    c = _clock()
    origin = c.start(PCAP_START)
    with pytest.raises((AttributeError, TypeError)):
        origin.replay_start = T_START + timedelta(hours=1)  # type: ignore[misc]


def test_the_clock_reads_wall_time_at_most_once():
    """THE dual-clock guard.

    With a `now` that advances on every call, a per-packet re-read would make
    successive display times drift. Because start() is the only caller, the
    spacing depends solely on packet timestamps.
    """
    c = _clock(ticking=True)
    c.start(PCAP_START)
    first = c.display_time(PCAP_START)
    second = c.display_time(PCAP_START + 1.0)
    third = c.display_time(PCAP_START + 2.0)

    assert (second - first) == timedelta(seconds=1)
    assert (third - second) == timedelta(seconds=1)
    # And repeated calls for the same packet are identical - no drift.
    assert c.display_time(PCAP_START) == first


# -------------------------------------------------------------- rebasing


def test_first_packet_maps_to_replay_start():
    c = _clock()
    c.start(PCAP_START)
    assert c.display_time(PCAP_START) == T_START


def test_offsets_follow_the_frozen_formula():
    c = _clock()
    c.start(PCAP_START)
    for delta in (0.0, 0.5, 1.0, 42.25):
        expected = T_START + timedelta(seconds=delta)
        assert c.display_time(PCAP_START + delta) == expected


@pytest.mark.parametrize(
    "speed,delta,expected",
    [
        (1.0, 10.0, 10.0),
        (2.0, 10.0, 5.0),  # twice as fast: half the display elapsed
        (0.5, 10.0, 20.0),  # half speed: twice the display elapsed
        (10.0, 60.0, 6.0),
    ],
)
def test_replay_speed_scales_display_time(speed, delta, expected):
    c = _clock(speed)
    c.start(PCAP_START)
    assert c.offset(PCAP_START + delta) == pytest.approx(expected)
    assert c.display_time(PCAP_START + delta) == T_START + timedelta(seconds=expected)


def test_speed_must_be_positive():
    for bad in (0, -1, -0.5):
        with pytest.raises(ValueError, match="must be positive"):
            ReplayClock(replay_speed=bad)


def test_packets_before_the_origin_produce_negative_offsets():
    # Out-of-order captures are represented honestly rather than clamped.
    c = _clock()
    c.start(PCAP_START)
    assert c.offset(PCAP_START - 5.0) == pytest.approx(-5.0)


# ------------------------------------------------------- observed vs display


def test_observed_time_preserves_the_original_capture_timestamp():
    c = _clock()
    c.start(PCAP_START)
    observed = c.observed_time(PCAP_START)
    assert observed == datetime.fromtimestamp(PCAP_START, tz=timezone.utc)
    # An old capture timestamp is never presented as current live time.
    assert observed != c.display_time(PCAP_START)


def test_observed_time_is_utc():
    c = _clock()
    c.start(PCAP_START)
    assert c.observed_time(PCAP_START).tzinfo is timezone.utc


# -------------------------------------------------------------- manifest


def test_manifest_entry_records_the_origin():
    c = _clock(2.0)
    c.start(PCAP_START)
    entry = c.manifest_entry()
    assert entry["t_pcap_start"] == PCAP_START
    assert entry["replay_speed"] == 2.0
    assert entry["t_replay_start"].startswith("2026-09-10T12:00:00")


def test_manifest_requires_a_started_clock():
    with pytest.raises(ReplayClockError):
        _clock().manifest_entry()
