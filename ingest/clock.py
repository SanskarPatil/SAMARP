"""The unified replay clock.

V6.3 section 6.1 freezes the rebasing formula::

    t_display = t_replay_start + (t_packet - t_pcap_start) / replay_speed

``t_replay_start`` is captured **exactly once**, when replay begins, and is
written into the scenario manifest.

WHY THIS IS A CLASS AND NOT A FUNCTION
--------------------------------------
V6 wrote ``now`` in this formula. Implemented literally, ``now`` is
re-evaluated per packet, so wall-clock elapsed is added on top of
PCAP-relative elapsed and the displayed clock drifts at roughly 2x. That is
the dual-clock correlation failure.

Capturing the origin in immutable state at construction makes the failure
unrepresentable: there is no code path that can re-read the current time per
packet, because the clock never reads the current time again after
:meth:`start`.

Suricata and the fast header counter consume the SAME clock instance.
Running them against independently constructed clocks reintroduces the same
divergence one level up.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable


class ReplayClockError(RuntimeError):
    """Raised on misuse of the single-start contract."""


@dataclass(frozen=True, slots=True)
class ClockOrigin:
    """Immutable record of the one moment replay began.

    Written into the scenario manifest so a replay can be correlated after
    the fact.
    """

    replay_start: datetime
    pcap_start: float
    replay_speed: float


class ReplayClock:
    """Rebases PCAP timestamps onto display time. Start-once by contract."""

    __slots__ = ("_origin", "_speed", "_now")

    def __init__(
        self,
        *,
        replay_speed: float = 1.0,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if replay_speed <= 0:
            raise ValueError(f"replay_speed must be positive, got {replay_speed!r}")
        self._speed = float(replay_speed)
        # Injectable purely so tests can pin the origin; production always
        # uses the default. It is called AT MOST ONCE, in start().
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._origin: ClockOrigin | None = None

    # -- lifecycle --------------------------------------------------------

    def start(self, pcap_start: float) -> ClockOrigin:
        """Capture ``t_replay_start`` once and pin the PCAP origin.

        Raises if called twice. A second start would silently rebase the
        remainder of a replay onto a different origin, which is exactly the
        drift this class exists to prevent.
        """
        if self._origin is not None:
            raise ReplayClockError(
                "replay clock already started - t_replay_start is captured "
                "exactly once per replay"
            )
        self._origin = ClockOrigin(
            replay_start=self._now(),
            pcap_start=float(pcap_start),
            replay_speed=self._speed,
        )
        return self._origin

    @property
    def started(self) -> bool:
        return self._origin is not None

    @property
    def origin(self) -> ClockOrigin:
        if self._origin is None:
            raise ReplayClockError("replay clock not started")
        return self._origin

    @property
    def replay_speed(self) -> float:
        return self._speed

    # -- rebasing ---------------------------------------------------------

    def offset(self, packet_time: float) -> float:
        """Seconds of display time elapsed since replay start."""
        origin = self.origin
        return (float(packet_time) - origin.pcap_start) / origin.replay_speed

    def display_time(self, packet_time: float) -> datetime:
        """Rebase one PCAP timestamp onto display time.

        Pure arithmetic over the pinned origin - it never reads the current
        time, so calling it a million times produces no drift.
        """
        origin = self.origin
        return origin.replay_start + timedelta(seconds=self.offset(packet_time))

    def observed_time(self, packet_time: float) -> datetime:
        """The original capture timestamp, preserved separately.

        Old PCAP timestamps are never silently presented as current live
        time; both values travel on the normalized event.
        """
        return datetime.fromtimestamp(float(packet_time), tz=timezone.utc)

    # -- manifest ---------------------------------------------------------

    def manifest_entry(self) -> dict[str, object]:
        """Serialise the origin for the scenario manifest."""
        origin = self.origin
        return {
            "t_replay_start": origin.replay_start.astimezone(timezone.utc).isoformat(
                timespec="microseconds"
            ),
            "t_pcap_start": origin.pcap_start,
            "replay_speed": origin.replay_speed,
        }

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        state = "started" if self._origin else "not started"
        return f"<ReplayClock speed={self._speed} {state}>"


__all__ = ["ReplayClock", "ReplayClockError", "ClockOrigin"]
