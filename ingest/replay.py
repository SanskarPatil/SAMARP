"""Deterministic PCAP replay driver.

Reads a classic pcap capture, decodes headers only, and emits normalized
events through the SAME normalizer every other input mode uses. There is no
second normalization implementation: a PCAP-specific one would let the replay
path drift from the live path, and replay is the demo path.

PASSIVE BY CONSTRUCTION
-----------------------
This module opens a file and yields objects. It has no socket, no outbound
call, and no way to reach an observed host. Replay observes a recording; it
never transmits.

DETERMINISM
-----------
The same capture produces the same events in the same order, every run. The
only wall-clock read in the whole path is ``t_replay_start``, captured once
by :class:`~ingest.clock.ReplayClock`. Real-time pacing is opt-in and affects
only *when* an event is yielded, never its content or order.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator

from .address_plan import AddressPlan
from .capability import Capability, CapabilityState, InputMode
from .clock import ReplayClock
from .headers import HeaderParseError, parse_packet
from .normalized_event import NormalizedEvent
from .pcap import PcapError, PcapReader, peek_first_timestamp


@dataclass(slots=True)
class ReplayStats:
    """Counters for one replay run.

    Loss is surfaced, never hidden. ``packets_unparseable`` counts packets the
    header decoder could not read (ARP, malformed, truncated-before-IP); they
    are reported, not silently dropped.
    """

    packets_read: int = 0
    packets_parsed: int = 0
    packets_unparseable: int = 0
    packets_truncated: int = 0
    records_malformed: int = 0
    events_emitted: int = 0
    captured_bytes: int = 0
    wire_bytes: int = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    wall_seconds: float = 0.0
    unparseable_reasons: dict[str, int] = field(default_factory=dict)

    @property
    def capture_duration(self) -> float:
        if self.first_timestamp is None or self.last_timestamp is None:
            return 0.0
        return self.last_timestamp - self.first_timestamp

    @property
    def parse_loss_pct(self) -> float:
        """Share of read packets that produced no event.

        A measured lower bound on visibility loss for this input mode. It is
        never reported as zero merely because no exception was raised.
        """
        if self.packets_read == 0:
            return 0.0
        return 100.0 * self.packets_unparseable / self.packets_read

    @property
    def events_per_second(self) -> float:
        if self.wall_seconds <= 0:
            return 0.0
        return self.events_emitted / self.wall_seconds

    def as_dict(self) -> dict[str, object]:
        return {
            "packets_read": self.packets_read,
            "packets_parsed": self.packets_parsed,
            "packets_unparseable": self.packets_unparseable,
            "packets_truncated": self.packets_truncated,
            "records_malformed": self.records_malformed,
            "events_emitted": self.events_emitted,
            "captured_bytes": self.captured_bytes,
            "wire_bytes": self.wire_bytes,
            "capture_duration_s": round(self.capture_duration, 6),
            "parse_loss_pct": round(self.parse_loss_pct, 4),
            "wall_seconds": round(self.wall_seconds, 6),
            "events_per_second": round(self.events_per_second, 2),
            "unparseable_reasons": dict(self.unparseable_reasons),
        }


class PcapReplay:
    """Replay one capture file into normalized events.

    ``realtime=False`` (the default) replays as fast as possible and is fully
    deterministic - used by tests, evaluation and throughput measurement.
    ``realtime=True`` paces to the rebased clock for the live demo.
    """

    __slots__ = (
        "_path",
        "_clock",
        "_plan",
        "_capability",
        "_realtime",
        "_sleep",
        "_monotonic",
        "stats",
    )

    def __init__(
        self,
        path: str | Path,
        *,
        replay_speed: float = 1.0,
        address_plan: AddressPlan | None = None,
        capability: CapabilityState | None = None,
        clock: ReplayClock | None = None,
        realtime: bool = False,
        sleep: Callable[[float], None] | None = None,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        self._path = Path(path)
        # ONE clock for the whole replay. Every consumer shares this instance;
        # constructing a second one reintroduces the dual-clock divergence.
        self._clock = clock or ReplayClock(replay_speed=replay_speed)
        self._plan = address_plan
        self._capability = capability or CapabilityState(InputMode.PCAP_REPLAY)
        self._realtime = realtime
        self._sleep = sleep or time.sleep
        self._monotonic = monotonic or time.monotonic
        self.stats = ReplayStats()

    @property
    def clock(self) -> ReplayClock:
        return self._clock

    @property
    def capability(self) -> CapabilityState:
        return self._capability

    # -- replay -----------------------------------------------------------

    def run(self) -> Iterator[NormalizedEvent]:
        """Yield normalized events for every parseable packet.

        Raises :class:`~ingest.pcap.PcapError` only for a file that cannot be
        opened or whose header is not classic pcap. Individual bad packets are
        counted and skipped.
        """
        pcap_start = peek_first_timestamp(self._path)
        if pcap_start is None:
            # A valid but empty capture. Start the clock so the manifest is
            # still complete, and finish cleanly.
            self._clock.start(0.0)
            return

        self._clock.start(pcap_start)
        capture_source = self._path.name
        wall_start = self._monotonic()

        with PcapReader(self._path) as reader:
            linktype = reader.linktype
            if not reader.header.linktype_supported:
                raise PcapError(
                    f"unsupported linktype {linktype} in {self._path}. "
                    "Supported: Ethernet(1), Null(0), Raw(101), "
                    "LinuxSLL(113), IPv4(228), IPv6(229)."
                )

            snaplen_seen = False

            for record in reader:
                self.stats.packets_read += 1
                self.stats.captured_bytes += record.caplen
                self.stats.wire_bytes += record.wirelen
                if self.stats.first_timestamp is None:
                    self.stats.first_timestamp = record.timestamp
                self.stats.last_timestamp = record.timestamp

                if record.truncated:
                    self.stats.packets_truncated += 1
                    snaplen_seen = True

                if self._realtime:
                    self._pace(record.timestamp, wall_start)

                try:
                    hdr = parse_packet(record.data, linktype, wire_bytes=record.wirelen)
                except HeaderParseError as exc:
                    self.stats.packets_unparseable += 1
                    reason = str(exc).split("(")[0].strip()
                    self.stats.unparseable_reasons[reason] = (
                        self.stats.unparseable_reasons.get(reason, 0) + 1
                    )
                    continue

                self.stats.packets_parsed += 1

                event = NormalizedEvent.from_flow(
                    observed_time=self._clock.observed_time(record.timestamp),
                    input_mode=InputMode.PCAP_REPLAY,
                    capability=self._capability,
                    src_ip=hdr.src_ip,
                    dst_ip=hdr.dst_ip,
                    src_port=hdr.src_port,
                    dst_port=hdr.dst_port,
                    protocol=hdr.protocol,
                    address_plan=self._plan,
                    display_time=self._clock.display_time(record.timestamp),
                    ip_version=hdr.ip_version,
                    tcp_flags=hdr.tcp_flags,
                    packets=1,
                    bytes=record.wirelen,
                    capture_source=capture_source,
                )
                self.stats.events_emitted += 1
                yield event

            self.stats.records_malformed = reader.stats.records_malformed

        self.stats.wall_seconds = self._monotonic() - wall_start

        # Capture loss is evidence. A snapped capture gives PARTIAL loss
        # visibility: truncation is observable from caplen vs wirelen, but
        # kernel/ring drop counters are not - those come from the sensor.
        # DEGRADED is the honest state; reporting OBSERVABLE would claim a
        # precision we do not have, and leaving it NOT_OBSERVABLE would hide
        # evidence we do have.
        if snaplen_seen:
            self._capability.set("capture_loss", Capability.DEGRADED)

    def _pace(self, packet_time: float, wall_start: float) -> None:
        """Sleep so emission tracks the rebased clock. Demo path only."""
        target = self._clock.offset(packet_time)
        elapsed = self._monotonic() - wall_start
        delay = target - elapsed
        if delay > 0:
            self._sleep(delay)

    # -- reporting --------------------------------------------------------

    def manifest(self) -> dict[str, object]:
        """Replay provenance for the scenario manifest."""
        entry: dict[str, object] = {
            "capture": str(self._path),
            "input_mode": str(InputMode.PCAP_REPLAY),
            "realtime": self._realtime,
        }
        if self._clock.started:
            entry.update(self._clock.manifest_entry())
        entry["stats"] = self.stats.as_dict()
        return entry

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"<PcapReplay {self._path.name!r} speed={self._clock.replay_speed} "
            f"realtime={self._realtime}>"
        )


def replay_to_events(
    path: str | Path,
    *,
    address_plan: AddressPlan | None = None,
    replay_speed: float = 1.0,
) -> tuple[list[NormalizedEvent], ReplayStats]:
    """Convenience: replay a capture and collect every event.

    Deterministic - no pacing, no wall-clock dependence beyond the single
    pinned ``t_replay_start``.
    """
    replay = PcapReplay(path, replay_speed=replay_speed, address_plan=address_plan)
    events = list(replay.run())
    return events, replay.stats


__all__ = ["PcapReplay", "ReplayStats", "replay_to_events", "Capability"]
