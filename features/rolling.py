"""Tumbling windows with watermark and bounded memory state.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md section 6.5, 11, 24.
Latency budget: 300 ms watermark, 1.0 s tumbling window, p95 < 2.0 s SLO.

Invariants:
- Windows close ONLY when the watermark advances past the window end.
- The 300 ms watermark is never shrunk (preserving late-arrival tolerance).
- State is bounded: hard cap on open windows and events per window.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence

from ingest.normalized_event import NormalizedEvent

from .entropy import StreamingEntropy

DEFAULT_WINDOW_DURATION_S = 1.0
DEFAULT_WATERMARK_DELAY_S = 0.3  # 300 ms
DEFAULT_MAX_OPEN_WINDOWS = 16
DEFAULT_MAX_EVENTS_PER_WINDOW = 10000
DEFAULT_MAX_TRACKED_ENTITIES = 1024


def _to_posix(ts: datetime | float | int) -> float:
    """Convert a timestamp to POSIX epoch seconds (float)."""
    if isinstance(ts, (int, float)):
        return float(ts)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.timestamp()


@dataclass(slots=True)
class WindowSummary:
    """Aggregated traffic observation over a closed time window."""

    start_time: float
    end_time: float
    duration_s: float
    event_count: int = 0
    packet_count: int = 0
    byte_count: int = 0

    tcp_flags: dict[str, int] = field(default_factory=dict)
    protocols: dict[str, int] = field(default_factory=dict)
    directions: dict[str, int] = field(default_factory=dict)

    src_entropy: float = 0.0
    dst_entropy: float = 0.0
    unique_src_count: int = 0
    unique_dst_count: int = 0
    unique_dst_ports_count: int = 0

    # Bounded samples for evidence drawer
    contributing_flow_ids: list[str] = field(default_factory=list)
    sample_events: list[NormalizedEvent] = field(default_factory=list)
    dns_queries: list[dict[str, Any]] = field(default_factory=list)
    tls_records: list[dict[str, Any]] = field(default_factory=list)
    flow_summaries: list[dict[str, Any]] = field(default_factory=list)

    # Top talkers / targets in this window (bounded)
    src_ip_counts: dict[str, int] = field(default_factory=dict)
    dst_ip_counts: dict[str, int] = field(default_factory=dict)
    dst_port_counts: dict[int, int] = field(default_factory=dict)

    # Latest capability context seen in this window
    latest_capability: Any = None
    latest_input_mode: str = "pcap_replay"

    @property
    def pps(self) -> float:
        """Packet rate over the window duration."""
        return self.packet_count / self.duration_s if self.duration_s > 0 else 0.0

    @property
    def bps(self) -> float:
        """Byte rate over the window duration."""
        return (self.byte_count * 8.0) / self.duration_s if self.duration_s > 0 else 0.0

    @property
    def syn_count(self) -> int:
        return self.tcp_flags.get("S", 0) + self.tcp_flags.get("SYN", 0)

    @property
    def ack_count(self) -> int:
        return self.tcp_flags.get("A", 0) + self.tcp_flags.get("ACK", 0)

    @property
    def rst_count(self) -> int:
        return self.tcp_flags.get("R", 0) + self.tcp_flags.get("RST", 0)

    @property
    def syn_ack_ratio(self) -> float:
        syns = self.syn_count
        acks = self.ack_count
        return (syns / acks) if acks > 0 else float(syns)


class _OpenWindow:
    """Internal accumulator for an in-flight open window."""

    __slots__ = (
        "start_time",
        "end_time",
        "duration_s",
        "event_count",
        "packet_count",
        "byte_count",
        "tcp_flags",
        "protocols",
        "directions",
        "_src_entropy",
        "_dst_entropy",
        "_dst_ports",
        "contributing_flow_ids",
        "sample_events",
        "dns_queries",
        "tls_records",
        "flow_summaries",
        "latest_capability",
        "latest_input_mode",
        "_max_events",
        "_max_entities",
    )

    def __init__(
        self,
        start_time: float,
        duration_s: float,
        max_events: int = DEFAULT_MAX_EVENTS_PER_WINDOW,
        max_entities: int = DEFAULT_MAX_TRACKED_ENTITIES,
    ) -> None:
        self.start_time = start_time
        self.end_time = start_time + duration_s
        self.duration_s = duration_s
        self.event_count = 0
        self.packet_count = 0
        self.byte_count = 0

        self.tcp_flags: Counter[str] = Counter()
        self.protocols: Counter[str] = Counter()
        self.directions: Counter[str] = Counter()

        self._src_entropy = StreamingEntropy(max_distinct=max_entities)
        self._dst_entropy = StreamingEntropy(max_distinct=max_entities)
        self._dst_ports: Counter[int] = Counter()

        self.contributing_flow_ids: list[str] = []
        self.sample_events: list[NormalizedEvent] = []
        self.dns_queries: list[dict[str, Any]] = []
        self.tls_records: list[dict[str, Any]] = []
        self.flow_summaries: list[dict[str, Any]] = []

        self.latest_capability = None
        self.latest_input_mode = "pcap_replay"
        self._max_events = max_events
        self._max_entities = max_entities

    def add(self, ev: NormalizedEvent) -> None:
        """Accumulate a NormalizedEvent into this window."""
        self.event_count += 1
        pkts = ev.packets if ev.packets is not None else 1
        bytes_ = ev.bytes if ev.bytes is not None else 0
        self.packet_count += pkts
        self.byte_count += bytes_

        if ev.protocol:
            self.protocols[str(ev.protocol)] += 1
        if ev.direction:
            self.directions[str(ev.direction)] += 1
        if ev.tcp_flags:
            flags_str = str(ev.tcp_flags)
            self.tcp_flags[flags_str] += 1
            # Also record individual flag characters if short string like "SA"
            for ch in ("S", "A", "R", "F", "P", "U"):
                if ch in flags_str:
                    self.tcp_flags[ch] += 1

        if ev.src_ip:
            self._src_entropy.add(ev.src_ip, pkts)
        if ev.dst_ip:
            self._dst_entropy.add(ev.dst_ip, pkts)
        if ev.dst_port is not None:
            if len(self._dst_ports) < self._max_entities or ev.dst_port in self._dst_ports:
                self._dst_ports[ev.dst_port] += 1

        if ev.flow_id and len(self.contributing_flow_ids) < 32:
            if ev.flow_id not in self.contributing_flow_ids:
                self.contributing_flow_ids.append(ev.flow_id)

        if ev.dns and len(self.dns_queries) < 100:
            self.dns_queries.append(ev.dns)

        if ev.tls and len(self.tls_records) < 100:
            self.tls_records.append(ev.tls)

        if ev.flow_summary and len(self.flow_summaries) < 100:
            self.flow_summaries.append(ev.flow_summary)

        if len(self.sample_events) < 50:
            self.sample_events.append(ev)

        self.latest_capability = ev.capability
        self.latest_input_mode = str(ev.input_mode)

    def to_summary(self) -> WindowSummary:
        """Close and produce an immutable WindowSummary."""
        src_counts = self._src_entropy.counts()
        dst_counts = self._dst_entropy.counts()
        return WindowSummary(
            start_time=self.start_time,
            end_time=self.end_time,
            duration_s=self.duration_s,
            event_count=self.event_count,
            packet_count=self.packet_count,
            byte_count=self.byte_count,
            tcp_flags=dict(self.tcp_flags),
            protocols=dict(self.protocols),
            directions=dict(self.directions),
            src_entropy=self._src_entropy.entropy(),
            dst_entropy=self._dst_entropy.entropy(),
            unique_src_count=self._src_entropy.distinct_count,
            unique_dst_count=self._dst_entropy.distinct_count,
            unique_dst_ports_count=len(self._dst_ports),
            contributing_flow_ids=list(self.contributing_flow_ids),
            sample_events=list(self.sample_events),
            dns_queries=list(self.dns_queries),
            tls_records=list(self.tls_records),
            flow_summaries=list(self.flow_summaries),
            src_ip_counts=src_counts,
            dst_ip_counts=dst_counts,
            dst_port_counts=dict(self._dst_ports),
            latest_capability=self.latest_capability,
            latest_input_mode=self.latest_input_mode,
        )


class TumblingWindowAggregator:
    """Maintains tumbling time windows with watermark-based closure and bounded state.

    Events are grouped into fixed-duration tumbling windows (e.g. 1.0 s).
    The watermark tracks ``max_observed_time - watermark_delay_s``.
    When the watermark passes a window's end time, that window closes and is yielded.
    """

    def __init__(
        self,
        window_duration_s: float = DEFAULT_WINDOW_DURATION_S,
        watermark_delay_s: float = DEFAULT_WATERMARK_DELAY_S,
        max_open_windows: int = DEFAULT_MAX_OPEN_WINDOWS,
        max_events_per_window: int = DEFAULT_MAX_EVENTS_PER_WINDOW,
    ) -> None:
        if window_duration_s <= 0:
            raise ValueError("window_duration_s must be > 0")
        if watermark_delay_s < 0:
            raise ValueError("watermark_delay_s must be >= 0")

        self.window_duration_s = window_duration_s
        self.watermark_delay_s = watermark_delay_s
        self.max_open_windows = max_open_windows
        self.max_events_per_window = max_events_per_window

        self._max_observed_time: float | None = None
        self._watermark: float | None = None
        # Dict keyed by window_start float -> _OpenWindow
        self._open_windows: dict[float, _OpenWindow] = {}

        # Telemetry
        self.events_processed = 0
        self.dropped_late_events = 0
        self.windows_emitted = 0

    @property
    def watermark(self) -> float | None:
        return self._watermark

    @property
    def max_observed_time(self) -> float | None:
        return self._max_observed_time

    def _window_start_for(self, ts: float) -> float:
        return math.floor(ts / self.window_duration_s) * self.window_duration_s

    def add_event(self, ev: NormalizedEvent) -> list[WindowSummary]:
        """Add an event and return any windows that closed as a result."""
        self.events_processed += 1
        ts = _to_posix(ev.observed_time)

        # Update clock & watermark
        if self._max_observed_time is None or ts > self._max_observed_time:
            self._max_observed_time = ts
            self._watermark = ts - self.watermark_delay_s

        w_start = self._window_start_for(ts)
        w_end = w_start + self.window_duration_s

        # Late arrival check: if window end is already behind the watermark
        if self._watermark is not None and w_end <= self._watermark and w_start not in self._open_windows:
            self.dropped_late_events += 1
            return self._close_ready_windows()

        if w_start not in self._open_windows:
            # Enforce max_open_windows bound by closing oldest early if necessary
            if len(self._open_windows) >= self.max_open_windows:
                oldest_key = min(self._open_windows.keys())
                closed = self._open_windows.pop(oldest_key).to_summary()
                self.windows_emitted += 1
                closed_windows = [closed]
            else:
                closed_windows = []

            self._open_windows[w_start] = _OpenWindow(
                start_time=w_start,
                duration_s=self.window_duration_s,
                max_events=self.max_events_per_window,
            )
        else:
            closed_windows = []

        self._open_windows[w_start].add(ev)
        closed_windows.extend(self._close_ready_windows())
        return closed_windows

    def add_events(self, events: Sequence[NormalizedEvent]) -> list[WindowSummary]:
        """Add multiple events in sequence, collecting all closed windows."""
        emitted: list[WindowSummary] = []
        for ev in events:
            closed = self.add_event(ev)
            if closed:
                emitted.extend(closed)
        return emitted

    def advance_time(self, current_time: float) -> list[WindowSummary]:
        """Advance the clock to ``current_time`` and return any closed windows."""
        if self._max_observed_time is None or current_time > self._max_observed_time:
            self._max_observed_time = current_time
            self._watermark = current_time - self.watermark_delay_s
        return self._close_ready_windows()

    def _close_ready_windows(self) -> list[WindowSummary]:
        """Check all open windows against the current watermark and close ready ones."""
        if self._watermark is None:
            return []

        ready_starts = [
            w_start
            for w_start, window in self._open_windows.items()
            if window.end_time <= self._watermark
        ]
        ready_starts.sort()

        closed: list[WindowSummary] = []
        for start in ready_starts:
            window = self._open_windows.pop(start)
            summary = window.to_summary()
            self.windows_emitted += 1
            closed.append(summary)

        return closed

    def flush(self) -> list[WindowSummary]:
        """Close and emit all remaining open windows in chronological order."""
        remaining_starts = sorted(self._open_windows.keys())
        closed: list[WindowSummary] = []
        for start in remaining_starts:
            window = self._open_windows.pop(start)
            summary = window.to_summary()
            self.windows_emitted += 1
            closed.append(summary)
        return closed
