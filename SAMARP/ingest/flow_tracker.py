"""Bounded in-process flow tracker.

V6.3 section 6.2 is explicit: ``flow_summary`` is produced HERE, by the
bounded flow tracker on the header path - NOT by Suricata EVE flow output.
EVE flow events stay disabled and must not be re-enabled to populate it.

V6.3 section 11: all rolling state is bounded.

    "Never maintain an unbounded dictionary keyed by arbitrary
     source/destination tuples. The attacker must not be able to weaponize
     the detector's own state."

A spoofed flood presents millions of distinct 5-tuples. Three bounds hold the
line, and every drop is COUNTED - eviction pressure is visible evidence, not
silent loss:

1. Hard cap on active flows. At the cap the least-recently-seen flow is
   evicted, in O(1), via OrderedDict ordering.
2. Idle timeout, swept on a bounded budget per packet so a flood cannot
   stall ingest with a long sweep.
3. Absolute lifetime, so a deliberately kept-alive flow still rotates out.

NO PAYLOAD IS STORED. FlowState has no field capable of holding packet bytes.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Iterator

from .headers import PacketHeaders
from .identity import flow_id_for_five_tuple
from .normalized_event import protocol_name

#: Defaults. Overridable per deployment; the point is that a bound exists.
DEFAULT_MAX_FLOWS = 65_536
DEFAULT_IDLE_TIMEOUT_S = 300.0
DEFAULT_MAX_LIFETIME_S = 3_600.0

#: Flows examined per sweep. Bounded so one packet never triggers an
#: unbounded scan - the sweep cost must not grow with the flood.
_SWEEP_BUDGET = 64

_FLAG_LETTERS = (
    (0x01, "F"),
    (0x02, "S"),
    (0x04, "R"),
    (0x08, "P"),
    (0x10, "A"),
    (0x20, "U"),
)


@dataclass(slots=True)
class FlowState:
    """Bounded per-flow state. Header-derived counters only."""

    flow_id: str
    first_seen: float
    last_seen: float

    #: The endpoint that sent the first packet. Used to attribute direction
    #: within the flow, so both directions share one flow_id while remaining
    #: individually countable.
    initiator: tuple[str | None, int | None]

    protocol: str | None = None
    packets: int = 0
    bytes: int = 0
    fwd_packets: int = 0
    fwd_bytes: int = 0
    rev_packets: int = 0
    rev_bytes: int = 0
    #: OR of every TCP flag seen on this flow.
    tcp_flags_seen: int = 0
    state: str = "NEW"

    @property
    def duration(self) -> float:
        return self.last_seen - self.first_seen

    @property
    def flags_str(self) -> str:
        if not self.tcp_flags_seen:
            return ""
        return "".join(c for bit, c in _FLAG_LETTERS if self.tcp_flags_seen & bit)

    def to_summary(self) -> dict[str, Any]:
        """The ``flow_summary`` object carried on the normalized event."""
        return {
            "flow_id": self.flow_id,
            "state": self.state,
            "packets": self.packets,
            "bytes": self.bytes,
            "fwd_packets": self.fwd_packets,
            "fwd_bytes": self.fwd_bytes,
            "rev_packets": self.rev_packets,
            "rev_bytes": self.rev_bytes,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_s": round(self.duration, 6),
            "tcp_flags_seen": self.flags_str,
        }


@dataclass(slots=True)
class FlowTrackerStats:
    """Counters describing tracker pressure. Eviction is visible evidence."""

    flows_created: int = 0
    flows_expired_idle: int = 0
    flows_expired_lifetime: int = 0
    flows_evicted_capacity: int = 0
    active_flows: int = 0
    peak_active_flows: int = 0

    @property
    def flows_dropped(self) -> int:
        """Flows removed while potentially still live.

        Capacity eviction is a visibility loss: the flow was still being
        observed when we let it go. Idle and lifetime expiry are normal
        lifecycle, not loss.
        """
        return self.flows_evicted_capacity

    def as_dict(self) -> dict[str, Any]:
        return {
            "flows_created": self.flows_created,
            "flows_expired_idle": self.flows_expired_idle,
            "flows_expired_lifetime": self.flows_expired_lifetime,
            "flows_evicted_capacity": self.flows_evicted_capacity,
            "flows_dropped": self.flows_dropped,
            "active_flows": self.active_flows,
            "peak_active_flows": self.peak_active_flows,
        }


class FlowTracker:
    """LRU-bounded flow table keyed by the frozen ``flow_id``."""

    __slots__ = ("_flows", "max_flows", "idle_timeout", "max_lifetime", "stats")

    def __init__(
        self,
        *,
        max_flows: int = DEFAULT_MAX_FLOWS,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT_S,
        max_lifetime: float = DEFAULT_MAX_LIFETIME_S,
    ) -> None:
        if max_flows < 1:
            raise ValueError("max_flows must be at least 1")
        self._flows: OrderedDict[str, FlowState] = OrderedDict()
        self.max_flows = max_flows
        self.idle_timeout = idle_timeout
        self.max_lifetime = max_lifetime
        self.stats = FlowTrackerStats()

    # -- observation ------------------------------------------------------

    def observe(self, hdr: PacketHeaders, timestamp: float) -> FlowState:
        """Fold one packet into its flow and return the updated state.

        Uses the frozen bidirectional identity rule, so both directions of a
        conversation land on one ``flow_id``.
        """
        # The protocol MUST be canonicalised the same way the normalizer
        # canonicalises it, or the tracker and the event derive different
        # flow_ids for the same flow - hashing 6 is not hashing "TCP".
        proto = protocol_name(hdr.protocol)
        flow_id = flow_id_for_five_tuple(
            hdr.src_ip, hdr.dst_ip, hdr.src_port, hdr.dst_port, proto
        )

        self._sweep(timestamp)

        flow = self._flows.get(flow_id)
        if flow is None:
            flow = self._create(flow_id, hdr, timestamp, proto)
        else:
            self._flows.move_to_end(flow_id)
            if flow.state == "NEW":
                flow.state = "ACTIVE"

        forward = (hdr.src_ip, hdr.src_port) == flow.initiator
        flow.last_seen = timestamp
        flow.packets += 1
        flow.bytes += hdr.wire_bytes
        if forward:
            flow.fwd_packets += 1
            flow.fwd_bytes += hdr.wire_bytes
        else:
            flow.rev_packets += 1
            flow.rev_bytes += hdr.wire_bytes

        if hdr.tcp_flags is not None:
            flow.tcp_flags_seen |= hdr.tcp_flags
            if hdr.tcp_flags & 0x04:
                flow.state = "RESET"
            elif hdr.tcp_flags & 0x01:
                flow.state = "CLOSING"

        return flow

    def _create(
        self,
        flow_id: str,
        hdr: PacketHeaders,
        timestamp: float,
        protocol: str | None,
    ) -> FlowState:
        # Enforce the hard cap BEFORE inserting, so the table never exceeds
        # max_flows even momentarily.
        while len(self._flows) >= self.max_flows:
            self._evict_lru()

        flow = FlowState(
            flow_id=flow_id,
            first_seen=timestamp,
            last_seen=timestamp,
            initiator=(hdr.src_ip, hdr.src_port),
            protocol=protocol,
        )
        self._flows[flow_id] = flow
        self.stats.flows_created += 1
        self._update_active()
        return flow

    # -- bounding ---------------------------------------------------------

    def _evict_lru(self) -> None:
        """Drop the least-recently-seen flow. O(1)."""
        self._flows.popitem(last=False)
        self.stats.flows_evicted_capacity += 1

    def _sweep(self, now: float) -> None:
        """Expire idle and over-age flows on a bounded budget.

        Only the LRU end is examined, and only up to ``_SWEEP_BUDGET`` entries
        per packet, so sweep cost stays constant under flood.
        """
        examined = 0
        while self._flows and examined < _SWEEP_BUDGET:
            flow_id, flow = next(iter(self._flows.items()))
            if now - flow.last_seen > self.idle_timeout:
                del self._flows[flow_id]
                self.stats.flows_expired_idle += 1
            elif now - flow.first_seen > self.max_lifetime:
                del self._flows[flow_id]
                self.stats.flows_expired_lifetime += 1
            else:
                # LRU order means nothing further along can be idler.
                break
            examined += 1
        self._update_active()

    def expire_all_idle(self, now: float) -> int:
        """Sweep every expired flow, ignoring the per-packet budget.

        For end-of-replay flushing, not the hot path.
        """
        removed = 0
        for flow_id in list(self._flows.keys()):
            flow = self._flows[flow_id]
            if now - flow.last_seen > self.idle_timeout:
                del self._flows[flow_id]
                self.stats.flows_expired_idle += 1
                removed += 1
            elif now - flow.first_seen > self.max_lifetime:
                del self._flows[flow_id]
                self.stats.flows_expired_lifetime += 1
                removed += 1
        self._update_active()
        return removed

    def _update_active(self) -> None:
        self.stats.active_flows = len(self._flows)
        if self.stats.active_flows > self.stats.peak_active_flows:
            self.stats.peak_active_flows = self.stats.active_flows

    # -- access -----------------------------------------------------------

    def get(self, flow_id: str) -> FlowState | None:
        return self._flows.get(flow_id)

    def __len__(self) -> int:
        return len(self._flows)

    def __contains__(self, flow_id: object) -> bool:
        return flow_id in self._flows

    def __iter__(self) -> Iterator[FlowState]:
        return iter(list(self._flows.values()))

    def clear(self) -> None:
        self._flows.clear()
        self._update_active()

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"<FlowTracker active={len(self._flows)}/{self.max_flows} "
            f"created={self.stats.flows_created} "
            f"evicted={self.stats.flows_evicted_capacity}>"
        )


__all__ = [
    "FlowTracker",
    "FlowState",
    "FlowTrackerStats",
    "DEFAULT_MAX_FLOWS",
    "DEFAULT_IDLE_TIMEOUT_S",
    "DEFAULT_MAX_LIFETIME_S",
]
