"""Header-only packet counters and capture-loss accounting.

Counters are derived entirely from header metadata. No payload is read.

Capture loss is SURFACED, never hidden (V6.3 section 14). On the PCAP replay
path there is no sensor, so kernel and ring drop counters genuinely do not
exist - they are reported as null and the capability state says
NOT_OBSERVABLE. What we can measure (snaplen truncation, unparseable frames,
malformed records) is reported as an explicit LOWER BOUND rather than dressed
up as a precise figure.

Reporting zero loss because no exception was raised is exactly the failure
this module exists to prevent.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .headers import PacketHeaders
from .normalized_event import protocol_name


@dataclass(slots=True)
class PacketCounter:
    """Fast-path counters over header metadata only.

    Bounded by construction: every breakdown is keyed by a small, closed
    vocabulary (protocol name, direction, IP version), never by an
    attacker-controlled value such as an address or port.
    """

    packets: int = 0
    bytes: int = 0
    captured_bytes: int = 0

    by_protocol: Counter[str] = field(default_factory=Counter)
    by_direction: Counter[str] = field(default_factory=Counter)
    by_ip_version: Counter[int] = field(default_factory=Counter)

    tcp_syn: int = 0
    tcp_syn_ack: int = 0
    tcp_fin: int = 0
    tcp_rst: int = 0

    fragmented: int = 0
    transport_truncated: int = 0

    first_seen: float | None = None
    last_seen: float | None = None

    def observe(
        self,
        hdr: PacketHeaders,
        timestamp: float,
        *,
        direction: str | None = None,
        captured_bytes: int | None = None,
    ) -> None:
        """Count one packet from its headers."""
        self.packets += 1
        self.bytes += hdr.wire_bytes
        self.captured_bytes += (
            hdr.wire_bytes if captured_bytes is None else captured_bytes
        )

        if self.first_seen is None:
            self.first_seen = timestamp
        self.last_seen = timestamp

        if hdr.ip_version is not None:
            self.by_ip_version[hdr.ip_version] += 1
        if hdr.protocol is not None:
            # Canonical name, matching the normalizer. Keying on the raw
            # number would make counter output disagree with event output.
            self.by_protocol[protocol_name(hdr.protocol) or "UNKNOWN"] += 1
        # Direction is only counted when it is actually known. An unknown
        # direction is not silently bucketed as "external".
        if direction is not None:
            self.by_direction[direction] += 1

        if hdr.fragmented:
            self.fragmented += 1
        if hdr.transport_truncated:
            self.transport_truncated += 1

        flags = hdr.tcp_flags
        if flags is not None:
            syn, ack = bool(flags & 0x02), bool(flags & 0x10)
            if syn and ack:
                self.tcp_syn_ack += 1
            elif syn:
                self.tcp_syn += 1
            if flags & 0x01:
                self.tcp_fin += 1
            if flags & 0x04:
                self.tcp_rst += 1

    @property
    def duration(self) -> float:
        if self.first_seen is None or self.last_seen is None:
            return 0.0
        return self.last_seen - self.first_seen

    @property
    def packets_per_second(self) -> float:
        d = self.duration
        return self.packets / d if d > 0 else 0.0

    @property
    def bits_per_second(self) -> float:
        d = self.duration
        return (self.bytes * 8) / d if d > 0 else 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "packets": self.packets,
            "bytes": self.bytes,
            "captured_bytes": self.captured_bytes,
            "duration_s": round(self.duration, 6),
            "packets_per_second": round(self.packets_per_second, 2),
            "bits_per_second": round(self.bits_per_second, 2),
            "by_protocol": dict(self.by_protocol),
            "by_direction": dict(self.by_direction),
            "by_ip_version": dict(self.by_ip_version),
            "tcp_syn": self.tcp_syn,
            "tcp_syn_ack": self.tcp_syn_ack,
            "tcp_fin": self.tcp_fin,
            "tcp_rst": self.tcp_rst,
            "fragmented": self.fragmented,
            "transport_truncated": self.transport_truncated,
        }


@dataclass(slots=True)
class CaptureLossAccount:
    """Measured visibility loss for one input source.

    The estimator name and the lower-bound flag travel with the number, so a
    consumer can never mistake a partial measurement for a complete one.
    """

    #: Packets the reader handed us.
    packets_read: int = 0
    #: Packets that produced a normalized event.
    packets_parsed: int = 0
    #: Frames the header decoder could not read (ARP, malformed, truncated).
    packets_unparseable: int = 0
    #: Records snapped shorter than their wire length.
    packets_truncated: int = 0
    #: Capture records the file reader rejected.
    records_malformed: int = 0
    #: Flows dropped by the bounded tracker - also a visibility loss.
    flows_evicted: int = 0

    #: Sensor counters. None on the PCAP path: there is no sensor, so these
    #: are NOT_OBSERVABLE rather than zero.
    kernel_drops: int | None = None
    ring_drops: int | None = None

    estimator: str = "pcap_parse_and_snaplen"

    def observe_packet(self, *, parsed: bool, truncated: bool = False) -> None:
        self.packets_read += 1
        if parsed:
            self.packets_parsed += 1
        else:
            self.packets_unparseable += 1
        if truncated:
            self.packets_truncated += 1

    @property
    def has_sensor_counters(self) -> bool:
        return self.kernel_drops is not None or self.ring_drops is not None

    @property
    def observed_loss_pct(self) -> float:
        """Measured share of input that produced no event.

        A LOWER BOUND. Packets the capture never saw are, by definition, not
        in the file - so this cannot account for them.
        """
        if self.packets_read == 0:
            return 0.0
        missed = self.packets_unparseable + self.records_malformed
        return 100.0 * missed / self.packets_read

    @property
    def truncated_pct(self) -> float:
        if self.packets_read == 0:
            return 0.0
        return 100.0 * self.packets_truncated / self.packets_read

    @property
    def is_lower_bound(self) -> bool:
        """True whenever sensor drop counters are unavailable.

        Without kernel/ring counters we cannot know what the capture layer
        discarded before we saw it, so the figure can only be a floor.
        """
        return not self.has_sensor_counters

    def to_sensor_loss(self) -> dict[str, Any]:
        """Serialise into the frozen ``sensor_loss`` block.

        ``kernel_drops`` and ``ring_drops`` stay null on this path - that is
        an honest NOT_OBSERVABLE, not a claim of zero drops.
        """
        return {
            "kernel_drops": self.kernel_drops,
            "ring_drops": self.ring_drops,
            "sensor_drop_pct": round(self.observed_loss_pct, 6),
            "estimator": self.estimator,
            "is_lower_bound": self.is_lower_bound,
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "packets_read": self.packets_read,
            "packets_parsed": self.packets_parsed,
            "packets_unparseable": self.packets_unparseable,
            "packets_truncated": self.packets_truncated,
            "records_malformed": self.records_malformed,
            "flows_evicted": self.flows_evicted,
            "observed_loss_pct": round(self.observed_loss_pct, 6),
            "truncated_pct": round(self.truncated_pct, 6),
            "estimator": self.estimator,
            "is_lower_bound": self.is_lower_bound,
        }


__all__ = ["PacketCounter", "CaptureLossAccount"]
