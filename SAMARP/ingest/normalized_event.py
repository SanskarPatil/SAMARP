"""The normalized event - P1's single output contract.

Every input mode converges here. PCAP replay, live tap, Suricata EVE,
NetFlow v9, IPFIX and sFlow all emit through this module; the only difference
between paths is the capability state attached by the adapter.

There is exactly ONE normalization implementation. A separate "fake"
normalizer for PCAP would let the replay path drift from the live path, and
the replay path is the demo path - the drift would only surface on stage.

The frozen schema (``schemas/normalized_event.schema.json``) sets
``additionalProperties: false``. No field may be invented here. Fields that
cannot be observed are emitted as ``None`` or omitted, never fabricated, and
the capability state records why.

NO PAYLOAD FIELD EXISTS. The contract has no representation for decrypted or
application-content data, so decryption cannot enter the pipeline even by
accident. That is a structural guarantee, not a matter of discipline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .address_plan import AddressPlan
from .capability import Capability, CapabilityState, InputMode
from .identity import (
    NOT_OBSERVABLE,
    flow_id_for_aggregate,
    flow_id_for_entity,
    flow_id_for_five_tuple,
)

SCHEMA_VERSION = 1

#: Frozen ``flow_ref_type`` enum.
FLOW_REF_TYPES = ("flow_5tuple", "aggregate", "entity")

_PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


class NormalizationError(ValueError):
    """Raised when an event cannot be built within the frozen contract."""


def iso8601(ts: datetime | float | int | None) -> str | None:
    """Render a timestamp in the schema's ``date-time`` format, UTC.

    Accepts an aware/naive ``datetime`` or a POSIX timestamp. Naive datetimes
    are treated as UTC rather than local time, so replay output does not shift
    with the machine's timezone.
    """
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    else:
        dt = ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def protocol_name(proto: int | str | None) -> str | None:
    """Map an IP protocol number to its short name, or pass a name through."""
    if proto is None:
        return None
    if isinstance(proto, str):
        return proto.upper() or None
    return _PROTOCOL_NAMES.get(proto, str(proto))


def tcp_flags_str(flags: int | str | None) -> str | None:
    """Render TCP flags as a stable short string, e.g. ``"SA"``.

    Header metadata only - no payload is examined.
    """
    if flags is None:
        return None
    if isinstance(flags, str):
        return flags or None
    order = (
        (0x01, "F"),
        (0x02, "S"),
        (0x04, "R"),
        (0x08, "P"),
        (0x10, "A"),
        (0x20, "U"),
        (0x40, "E"),
        (0x80, "C"),
    )
    out = "".join(ch for bit, ch in order if flags & bit)
    return out or "-"


@dataclass(slots=True)
class NormalizedEvent:
    """One observation, in the frozen contract.

    Construct via :meth:`from_flow` (an observable single flow) or
    :meth:`from_aggregate` / :meth:`from_entity` where a single 5-tuple would
    be a misleading identity.
    """

    observed_time: datetime | float
    input_mode: InputMode | str
    capability: CapabilityState

    display_time: datetime | float | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | int | None = None
    ip_version: int | None = None
    tcp_flags: int | str | None = None
    packets: int | None = None
    bytes: int | None = None
    direction: str | None = None
    flow_id: str | None = None
    flow_ref_type: str | None = None
    flow_summary: dict[str, Any] | None = None
    dns: dict[str, Any] | None = None
    tls: dict[str, Any] | None = None
    quic: dict[str, Any] | None = None
    shape: dict[str, Any] | None = None
    capture_source: str | None = None
    sensor_loss: dict[str, Any] | None = None
    exporter: dict[str, Any] | None = None

    _extras: dict[str, Any] = field(default_factory=dict, repr=False)

    # -- construction -----------------------------------------------------

    @classmethod
    def from_flow(
        cls,
        *,
        observed_time: datetime | float,
        input_mode: InputMode | str,
        capability: CapabilityState,
        src_ip: str | None,
        dst_ip: str | None,
        src_port: int | None = None,
        dst_port: int | None = None,
        protocol: str | int | None = None,
        address_plan: AddressPlan | None = None,
        **kwargs: Any,
    ) -> "NormalizedEvent":
        """Build an event identified by a concrete observable flow."""
        proto = protocol_name(protocol)
        ev = cls(
            observed_time=observed_time,
            input_mode=input_mode,
            capability=capability,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            **kwargs,
        )
        ev.flow_ref_type = "flow_5tuple"
        ev.flow_id = flow_id_for_five_tuple(src_ip, dst_ip, src_port, dst_port, proto)
        if address_plan is not None and ev.direction is None:
            ev.direction = address_plan.direction(src_ip, dst_ip)
        return ev

    @classmethod
    def from_aggregate(
        cls,
        *,
        observed_time: datetime | float,
        input_mode: InputMode | str,
        capability: CapabilityState,
        dedup_key: Any,
        **kwargs: Any,
    ) -> "NormalizedEvent":
        """Build an event whose identity is a multi-flow aggregate.

        For a spoofed flood there is no honest single source flow. Unavailable
        key components must already carry the NOT_OBSERVABLE sentinel.
        """
        ev = cls(
            observed_time=observed_time,
            input_mode=input_mode,
            capability=capability,
            **kwargs,
        )
        ev.flow_ref_type = "aggregate"
        ev.flow_id = flow_id_for_aggregate(dedup_key)
        return ev

    @classmethod
    def from_entity(
        cls,
        *,
        observed_time: datetime | float,
        input_mode: InputMode | str,
        capability: CapabilityState,
        entity: Any,
        **kwargs: Any,
    ) -> "NormalizedEvent":
        """Build an event whose identity is a source/entity, not a flow."""
        ev = cls(
            observed_time=observed_time,
            input_mode=input_mode,
            capability=capability,
            **kwargs,
        )
        ev.flow_ref_type = "entity"
        ev.flow_id = flow_id_for_entity(entity)
        return ev

    # -- serialisation ----------------------------------------------------

    def to_dict(self, *, drop_none: bool = True) -> dict[str, Any]:
        """Serialise to a dict conforming to the frozen schema.

        ``drop_none`` omits unobserved optional fields rather than emitting
        explicit nulls. Both forms validate; omission keeps the wire payload
        small under flood. Required fields are always present.
        """
        out: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "observed_time": iso8601(self.observed_time),
            "input_mode": str(InputMode(self.input_mode)),
            "capability": self.capability.to_dict(),
        }

        # display_time is typed `string` (not nullable) by the frozen schema,
        # unlike every other optional field. It is therefore omitted when
        # absent rather than emitted as an explicit null, in both modes.
        display = iso8601(self.display_time)
        if display is not None:
            out["display_time"] = display

        optional: dict[str, Any] = {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": protocol_name(self.protocol),
            "ip_version": self.ip_version,
            "tcp_flags": tcp_flags_str(self.tcp_flags),
            "packets": self.packets,
            "bytes": self.bytes,
            "direction": self.direction,
            "flow_id": self.flow_id,
            "flow_ref_type": self.flow_ref_type,
            "flow_summary": self.flow_summary,
            "dns": self.dns,
            "tls": self.tls,
            "quic": self.quic,
            "shape": self.shape,
            "capture_source": self.capture_source,
            "sensor_loss": self.sensor_loss,
            "exporter": self.exporter,
        }

        for key, value in optional.items():
            if value is None and drop_none:
                continue
            out[key] = value

        return out

    # -- validation -------------------------------------------------------

    def validate(self) -> None:
        """Check the invariants P1 is accountable for.

        Cheap and always-on, independent of the jsonschema check used in
        tests. These are the rules whose violation would be silent.
        """
        if self.observed_time is None:
            raise NormalizationError("observed_time is required")

        try:
            InputMode(self.input_mode)
        except ValueError as exc:
            raise NormalizationError(
                f"input_mode must be one of {[m.value for m in InputMode]}: {exc}"
            ) from exc

        if self.flow_ref_type is not None:
            if self.flow_ref_type not in FLOW_REF_TYPES:
                raise NormalizationError(
                    f"flow_ref_type must be one of {FLOW_REF_TYPES}, "
                    f"got {self.flow_ref_type!r}"
                )
            # PS constraint (e): where an alertable observation exists,
            # flow_id is never null.
            if not self.flow_id:
                raise NormalizationError(
                    "flow_id must not be null when flow_ref_type is set"
                )

        if self.flow_id is not None:
            if len(self.flow_id) != 16 or any(
                c not in "0123456789abcdef" for c in self.flow_id
            ):
                raise NormalizationError(
                    f"flow_id must match ^[0-9a-f]{{16}}$, got {self.flow_id!r}"
                )

        if self.direction is not None and self.direction not in (
            "inbound",
            "outbound",
            "internal",
            "external",
        ):
            raise NormalizationError(f"invalid direction: {self.direction!r}")

        if self.ip_version is not None and self.ip_version not in (4, 6):
            raise NormalizationError(f"invalid ip_version: {self.ip_version!r}")

        for name, port in (("src_port", self.src_port), ("dst_port", self.dst_port)):
            if port is not None and not (0 <= port <= 65535):
                raise NormalizationError(f"{name} out of range: {port!r}")

        for name, count in (("packets", self.packets), ("bytes", self.bytes)):
            if count is not None and count < 0:
                raise NormalizationError(f"{name} must not be negative: {count!r}")

        if self._extras:
            raise NormalizationError(
                "schema sets additionalProperties:false - cannot emit "
                f"invented fields: {sorted(self._extras)}"
            )


__all__ = [
    "SCHEMA_VERSION",
    "FLOW_REF_TYPES",
    "NormalizationError",
    "NormalizedEvent",
    "iso8601",
    "protocol_name",
    "tcp_flags_str",
    "Capability",
    "CapabilityState",
    "InputMode",
    "NOT_OBSERVABLE",
]
