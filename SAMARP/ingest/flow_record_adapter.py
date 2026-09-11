"""Shared NetFlow v9 / IPFIX v10 flow-record adapter.

V6.3 section 2.4:

    "Use one shared template-based decoder for NetFlow v9 and IPFIX v10.
     Do not write two independent parsers. NetFlow v9 and IPFIX both use
     template-defined records; the adapter normalizes the common fields into
     the same event contract used by PCAP/EVE."

The two protocols share field-type IDs 1-127, so only the packet header and
the set-ID conventions differ. One decoder, one template cache.

BOUNDED STATE
-------------
A malformed or attacker-controlled template stream must not create unbounded
parser state (V6.3 section 5). The cache has a hard cap with LRU eviction and
an idle expiry, and every eviction is counted.

WHAT THIS ADAPTER DOES NOT DO
-----------------------------
It never reconstructs packets, DNS names, TLS fingerprints or TCP state the
exporter did not export (V6.3 section 49). Absent fields are omitted, and the
capability state reports NOT_OBSERVABLE. Inventing packet-level detail from
flow records would be a fabrication, not a degradation.

PASSIVE
-------
Reads bytes. No socket, no transmission, no outbound call.
"""

from __future__ import annotations

import ipaddress
import struct
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from .address_plan import AddressPlan
from .capability import Capability, CapabilityState, InputMode
from .normalized_event import NormalizedEvent

# ------------------------------------------------------------- constants

NETFLOW_V9 = 9
IPFIX = 10

_NF9_HEADER = struct.Struct("!HHIIII")  # version,count,uptime,secs,seq,source_id
_IPFIX_HEADER = struct.Struct("!HHIII")  # version,length,export_time,seq,domain
_SET_HEADER = struct.Struct("!HH")
_TEMPLATE_HEADER = struct.Struct("!HH")
_FIELD_SPEC = struct.Struct("!HH")

NF9_TEMPLATE_SET = 0
NF9_OPTIONS_SET = 1
IPFIX_TEMPLATE_SET = 2
IPFIX_OPTIONS_SET = 3
FIRST_DATA_SET = 256

#: Field type IDs the adapter maps. Shared by both protocols for IDs 1-127.
F_IN_BYTES = 1
F_IN_PKTS = 2
F_PROTOCOL = 4
F_TCP_FLAGS = 6
F_SRC_PORT = 7
F_SRC_IPV4 = 8
F_DST_PORT = 11
F_DST_IPV4 = 12
F_LAST_SWITCHED = 21
F_FIRST_SWITCHED = 22
F_SRC_IPV6 = 27
F_DST_IPV6 = 28
F_SAMPLING_INTERVAL = 34
F_IP_VERSION = 60
F_DIRECTION = 61
# IPFIX-only absolute timestamps.
F_FLOW_START_SECONDS = 150
F_FLOW_END_SECONDS = 151
F_FLOW_START_MILLIS = 152
F_FLOW_END_MILLIS = 153
F_SAMPLING_PACKET_INTERVAL = 305

_NUMERIC_FIELDS = frozenset(
    {
        F_IN_BYTES,
        F_IN_PKTS,
        F_PROTOCOL,
        F_TCP_FLAGS,
        F_SRC_PORT,
        F_DST_PORT,
        F_FIRST_SWITCHED,
        F_LAST_SWITCHED,
        F_SAMPLING_INTERVAL,
        F_IP_VERSION,
        F_DIRECTION,
        F_FLOW_START_SECONDS,
        F_FLOW_END_SECONDS,
        F_FLOW_START_MILLIS,
        F_FLOW_END_MILLIS,
        F_SAMPLING_PACKET_INTERVAL,
    }
)

#: Bounds. A cap must exist; the exact number is tunable.
DEFAULT_MAX_TEMPLATES = 4096
DEFAULT_TEMPLATE_IDLE_S = 1800.0

#: Refuse absurd set lengths rather than attempting a huge read.
MAX_SET_BYTES = 65535
#: A template claiming more fields than this is malformed.
MAX_TEMPLATE_FIELDS = 256

_VARIABLE_LENGTH = 0xFFFF


class FlowRecordError(ValueError):
    """Fatal: the datagram cannot be read as NetFlow v9 or IPFIX."""


# -------------------------------------------------------------- templates


@dataclass(frozen=True, slots=True)
class TemplateKey:
    """Templates are scoped by exporter AND observation domain.

    Two exporters may legitimately use template ID 256 for different layouts.
    Keying on template_id alone would let one exporter corrupt another's
    decoding.
    """

    exporter_id: str
    domain_id: int
    template_id: int


@dataclass(slots=True)
class Template:
    """A decoded template: an ordered list of (field_type, length)."""

    key: TemplateKey
    fields: tuple[tuple[int, int], ...]
    registered_at: float
    version: int = 1

    @property
    def record_length(self) -> int | None:
        """Fixed record length, or None when any field is variable-length."""
        total = 0
        for _ftype, flen in self.fields:
            if flen == _VARIABLE_LENGTH:
                return None
            total += flen
        return total


@dataclass(slots=True)
class TemplateCacheStats:
    templates_registered: int = 0
    templates_replaced: int = 0
    templates_evicted: int = 0
    templates_expired: int = 0
    active_templates: int = 0
    peak_templates: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "templates_registered": self.templates_registered,
            "templates_replaced": self.templates_replaced,
            "templates_evicted": self.templates_evicted,
            "templates_expired": self.templates_expired,
            "active_templates": self.active_templates,
            "peak_templates": self.peak_templates,
        }


class TemplateCache:
    """Bounded LRU template store shared by NetFlow v9 and IPFIX."""

    __slots__ = ("_templates", "max_templates", "idle_timeout", "stats")

    def __init__(
        self,
        *,
        max_templates: int = DEFAULT_MAX_TEMPLATES,
        idle_timeout: float = DEFAULT_TEMPLATE_IDLE_S,
    ) -> None:
        if max_templates < 1:
            raise ValueError("max_templates must be at least 1")
        self._templates: OrderedDict[TemplateKey, Template] = OrderedDict()
        self.max_templates = max_templates
        self.idle_timeout = idle_timeout
        self.stats = TemplateCacheStats()

    def register(
        self, key: TemplateKey, fields: tuple[tuple[int, int], ...], now: float
    ) -> Template:
        """Register or replace a template.

        Re-registration with the same key REPLACES the layout. Exporters
        resend templates periodically and may change them; keeping the old
        layout would silently mis-decode every later record.
        """
        existing = self._templates.get(key)
        version = 1
        if existing is not None:
            version = existing.version + 1
            self.stats.templates_replaced += 1
            del self._templates[key]
        else:
            while len(self._templates) >= self.max_templates:
                self._templates.popitem(last=False)
                self.stats.templates_evicted += 1

        template = Template(key=key, fields=fields, registered_at=now, version=version)
        self._templates[key] = template
        self.stats.templates_registered += 1
        self._touch_stats()
        return template

    def get(self, key: TemplateKey, now: float | None = None) -> Template | None:
        template = self._templates.get(key)
        if template is None:
            return None
        if now is not None and now - template.registered_at > self.idle_timeout:
            del self._templates[key]
            self.stats.templates_expired += 1
            self._touch_stats()
            return None
        self._templates.move_to_end(key)
        return template

    def _touch_stats(self) -> None:
        self.stats.active_templates = len(self._templates)
        if self.stats.active_templates > self.stats.peak_templates:
            self.stats.peak_templates = self.stats.active_templates

    def __len__(self) -> int:
        return len(self._templates)

    def __contains__(self, key: object) -> bool:
        return key in self._templates


# ------------------------------------------------------------ decode stats


@dataclass(slots=True)
class FlowDecodeStats:
    datagrams_read: int = 0
    datagrams_malformed: int = 0
    template_sets: int = 0
    options_sets_skipped: int = 0
    data_sets: int = 0
    data_sets_deferred: int = 0  # no template yet
    records_decoded: int = 0
    records_malformed: int = 0
    events_emitted: int = 0
    unknown_templates: set[int] = field(default_factory=set)

    def as_dict(self) -> dict[str, Any]:
        return {
            "datagrams_read": self.datagrams_read,
            "datagrams_malformed": self.datagrams_malformed,
            "template_sets": self.template_sets,
            "options_sets_skipped": self.options_sets_skipped,
            "data_sets": self.data_sets,
            "data_sets_deferred": self.data_sets_deferred,
            "records_decoded": self.records_decoded,
            "records_malformed": self.records_malformed,
            "events_emitted": self.events_emitted,
            "unknown_templates": sorted(self.unknown_templates),
        }


# ---------------------------------------------------------------- decoding


def _read_uint(buf: memoryview, offset: int, length: int) -> int:
    return int.from_bytes(buf[offset : offset + length], "big")


def _decode_value(ftype: int, raw: memoryview) -> Any:
    """Decode one field. Unmapped types return None and are dropped."""
    if ftype in (F_SRC_IPV4, F_DST_IPV4):
        return str(ipaddress.IPv4Address(bytes(raw))) if len(raw) == 4 else None
    if ftype in (F_SRC_IPV6, F_DST_IPV6):
        return str(ipaddress.IPv6Address(bytes(raw))) if len(raw) == 16 else None
    if ftype in _NUMERIC_FIELDS:
        return int.from_bytes(bytes(raw), "big")
    return None


@dataclass(slots=True)
class _Context:
    """Per-datagram header context."""

    input_mode: InputMode
    export_time: float
    domain_id: int
    sys_uptime_ms: int = 0
    exporter_host: str = "fixture"

    @property
    def exporter_id(self) -> str:
        return f"{self.exporter_host}:{self.domain_id}"

    def flow_end_time(self, v: dict[int, Any]) -> float:
        """Best available observation time, in POSIX seconds.

        IPFIX absolute timestamps win. NetFlow v9 switched-times are
        sysUptime-relative milliseconds and are rebased against the header.
        Falling back to export time is honest: it is when the exporter said
        so, not an invented flow time.
        """
        if F_FLOW_END_SECONDS in v:
            return float(v[F_FLOW_END_SECONDS])
        if F_FLOW_END_MILLIS in v:
            return v[F_FLOW_END_MILLIS] / 1000.0
        if F_LAST_SWITCHED in v and self.sys_uptime_ms:
            delta_ms = self.sys_uptime_ms - v[F_LAST_SWITCHED]
            return self.export_time - (delta_ms / 1000.0)
        return self.export_time


class FlowRecordAdapter:
    """Decode NetFlow v9 / IPFIX datagrams into normalized events."""

    __slots__ = ("cache", "_plan", "_capability", "stats", "_source")

    def __init__(
        self,
        *,
        address_plan: AddressPlan | None = None,
        capability: CapabilityState | None = None,
        cache: TemplateCache | None = None,
        capture_source: str | None = None,
    ) -> None:
        self.cache = cache if cache is not None else TemplateCache()
        self._plan = address_plan
        self._capability = capability
        self._source = capture_source
        self.stats = FlowDecodeStats()

    @property
    def capability(self) -> CapabilityState | None:
        return self._capability

    # -- entry points -----------------------------------------------------

    def decode_file(self, path: str | Path) -> Iterator[NormalizedEvent]:
        """Decode a file holding one or more concatenated datagrams."""
        p = Path(path)
        if not p.is_file():
            raise FlowRecordError(f"flow-record fixture not found: {p}")
        if self._source is None:
            self._source = p.name
        yield from self.decode_stream(p.read_bytes())

    def decode_stream(self, data: bytes) -> Iterator[NormalizedEvent]:
        """Decode concatenated datagrams from one buffer."""
        buf = memoryview(data)
        offset = 0
        while offset + 4 <= len(buf):
            consumed, events = self._decode_one(buf, offset)
            if consumed <= 0:
                return
            yield from events
            offset += consumed

    def decode_datagram(self, data: bytes) -> list[NormalizedEvent]:
        """Decode exactly one datagram."""
        _consumed, events = self._decode_one(memoryview(data), 0)
        return events

    # -- per-datagram -----------------------------------------------------

    def _decode_one(
        self, buf: memoryview, start: int
    ) -> tuple[int, list[NormalizedEvent]]:
        if start + 2 > len(buf):
            return 0, []
        version = _read_uint(buf, start, 2)

        if version == NETFLOW_V9:
            return self._decode_netflow_v9(buf, start)
        if version == IPFIX:
            return self._decode_ipfix(buf, start)

        self.stats.datagrams_malformed += 1
        raise FlowRecordError(
            f"unsupported flow-record version {version}; "
            "expected 9 (NetFlow v9) or 10 (IPFIX)"
        )

    def _decode_netflow_v9(
        self, buf: memoryview, start: int
    ) -> tuple[int, list[NormalizedEvent]]:
        if start + _NF9_HEADER.size > len(buf):
            self.stats.datagrams_malformed += 1
            return 0, []
        (
            _version,
            _count,
            sys_uptime_ms,
            unix_secs,
            _sequence,
            source_id,
        ) = _NF9_HEADER.unpack_from(buf, start)

        self.stats.datagrams_read += 1
        ctx = _Context(
            input_mode=InputMode.NETFLOW_V9,
            export_time=float(unix_secs),
            domain_id=source_id,
            sys_uptime_ms=sys_uptime_ms,
        )
        # NetFlow v9 headers count RECORDS, not bytes, so one datagram runs
        # to the end of the buffer it was handed.
        events = self._decode_sets(buf, start + _NF9_HEADER.size, len(buf), ctx)
        return len(buf) - start, events

    def _decode_ipfix(
        self, buf: memoryview, start: int
    ) -> tuple[int, list[NormalizedEvent]]:
        if start + _IPFIX_HEADER.size > len(buf):
            self.stats.datagrams_malformed += 1
            return 0, []
        (
            _version,
            length,
            export_time,
            _sequence,
            domain_id,
        ) = _IPFIX_HEADER.unpack_from(buf, start)

        if length < _IPFIX_HEADER.size or start + length > len(buf):
            # Truncated datagram. Count it and stop cleanly.
            self.stats.datagrams_malformed += 1
            return 0, []

        self.stats.datagrams_read += 1
        ctx = _Context(
            input_mode=InputMode.IPFIX,
            export_time=float(export_time),
            domain_id=domain_id,
        )
        events = self._decode_sets(
            buf, start + _IPFIX_HEADER.size, start + length, ctx
        )
        return length, events

    def _decode_sets(
        self, buf: memoryview, offset: int, limit: int, ctx: _Context
    ) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []

        while offset + _SET_HEADER.size <= limit:
            set_id, set_len = _SET_HEADER.unpack_from(buf, offset)

            if set_len < _SET_HEADER.size or set_len > MAX_SET_BYTES:
                self.stats.datagrams_malformed += 1
                break
            if offset + set_len > limit:
                # Truncated set: count it, stop this datagram.
                self.stats.datagrams_malformed += 1
                break

            body = buf[offset + _SET_HEADER.size : offset + set_len]

            if set_id in (NF9_TEMPLATE_SET, IPFIX_TEMPLATE_SET):
                self._register_templates(body, ctx)
                self.stats.template_sets += 1
            elif set_id in (NF9_OPTIONS_SET, IPFIX_OPTIONS_SET):
                # Options templates carry exporter metadata, not flow records.
                # Out of scope for V6.3; skipped and counted, never guessed.
                self.stats.options_sets_skipped += 1
            elif set_id >= FIRST_DATA_SET:
                self.stats.data_sets += 1
                events.extend(self._decode_data_set(body, set_id, ctx))
            else:
                self.stats.datagrams_malformed += 1

            offset += set_len

        return events

    # -- templates --------------------------------------------------------

    def _register_templates(self, body: memoryview, ctx: _Context) -> None:
        offset = 0
        while offset + _TEMPLATE_HEADER.size <= len(body):
            template_id, field_count = _TEMPLATE_HEADER.unpack_from(body, offset)
            offset += _TEMPLATE_HEADER.size

            if field_count == 0 or field_count > MAX_TEMPLATE_FIELDS:
                # Malformed or hostile template. Stop parsing this set.
                self.stats.records_malformed += 1
                return
            if offset + field_count * _FIELD_SPEC.size > len(body):
                self.stats.records_malformed += 1
                return

            fields: list[tuple[int, int]] = []
            ok = True
            for _ in range(field_count):
                ftype, flen = _FIELD_SPEC.unpack_from(body, offset)
                offset += _FIELD_SPEC.size
                if ftype & 0x8000:
                    # Enterprise-specific field: a 4-byte PEN follows. Skip
                    # the PEN and keep the field as opaque padding rather
                    # than guessing its meaning.
                    if offset + 4 > len(body):
                        self.stats.records_malformed += 1
                        ok = False
                        break
                    offset += 4
                    ftype = 0  # unmapped; its length is still consumed
                fields.append((ftype, flen))
            if not ok:
                return

            key = TemplateKey(
                exporter_id=ctx.exporter_id,
                domain_id=ctx.domain_id,
                template_id=template_id,
            )
            self.cache.register(key, tuple(fields), ctx.export_time)

    # -- data -------------------------------------------------------------

    def _decode_data_set(
        self, body: memoryview, set_id: int, ctx: _Context
    ) -> list[NormalizedEvent]:
        key = TemplateKey(
            exporter_id=ctx.exporter_id, domain_id=ctx.domain_id, template_id=set_id
        )
        template = self.cache.get(key, ctx.export_time)
        if template is None:
            # Data before its template is normal on a lossy transport. Count
            # it, skip it, keep decoding. Never guess a layout.
            self.stats.data_sets_deferred += 1
            self.stats.unknown_templates.add(set_id)
            return []

        rec_len = template.record_length
        if not rec_len:
            # Variable-length record. Out of scope for V6.3 flow fixtures;
            # counted and skipped rather than mis-decoded.
            self.stats.records_malformed += 1
            return []

        events: list[NormalizedEvent] = []
        offset = 0
        while offset + rec_len <= len(body):
            values = self._decode_record(body, offset, template)
            offset += rec_len
            self.stats.records_decoded += 1
            event = self._to_event(values, ctx)
            if event is not None:
                self.stats.events_emitted += 1
                events.append(event)
        return events

    @staticmethod
    def _decode_record(
        body: memoryview, offset: int, template: Template
    ) -> dict[int, Any]:
        values: dict[int, Any] = {}
        pos = offset
        for ftype, flen in template.fields:
            raw = body[pos : pos + flen]
            pos += flen
            if ftype == 0:
                continue
            value = _decode_value(ftype, raw)
            if value is not None:
                values[ftype] = value
        return values

    # -- normalization ----------------------------------------------------

    def _to_event(self, v: dict[int, Any], ctx: _Context) -> NormalizedEvent | None:
        src_ip = v.get(F_SRC_IPV4) or v.get(F_SRC_IPV6)
        dst_ip = v.get(F_DST_IPV4) or v.get(F_DST_IPV6)
        if src_ip is None and dst_ip is None:
            # No usable flow identity. Reported as malformed, not fabricated.
            self.stats.records_malformed += 1
            return None

        ip_version = v.get(F_IP_VERSION)
        if ip_version not in (4, 6):
            ip_version = 6 if (F_SRC_IPV6 in v or F_DST_IPV6 in v) else 4

        sampling = v.get(F_SAMPLING_INTERVAL) or v.get(F_SAMPLING_PACKET_INTERVAL)
        exporter = {
            "exporter_id": ctx.exporter_id,
            "template_id": None,
            "observation_time": None,
            "sampling_rate": int(sampling) if sampling else None,
            "sampled": bool(sampling and sampling > 1),
        }

        capability = self._capability or CapabilityState(ctx.input_mode)
        if sampling and sampling > 1:
            capability.set("flow_sampling", Capability.OBSERVABLE)

        tcp_flags = v.get(F_TCP_FLAGS)

        return NormalizedEvent.from_flow(
            observed_time=ctx.flow_end_time(v),
            input_mode=ctx.input_mode,
            capability=capability,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=v.get(F_SRC_PORT),
            dst_port=v.get(F_DST_PORT),
            protocol=v.get(F_PROTOCOL),
            address_plan=self._plan,
            ip_version=ip_version,
            tcp_flags=tcp_flags if tcp_flags else None,
            packets=v.get(F_IN_PKTS),
            bytes=v.get(F_IN_BYTES),
            capture_source=self._source,
            exporter=exporter,
        )


__all__ = [
    "FlowRecordAdapter",
    "FlowRecordError",
    "TemplateCache",
    "TemplateKey",
    "Template",
    "TemplateCacheStats",
    "FlowDecodeStats",
    "NETFLOW_V9",
    "IPFIX",
    "DEFAULT_MAX_TEMPLATES",
    "DEFAULT_TEMPLATE_IDLE_S",
]
