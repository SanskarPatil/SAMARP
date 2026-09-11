"""Header-only packet decoding.

Parses link, network and transport headers and returns metadata. It never
retains, returns or inspects application payload contents - there is no field
on :class:`PacketHeaders` capable of carrying them.

This is the fast path. It is deliberately allocation-light: it slices only the
header bytes it needs from a memoryview and never copies the packet body.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from typing import Final

# ---------------------------------------------------------------- link types

LINKTYPE_NULL: Final = 0
LINKTYPE_ETHERNET: Final = 1
LINKTYPE_RAW: Final = 101
LINKTYPE_LINUX_SLL: Final = 113
LINKTYPE_IPV4: Final = 228
LINKTYPE_IPV6: Final = 229

SUPPORTED_LINKTYPES: Final = frozenset(
    {
        LINKTYPE_NULL,
        LINKTYPE_ETHERNET,
        LINKTYPE_RAW,
        LINKTYPE_LINUX_SLL,
        LINKTYPE_IPV4,
        LINKTYPE_IPV6,
    }
)

# ------------------------------------------------------------- ethertypes

ETH_IPV4: Final = 0x0800
ETH_IPV6: Final = 0x86DD
ETH_VLAN: Final = 0x8100
ETH_QINQ: Final = 0x88A8
ETH_QINQ_LEGACY: Final = 0x9100

# ------------------------------------------------------------- protocols

PROTO_ICMP: Final = 1
PROTO_TCP: Final = 6
PROTO_UDP: Final = 17
PROTO_ICMPV6: Final = 58

#: IPv6 extension headers that are skipped to reach the transport header.
#: 59 is "no next header" and terminates the chain.
_IPV6_EXT_HEADERS: Final = frozenset({0, 43, 44, 51, 60, 135, 139, 140})
_IPV6_NO_NEXT: Final = 59

_MAX_IPV6_EXT_CHAIN: Final = 8  # bounded: a crafted chain must not spin

_eth_hdr = struct.Struct("!6s6sH")
_vlan = struct.Struct("!HH")
_ipv4_hdr = struct.Struct("!BBHHHBBH4s4s")
_ipv6_hdr = struct.Struct("!IHBB16s16s")
_tcp_hdr = struct.Struct("!HHIIBBHHH")
_udp_hdr = struct.Struct("!HHHH")


class HeaderParseError(ValueError):
    """Raised when a packet cannot be decoded as far as requested.

    Callers count these and continue. A malformed packet is an observation
    about the capture, not a reason to abort a replay.
    """


@dataclass(slots=True)
class PacketHeaders:
    """Decoded header metadata for one packet. No payload, by construction."""

    ip_version: int | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: int | None = None
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: int | None = None
    ttl: int | None = None

    #: Bytes on the wire for this packet, from the capture record.
    wire_bytes: int = 0
    #: Length of the IP payload as declared by the IP header, where visible.
    ip_payload_bytes: int | None = None
    #: VLAN ids outermost-first, empty when untagged.
    vlan_ids: tuple[int, ...] = ()
    #: True when the IPv4 header signals a fragment.
    fragmented: bool = False
    #: True when parsing stopped before the transport header.
    transport_truncated: bool = False


def _read_vlan_stack(
    buf: memoryview, offset: int, ethertype: int
) -> tuple[int, int, tuple[int, ...]]:
    """Walk 802.1Q / QinQ tags. Returns (offset, ethertype, vlan_ids)."""
    vlans: list[int] = []
    while ethertype in (ETH_VLAN, ETH_QINQ, ETH_QINQ_LEGACY):
        if offset + 4 > len(buf):
            raise HeaderParseError("truncated VLAN tag")
        tci, ethertype = _vlan.unpack_from(buf, offset)
        vlans.append(tci & 0x0FFF)
        offset += 4
        if len(vlans) > 4:  # bounded
            raise HeaderParseError("excessive VLAN nesting")
    return offset, ethertype, tuple(vlans)


def _parse_link(
    buf: memoryview, linktype: int
) -> tuple[int, int | None, tuple[int, ...]]:
    """Return (offset_of_network_header, ethertype_or_None, vlan_ids)."""
    if linktype == LINKTYPE_ETHERNET:
        if len(buf) < _eth_hdr.size:
            raise HeaderParseError("truncated Ethernet header")
        _, _, ethertype = _eth_hdr.unpack_from(buf, 0)
        return _read_vlan_stack(buf, _eth_hdr.size, ethertype)

    if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        return 0, None, ()

    if linktype == LINKTYPE_NULL:
        if len(buf) < 4:
            raise HeaderParseError("truncated null/loopback header")
        # Host-endian AF_ value; only the low byte varies in practice.
        family = struct.unpack_from("<I", buf, 0)[0]
        if family > 0xFFFF:
            family = struct.unpack_from(">I", buf, 0)[0]
        if family == 2:
            return 4, ETH_IPV4, ()
        if family in (10, 23, 24, 28, 30):
            return 4, ETH_IPV6, ()
        raise HeaderParseError(f"unsupported null/loopback family {family}")

    if linktype == LINKTYPE_LINUX_SLL:
        if len(buf) < 16:
            raise HeaderParseError("truncated Linux SLL header")
        ethertype = struct.unpack_from("!H", buf, 14)[0]
        return _read_vlan_stack(buf, 16, ethertype)

    raise HeaderParseError(f"unsupported linktype {linktype}")


def _skip_ipv6_extensions(
    buf: memoryview, offset: int, next_header: int
) -> tuple[int, int]:
    """Walk the IPv6 extension chain to the transport header."""
    hops = 0
    while next_header in _IPV6_EXT_HEADERS:
        hops += 1
        if hops > _MAX_IPV6_EXT_CHAIN:
            raise HeaderParseError("excessive IPv6 extension chain")
        if offset + 2 > len(buf):
            raise HeaderParseError("truncated IPv6 extension header")
        nxt = buf[offset]
        ext_len = buf[offset + 1]
        if next_header == 44:  # fragment header is fixed 8 bytes
            offset += 8
        else:
            offset += (ext_len + 1) * 8
        next_header = nxt
    return offset, next_header


def parse_packet(
    data: bytes | memoryview,
    linktype: int,
    *,
    wire_bytes: int | None = None,
) -> PacketHeaders:
    """Decode header metadata from one captured packet.

    ``data`` is the captured bytes (which may be shorter than the wire length
    when the capture was snapped). Only header bytes are read; the payload is
    never touched.
    """
    buf = memoryview(data)
    hdr = PacketHeaders(wire_bytes=wire_bytes if wire_bytes is not None else len(buf))

    offset, ethertype, hdr.vlan_ids = _parse_link(buf, linktype)

    # Infer IP version when the link layer does not declare one.
    if ethertype is None:
        if offset >= len(buf):
            raise HeaderParseError("no network header present")
        version = buf[offset] >> 4
        if linktype == LINKTYPE_IPV4:
            version = 4
        elif linktype == LINKTYPE_IPV6:
            version = 6
    elif ethertype == ETH_IPV4:
        version = 4
    elif ethertype == ETH_IPV6:
        version = 6
    else:
        # Non-IP (ARP and friends). Counted, not an error worth aborting on.
        raise HeaderParseError(f"non-IP ethertype 0x{ethertype:04x}")

    if version == 4:
        if offset + _ipv4_hdr.size > len(buf):
            raise HeaderParseError("truncated IPv4 header")
        (
            ver_ihl,
            _tos,
            total_len,
            _ident,
            flags_frag,
            ttl,
            proto,
            _cksum,
            src,
            dst,
        ) = _ipv4_hdr.unpack_from(buf, offset)
        ihl = (ver_ihl & 0x0F) * 4
        if ihl < 20:
            raise HeaderParseError(f"invalid IPv4 IHL {ihl}")

        hdr.ip_version = 4
        hdr.src_ip = str(ipaddress.IPv4Address(src))
        hdr.dst_ip = str(ipaddress.IPv4Address(dst))
        hdr.protocol = proto
        hdr.ttl = ttl
        hdr.ip_payload_bytes = max(total_len - ihl, 0)
        # MF bit set, or a non-zero fragment offset.
        hdr.fragmented = bool(flags_frag & 0x2000) or bool(flags_frag & 0x1FFF)
        transport_offset = offset + ihl
        # A non-initial fragment carries no transport header.
        first_fragment = (flags_frag & 0x1FFF) == 0

    elif version == 6:
        if offset + _ipv6_hdr.size > len(buf):
            raise HeaderParseError("truncated IPv6 header")
        _vtf, payload_len, next_header, hop_limit, src6, dst6 = _ipv6_hdr.unpack_from(
            buf, offset
        )
        hdr.ip_version = 6
        hdr.src_ip = str(ipaddress.IPv6Address(src6))
        hdr.dst_ip = str(ipaddress.IPv6Address(dst6))
        hdr.ttl = hop_limit
        hdr.ip_payload_bytes = payload_len
        transport_offset, next_header = _skip_ipv6_extensions(
            buf, offset + _ipv6_hdr.size, next_header
        )
        hdr.protocol = None if next_header == _IPV6_NO_NEXT else next_header
        first_fragment = True

    else:
        raise HeaderParseError(f"unsupported IP version {version}")

    # --- transport ---------------------------------------------------
    if not first_fragment:
        hdr.transport_truncated = False
        return hdr

    if hdr.protocol == PROTO_TCP:
        if transport_offset + _tcp_hdr.size > len(buf):
            hdr.transport_truncated = True
            return hdr
        (
            sport,
            dport,
            _seq,
            _ack,
            _off_res,
            flags,
            _win,
            _ck,
            _urg,
        ) = _tcp_hdr.unpack_from(buf, transport_offset)
        hdr.src_port = sport
        hdr.dst_port = dport
        hdr.tcp_flags = flags

    elif hdr.protocol == PROTO_UDP:
        if transport_offset + _udp_hdr.size > len(buf):
            hdr.transport_truncated = True
            return hdr
        sport, dport, _ulen, _ck = _udp_hdr.unpack_from(buf, transport_offset)
        hdr.src_port = sport
        hdr.dst_port = dport

    elif hdr.protocol in (PROTO_ICMP, PROTO_ICMPV6):
        # Type/code are header metadata but carry no port semantics. Left
        # unset rather than faked into port fields.
        if transport_offset + 4 > len(buf):
            hdr.transport_truncated = True

    return hdr


__all__ = [
    "HeaderParseError",
    "PacketHeaders",
    "parse_packet",
    "SUPPORTED_LINKTYPES",
    "LINKTYPE_NULL",
    "LINKTYPE_ETHERNET",
    "LINKTYPE_RAW",
    "LINKTYPE_LINUX_SLL",
    "LINKTYPE_IPV4",
    "LINKTYPE_IPV6",
    "PROTO_TCP",
    "PROTO_UDP",
    "PROTO_ICMP",
    "PROTO_ICMPV6",
]
