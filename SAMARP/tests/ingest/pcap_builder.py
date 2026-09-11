"""Deterministic PCAP fixture builder for P1 ingest tests.

Pure standard library. Writes classic libpcap files byte-for-byte, so tests
never depend on real internet traffic, a capture device, or a third-party
library.

These fixtures belong to P1's ingest tests. The attack/benign PCAP corpora
under scenarios/ are P2's and are not touched here.

Every packet carries a zero-filled payload of the requested length. Nothing
in the pipeline reads it - that is the point. The structural no-payload-field
assertion in test_normalized_event.py is what actually guarantees the
header-only boundary.
"""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

MAGIC_US_LE = 0xA1B2C3D4
MAGIC_US_BE = 0xD4C3B2A1
MAGIC_NS_LE = 0xA1B23C4D
MAGIC_PCAPNG = 0x0A0D0D0A

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_ARP = 0x0806
ETH_VLAN = 0x8100

PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1

# TCP flag bits
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def _ipv4(addr: str) -> bytes:
    return bytes(int(p) for p in addr.split("."))


def _ipv6(addr: str) -> bytes:
    return ipaddress.IPv6Address(addr).packed


def ethernet(
    payload: bytes, ethertype: int = ETH_IPV4, vlan: int | None = None
) -> bytes:
    """Ethernet II frame with fixed, deterministic MAC addresses."""
    dst_mac = bytes.fromhex("020000000001")
    src_mac = bytes.fromhex("020000000002")
    if vlan is not None:
        return (
            dst_mac
            + src_mac
            + struct.pack("!H", ETH_VLAN)
            + struct.pack("!HH", vlan & 0x0FFF, ethertype)
            + payload
        )
    return dst_mac + src_mac + struct.pack("!H", ethertype) + payload


def ipv4(
    src: str,
    dst: str,
    proto: int,
    payload: bytes,
    *,
    ttl: int = 64,
    ihl_words: int = 5,
    flags_frag: int = 0,
) -> bytes:
    """IPv4 header + payload. Checksum is left zero - never validated."""
    options = b"\x00" * ((ihl_words - 5) * 4)
    total_len = ihl_words * 4 + len(payload)
    return (
        struct.pack(
            "!BBHHHBBH",
            (4 << 4) | ihl_words,
            0,
            total_len,
            0x1234,
            flags_frag,
            ttl,
            proto,
            0,
        )
        + _ipv4(src)
        + _ipv4(dst)
        + options
        + payload
    )


def ipv6(
    src: str, dst: str, next_header: int, payload: bytes, *, hop_limit: int = 64
) -> bytes:
    return (
        struct.pack("!IHBB", 6 << 28, len(payload), next_header, hop_limit)
        + _ipv6(src)
        + _ipv6(dst)
        + payload
    )


def tcp(sport: int, dport: int, flags: int = SYN, payload: bytes = b"") -> bytes:
    return (
        struct.pack("!HHIIBBHHH", sport, dport, 1000, 0, (5 << 4), flags, 8192, 0, 0)
        + payload
    )


def udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def arp() -> bytes:
    """A non-IP frame. Must be counted as unparseable, not crash the replay."""
    return b"\x00" * 28


class PcapWriter:
    """Build a classic pcap file in memory, then write it."""

    def __init__(
        self,
        *,
        linktype: int = LINKTYPE_ETHERNET,
        magic: int = MAGIC_US_LE,
        snaplen: int = 65535,
    ) -> None:
        self.linktype = linktype
        self.magic = magic
        self.snaplen = snaplen
        self.endian = ">" if magic == MAGIC_US_BE else "<"
        self.nanosecond = magic == MAGIC_NS_LE
        self._records: list[bytes] = []

    def add(
        self,
        packet: bytes,
        timestamp: float,
        *,
        wirelen: int | None = None,
        caplen: int | None = None,
    ) -> "PcapWriter":
        """Append one record.

        ``wirelen`` larger than the packet simulates a snapped capture, which
        the reader reports as truncated - capture-loss evidence.
        """
        cap = len(packet) if caplen is None else caplen
        wire = cap if wirelen is None else wirelen
        sec = int(timestamp)
        frac = timestamp - sec
        sub = int(round(frac * (1_000_000_000 if self.nanosecond else 1_000_000)))
        self._records.append(
            struct.pack(self.endian + "IIII", sec, sub, cap, wire) + packet[:cap]
        )
        return self

    def add_raw_record(self, raw: bytes) -> "PcapWriter":
        """Append arbitrary bytes - used to build malformed fixtures."""
        self._records.append(raw)
        return self

    def to_bytes(self) -> bytes:
        # A big-endian capture stores the CANONICAL magic (a1b2c3d4) in
        # big-endian byte order; a little-endian reader then sees d4c3b2a1
        # and infers the swap. Writing the swapped value would produce a
        # file that reads back as little-endian - which is exactly the bug
        # test_all_supported_magics_are_read caught.
        canonical_magic = MAGIC_NS_LE if self.nanosecond else MAGIC_US_LE
        header = struct.pack(
            self.endian + "IHHiIII",
            canonical_magic,
            2,
            4,
            0,
            0,
            self.snaplen,
            self.linktype,
        )
        return header + b"".join(self._records)

    def write(self, path: str | Path) -> Path:
        p = Path(path)
        p.write_bytes(self.to_bytes())
        return p


def simple_capture(path: str | Path) -> Path:
    """The canonical deterministic fixture used across replay tests.

    Six packets, fixed timestamps one second apart, covering:
      1. TCP SYN     outbound  (enclave -> external)
      2. TCP SYN-ACK inbound   (external -> enclave, reverse of #1)
      3. UDP DNS     internal  (enclave -> enclave resolver)
      4. IPv6 UDP    external
      5. ARP                   (non-IP - unparseable, counted)
      6. TCP SYN     outbound, snapped (truncated - capture-loss evidence)
    """
    w = PcapWriter()
    base = CAPTURE_BASE_TS

    w.add(
        ethernet(ipv4("10.10.0.5", "93.184.216.34", PROTO_TCP, tcp(44321, 443, SYN))),
        base + 0.0,
    )
    w.add(
        ethernet(
            ipv4("93.184.216.34", "10.10.0.5", PROTO_TCP, tcp(443, 44321, SYN | ACK))
        ),
        base + 1.0,
    )
    w.add(
        ethernet(
            ipv4("10.10.0.5", "10.10.0.53", PROTO_UDP, udp(51000, 53, b"\x00" * 24))
        ),
        base + 2.0,
    )
    w.add(
        ethernet(
            ipv6("2001:db8::1", "2001:db8::2", PROTO_UDP, udp(1234, 53, b"\x00" * 8)),
            ethertype=ETH_IPV6,
        ),
        base + 3.0,
    )
    w.add(ethernet(arp(), ethertype=ETH_ARP), base + 4.0)
    full = ethernet(ipv4("10.10.0.9", "93.184.216.34", PROTO_TCP, tcp(40000, 80, SYN)))
    w.add(full, base + 5.0, caplen=34, wirelen=len(full))

    return w.write(path)


#: Fixed epoch so fixtures are byte-identical on every machine.
CAPTURE_BASE_TS = 1_757_500_000.0
SIMPLE_CAPTURE_PACKETS = 6
SIMPLE_CAPTURE_PARSEABLE = 5  # ARP is not IP
SIMPLE_CAPTURE_TRUNCATED = 1


__all__ = [
    "PcapWriter",
    "simple_capture",
    "ethernet",
    "ipv4",
    "ipv6",
    "tcp",
    "udp",
    "arp",
    "MAGIC_US_LE",
    "MAGIC_US_BE",
    "MAGIC_NS_LE",
    "MAGIC_PCAPNG",
    "LINKTYPE_ETHERNET",
    "LINKTYPE_RAW",
    "ETH_IPV4",
    "ETH_IPV6",
    "ETH_ARP",
    "PROTO_TCP",
    "PROTO_UDP",
    "PROTO_ICMP",
    "SYN",
    "ACK",
    "FIN",
    "RST",
    "PSH",
    "CAPTURE_BASE_TS",
    "SIMPLE_CAPTURE_PACKETS",
    "SIMPLE_CAPTURE_PARSEABLE",
    "SIMPLE_CAPTURE_TRUNCATED",
]
