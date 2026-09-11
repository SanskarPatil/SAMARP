"""Header-only decoding: link, network and transport metadata."""

from __future__ import annotations

import pytest

from ingest.headers import (
    LINKTYPE_ETHERNET,
    LINKTYPE_NULL,
    LINKTYPE_RAW,
    PROTO_ICMP,
    PROTO_TCP,
    PROTO_UDP,
    HeaderParseError,
    parse_packet,
)

from pcap_builder import (  # noqa: E402  (tests/ingest is on sys.path via pytest)
    ACK,
    ETH_ARP,
    ETH_IPV6,
    FIN,
    PSH,
    RST,
    SYN,
    arp,
    ethernet,
    ipv4,
    ipv6,
    tcp,
    udp,
)

LAB = "10.10.0.5"
EXT = "93.184.216.34"


# ------------------------------------------------------------------ IPv4


def test_ipv4_tcp_metadata():
    pkt = ethernet(ipv4(LAB, EXT, PROTO_TCP, tcp(44321, 443, SYN)))
    h = parse_packet(pkt, LINKTYPE_ETHERNET)
    assert h.ip_version == 4
    assert h.src_ip == LAB
    assert h.dst_ip == EXT
    assert h.protocol == PROTO_TCP
    assert h.src_port == 44321
    assert h.dst_port == 443
    assert h.tcp_flags == SYN
    assert h.ttl == 64


def test_ipv4_udp_metadata():
    pkt = ethernet(ipv4(LAB, "10.10.0.53", PROTO_UDP, udp(51000, 53, b"\x00" * 12)))
    h = parse_packet(pkt, LINKTYPE_ETHERNET)
    assert h.protocol == PROTO_UDP
    assert (h.src_port, h.dst_port) == (51000, 53)
    assert h.tcp_flags is None


@pytest.mark.parametrize("flags", [SYN, SYN | ACK, ACK, FIN | ACK, RST, PSH | ACK])
def test_tcp_flag_combinations_round_trip(flags):
    pkt = ethernet(ipv4(LAB, EXT, PROTO_TCP, tcp(1, 2, flags)))
    assert parse_packet(pkt, LINKTYPE_ETHERNET).tcp_flags == flags


def test_ipv4_options_are_skipped_via_ihl():
    pkt = ethernet(ipv4(LAB, EXT, PROTO_TCP, tcp(1234, 80, SYN), ihl_words=7))
    h = parse_packet(pkt, LINKTYPE_ETHERNET)
    assert (h.src_port, h.dst_port) == (1234, 80), "IHL must drive the transport offset"


def test_invalid_ihl_is_rejected():
    bad = ethernet(bytes([0x43]) + b"\x00" * 40)  # version 4, IHL 3 -> 12 bytes
    with pytest.raises(HeaderParseError, match="invalid IPv4 IHL"):
        parse_packet(bad, LINKTYPE_ETHERNET)


def test_fragmented_packet_is_flagged():
    # MF bit set.
    pkt = ethernet(ipv4(LAB, EXT, PROTO_TCP, tcp(1, 2, SYN), flags_frag=0x2000))
    assert parse_packet(pkt, LINKTYPE_ETHERNET).fragmented is True


def test_non_initial_fragment_has_no_transport_ports():
    # Fragment offset non-zero: no transport header present.
    pkt = ethernet(ipv4(LAB, EXT, PROTO_TCP, b"\x00" * 20, flags_frag=0x0010))
    h = parse_packet(pkt, LINKTYPE_ETHERNET)
    assert h.fragmented is True
    assert h.src_port is None and h.dst_port is None


# ------------------------------------------------------------------ IPv6


def test_ipv6_udp_metadata():
    pkt = ethernet(
        ipv6("2001:db8::1", "2001:db8::2", PROTO_UDP, udp(1234, 53)),
        ethertype=ETH_IPV6,
    )
    h = parse_packet(pkt, LINKTYPE_ETHERNET)
    assert h.ip_version == 6
    assert h.src_ip == "2001:db8::1"
    assert h.dst_ip == "2001:db8::2"
    assert (h.src_port, h.dst_port) == (1234, 53)


def test_ipv6_extension_header_is_walked():
    # Hop-by-hop (0) of 8 bytes, then UDP.
    ext = bytes([PROTO_UDP, 0]) + b"\x00" * 6
    pkt = ethernet(
        ipv6("2001:db8::1", "2001:db8::2", 0, ext + udp(7000, 53)),
        ethertype=ETH_IPV6,
    )
    h = parse_packet(pkt, LINKTYPE_ETHERNET)
    assert h.protocol == PROTO_UDP
    assert (h.src_port, h.dst_port) == (7000, 53)


def test_ipv6_extension_chain_is_bounded():
    # A crafted chain must not spin: many hop-by-hop headers pointing on.
    chain = b"".join(bytes([0, 0]) + b"\x00" * 6 for _ in range(20))
    pkt = ethernet(ipv6("2001:db8::1", "2001:db8::2", 0, chain), ethertype=ETH_IPV6)
    with pytest.raises(HeaderParseError, match="excessive IPv6 extension chain"):
        parse_packet(pkt, LINKTYPE_ETHERNET)


# ------------------------------------------------------------- link types


def test_vlan_tag_is_stripped_and_recorded():
    pkt = ethernet(ipv4(LAB, EXT, PROTO_TCP, tcp(1, 2, SYN)), vlan=42)
    h = parse_packet(pkt, LINKTYPE_ETHERNET)
    assert h.vlan_ids == (42,)
    assert h.src_ip == LAB


def test_raw_linktype_needs_no_ethernet_header():
    pkt = ipv4(LAB, EXT, PROTO_TCP, tcp(1, 2, SYN))
    h = parse_packet(pkt, LINKTYPE_RAW)
    assert h.src_ip == LAB


def test_null_loopback_linktype():
    pkt = (2).to_bytes(4, "little") + ipv4(LAB, EXT, PROTO_UDP, udp(1, 2))
    h = parse_packet(pkt, LINKTYPE_NULL)
    assert h.ip_version == 4 and h.dst_port == 2


def test_unsupported_linktype_is_rejected():
    with pytest.raises(HeaderParseError, match="unsupported linktype"):
        parse_packet(b"\x00" * 40, 9999)


# ------------------------------------------------------------- malformed


def test_non_ip_ethertype_is_reported_not_crashed():
    with pytest.raises(HeaderParseError, match="non-IP ethertype"):
        parse_packet(ethernet(arp(), ethertype=ETH_ARP), LINKTYPE_ETHERNET)


def test_truncated_ethernet_header():
    with pytest.raises(HeaderParseError, match="truncated Ethernet"):
        parse_packet(b"\x00" * 6, LINKTYPE_ETHERNET)


def test_truncated_ip_header():
    with pytest.raises(HeaderParseError, match="truncated IPv4"):
        parse_packet(ethernet(b"\x45\x00\x00"), LINKTYPE_ETHERNET)


def test_transport_truncated_is_flagged_rather_than_faked():
    """A snapped capture must not invent ports."""
    full = ethernet(ipv4(LAB, EXT, PROTO_TCP, tcp(44321, 443, SYN)))
    snapped = full[:38]  # past the IP header, short of the full TCP header
    h = parse_packet(snapped, LINKTYPE_ETHERNET, wire_bytes=len(full))
    assert h.src_ip == LAB
    assert h.transport_truncated is True
    assert h.src_port is None and h.dst_port is None


def test_wire_bytes_reflect_the_original_length():
    full = ethernet(ipv4(LAB, EXT, PROTO_TCP, tcp(1, 2, SYN)))
    h = parse_packet(full[:40], LINKTYPE_ETHERNET, wire_bytes=len(full))
    assert h.wire_bytes == len(full)


def test_icmp_has_no_port_semantics():
    pkt = ethernet(ipv4(LAB, EXT, PROTO_ICMP, b"\x08\x00\x00\x00"))
    h = parse_packet(pkt, LINKTYPE_ETHERNET)
    assert h.protocol == PROTO_ICMP
    # Ports are left unset rather than faked from ICMP type/code.
    assert h.src_port is None and h.dst_port is None


# ------------------------------------------------- header-only guarantee


def test_parsed_headers_expose_no_payload_field():
    """Structural: there is nowhere for payload to live."""
    pkt = ethernet(ipv4(LAB, EXT, PROTO_TCP, tcp(1, 2, PSH | ACK, b"SECRET-BYTES")))
    h = parse_packet(pkt, LINKTYPE_ETHERNET)
    fields = set(h.__slots__)
    for banned in ("payload", "data", "body", "content", "raw"):
        assert banned not in fields, banned
    assert b"SECRET" not in repr(h).encode()
