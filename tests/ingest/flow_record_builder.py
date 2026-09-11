"""Deterministic NetFlow v9 / IPFIX fixture builder.

Pure standard library. Builds datagrams byte-for-byte so tests never need a
real exporter, a network, or a third-party library.

Production fixtures are exported at build time from project PCAPs with yaf,
nfpcapd or softflowd and vendored offline (V6.3 Ticket 9). These synthetic
ones exist so P1 can test decode paths - malformed sets, unknown templates,
template replacement - that a well-formed capture never exercises.
"""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

NETFLOW_V9 = 9
IPFIX = 10

NF9_TEMPLATE_SET = 0
NF9_OPTIONS_SET = 1
IPFIX_TEMPLATE_SET = 2
IPFIX_OPTIONS_SET = 3

# Field type IDs (shared 1-127 across both protocols).
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
F_FLOW_END_SECONDS = 151

#: Fixed export time so fixtures are identical on every machine.
EXPORT_TIME = 1_757_500_000
SYS_UPTIME_MS = 1_000_000

#: The standard five-tuple template used across tests.
BASIC_FIELDS = (
    (F_SRC_IPV4, 4),
    (F_DST_IPV4, 4),
    (F_SRC_PORT, 2),
    (F_DST_PORT, 2),
    (F_PROTOCOL, 1),
    (F_IN_PKTS, 4),
    (F_IN_BYTES, 4),
)

#: A different layout, for template-replacement tests. Same template ID,
#: different fields - decoding a new record with the old layout would give
#: garbage, which is exactly why replacement must take effect.
EXTENDED_FIELDS = (
    (F_SRC_IPV4, 4),
    (F_DST_IPV4, 4),
    (F_SRC_PORT, 2),
    (F_DST_PORT, 2),
    (F_PROTOCOL, 1),
    (F_TCP_FLAGS, 1),
    (F_IN_PKTS, 4),
    (F_IN_BYTES, 4),
)

IPV6_FIELDS = (
    (F_SRC_IPV6, 16),
    (F_DST_IPV6, 16),
    (F_SRC_PORT, 2),
    (F_DST_PORT, 2),
    (F_PROTOCOL, 1),
    (F_IP_VERSION, 1),
    (F_IN_PKTS, 4),
    (F_IN_BYTES, 4),
)


def template_set(template_id: int, fields, *, set_id: int) -> bytes:
    """One template set holding a single template."""
    body = struct.pack("!HH", template_id, len(fields))
    for ftype, flen in fields:
        body += struct.pack("!HH", ftype, flen)
    return struct.pack("!HH", set_id, 4 + len(body)) + body


def nf9_template_set(template_id: int, fields=BASIC_FIELDS) -> bytes:
    return template_set(template_id, fields, set_id=NF9_TEMPLATE_SET)


def ipfix_template_set(template_id: int, fields=BASIC_FIELDS) -> bytes:
    return template_set(template_id, fields, set_id=IPFIX_TEMPLATE_SET)


def basic_record(
    src="10.10.0.5",
    dst="93.184.216.34",
    sport=44321,
    dport=443,
    proto=6,
    packets=10,
    octets=1500,
) -> bytes:
    return (
        ipaddress.IPv4Address(src).packed
        + ipaddress.IPv4Address(dst).packed
        + struct.pack("!HHB", sport, dport, proto)
        + struct.pack("!II", packets, octets)
    )


def extended_record(
    src="10.10.0.5",
    dst="93.184.216.34",
    sport=44321,
    dport=443,
    proto=6,
    flags=0x02,
    packets=10,
    octets=1500,
) -> bytes:
    return (
        ipaddress.IPv4Address(src).packed
        + ipaddress.IPv4Address(dst).packed
        + struct.pack("!HHBB", sport, dport, proto, flags)
        + struct.pack("!II", packets, octets)
    )


def ipv6_record(
    src="2001:db8::1",
    dst="2001:db8::2",
    sport=1234,
    dport=53,
    proto=17,
    packets=4,
    octets=400,
) -> bytes:
    return (
        ipaddress.IPv6Address(src).packed
        + ipaddress.IPv6Address(dst).packed
        + struct.pack("!HHBB", sport, dport, proto, 6)
        + struct.pack("!II", packets, octets)
    )


def data_set(template_id: int, records: list[bytes]) -> bytes:
    body = b"".join(records)
    return struct.pack("!HH", template_id, 4 + len(body)) + body


def nf9_datagram(*sets: bytes, record_count: int = 1, sequence: int = 1) -> bytes:
    """NetFlow v9 datagram. Header counts RECORDS, not bytes."""
    header = struct.pack(
        "!HHIIII",
        NETFLOW_V9,
        record_count,
        SYS_UPTIME_MS,
        EXPORT_TIME,
        sequence,
        1,  # source_id / observation domain
    )
    return header + b"".join(sets)


def ipfix_datagram(*sets: bytes, sequence: int = 1, domain: int = 1) -> bytes:
    """IPFIX datagram. Header carries total LENGTH in bytes."""
    body = b"".join(sets)
    length = 16 + len(body)
    header = struct.pack("!HHIII", IPFIX, length, EXPORT_TIME, sequence, domain)
    return header + body


# ------------------------------------------------------- canonical fixtures


def netflow_v9_fixture(path) -> Path:
    """Template followed by three data records, one datagram."""
    dgram = nf9_datagram(
        nf9_template_set(256),
        data_set(
            256,
            [
                basic_record(),
                basic_record(
                    src="10.10.0.9", sport=40000, dport=80, packets=2, octets=120
                ),
                basic_record(
                    src="93.184.216.34",
                    dst="10.10.0.5",
                    sport=443,
                    dport=44321,
                    packets=8,
                    octets=9000,
                ),
            ],
        ),
        record_count=3,
    )
    p = Path(path)
    p.write_bytes(dgram)
    return p


def ipfix_fixture(path) -> Path:
    """Template followed by two data records, one datagram."""
    dgram = ipfix_datagram(
        ipfix_template_set(256),
        data_set(
            256,
            [
                basic_record(),
                basic_record(
                    src="10.10.0.7",
                    sport=51000,
                    dport=53,
                    proto=17,
                    packets=1,
                    octets=90,
                ),
            ],
        ),
    )
    p = Path(path)
    p.write_bytes(dgram)
    return p


NETFLOW_V9_FIXTURE_RECORDS = 3
IPFIX_FIXTURE_RECORDS = 2


__all__ = [
    "NETFLOW_V9",
    "IPFIX",
    "EXPORT_TIME",
    "SYS_UPTIME_MS",
    "BASIC_FIELDS",
    "EXTENDED_FIELDS",
    "IPV6_FIELDS",
    "template_set",
    "nf9_template_set",
    "ipfix_template_set",
    "basic_record",
    "extended_record",
    "ipv6_record",
    "data_set",
    "nf9_datagram",
    "ipfix_datagram",
    "netflow_v9_fixture",
    "ipfix_fixture",
    "NETFLOW_V9_FIXTURE_RECORDS",
    "IPFIX_FIXTURE_RECORDS",
    "F_TCP_FLAGS",
    "F_SAMPLING_INTERVAL",
    "F_SRC_IPV4",
    "F_DST_IPV4",
    "F_SRC_PORT",
    "F_DST_PORT",
    "F_PROTOCOL",
    "F_IN_PKTS",
    "F_IN_BYTES",
    "NF9_OPTIONS_SET",
    "IPFIX_OPTIONS_SET",
]
