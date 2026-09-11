"""Classic pcap reading, including malformed input.

A malformed FILE is fatal. A malformed RECORD is counted and skipped - one
bad packet must not abandon a replay mid-demo.
"""

from __future__ import annotations

import struct

import pytest

from ingest.pcap import (
    MAX_RECORD_BYTES,
    PcapError,
    PcapFormatError,
    PcapReader,
    peek_first_timestamp,
)

from pcap_builder import (  # noqa: E402  (tests/ingest is on sys.path via pytest)
    CAPTURE_BASE_TS,
    LINKTYPE_RAW,
    MAGIC_NS_LE,
    MAGIC_PCAPNG,
    MAGIC_US_BE,
    MAGIC_US_LE,
    PROTO_TCP,
    SYN,
    PcapWriter,
    ethernet,
    ipv4,
    simple_capture,
    tcp,
)


def _one_packet() -> bytes:
    return ethernet(ipv4("10.10.0.5", "93.184.216.34", PROTO_TCP, tcp(1234, 443, SYN)))


# ------------------------------------------------------------- file header


@pytest.mark.parametrize("magic", [MAGIC_US_LE, MAGIC_US_BE, MAGIC_NS_LE])
def test_all_supported_magics_are_read(tmp_path, magic):
    p = (
        PcapWriter(magic=magic)
        .add(_one_packet(), CAPTURE_BASE_TS)
        .write(tmp_path / "m.pcap")
    )
    with PcapReader(p) as r:
        records = list(r)
    assert len(records) == 1
    assert records[0].timestamp == pytest.approx(CAPTURE_BASE_TS)


def test_nanosecond_resolution_is_preserved(tmp_path):
    ts = CAPTURE_BASE_TS + 0.123456789
    p = PcapWriter(magic=MAGIC_NS_LE).add(_one_packet(), ts).write(tmp_path / "ns.pcap")
    with PcapReader(p) as r:
        rec = next(iter(r))
    assert rec.timestamp == pytest.approx(ts, abs=1e-9)


def test_header_exposes_linktype_and_snaplen(tmp_path):
    p = (
        PcapWriter(linktype=LINKTYPE_RAW, snaplen=1500)
        .add(_one_packet(), CAPTURE_BASE_TS)
        .write(tmp_path / "h.pcap")
    )
    with PcapReader(p) as r:
        assert r.header.linktype == LINKTYPE_RAW
        assert r.header.snaplen == 1500
        assert r.header.linktype_supported


def test_unsupported_linktype_is_flagged_not_guessed(tmp_path):
    p = (
        PcapWriter(linktype=999)
        .add(_one_packet(), CAPTURE_BASE_TS)
        .write(tmp_path / "lt.pcap")
    )
    with PcapReader(p) as r:
        assert r.header.linktype_supported is False


# ------------------------------------------------------- malformed files


def test_pcapng_is_rejected_with_an_actionable_message(tmp_path):
    p = tmp_path / "ng.pcapng"
    p.write_bytes(struct.pack("<I", MAGIC_PCAPNG) + b"\x00" * 40)
    with pytest.raises(PcapFormatError, match="PCAPNG"):
        PcapReader(p)


def test_pcapng_error_names_the_conversion_command(tmp_path):
    p = tmp_path / "ng.pcapng"
    p.write_bytes(struct.pack("<I", MAGIC_PCAPNG) + b"\x00" * 40)
    with pytest.raises(PcapFormatError, match="editcap"):
        PcapReader(p)


def test_unknown_magic_is_rejected(tmp_path):
    p = tmp_path / "junk.pcap"
    p.write_bytes(b"\xde\xad\xbe\xef" + b"\x00" * 40)
    with pytest.raises(PcapFormatError, match="unrecognised pcap magic"):
        PcapReader(p)


def test_empty_file_is_rejected(tmp_path):
    p = tmp_path / "empty.pcap"
    p.write_bytes(b"")
    with pytest.raises(PcapFormatError, match="empty"):
        PcapReader(p)


def test_file_shorter_than_header_is_rejected(tmp_path):
    p = tmp_path / "short.pcap"
    p.write_bytes(struct.pack("<I", MAGIC_US_LE) + b"\x00" * 4)
    with pytest.raises(PcapFormatError, match="shorter than a pcap header"):
        PcapReader(p)


def test_missing_file_is_rejected(tmp_path):
    with pytest.raises(PcapError, match="not found"):
        PcapReader(tmp_path / "nope.pcap")


# ----------------------------------------------------- malformed records


def test_valid_records_before_a_truncated_tail_are_still_read(tmp_path):
    w = PcapWriter()
    w.add(_one_packet(), CAPTURE_BASE_TS)
    w.add(_one_packet(), CAPTURE_BASE_TS + 1)
    # A record header claiming more bytes than remain.
    w.add_raw_record(struct.pack("<IIII", 1, 0, 500, 500) + b"\x00" * 10)
    p = w.write(tmp_path / "tail.pcap")

    with PcapReader(p) as r:
        records = list(r)
        stats = r.stats

    assert len(records) == 2, "good records before the bad tail must survive"
    assert stats.records_read == 2
    assert stats.records_malformed == 1


def test_partial_record_header_is_counted_and_stops_cleanly(tmp_path):
    w = PcapWriter()
    w.add(_one_packet(), CAPTURE_BASE_TS)
    w.add_raw_record(b"\x00" * 7)  # shorter than a 16-byte record header
    p = w.write(tmp_path / "partial.pcap")

    with PcapReader(p) as r:
        records = list(r)
        assert len(records) == 1
        assert r.stats.records_malformed == 1


def test_caplen_greater_than_wirelen_is_skipped_but_replay_continues(tmp_path):
    pkt = _one_packet()
    w = PcapWriter()
    w.add_raw_record(struct.pack("<IIII", 1, 0, len(pkt), 4) + pkt)  # impossible
    w.add(pkt, CAPTURE_BASE_TS)
    p = w.write(tmp_path / "impossible.pcap")

    with PcapReader(p) as r:
        records = list(r)
        assert len(records) == 1, "reader must continue past one bad record"
        assert r.stats.records_malformed == 1


def test_absurd_record_length_does_not_allocate(tmp_path):
    w = PcapWriter()
    w.add_raw_record(
        struct.pack("<IIII", 1, 0, MAX_RECORD_BYTES + 1, MAX_RECORD_BYTES + 1)
    )
    p = w.write(tmp_path / "huge.pcap")
    with PcapReader(p) as r:
        assert list(r) == []
        assert r.stats.records_malformed == 1


# ------------------------------------------------------------- statistics


def test_truncated_capture_is_reported_not_hidden(tmp_path):
    pkt = _one_packet()
    p = (
        PcapWriter()
        .add(pkt, CAPTURE_BASE_TS, caplen=20, wirelen=len(pkt))
        .write(tmp_path / "snap.pcap")
    )
    with PcapReader(p) as r:
        rec = next(iter(r))
        assert rec.truncated is True
        assert r.stats.records_truncated == 1


def test_stats_track_bytes_and_timestamps(tmp_path):
    p = simple_capture(tmp_path / "s.pcap")
    with PcapReader(p) as r:
        list(r)
        s = r.stats
    assert s.records_read == 6
    assert s.wire_bytes > s.captured_bytes  # one snapped packet
    assert s.first_timestamp == pytest.approx(CAPTURE_BASE_TS)
    assert s.last_timestamp == pytest.approx(CAPTURE_BASE_TS + 5.0)


def test_peek_first_timestamp_does_not_disturb_a_later_read(tmp_path):
    p = simple_capture(tmp_path / "s.pcap")
    first = peek_first_timestamp(p)
    assert first == pytest.approx(CAPTURE_BASE_TS)
    with PcapReader(p) as r:
        assert len(list(r)) == 6


def test_peek_on_empty_capture_returns_none(tmp_path):
    p = PcapWriter().write(tmp_path / "none.pcap")
    assert peek_first_timestamp(p) is None


def test_reader_closes_its_own_file(tmp_path):
    p = simple_capture(tmp_path / "s.pcap")
    r = PcapReader(p)
    list(r)
    r.close()
    # Closing twice must not raise.
    r.close()
