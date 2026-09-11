"""Classic libpcap reader - header-only, pure standard library.

No third-party dependency. The capture file format is simple enough that
vendoring a parser would add an offline-bundle liability for no benefit, and
a header-only reader is exactly what the architecture permits.

Supported magics (all four, both endiannesses)::

    a1b2c3d4 / d4c3b2a1   microsecond resolution
    a1b23c4d / 4d3cb2a1   nanosecond  resolution

PCAPNG is DETECTED AND REJECTED with an actionable message rather than
mis-parsed. V6.3's replay path is tcpreplay-driven classic pcap; converting
is a one-line ``editcap``. Silently misreading a pcapng file would produce
plausible-looking garbage, which is worse than failing.

Error policy
------------
* A malformed FILE header is fatal - there is nothing to replay.
* A malformed RECORD is counted and skipped; replay continues. A truncated
  or corrupt packet is an observation about the capture, not a reason to
  abandon a run mid-demo.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Final, Iterator

from .headers import SUPPORTED_LINKTYPES

# --------------------------------------------------------------------- magics

_MAGIC_US_LE: Final = 0xA1B2C3D4
_MAGIC_US_BE: Final = 0xD4C3B2A1
_MAGIC_NS_LE: Final = 0xA1B23C4D
_MAGIC_NS_BE: Final = 0x4D3CB2A1
_MAGIC_PCAPNG: Final = 0x0A0D0D0A

_FILE_HEADER_LEN: Final = 24
_RECORD_HEADER_LEN: Final = 16

#: Refuse absurd record lengths rather than attempting a huge allocation.
#: A crafted caplen must not be able to exhaust memory.
MAX_RECORD_BYTES: Final = 16 * 1024 * 1024


class PcapError(ValueError):
    """Fatal: the file cannot be read as a classic pcap capture."""


class PcapFormatError(PcapError):
    """The file is not classic pcap (wrong or unrecognised magic)."""


@dataclass(frozen=True, slots=True)
class PcapFileHeader:
    """Decoded 24-byte capture file header."""

    magic: int
    endian: str  # "<" or ">"
    nanosecond: bool
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    linktype: int

    @property
    def linktype_supported(self) -> bool:
        return self.linktype in SUPPORTED_LINKTYPES


@dataclass(slots=True)
class PcapRecord:
    """One capture record. Carries header metadata and the captured bytes.

    ``data`` holds ONLY what the reader must hand to the header parser. It is
    not retained by the reader once the caller advances the iterator, and
    nothing downstream stores it.
    """

    timestamp: float
    caplen: int
    wirelen: int
    data: bytes
    index: int

    @property
    def truncated(self) -> bool:
        """True when the capture was snapped shorter than the wire length.

        This is capture-loss evidence and is surfaced, not hidden.
        """
        return self.caplen < self.wirelen


@dataclass(slots=True)
class PcapReadStats:
    """Counters for one pass over a capture file."""

    records_read: int = 0
    records_malformed: int = 0
    records_truncated: int = 0
    captured_bytes: int = 0
    wire_bytes: int = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "records_read": self.records_read,
            "records_malformed": self.records_malformed,
            "records_truncated": self.records_truncated,
            "captured_bytes": self.captured_bytes,
            "wire_bytes": self.wire_bytes,
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
        }


def _decode_file_header(raw: bytes) -> PcapFileHeader:
    if len(raw) < _FILE_HEADER_LEN:
        raise PcapFormatError(
            f"file shorter than a pcap header ({len(raw)} < {_FILE_HEADER_LEN} bytes)"
        )

    magic_le = struct.unpack_from("<I", raw, 0)[0]

    if magic_le == _MAGIC_PCAPNG:
        raise PcapFormatError(
            "file is PCAPNG, not classic pcap. Convert it first, e.g. "
            "`editcap -F pcap input.pcapng output.pcap`. The replay path is "
            "classic pcap by design; misreading pcapng would yield "
            "plausible-looking garbage."
        )

    if magic_le == _MAGIC_US_LE:
        endian, nanosecond = "<", False
    elif magic_le == _MAGIC_NS_LE:
        endian, nanosecond = "<", True
    elif magic_le == _MAGIC_US_BE:
        endian, nanosecond = ">", False
    elif magic_le == _MAGIC_NS_BE:
        endian, nanosecond = ">", True
    else:
        raise PcapFormatError(f"unrecognised pcap magic 0x{magic_le:08x}")

    (
        magic,
        vmaj,
        vmin,
        thiszone,
        sigfigs,
        snaplen,
        linktype,
    ) = struct.unpack_from(endian + "IHHiIII", raw, 0)

    return PcapFileHeader(
        magic=magic,
        endian=endian,
        nanosecond=nanosecond,
        version_major=vmaj,
        version_minor=vmin,
        thiszone=thiszone,
        sigfigs=sigfigs,
        snaplen=snaplen,
        linktype=linktype,
    )


class PcapReader:
    """Iterate a classic pcap file, yielding :class:`PcapRecord`.

    Usage::

        with PcapReader(path) as reader:
            for record in reader:
                ...
            stats = reader.stats
    """

    __slots__ = ("_path", "_fh", "_owns_fh", "header", "stats", "_rec_struct")

    def __init__(self, source: str | Path | BinaryIO) -> None:
        if hasattr(source, "read"):
            self._fh: BinaryIO = source  # type: ignore[assignment]
            self._owns_fh = False
            self._path = getattr(source, "name", "<stream>")
        else:
            self._path = str(source)
            path = Path(source)
            if not path.is_file():
                raise PcapError(f"capture file not found: {path}")
            if path.stat().st_size == 0:
                raise PcapFormatError(f"capture file is empty: {path}")
            self._fh = path.open("rb")
            self._owns_fh = True

        try:
            self.header = _decode_file_header(self._fh.read(_FILE_HEADER_LEN))
        except Exception:
            self.close()
            raise

        self.stats = PcapReadStats()
        self._rec_struct = struct.Struct(self.header.endian + "IIII")

    # -- context management ----------------------------------------------

    def __enter__(self) -> "PcapReader":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if getattr(self, "_owns_fh", False) and not self._fh.closed:
            self._fh.close()

    @property
    def path(self) -> str:
        return self._path

    @property
    def linktype(self) -> int:
        return self.header.linktype

    # -- iteration --------------------------------------------------------

    def __iter__(self) -> Iterator[PcapRecord]:
        index = 0
        divisor = 1_000_000_000.0 if self.header.nanosecond else 1_000_000.0

        while True:
            raw = self._fh.read(_RECORD_HEADER_LEN)
            if not raw:
                return  # clean end of file
            if len(raw) < _RECORD_HEADER_LEN:
                # Trailing partial record: count it, stop cleanly.
                self.stats.records_malformed += 1
                return

            ts_sec, ts_frac, caplen, wirelen = self._rec_struct.unpack(raw)

            if caplen > MAX_RECORD_BYTES or wirelen > MAX_RECORD_BYTES:
                # A crafted length must not become a huge allocation.
                self.stats.records_malformed += 1
                return

            data = self._fh.read(caplen)
            if len(data) < caplen:
                # Truncated final record.
                self.stats.records_malformed += 1
                return

            if caplen > wirelen:
                # Physically impossible; treat as malformed but keep going -
                # one bad record does not invalidate the rest of the file.
                self.stats.records_malformed += 1
                index += 1
                continue

            timestamp = ts_sec + (ts_frac / divisor)

            self.stats.records_read += 1
            self.stats.captured_bytes += caplen
            self.stats.wire_bytes += wirelen
            if caplen < wirelen:
                self.stats.records_truncated += 1
            if self.stats.first_timestamp is None:
                self.stats.first_timestamp = timestamp
            self.stats.last_timestamp = timestamp

            yield PcapRecord(
                timestamp=timestamp,
                caplen=caplen,
                wirelen=wirelen,
                data=data,
                index=index,
            )
            index += 1

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"<PcapReader {self._path!r} linktype={self.header.linktype} "
            f"snaplen={self.header.snaplen} "
            f"{'ns' if self.header.nanosecond else 'us'}>"
        )


def peek_first_timestamp(source: str | Path) -> float | None:
    """Return the first record's timestamp without consuming the caller's file.

    The replay driver needs ``t_pcap_start`` before it starts the clock.
    """
    with PcapReader(source) as reader:
        for record in reader:
            return record.timestamp
    return None


__all__ = [
    "PcapError",
    "PcapFormatError",
    "PcapFileHeader",
    "PcapRecord",
    "PcapReadStats",
    "PcapReader",
    "peek_first_timestamp",
    "MAX_RECORD_BYTES",
]
