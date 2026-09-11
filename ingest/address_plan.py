"""Lab address plan - address semantics for the normalizer.

Several features carry address meaning. Without a declared plan they misfire
inside an RFC 1918 lab. This module is the ONLY place that interprets address
semantics; no detector hardcodes a prefix check (design.md section 2.2).

Two traps this fixes, both from the same failure family:

1. Reflection reserved-source share. In a pure RFC 1918 lab that share is
   100% on benign traffic, so the detector fires continuously and destroys the
   false-alerts-per-hour figure. Rule: the reserved-share feature is computed
   against the EXTERNAL address space only, with declared lab prefixes
   excluded from the bogon set.

2. Geolocation. Private lab addresses have no country. The external side is
   assigned GeoLite2-resolvable ranges; anything unresolvable is badged as a
   demo fixture. Geolocation is not attribution.

``direction`` was never defined anywhere before this plan existed, yet
``exfil.py`` cannot exist without it.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any, Iterable, Sequence

import yaml

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network
_Address = ipaddress.IPv4Address | ipaddress.IPv6Address

#: Repository-root-relative default location of the frozen plan.
DEFAULT_PLAN_PATH = (
    Path(__file__).resolve().parent.parent / "config" / "address_plan.yaml"
)

#: Direction values permitted by the frozen normalized-event schema.
DIRECTIONS = ("inbound", "outbound", "internal", "external")


class AddressPlanError(ValueError):
    """Raised when the address plan is missing, malformed or inconsistent."""


def _parse_networks(
    values: Iterable[str] | None, *, label: str
) -> tuple[_Network, ...]:
    if not values:
        return ()
    out: list[_Network] = []
    for raw in values:
        try:
            out.append(ipaddress.ip_network(str(raw), strict=False))
        except ValueError as exc:
            raise AddressPlanError(f"{label}: invalid network {raw!r}: {exc}") from exc
    return tuple(out)


class AddressPlan:
    """Loaded, validated view of ``config/address_plan.yaml``."""

    __slots__ = (
        "_raw",
        "monitored",
        "monitoring",
        "lab_transport",
        "dns_resolver",
        "external_benign",
        "external_malicious",
        "amplifier_hosts",
        "amplifier_ports",
        "ipv6_prefixes",
        "ipv6_bucket_len",
        "bogon_external_only",
        "bogon_exclude_lab",
    )

    def __init__(self, data: dict[str, Any]) -> None:
        self._raw = data

        monitored = data.get("monitored_enclave") or {}
        monitoring = data.get("monitoring_enclave") or {}
        transport = data.get("lab_transport") or {}
        external = data.get("external") or {}
        ipv6 = data.get("ipv6") or {}
        bogon = data.get("bogon") or {}

        self.monitored = _parse_networks(
            monitored.get("prefixes"), label="monitored_enclave.prefixes"
        )
        if not self.monitored:
            raise AddressPlanError(
                "monitored_enclave.prefixes is empty - direction cannot be inferred, "
                "and exfil/reflection features depend on it"
            )

        self.monitoring = _parse_networks(
            monitoring.get("prefixes"), label="monitoring_enclave.prefixes"
        )
        self.lab_transport = _parse_networks(
            transport.get("prefixes"), label="lab_transport.prefixes"
        )

        resolver = monitored.get("dns_resolver")
        self.dns_resolver = ipaddress.ip_address(str(resolver)) if resolver else None

        self.external_benign = _parse_networks(
            external.get("benign"), label="external.benign"
        )
        self.external_malicious = _parse_networks(
            external.get("synthetic_malicious"), label="external.synthetic_malicious"
        )
        self.amplifier_hosts = _parse_networks(
            external.get("amplifier_hosts"), label="external.amplifier_hosts"
        )
        self.amplifier_ports = tuple(external.get("amplifier_ports") or ())

        self.ipv6_prefixes = _parse_networks(ipv6.get("prefixes"), label="ipv6.prefixes")
        self.ipv6_bucket_len = int(ipv6.get("entropy_bucket_prefix_len", 48))

        self.bogon_external_only = bogon.get("compute_against") == "external_only"
        self.bogon_exclude_lab = bool(bogon.get("exclude_declared_lab_prefixes", True))

    # -- loading ----------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path | None = None) -> "AddressPlan":
        p = Path(path) if path is not None else DEFAULT_PLAN_PATH
        if not p.is_file():
            raise AddressPlanError(f"address plan not found: {p}")
        with p.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            raise AddressPlanError(f"address plan is not a mapping: {p}")
        return cls(data)

    # -- membership -------------------------------------------------------

    @staticmethod
    def _to_address(value: str | _Address | None) -> _Address | None:
        if value is None:
            return None
        if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return value
        try:
            return ipaddress.ip_address(str(value))
        except ValueError:
            return None

    @staticmethod
    def _in(addr: _Address | None, networks: Sequence[_Network]) -> bool:
        if addr is None:
            return False
        return any(addr.version == n.version and addr in n for n in networks)

    def is_monitored(self, value: str | _Address | None) -> bool:
        """True if the address is inside the monitored enclave."""
        return self._in(self._to_address(value), self.monitored)

    def is_monitoring(self, value: str | _Address | None) -> bool:
        """True if the address is inside the monitoring enclave (Plane B)."""
        return self._in(self._to_address(value), self.monitoring)

    def is_lab_transport(self, value: str | _Address | None) -> bool:
        """True if the address belongs to a declared lab veth range."""
        return self._in(self._to_address(value), self.lab_transport)

    def is_declared_lab(self, value: str | _Address | None) -> bool:
        """True if the address is in ANY declared lab prefix.

        These are excluded from the bogon set. Without this exclusion the
        reserved-source share is 100% on benign lab traffic and the reflection
        detector fires continuously.
        """
        addr = self._to_address(value)
        return (
            self._in(addr, self.monitored)
            or self._in(addr, self.monitoring)
            or self._in(addr, self.lab_transport)
        )

    def is_external(self, value: str | _Address | None) -> bool:
        """True if the address is outside every declared lab prefix."""
        addr = self._to_address(value)
        if addr is None:
            return False
        return not self.is_declared_lab(addr)

    # -- direction --------------------------------------------------------

    def direction(
        self, src_ip: str | _Address | None, dst_ip: str | _Address | None
    ) -> str | None:
        """Infer ``direction`` for the frozen schema enum.

        The plan declares two rules explicitly::

            inbound_when_dst_in : monitored_enclave
            outbound_when_src_in: monitored_enclave

        The schema's enum has four values. The remaining two follow from the
        same enclave membership and are the only assignment consistent with
        the declared pair - both endpoints inside is ``internal``, neither
        inside is ``external``. No new rule is introduced.

        Returns None when either address is absent or unparseable, so the
        field is reported as unknown rather than guessed. Direction is never
        inferred from a missing address.
        """
        src = self._to_address(src_ip)
        dst = self._to_address(dst_ip)
        if src is None or dst is None:
            return None

        src_in = self._in(src, self.monitored)
        dst_in = self._in(dst, self.monitored)

        if src_in and dst_in:
            return "internal"
        if src_in:
            return "outbound"
        if dst_in:
            return "inbound"
        return "external"

    # -- bogon / reserved source space ------------------------------------

    def is_bogon(self, value: str | _Address | None) -> bool:
        """True if the address is reserved/invalid source space.

        Declared lab prefixes are excluded when the plan says so. This is the
        exclusion that keeps the reflection detector usable in an RFC 1918
        lab, and it is stated in the evidence drawer text.
        """
        addr = self._to_address(value)
        if addr is None:
            return False

        if self.bogon_exclude_lab and self.is_declared_lab(addr):
            return False

        if self.bogon_external_only and not self.is_external(addr):
            return False

        return bool(
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        )

    def is_amplifier_port(self, port: int | None) -> bool:
        """True if the port is a declared reflection/amplification service."""
        return port is not None and port in self.amplifier_ports

    # -- ipv6 -------------------------------------------------------------

    def ipv6_entropy_bucket(self, value: str | _Address | None) -> str | None:
        """Return the /48 (or configured) bucket for IPv6 entropy estimation."""
        addr = self._to_address(value)
        if addr is None or addr.version != 6:
            return None
        net = ipaddress.ip_network(f"{addr}/{self.ipv6_bucket_len}", strict=False)
        return str(net)

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"<AddressPlan monitored={[str(n) for n in self.monitored]} "
            f"monitoring={[str(n) for n in self.monitoring]} "
            f"lab={[str(n) for n in self.lab_transport]}>"
        )


__all__ = ["AddressPlan", "AddressPlanError", "DEFAULT_PLAN_PATH", "DIRECTIONS"]
