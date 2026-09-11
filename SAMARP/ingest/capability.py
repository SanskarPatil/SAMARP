"""Capability state - what the sensor can and cannot see.

Two independent axes. They are frequently conflated and must not be.

Evidence visibility (per detector / per field)::

    OBSERVABLE | DEGRADED | NOT_OBSERVABLE

Component health (per component)::

    HEALTHY | DEGRADED | UNAVAILABLE

``UNAVAILABLE`` describes a component that is down - sensor, normalizer,
detector process, API, WebSocket. It is NOT an evidence state and never
appears in a capability declaration on a normalized event. The frozen
normalized-event schema enforces this: its ``capability_state`` enum contains
only the three evidence values.

The governing rule, from design.md section 23:

    Missing evidence is NEVER converted into a benign result.

A field that cannot be seen is reported as NOT_OBSERVABLE. It is never
silently omitted, never defaulted to zero, and never inferred.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

# --------------------------------------------------------------------------
# Frozen vocabularies
# --------------------------------------------------------------------------


class Capability(StrEnum):
    """Evidence-visibility axis. Matches the frozen schema enum exactly."""

    OBSERVABLE = "OBSERVABLE"
    DEGRADED = "DEGRADED"
    NOT_OBSERVABLE = "NOT_OBSERVABLE"


class Health(StrEnum):
    """Component-health axis. Never appears on a normalized event."""

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"


class InputMode(StrEnum):
    """Frozen ``input_mode`` enum.

    Describes the primary input contract, not an internal combination such as
    ``pcap_replay+eve``. Sensor subpaths live in capability state.
    """

    PCAP_REPLAY = "pcap_replay"
    LIVE_TAP = "live_tap"
    IPFIX = "ipfix"
    NETFLOW_V9 = "netflow_v9"
    SFLOW = "sflow"


#: The 15 capability fields the frozen schema defines, excluding ``input_mode``
#: which is carried separately.
CAPABILITY_FIELDS: tuple[str, ...] = (
    "ipv4",
    "ipv6",
    "dns_names",
    "dns_responses",
    "tls_handshake",
    "quic_metadata",
    "ja3",
    "ja3s",
    "ja4",
    "flow_records",
    "flow_sampling",
    "geo",
    "capture_loss",
    "bidirectional_visibility",
)


# --------------------------------------------------------------------------
# Per-input-mode baselines
# --------------------------------------------------------------------------

_O = Capability.OBSERVABLE
_D = Capability.DEGRADED
_N = Capability.NOT_OBSERVABLE

# Packet-visible input. DNS/TLS/QUIC capability is not asserted here - it is
# raised to OBSERVABLE only when the Suricata capability probe confirms the
# sensor actually emits those events (design.md section 7A.3). Claiming ja4
# before the probe has verified the build exposes it would be exactly the
# "silent default" failure section 7A exists to prevent.
_PACKET_BASELINE: dict[str, Capability] = {
    "ipv4": _O,
    "ipv6": _O,
    "dns_names": _N,
    "dns_responses": _N,
    "tls_handshake": _N,
    "quic_metadata": _N,
    "ja3": _N,
    "ja3s": _N,
    "ja4": _N,
    "flow_records": _N,
    "flow_sampling": _N,
    "geo": _N,
    "capture_loss": _N,
    "bidirectional_visibility": _O,
}

# Plain NetFlow v9 / IPFIX. design.md section 23.4:
#   "For plain NetFlow/IPFIX: DDoS and scan generally remain flow-observable;
#    C2 and exfiltration may remain usable depending on timing and direction
#    fields; DNS names and TLS/QUIC fingerprints are normally NOT_OBSERVABLE."
#
# The adapter does not reconstruct packets, DNS names, TLS fingerprints or TCP
# state the exporter did not export (section 23.5). That is a capability
# boundary, not a claim that the underlying threat is absent.
_FLOW_RECORD_BASELINE: dict[str, Capability] = {
    "ipv4": _O,
    "ipv6": _O,
    "dns_names": _N,
    "dns_responses": _N,
    "tls_handshake": _N,
    "quic_metadata": _N,
    "ja3": _N,
    "ja3s": _N,
    "ja4": _N,
    "flow_records": _O,
    "flow_sampling": _N,
    "geo": _N,
    "capture_loss": _N,
    "bidirectional_visibility": _D,
}

# Sampled sFlow. V6.3 section 49:
#   "sFlow is recognized as a sampled input mode but is not implemented as a
#    packet-equivalent detector source in this 24-hour build. Sampling
#    metadata is surfaced so the operator can see the limitation."
#
# 'sflow' IS a valid input_mode. NOT_OBSERVABLE is a per-field evidence state,
# never a property of an input mode. Sampling-aware volumetric statistics may
# remain usable; anything depending on unsampled packet order, complete port
# spread, DNS names or TLS fingerprints degrades explicitly.
#
# Packet-level information is NEVER fabricated from sampled data.
_SFLOW_BASELINE: dict[str, Capability] = {
    "ipv4": _D,
    "ipv6": _D,
    "dns_names": _N,
    "dns_responses": _N,
    "tls_handshake": _N,
    "quic_metadata": _N,
    "ja3": _N,
    "ja3s": _N,
    "ja4": _N,
    "flow_records": _D,
    "flow_sampling": _O,  # the fact OF sampling is fully observable
    "geo": _N,
    "capture_loss": _D,
    "bidirectional_visibility": _N,
}

_BASELINES: dict[InputMode, dict[str, Capability]] = {
    InputMode.PCAP_REPLAY: _PACKET_BASELINE,
    InputMode.LIVE_TAP: _PACKET_BASELINE,
    InputMode.IPFIX: _FLOW_RECORD_BASELINE,
    InputMode.NETFLOW_V9: _FLOW_RECORD_BASELINE,
    InputMode.SFLOW: _SFLOW_BASELINE,
}


# --------------------------------------------------------------------------
# Capability state
# --------------------------------------------------------------------------


class CapabilityState:
    """Mutable capability declaration for one input source.

    Built from the baseline for the input mode, then raised or lowered by
    observed evidence - for example the Suricata capability probe confirming
    that JA3S is actually emitted by the installed build.
    """

    __slots__ = ("_input_mode", "_fields")

    def __init__(self, input_mode: InputMode | str) -> None:
        mode = InputMode(input_mode)
        self._input_mode = mode
        self._fields: dict[str, Capability] = dict(_BASELINES[mode])

    @property
    def input_mode(self) -> InputMode:
        return self._input_mode

    def get(self, field: str) -> Capability:
        if field not in CAPABILITY_FIELDS:
            raise KeyError(f"unknown capability field: {field!r}")
        return self._fields[field]

    def set(self, field: str, state: Capability | str) -> None:
        """Set one capability field.

        Raising a field to OBSERVABLE is an assertion that the evidence was
        actually seen - by a probe or by the record itself. Never set it
        optimistically.
        """
        if field not in CAPABILITY_FIELDS:
            raise KeyError(f"unknown capability field: {field!r}")
        self._fields[field] = Capability(state)

    def update(self, **fields: Capability | str) -> "CapabilityState":
        for name, state in fields.items():
            self.set(name, state)
        return self

    def degrade(self, field: str) -> None:
        """Lower a field to DEGRADED unless it is already NOT_OBSERVABLE."""
        if self.get(field) is not Capability.NOT_OBSERVABLE:
            self.set(field, Capability.DEGRADED)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to the frozen schema's ``capability`` object."""
        out: dict[str, Any] = {"input_mode": str(self._input_mode)}
        for name in CAPABILITY_FIELDS:
            out[name] = str(self._fields[name])
        return out

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        visible = [
            f for f in CAPABILITY_FIELDS if self._fields[f] is Capability.OBSERVABLE
        ]
        return f"<CapabilityState {self._input_mode} observable={visible}>"


def baseline_for(input_mode: InputMode | str) -> CapabilityState:
    """Return a fresh capability state for ``input_mode``."""
    return CapabilityState(input_mode)


__all__ = [
    "Capability",
    "Health",
    "InputMode",
    "CAPABILITY_FIELDS",
    "CapabilityState",
    "baseline_for",
]
