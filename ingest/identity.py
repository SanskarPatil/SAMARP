"""Canonical serialisation and deterministic identifiers.

Frozen contract - Phase 0 decision DOC-006 (see bugs.md, memory.md):

    identifier = sha256(canonical_value).hexdigest()[:16]

Exactly 16 lowercase hexadecimal characters: a 64-bit truncated SHA-256,
matching ``^[0-9a-f]{16}$``. The truncation is applied to the HEX DIGEST,
never to ``digest()``. ``[:16]`` is not 16 bytes.

Applies to ``flow_id`` and ``incident_id`` only. Hash-chain fields
(``payload_hash``, ``entry_hash``, ``prev_hash``) are full 64-character
digests and are never truncated.

CROSS-TRACK NOTE (P1 -> P4)
---------------------------
design.md section 9.4 requires the canonicalisation helper and the truncation
rule to be defined ONCE and imported by every producer and every verifier, and
names ``alerts/hash_chain.py`` as that home. That file is P4's and does not
exist yet, while P1 needs ``flow_id`` from the first normalized event onward.

This module is therefore the current single definition. When P4 builds
``alerts/hash_chain.py`` it must IMPORT ``canonical`` and ``identifier`` from
here rather than reimplement them. ``tests/ingest/test_identity.py`` pins the
exact output vectors so any second implementation can be asserted identical.
Two divergent implementations is the precise failure DOC-006 exists to prevent.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

# --------------------------------------------------------------------------
# Frozen constants
# --------------------------------------------------------------------------

#: Phase 0 decision DOC-007. Exact canonical sentinel for a key component that
#: is unavailable under the current observation mode. Never substitute None,
#: "", 0, "unknown", or any other placeholder.
#:
#: This is an IDENTITY rule, not a detection rule. It governs how an
#: observation is identified once it is emitted; it never authorises treating
#: absent evidence as present. The capability state carries the same string on
#: a different axis - see ingest/capability.py.
NOT_OBSERVABLE = "NOT_OBSERVABLE"

#: Characters retained from the hex digest for truncated identifiers.
IDENTIFIER_HEX_LEN = 16

#: Regex the schema enforces on flow_id / incident_id.
IDENTIFIER_PATTERN = r"^[0-9a-f]{16}$"


class CanonicalisationError(ValueError):
    """Raised when a value cannot be canonically serialised."""


# --------------------------------------------------------------------------
# Canonical serialisation
# --------------------------------------------------------------------------


def _reject_non_finite(value: Any) -> None:
    """Recursively reject NaN and Inf.

    design.md section 18 freezes canonical form as "JSON, keys sorted, no
    whitespace, UTF-8, NaN/Inf rejected". json.dumps emits bare ``NaN`` and
    ``Infinity`` tokens by default, which are not valid JSON and would hash
    differently across implementations.
    """
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise CanonicalisationError(
                f"non-finite float rejected by canonical form: {value!r}"
            )
    elif isinstance(value, dict):
        for k, v in value.items():
            _reject_non_finite(k)
            _reject_non_finite(v)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_non_finite(item)


def canonical(value: Any) -> str:
    """Return the frozen canonical string form of ``value``.

    JSON, keys sorted, no whitespace, UTF-8, NaN/Inf rejected.

    A plain string is returned unchanged rather than JSON-quoted, so that a
    pre-serialised canonical key (for example a deduplication key already
    joined by its owner) hashes to the same value as the structure it came
    from. Every other type goes through deterministic JSON.
    """
    if isinstance(value, str):
        return value

    _reject_non_finite(value)
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
        raise CanonicalisationError(
            f"value is not canonically serialisable: {exc}"
        ) from exc


def identifier(value: Any) -> str:
    """Return the frozen 16-hex-character identifier for ``value``.

    ``sha256(canonical(value)).hexdigest()[:16]``
    """
    encoded = canonical(value).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:IDENTIFIER_HEX_LEN]


def full_digest(value: Any) -> str:
    """Return the FULL 64-character sha256 hex digest.

    Provided for hash-chain use (P4). Never truncate this.
    """
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Flow identity
# --------------------------------------------------------------------------


def _component(value: Any) -> Any:
    """Normalise one key component, substituting the frozen sentinel."""
    if value is None or value == "":
        return NOT_OBSERVABLE
    return value


def canonical_five_tuple(
    src_ip: str | None,
    dst_ip: str | None,
    src_port: int | None,
    dst_port: int | None,
    protocol: str | None,
    *,
    bidirectional: bool = True,
) -> list[Any]:
    """Return the canonical 5-tuple used to derive a ``flow_5tuple`` flow_id.

    Bidirectional normalisation
    ---------------------------
    When ``bidirectional`` is True (the default) the two endpoints are ordered
    deterministically, so both directions of one conversation share a single
    ``flow_id``.

    This is required by the frozen contract, not a preference. FEATURE_ORDER
    contains ``upstream_packet_ratio`` and ``downstream_packet_ratio``; a
    directional ratio cannot be computed unless both directions of a flow are
    tracked under one identity. Keying each direction separately would make
    those two frozen features unconstructable.

    Direction is preserved separately on the normalized event via the
    ``direction`` field, so no directional information is lost.
    """
    a = (_component(src_ip), _component(src_port))
    b = (_component(dst_ip), _component(dst_port))

    if bidirectional:
        # Order endpoints by their canonical string form so the result does
        # not depend on which direction was observed first, and does not
        # depend on Python's ordering of mixed str/int types.
        endpoints = sorted([a, b], key=lambda e: (canonical(e[0]), canonical(e[1])))
    else:
        endpoints = [a, b]

    return [
        endpoints[0][0],
        endpoints[0][1],
        endpoints[1][0],
        endpoints[1][1],
        _component(protocol),
    ]


def flow_id_for_five_tuple(
    src_ip: str | None,
    dst_ip: str | None,
    src_port: int | None,
    dst_port: int | None,
    protocol: str | None,
    *,
    bidirectional: bool = True,
) -> str:
    """Deterministic ``flow_id`` for an observable single flow."""
    return identifier(
        canonical_five_tuple(
            src_ip, dst_ip, src_port, dst_port, protocol, bidirectional=bidirectional
        )
    )


def flow_id_for_aggregate(dedup_key: Any) -> str:
    """Deterministic ``flow_id`` for a multi-flow event.

    Used where a single concrete flow would be misleading - a spoofed flood,
    a reflection event. The canonical aggregate/dedup identity is hashed.
    Unavailable components must already carry the NOT_OBSERVABLE sentinel.
    """
    return identifier(dedup_key)


def flow_id_for_entity(entity: Any) -> str:
    """Deterministic ``flow_id`` for entity-scoped behaviour.

    Used where a source or entity identity represents the observation better
    than any single flow - a DGA burst, a port sweep.
    """
    return identifier(entity)


__all__ = [
    "NOT_OBSERVABLE",
    "IDENTIFIER_HEX_LEN",
    "IDENTIFIER_PATTERN",
    "CanonicalisationError",
    "canonical",
    "identifier",
    "full_digest",
    "canonical_five_tuple",
    "flow_id_for_five_tuple",
    "flow_id_for_aggregate",
    "flow_id_for_entity",
]
