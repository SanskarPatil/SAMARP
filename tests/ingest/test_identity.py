"""Flow identity and canonical serialisation.

Pins the frozen Phase 0 decision DOC-006 with explicit vectors, so that any
second implementation - notably P4's alerts/hash_chain.py - can be asserted
byte-identical to this one. Two divergent implementations of the identifier
rule is the exact failure DOC-006 exists to prevent.
"""

from __future__ import annotations

import hashlib
import re

import pytest

from ingest.identity import (
    IDENTIFIER_PATTERN,
    NOT_OBSERVABLE,
    CanonicalisationError,
    canonical,
    canonical_five_tuple,
    flow_id_for_aggregate,
    flow_id_for_entity,
    flow_id_for_five_tuple,
    full_digest,
    identifier,
)

ID_RE = re.compile(IDENTIFIER_PATTERN)


# ---------------------------------------------------------------- canonical


def test_canonical_sorts_keys_and_strips_whitespace():
    assert canonical({"b": 2, "a": 1}) == '{"a":1,"b":2}'
    assert canonical({"a": 1, "b": 2}) == canonical({"b": 2, "a": 1})


def test_canonical_is_stable_across_nesting_order():
    left = {"outer": {"z": [1, 2], "a": "x"}}
    right = {"outer": {"a": "x", "z": [1, 2]}}
    assert canonical(left) == canonical(right)


def test_canonical_passes_plain_strings_through_unquoted():
    # A pre-serialised canonical key must hash to the same value as the
    # structure it came from.
    assert canonical("already-canonical") == "already-canonical"


def test_canonical_rejects_nan_and_inf():
    # design.md section 18: NaN/Inf rejected. json.dumps would otherwise emit
    # bare NaN/Infinity tokens, which are not valid JSON.
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(CanonicalisationError):
            canonical({"value": bad})
        with pytest.raises(CanonicalisationError):
            canonical([bad])


def test_canonical_preserves_unicode_without_escaping():
    assert canonical({"k": "café"}) == '{"k":"café"}'


# --------------------------------------------------------------- identifier


def test_identifier_is_16_lowercase_hex_not_16_bytes():
    ident = identifier({"a": 1})
    assert ID_RE.match(ident), ident
    assert len(ident) == 16
    assert ident == ident.lower()


def test_identifier_matches_frozen_algorithm_exactly():
    """The pinned definition: sha256(canonical).hexdigest()[:16]."""
    value = {"ps_class": "Volumetric DDoS / flooding", "dst_ip": "10.10.0.5"}
    expected = hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()[:16]
    assert identifier(value) == expected
    # And explicitly NOT the 16-byte reading, which yields 32 hex chars.
    wrong = hashlib.sha256(canonical(value).encode("utf-8")).digest()[:16].hex()
    assert identifier(value) != wrong
    assert len(wrong) == 32


def test_full_digest_is_64_hex_and_never_truncated():
    d = full_digest({"a": 1})
    assert len(d) == 64
    assert re.fullmatch(r"[0-9a-f]{64}", d)
    assert d.startswith(identifier({"a": 1}))


def test_identifier_is_deterministic_across_calls():
    value = ["scan", "10.10.0.9"]
    assert identifier(value) == identifier(value)


def test_identifier_differs_for_different_input():
    assert identifier({"a": 1}) != identifier({"a": 2})


# ------------------------------------------------------------- five tuple


def test_five_tuple_is_bidirectional_by_default():
    """Both directions of one conversation share a flow_id.

    Required by the frozen FEATURE_ORDER: upstream_packet_ratio and
    downstream_packet_ratio cannot be computed unless both directions are
    tracked under one identity.
    """
    fwd = flow_id_for_five_tuple("10.10.0.5", "203.0.113.7", 44321, 443, "TCP")
    rev = flow_id_for_five_tuple("203.0.113.7", "10.10.0.5", 443, 44321, "TCP")
    assert fwd == rev


def test_five_tuple_directional_mode_distinguishes_directions():
    fwd = flow_id_for_five_tuple(
        "10.10.0.5", "203.0.113.7", 44321, 443, "TCP", bidirectional=False
    )
    rev = flow_id_for_five_tuple(
        "203.0.113.7", "10.10.0.5", 443, 44321, "TCP", bidirectional=False
    )
    assert fwd != rev


def test_five_tuple_separates_protocols():
    tcp = flow_id_for_five_tuple("10.10.0.5", "203.0.113.7", 1234, 53, "TCP")
    udp = flow_id_for_five_tuple("10.10.0.5", "203.0.113.7", 1234, 53, "UDP")
    assert tcp != udp


def test_five_tuple_substitutes_sentinel_for_missing_components():
    tup = canonical_five_tuple("10.10.0.5", "203.0.113.7", None, 443, "TCP")
    assert NOT_OBSERVABLE in tup
    # Never null, empty string, zero or "unknown".
    assert None not in tup
    assert "" not in tup
    assert "unknown" not in tup


def test_five_tuple_missing_component_still_yields_valid_flow_id():
    fid = flow_id_for_five_tuple(None, None, None, None, None)
    assert ID_RE.match(fid), fid


def test_sentinel_is_the_exact_frozen_string():
    assert NOT_OBSERVABLE == "NOT_OBSERVABLE"


# ------------------------------------------------------- aggregate / entity


def test_aggregate_identity_is_stable_and_valid():
    # A spoofed flood: no honest single source flow, so the frozen dedup key
    # is hashed instead. ddos never keys on source.
    key = ["Volumetric DDoS / flooding", "10.10.0.5", 80]
    fid = flow_id_for_aggregate(key)
    assert ID_RE.match(fid)
    assert fid == flow_id_for_aggregate(key)


def test_aggregate_identity_carries_sentinel_deterministically():
    # tls_quic keys on ja3, which is NOT_OBSERVABLE under NetFlow/IPFIX.
    key = ["Malware in encrypted sessions", "10.10.0.5", NOT_OBSERVABLE, "203.0.113.7"]
    assert flow_id_for_aggregate(key) == flow_id_for_aggregate(list(key))


def test_entity_identity_is_stable_and_valid():
    fid = flow_id_for_entity(
        {"ps_class": "Port scanning / reconnaissance", "src_ip": "10.10.0.9"}
    )
    assert ID_RE.match(fid)


def test_the_three_ref_types_do_not_collide():
    ids = {
        flow_id_for_five_tuple("10.10.0.5", "203.0.113.7", 1, 2, "TCP"),
        flow_id_for_aggregate(["ddos", "10.10.0.5", 80]),
        flow_id_for_entity(["scan", "10.10.0.9"]),
    }
    assert len(ids) == 3
