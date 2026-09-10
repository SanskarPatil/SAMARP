"""Cryptographic hash chain writer and standalone verifier.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 18, 19.1, design.md section 18.
Schema: schemas/alert.schema.json (lines 221-240).

Frozen Specification:
- canonical(x): JSON, keys sorted, no whitespace, UTF-8, NaN/Inf rejected.
- payload_hash: sha256(canonical(incident_payload)) -> 64 lowercase hex chars.
- entry_hash: sha256(prev_hash || seq || incident_id || last_updated || payload_hash) -> 64 lowercase hex chars.
- genesis prev_hash: "0" * 64 (64 zeros).
- seq: monotonic integer across the entire store, not per incident.
- byte concatenation: prev_hash || seq || incident_id || last_updated || payload_hash.
- Defined ONCE in this module and imported by the verifier.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any

GENESIS_PREV_HASH = "0" * 64
CHAIN_EXCLUDED_FIELDS = ("seq", "prev_hash", "entry_hash", "payload_hash")


def canonical_json(obj: Any) -> str:
    """Serialize object to canonical JSON: sorted keys, no whitespace, UTF-8, no NaN/Inf."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def compute_payload_hash(payload: dict[str, Any]) -> str:
    """Compute 64-character SHA-256 digest of canonical incident payload."""
    cleaned = {k: v for k, v in payload.items() if k not in CHAIN_EXCLUDED_FIELDS}
    serialized = canonical_json(cleaned).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def compute_entry_concat(
    prev_hash: str,
    seq: int,
    incident_id: str,
    last_updated: str,
    payload_hash: str,
) -> bytes:
    """Canonical concatenation rule: prev_hash || seq || incident_id || last_updated || payload_hash."""
    return f"{prev_hash}{seq}{incident_id}{last_updated}{payload_hash}".encode("utf-8")


def compute_entry_hash(
    prev_hash: str,
    seq: int,
    incident_id: str,
    last_updated: str,
    payload_hash: str,
) -> str:
    """Compute 64-character SHA-256 entry hash from concatenated components."""
    concat_bytes = compute_entry_concat(prev_hash, seq, incident_id, last_updated, payload_hash)
    return hashlib.sha256(concat_bytes).hexdigest()


class HashChainWriter:
    """Monotonic hash chain writer maintaining continuous provenance across all incidents."""

    def __init__(self, initial_seq: int = 0, initial_prev_hash: str = GENESIS_PREV_HASH) -> None:
        self.seq = initial_seq
        self.prev_hash = initial_prev_hash

    def append(self, incident: dict[str, Any]) -> dict[str, Any]:
        """Sign and append an incident to the hash chain, returning a signed copy."""
        self.seq += 1
        record = deepcopy(incident)

        incident_id = str(record.get("incident_id", ""))
        last_updated = str(record.get("last_observed") or record.get("timestamp") or "")

        payload_h = compute_payload_hash(record)
        entry_h = compute_entry_hash(self.prev_hash, self.seq, incident_id, last_updated, payload_h)

        record["seq"] = self.seq
        record["prev_hash"] = self.prev_hash
        record["payload_hash"] = payload_h
        record["entry_hash"] = entry_h

        # Monotonically advance chain state
        self.prev_hash = entry_h
        return record


def verify_hash_chain(entries: list[dict[str, Any]]) -> tuple[bool, str | None]:
    """Verify integrity of an exported hash chain sequence.

    Runs as a standalone verifier against exported JSON dictionaries.

    Returns:
        (True, None) if completely valid and intact.
        (False, error_message) if any link or payload is tampered.
    """
    if not entries:
        return True, None

    expected_prev = GENESIS_PREV_HASH
    last_seq = None

    for i, entry in enumerate(entries):
        # 1. Validate presence of mandatory chain fields
        for f in ("seq", "prev_hash", "entry_hash", "payload_hash", "incident_id"):
            if f not in entry or entry[f] is None:
                return False, f"Entry at index {i} missing required hash chain field '{f}'"

        seq = entry["seq"]
        prev_h = entry["prev_hash"]
        entry_h = entry["entry_hash"]
        payload_h = entry["payload_hash"]
        inc_id = entry["incident_id"]
        last_updated = str(entry.get("last_observed") or entry.get("timestamp") or "")

        # 2. Monotonic sequence check
        if not isinstance(seq, int) or seq < 0:
            return False, f"Entry at index {i} has invalid non-integer seq {seq}"
        if last_seq is not None and seq <= last_seq:
            return False, f"Sequence broken at index {i}: seq {seq} <= previous seq {last_seq}"
        last_seq = seq

        # 3. Chain link check (prev_hash matches preceding entry_hash or genesis)
        if prev_h != expected_prev:
            return False, f"Link mismatch at index {i}: expected prev_hash '{expected_prev}', got '{prev_h}'"

        # 4. Payload hash integrity check
        recomputed_payload_h = compute_payload_hash(entry)
        if recomputed_payload_h != payload_h:
            return False, (
                f"Payload tamper detected at index {i} (seq {seq}): "
                f"expected payload_hash '{payload_h}', recomputed '{recomputed_payload_h}'"
            )

        # 5. Entry hash integrity check
        recomputed_entry_h = compute_entry_hash(prev_h, seq, inc_id, last_updated, payload_h)
        if recomputed_entry_h != entry_h:
            return False, (
                f"Entry hash mismatch at index {i} (seq {seq}): "
                f"expected entry_hash '{entry_h}', recomputed '{recomputed_entry_h}'"
            )

        expected_prev = entry_h

    return True, None
