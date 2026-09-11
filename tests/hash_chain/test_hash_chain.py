"""Unit and tamper-detection tests for the cryptographic hash chain.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 18, 19, design.md section 18.
Schema: schemas/alert.schema.json.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from alerts.hash_chain import (
    GENESIS_PREV_HASH,
    HashChainWriter,
    canonical_json,
    compute_entry_hash,
    compute_payload_hash,
    verify_hash_chain,
)
from tests.hash_chain.verify_hash_chain import verify_exported_file


def _create_sample_incident(inc_id: str, count: int = 1) -> dict[str, Any]:
    return {
        "schema_version": "1.3",
        "timestamp": "2026-09-11T00:00:00.000000+00:00",
        "flow_id": "0123456789abcdef",
        "flow_ref_type": "aggregate",
        "ps_class": "Volumetric DDoS / flooding",
        "threat_class": "syn_flood",
        "detector": "ddos",
        "confidence": None,
        "score": 12.5,
        "score_type": "robust_z",
        "calibrated": False,
        "evidence": {
            "interpretation": "SYN flood detected exceeding 1000 pps",
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
        },
        "incident_id": inc_id,
        "status": "NEW" if count == 1 else "UPDATED",
        "severity": "HIGH",
        "first_observed": "2026-09-11T00:00:00.000000+00:00",
        "last_observed": "2026-09-11T00:00:01.000000+00:00",
        "event_count": count,
        "capability": {
            "detector_state": "OBSERVABLE",
            "input_mode": "pcap_replay",
        },
    }


def test_genesis_block_and_monotonicity():
    """Verify genesis prev_hash is 64 zeros and seq starts at 1 and increases monotonically."""
    writer = HashChainWriter()
    assert writer.prev_hash == "0" * 64
    assert writer.seq == 0

    inc1 = writer.append(_create_sample_incident("inc0000000000001", count=1))
    assert inc1["seq"] == 1
    assert inc1["prev_hash"] == "0" * 64
    assert len(inc1["entry_hash"]) == 64
    assert len(inc1["payload_hash"]) == 64

    inc2 = writer.append(_create_sample_incident("inc0000000000001", count=2))
    assert inc2["seq"] == 2
    assert inc2["prev_hash"] == inc1["entry_hash"]
    assert inc2["entry_hash"] != inc1["entry_hash"]


def test_chain_link_continuity():
    """Verify continuity across multiple distinct incidents."""
    writer = HashChainWriter()
    chain: list[dict[str, Any]] = []

    for i in range(10):
        inc = _create_sample_incident(f"inc{i:013d}")
        signed = writer.append(inc)
        chain.append(signed)

    for i in range(1, len(chain)):
        assert chain[i]["prev_hash"] == chain[i - 1]["entry_hash"]
        assert chain[i]["seq"] == chain[i - 1]["seq"] + 1

    valid, err = verify_hash_chain(chain)
    assert valid is True
    assert err is None


def test_canonical_json_determinism():
    """Verify canonical serialization sorts keys and eliminates whitespace."""
    dict_a = {"z": 1, "a": 2, "m": {"sub_b": "ok", "sub_a": 10}}
    dict_b = {"a": 2, "m": {"sub_a": 10, "sub_b": "ok"}, "z": 1}

    assert canonical_json(dict_a) == canonical_json(dict_b)
    assert " " not in canonical_json(dict_a)
    assert compute_payload_hash(dict_a) == compute_payload_hash(dict_b)


def test_tamper_detection_payload_modification():
    """Tampering with any payload attribute fails verification."""
    writer = HashChainWriter()
    chain = [
        writer.append(_create_sample_incident("inc0000000000001")),
        writer.append(_create_sample_incident("inc0000000000002")),
        writer.append(_create_sample_incident("inc0000000000003")),
    ]

    # Tamper with severity in the second entry
    tampered_chain = [deepcopy(x) for x in chain]
    tampered_chain[1]["severity"] = "LOW"

    valid, err = verify_hash_chain(tampered_chain)
    assert valid is False
    assert "Payload tamper detected" in str(err)


def test_tamper_detection_evidence_modification():
    """Tampering with nested evidence fails verification."""
    writer = HashChainWriter()
    chain = [
        writer.append(_create_sample_incident("inc0000000000001")),
        writer.append(_create_sample_incident("inc0000000000002")),
    ]

    tampered_chain = [deepcopy(x) for x in chain]
    tampered_chain[0]["evidence"]["dst_port"] = 8080

    valid, err = verify_hash_chain(tampered_chain)
    assert valid is False
    assert "Payload tamper detected" in str(err)


def test_tamper_detection_seq_modification():
    """Modifying seq fails verification."""
    writer = HashChainWriter()
    chain = [
        writer.append(_create_sample_incident("inc0000000000001")),
        writer.append(_create_sample_incident("inc0000000000002")),
    ]

    tampered_chain = [deepcopy(x) for x in chain]
    tampered_chain[1]["seq"] = 5

    valid, err = verify_hash_chain(tampered_chain)
    assert valid is False
    assert "Sequence broken" in str(err) or "Entry hash mismatch" in str(err)


def test_tamper_detection_prev_hash_modification():
    """Modifying prev_hash fails verification."""
    writer = HashChainWriter()
    chain = [
        writer.append(_create_sample_incident("inc0000000000001")),
        writer.append(_create_sample_incident("inc0000000000002")),
    ]

    tampered_chain = [deepcopy(x) for x in chain]
    tampered_chain[1]["prev_hash"] = "f" * 64

    valid, err = verify_hash_chain(tampered_chain)
    assert valid is False
    assert "Link mismatch" in str(err)


def test_tamper_detection_entry_omission():
    """Deleting an entry in the middle breaks the chain link and sequence."""
    writer = HashChainWriter()
    chain = [
        writer.append(_create_sample_incident("inc0000000000001")),
        writer.append(_create_sample_incident("inc0000000000002")),
        writer.append(_create_sample_incident("inc0000000000003")),
    ]

    # Omit entry 1
    omitted_chain = [deepcopy(chain[0]), deepcopy(chain[2])]
    valid, err = verify_hash_chain(omitted_chain)
    assert valid is False
    assert "Link mismatch" in str(err) or "Sequence broken" in str(err)


def test_verify_exported_file(tmp_path: Path):
    """Verify that verify_exported_file verifies valid files and catches invalid ones."""
    writer = HashChainWriter()
    chain = [
        writer.append(_create_sample_incident("inc0000000000001")),
        writer.append(_create_sample_incident("inc0000000000002")),
    ]

    valid_file = tmp_path / "valid_chain.json"
    with open(valid_file, "w", encoding="utf-8") as f:
        json.dump(chain, f)

    ok, err = verify_exported_file(valid_file)
    assert ok is True
    assert err is None

    # Tamper file
    chain[1]["score"] = 999.9
    invalid_file = tmp_path / "invalid_chain.json"
    with open(invalid_file, "w", encoding="utf-8") as f:
        json.dump(chain, f)

    ok, err = verify_exported_file(invalid_file)
    assert ok is False
    assert "Payload tamper detected" in str(err)


def test_empty_chain_is_valid():
    """An empty chain returns valid."""
    assert verify_hash_chain([]) == (True, None)
