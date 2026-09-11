"""Acceptance tests for DGA rule-based fallback detection.

Asserts:
- Conformance to schemas/alert.schema.json.
- Rule-based fallback contract: calibrated=False, model_version="rules-fallback".
- Tranco allowlist filtering on top domains.
- High-entropy, low-vowel algorithmic domain burst detection.
- NXDOMAIN rate integration.
- Flow identity entity semantics: flow_id == sha256(canonical(src_ip))[:16].
- Dedup key semantics: [ps_class, src_ip] (never keyed on domain).
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from detectors.dga import (
    DGADetector,
    calculate_lexical_features,
    calculate_ngram_anomaly,
    extract_domain_labels,
)
from ingest.capability import CapabilityState, InputMode
from ingest.identity import identifier
from ingest.normalized_event import NormalizedEvent

REPO = Path(__file__).resolve().parents[2]
ALERT_SCHEMA_PATH = REPO / "schemas" / "alert.schema.json"


@pytest.fixture(scope="module")
def alert_schema() -> dict:
    return json.loads(ALERT_SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def alert_validator(alert_schema: dict) -> jsonschema.Draft202012Validator:
    jsonschema.Draft202012Validator.check_schema(alert_schema)
    return jsonschema.Draft202012Validator(alert_schema)


def _dns_event(src_ip: str, qname: str, nxdomain: bool = False, ts: float = 100.0) -> NormalizedEvent:
    return NormalizedEvent(
        observed_time=ts,
        input_mode=InputMode.PCAP_REPLAY,
        capability=CapabilityState(InputMode.PCAP_REPLAY),
        src_ip=src_ip,
        dst_ip="10.10.0.53",
        src_port=53123,
        dst_port=53,
        protocol="UDP",
        dns={"qname": qname, "qtype": "A", "nxdomain": nxdomain},
    )


def test_lexical_feature_extraction() -> None:
    feats = calculate_lexical_features("testdomain123.com")
    assert feats["length"] == 13.0
    assert feats["digit_ratio"] > 0.0
    assert feats["vowel_ratio"] > 0.0
    assert feats["entropy"] > 2.0


def test_ngram_anomaly_scoring() -> None:
    # Natural english domain has low anomaly
    natural_score = calculate_ngram_anomaly("weatherforecast")
    assert natural_score < 0.35

    # Random consonant sequence has high anomaly
    random_score = calculate_ngram_anomaly("xzkjqwyfp")
    assert random_score > 0.60


def test_tranco_allowlist_filtering() -> None:
    detector = DGADetector()
    score, _ = detector.score_domain("www.google.com")
    assert score == 0.0

    score2, _ = detector.score_domain("subdomain.github.com")
    assert score2 == 0.0


def test_dga_burst_detection(alert_validator: jsonschema.Draft202012Validator) -> None:
    detector = DGADetector(score_threshold=0.80, min_queries=5)
    src = "10.10.0.45"

    dga_names = [
        "xzkjqwyfp7931.org",
        "qwrtyzxvbm992.net",
        "bdfhjlnprtxz12.com",
        "zxvcbmnlkjhg88.info",
        "mnbvcxzasdfg77.ru",
        "lkjhgfdsamnb55.com",
    ]

    alert = None
    for i, name in enumerate(dga_names):
        ev = _dns_event(src, name, nxdomain=True, ts=100.0 + i * 0.5)
        res = detector.evaluate_event(ev)
        if res:
            alert = res

    assert alert is not None
    alert_validator.validate(alert)

    assert alert["ps_class"] == "DGA / DNS tunnelling"
    assert alert["threat_class"] == "dga_domain"
    assert alert["detector"] == "dga"
    assert alert["flow_ref_type"] == "entity"
    assert alert["flow_id"] == identifier(src)
    assert alert["incident_id"] == identifier(["DGA / DNS tunnelling", src])
    assert alert["calibrated"] is False
    assert alert["model_version"] == "rules-fallback"
    assert alert["score_type"] == "rule_score"
    assert alert["evidence"]["query_count"] >= 5
    assert alert["evidence"]["nxdomain_rate"] > 0.0
    assert len(alert["evidence"]["sample_domains"]) > 0
