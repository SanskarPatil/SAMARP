"""PS26145 constraint (e): every emitted alert carries the five mandated fields, non-null.

timestamp · flow identifier · threat class · confidence score · supporting evidence
plus the measured latency_ms and the calibration source (calibrated_on).
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import jsonschema
import pytest

from detectors.pipeline import DetectionPipeline
from scenarios.canonical_campaign import generate_canonical_campaign_events

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "schemas" / "alert.schema.json").read_text(encoding="utf-8"))
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)
PS_FIELDS = ("timestamp", "flow_id", "ps_class", "threat_class", "confidence", "evidence")


def _campaign_alerts() -> list[dict]:
    pipeline = DetectionPipeline()
    alerts: list[dict] = []
    for event in generate_canonical_campaign_events():
        alerts.extend(pipeline.process_event(event))
    alerts.extend(pipeline.flush())
    return alerts


ALERTS = _campaign_alerts()


def assert_ps_complete(alert: dict) -> None:
    missing = [name for name in PS_FIELDS if alert.get(name) is None]
    assert not missing, f"{alert.get('detector')} alert has null PS field(s): {missing}"
    assert isinstance(alert["evidence"], dict) and alert["evidence"], "evidence must be a non-empty object"
    assert 0.0 <= alert["confidence"] <= 1.0
    assert alert["calibrated_on"] in ("synthetic_replay", "platt_dga", "uncalibrated")
    assert alert["calibrated"] == (alert["calibrated_on"] != "uncalibrated")
    assert alert.get("latency_ms") is not None and alert["latency_ms"] >= 0.0, "latency_ms must be measured"


def test_campaign_emits_alerts_for_every_detector_family():
    assert len(ALERTS) >= 7
    assert len({a["ps_class"] for a in ALERTS}) == 6


@pytest.mark.parametrize("index", range(len(ALERTS)))
def test_every_emitted_alert_is_schema_valid_and_ps_complete(index: int):
    alert = ALERTS[index]
    errors = sorted(VALIDATOR.iter_errors(alert), key=lambda e: list(e.path))
    assert not errors, [f"{list(e.path)}: {e.message}" for e in errors]
    assert_ps_complete(alert)


@pytest.mark.parametrize("field", PS_FIELDS)
def test_schema_rejects_a_null_ps_field(field: str):
    alert = dict(ALERTS[0])
    alert[field] = None
    assert list(VALIDATOR.iter_errors(alert)), f"schema accepted null {field}"


def test_schema_rejects_missing_calibration_source():
    alert = {k: v for k, v in ALERTS[0].items() if k != "calibrated_on"}
    assert list(VALIDATOR.iter_errors(alert))


def test_persisted_incidents_keep_ps_fields_and_measured_latency():
    pytest.importorskip("starlette")
    if "api" not in sys.modules:  # load api.state without importing FastAPI via api/__init__.py
        pkg = types.ModuleType("api"); pkg.__path__ = [str(ROOT / "api")]; sys.modules["api"] = pkg
    import time

    from api.state import AppState

    state = AppState(db_path=":memory:")
    pipeline = DetectionPipeline()
    for event in generate_canonical_campaign_events():
        t0 = time.perf_counter_ns()
        for alert in pipeline.process_event(event, ingest_perf_ns=t0):
            state.ingest_alert(alert, ingest_perf_ns=t0)
    t0 = time.perf_counter_ns()
    for alert in pipeline.flush(ingest_perf_ns=t0):
        state.ingest_alert(alert, ingest_perf_ns=t0)
    incidents = state.store.list_incidents(limit=1000)
    assert incidents
    for incident in incidents:
        assert_ps_complete(incident)
