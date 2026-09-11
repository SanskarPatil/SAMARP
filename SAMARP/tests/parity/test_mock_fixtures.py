"""Test verifying that all mock fixtures strictly validate against schemas/alert.schema.json.

Source: AGENTS.md section 8 (rule 4: A schema-validity test guards the fixtures).
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "schemas" / "alert.schema.json"
FIXTURES_PATH = PROJECT_ROOT / "scenarios" / "mock_fixtures" / "incidents.json"


def test_mock_fixtures_validate_against_schema():
    assert SCHEMA_PATH.exists(), f"Schema file not found at {SCHEMA_PATH}"
    assert FIXTURES_PATH.exists(), f"Fixtures file not found at {FIXTURES_PATH}"

    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema = json.load(f)

    with open(FIXTURES_PATH, "r", encoding="utf-8") as f:
        fixtures = json.load(f)

    assert isinstance(fixtures, list)
    assert len(fixtures) >= 6

    # Verify coverage of all 6 PS threat classes
    ps_classes = {f["ps_class"] for f in fixtures}
    assert len(ps_classes) == 6

    # Verify every fixture validates
    for i, fixture in enumerate(fixtures):
        jsonschema.validate(instance=fixture, schema=schema)
