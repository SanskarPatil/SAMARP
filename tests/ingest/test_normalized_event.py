"""Normalization against the frozen contract.

Every event this project emits must validate against
schemas/normalized_event.schema.json. The schema sets
``additionalProperties: false``, so it also proves no field was invented.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
import pytest

from ingest.address_plan import AddressPlan
from ingest.capability import Capability, CapabilityState, InputMode
from ingest.identity import NOT_OBSERVABLE
from ingest.normalized_event import (
    FLOW_REF_TYPES,
    NormalizationError,
    NormalizedEvent,
    iso8601,
    protocol_name,
    tcp_flags_str,
)

REPO = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO / "schemas" / "normalized_event.schema.json"

MONITORED = "10.10.0.5"
EXTERNAL = "203.0.113.7"
T0 = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def validator(schema: dict) -> jsonschema.Draft202012Validator:
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


@pytest.fixture(scope="module")
def plan() -> AddressPlan:
    return AddressPlan.load()


def _flow(**kw) -> NormalizedEvent:
    kw.setdefault("observed_time", T0)
    kw.setdefault("input_mode", InputMode.PCAP_REPLAY)
    kw.setdefault("capability", CapabilityState(InputMode.PCAP_REPLAY))
    kw.setdefault("src_ip", MONITORED)
    kw.setdefault("dst_ip", EXTERNAL)
    kw.setdefault("src_port", 44321)
    kw.setdefault("dst_port", 443)
    kw.setdefault("protocol", 6)
    return NormalizedEvent.from_flow(**kw)


# ------------------------------------------------------- schema conformance


def test_flow_event_validates_against_frozen_schema(validator, plan):
    ev = _flow(address_plan=plan, packets=4, bytes=512, tcp_flags=0x12)
    ev.validate()
    validator.validate(ev.to_dict())


def test_event_validates_with_explicit_nulls_too(validator, plan):
    ev = _flow(address_plan=plan)
    validator.validate(ev.to_dict(drop_none=False))


def test_required_fields_are_always_present(plan):
    d = _flow(address_plan=plan).to_dict()
    for key in ("schema_version", "observed_time", "input_mode", "capability"):
        assert key in d, key
    assert d["schema_version"] == 1


def test_every_input_mode_produces_a_valid_event(validator):
    for mode in InputMode:
        ev = NormalizedEvent.from_flow(
            observed_time=T0,
            input_mode=mode,
            capability=CapabilityState(mode),
            src_ip=MONITORED,
            dst_ip=EXTERNAL,
            src_port=1234,
            dst_port=53,
            protocol=17,
        )
        ev.validate()
        validator.validate(ev.to_dict())


def test_schema_has_no_payload_or_content_field(schema):
    """No-decryption is structural: the contract cannot carry payload."""
    blob = json.dumps(schema).lower()
    for banned in (
        "payload_byte",
        "payload_data",
        "plaintext",
        "cleartext",
        "session_key",
        "content_body",
    ):
        assert banned not in blob, banned


# --------------------------------------------------------------- flow_id


def test_flow_id_is_never_null_when_ref_type_is_set(plan):
    ev = _flow(address_plan=plan)
    assert ev.flow_id
    assert ev.flow_ref_type == "flow_5tuple"


def test_flow_id_matches_the_frozen_pattern(validator, plan):
    ev = _flow(address_plan=plan)
    assert len(ev.flow_id) == 16
    validator.validate(ev.to_dict())


def test_aggregate_event_has_flow_id_without_a_five_tuple(validator):
    # A spoofed flood: no honest single source flow.
    ev = NormalizedEvent.from_aggregate(
        observed_time=T0,
        input_mode=InputMode.PCAP_REPLAY,
        capability=CapabilityState(InputMode.PCAP_REPLAY),
        dedup_key=["Volumetric DDoS / flooding", MONITORED, 80],
    )
    ev.validate()
    assert ev.flow_ref_type == "aggregate"
    assert ev.flow_id
    validator.validate(ev.to_dict())


def test_entity_event_has_flow_id(validator):
    ev = NormalizedEvent.from_entity(
        observed_time=T0,
        input_mode=InputMode.PCAP_REPLAY,
        capability=CapabilityState(InputMode.PCAP_REPLAY),
        entity=["Port scanning / reconnaissance", MONITORED],
    )
    ev.validate()
    assert ev.flow_ref_type == "entity"
    validator.validate(ev.to_dict())


def test_all_three_ref_types_are_in_the_frozen_enum():
    assert set(FLOW_REF_TYPES) == {"flow_5tuple", "aggregate", "entity"}


def test_null_flow_id_with_ref_type_is_rejected(plan):
    ev = _flow(address_plan=plan)
    ev.flow_id = None
    with pytest.raises(NormalizationError, match="flow_id must not be null"):
        ev.validate()


def test_malformed_flow_id_is_rejected(plan):
    ev = _flow(address_plan=plan)
    ev.flow_id = "NOTHEX"
    with pytest.raises(NormalizationError, match="flow_id must match"):
        ev.validate()


# -------------------------------------------------------------- direction


def test_direction_is_populated_from_the_address_plan(validator, plan):
    ev = _flow(address_plan=plan)
    assert ev.direction == "outbound"
    validator.validate(ev.to_dict())


def test_direction_absent_when_no_plan_supplied():
    ev = _flow()
    assert ev.direction is None


def test_invalid_direction_is_rejected(plan):
    ev = _flow(address_plan=plan)
    ev.direction = "sideways"
    with pytest.raises(NormalizationError, match="invalid direction"):
        ev.validate()


# ------------------------------------------------------------- capability


def test_capability_is_serialised_with_all_frozen_fields(plan, schema):
    d = _flow(address_plan=plan).to_dict()
    expected = set(schema["properties"]["capability"]["properties"])
    assert set(d["capability"]) == expected


def test_capability_uses_only_evidence_states(plan):
    d = _flow(address_plan=plan).to_dict()
    allowed = {"OBSERVABLE", "DEGRADED", "NOT_OBSERVABLE"}
    for key, value in d["capability"].items():
        if key == "input_mode":
            continue
        assert value in allowed, (key, value)


def test_component_health_never_leaks_into_capability(plan):
    # UNAVAILABLE is a component-health state and must never appear here.
    d = _flow(address_plan=plan).to_dict()
    assert "UNAVAILABLE" not in set(d["capability"].values())


def test_sflow_does_not_claim_packet_level_visibility():
    """Never fabricate packet-level information from sampled data."""
    cap = CapabilityState(InputMode.SFLOW)
    assert cap.get("flow_sampling") is Capability.OBSERVABLE
    for field in (
        "dns_names",
        "tls_handshake",
        "ja3",
        "ja3s",
        "ja4",
        "bidirectional_visibility",
    ):
        assert cap.get(field) is Capability.NOT_OBSERVABLE, field


def test_flow_record_modes_do_not_claim_dns_or_tls():
    for mode in (InputMode.IPFIX, InputMode.NETFLOW_V9):
        cap = CapabilityState(mode)
        assert cap.get("flow_records") is Capability.OBSERVABLE
        assert cap.get("dns_names") is Capability.NOT_OBSERVABLE
        assert cap.get("ja3") is Capability.NOT_OBSERVABLE


def test_packet_modes_do_not_claim_fingerprints_before_the_probe():
    # Claiming ja4 before the capability probe confirms the build exposes it
    # is the "silent default" failure design.md section 7A exists to prevent.
    cap = CapabilityState(InputMode.PCAP_REPLAY)
    assert cap.get("ja4") is Capability.NOT_OBSERVABLE
    assert cap.get("ipv4") is Capability.OBSERVABLE


def test_capability_can_be_raised_by_a_probe(validator, plan):
    cap = CapabilityState(InputMode.PCAP_REPLAY)
    cap.update(dns_names="OBSERVABLE", ja3="OBSERVABLE", ja3s="DEGRADED")
    ev = _flow(capability=cap, address_plan=plan)
    validator.validate(ev.to_dict())
    assert ev.to_dict()["capability"]["ja3s"] == "DEGRADED"


def test_unknown_capability_field_is_rejected():
    cap = CapabilityState(InputMode.PCAP_REPLAY)
    with pytest.raises(KeyError):
        cap.set("nonexistent_field", "OBSERVABLE")


# ----------------------------------------------------------- field helpers


def test_iso8601_is_utc_and_timezone_stable():
    naive = datetime(2026, 9, 10, 12, 0, 0)
    assert iso8601(naive).endswith("+00:00")
    assert iso8601(T0) == iso8601(naive)


def test_iso8601_accepts_posix_timestamps():
    assert iso8601(T0.timestamp()) == iso8601(T0)


def test_protocol_names_map_from_numbers():
    assert protocol_name(6) == "TCP"
    assert protocol_name(17) == "UDP"
    assert protocol_name(1) == "ICMP"
    assert protocol_name(None) is None
    assert protocol_name(253) == "253"


def test_tcp_flags_render_as_stable_letters():
    assert tcp_flags_str(0x02) == "S"
    assert tcp_flags_str(0x12) == "SA"
    assert tcp_flags_str(0) == "-"
    assert tcp_flags_str(None) is None


# ------------------------------------------------------------- validation


def test_out_of_range_port_is_rejected(plan):
    ev = _flow(address_plan=plan)
    ev.dst_port = 70000
    with pytest.raises(NormalizationError, match="out of range"):
        ev.validate()


def test_negative_counters_are_rejected(plan):
    ev = _flow(address_plan=plan)
    ev.packets = -1
    with pytest.raises(NormalizationError, match="must not be negative"):
        ev.validate()


def test_unknown_input_mode_is_rejected(plan):
    ev = _flow(address_plan=plan)
    ev.input_mode = "carrier_pigeon"
    with pytest.raises(NormalizationError, match="input_mode must be one of"):
        ev.validate()


def test_exporter_metadata_validates_for_flow_records(validator):
    cap = CapabilityState(InputMode.IPFIX)
    ev = NormalizedEvent.from_flow(
        observed_time=T0,
        input_mode=InputMode.IPFIX,
        capability=cap,
        src_ip=MONITORED,
        dst_ip=EXTERNAL,
        src_port=1234,
        dst_port=443,
        protocol=6,
        exporter={
            "exporter_id": "lab-exporter-1",
            "template_id": 256,
            "observation_time": iso8601(T0),
            "sampling_rate": 1,
            "sampled": False,
        },
    )
    ev.validate()
    validator.validate(ev.to_dict())


def test_sentinel_survives_into_aggregate_identity(validator):
    ev = NormalizedEvent.from_aggregate(
        observed_time=T0,
        input_mode=InputMode.IPFIX,
        capability=CapabilityState(InputMode.IPFIX),
        dedup_key=[
            "Malware in encrypted sessions",
            MONITORED,
            NOT_OBSERVABLE,
            EXTERNAL,
        ],
    )
    ev.validate()
    validator.validate(ev.to_dict())
