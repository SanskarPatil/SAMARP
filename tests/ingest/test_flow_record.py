"""NetFlow v9 / IPFIX adapter: decoding, templates, bounds, contract.

One decoder serves both protocols (V6.3 section 2.4). These tests assert that
the two paths produce identical event structure, that template lifecycle is
handled correctly, and that the adapter never invents packet-level detail a
flow record cannot carry.
"""

from __future__ import annotations

import ipaddress
import json
import struct
from pathlib import Path

import jsonschema
import pytest

from ingest.address_plan import AddressPlan
from ingest.capability import Capability, CapabilityState, InputMode
from ingest.flow_record_adapter import (
    DEFAULT_MAX_TEMPLATES,
    FlowRecordAdapter,
    FlowRecordError,
    TemplateCache,
    TemplateKey,
)

from flow_record_builder import (  # noqa: E402
    EXPORT_TIME,
    EXTENDED_FIELDS,
    IPFIX_FIXTURE_RECORDS,
    IPFIX_OPTIONS_SET,
    IPV6_FIELDS,
    NETFLOW_V9_FIXTURE_RECORDS,
    basic_record,
    data_set,
    extended_record,
    ipfix_datagram,
    ipfix_fixture,
    ipfix_template_set,
    ipv6_record,
    netflow_v9_fixture,
    nf9_datagram,
    nf9_template_set,
    template_set,
)

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def validator():
    schema = json.loads(
        (REPO / "schemas" / "normalized_event.schema.json").read_text(encoding="utf-8")
    )
    return jsonschema.Draft202012Validator(schema)


@pytest.fixture(scope="module")
def plan():
    return AddressPlan.load()


def adapter(plan=None, **kw) -> FlowRecordAdapter:
    return FlowRecordAdapter(address_plan=plan, capture_source="fixture", **kw)


# --------------------------------------------------- both protocols decode


def test_netflow_v9_fixture_decodes(tmp_path, validator, plan):
    path = netflow_v9_fixture(tmp_path / "nf9.bin")
    a = adapter(plan)
    events = list(a.decode_file(path))

    assert len(events) == NETFLOW_V9_FIXTURE_RECORDS
    for ev in events:
        ev.validate()
        validator.validate(ev.to_dict())
        assert str(InputMode(ev.input_mode)) == "netflow_v9"


def test_ipfix_fixture_decodes(tmp_path, validator, plan):
    path = ipfix_fixture(tmp_path / "ipfix.bin")
    a = adapter(plan)
    events = list(a.decode_file(path))

    assert len(events) == IPFIX_FIXTURE_RECORDS
    for ev in events:
        ev.validate()
        validator.validate(ev.to_dict())
        assert str(InputMode(ev.input_mode)) == "ipfix"


def test_both_protocols_produce_identical_structure(plan):
    """One decoder, one contract - only input_mode differs."""
    rec = basic_record()
    nf9 = adapter(plan).decode_datagram(
        nf9_datagram(nf9_template_set(256), data_set(256, [rec]))
    )
    ipfix = adapter(plan).decode_datagram(
        ipfix_datagram(ipfix_template_set(256), data_set(256, [rec]))
    )

    a, b = nf9[0].to_dict(), ipfix[0].to_dict()
    assert a["input_mode"] == "netflow_v9"
    assert b["input_mode"] == "ipfix"
    for key in (
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "packets",
        "bytes",
        "flow_id",
        "flow_ref_type",
        "direction",
    ):
        assert a[key] == b[key], key


def test_field_values_decode_correctly(plan):
    events = adapter(plan).decode_datagram(
        ipfix_datagram(ipfix_template_set(256), data_set(256, [basic_record()]))
    )
    ev = events[0]
    assert ev.src_ip == "10.10.0.5"
    assert ev.dst_ip == "93.184.216.34"
    assert ev.src_port == 44321
    assert ev.dst_port == 443
    assert ev.protocol == "TCP"
    assert ev.packets == 10
    assert ev.bytes == 1500
    assert ev.direction == "outbound"


def test_ipv6_records_decode(plan, validator):
    events = adapter(plan).decode_datagram(
        ipfix_datagram(
            ipfix_template_set(300, IPV6_FIELDS), data_set(300, [ipv6_record()])
        )
    )
    ev = events[0]
    assert ev.ip_version == 6
    assert ev.src_ip == "2001:db8::1"
    validator.validate(ev.to_dict())


def test_multiple_records_in_one_data_set(plan):
    records = [basic_record(sport=1000 + i) for i in range(20)]
    events = adapter(plan).decode_datagram(
        ipfix_datagram(ipfix_template_set(256), data_set(256, records))
    )
    assert len(events) == 20
    assert len({e.flow_id for e in events}) == 20


# ------------------------------------------------------- flow identity


def test_flow_id_is_deterministic_across_runs(plan):
    dgram = ipfix_datagram(ipfix_template_set(256), data_set(256, [basic_record()]))
    first = adapter(plan).decode_datagram(dgram)[0]
    second = adapter(plan).decode_datagram(dgram)[0]
    assert first.flow_id == second.flow_id


def test_flow_id_matches_the_shared_identity_helper(plan):
    from ingest.identity import flow_id_for_five_tuple

    ev = adapter(plan).decode_datagram(
        ipfix_datagram(ipfix_template_set(256), data_set(256, [basic_record()]))
    )[0]
    expected = flow_id_for_five_tuple("10.10.0.5", "93.184.216.34", 44321, 443, "TCP")
    assert ev.flow_id == expected


def test_flow_ref_type_is_five_tuple(plan):
    ev = adapter(plan).decode_datagram(
        ipfix_datagram(ipfix_template_set(256), data_set(256, [basic_record()]))
    )[0]
    assert ev.flow_ref_type == "flow_5tuple"
    assert ev.flow_id is not None


def test_reverse_direction_record_shares_the_flow_id(plan):
    fwd = adapter(plan).decode_datagram(
        ipfix_datagram(ipfix_template_set(256), data_set(256, [basic_record()]))
    )[0]
    rev = adapter(plan).decode_datagram(
        ipfix_datagram(
            ipfix_template_set(256),
            data_set(
                256,
                [
                    basic_record(
                        src="93.184.216.34", dst="10.10.0.5", sport=443, dport=44321
                    )
                ],
            ),
        )
    )[0]
    assert fwd.flow_id == rev.flow_id
    assert fwd.direction != rev.direction


# ---------------------------------------------------- template lifecycle


def test_template_registration(plan):
    a = adapter(plan)
    a.decode_datagram(ipfix_datagram(ipfix_template_set(256)))
    assert a.cache.stats.templates_registered == 1
    assert len(a.cache) == 1


def test_template_replacement_changes_decoding(plan):
    """Re-registering the same ID must REPLACE the layout.

    Keeping the old layout would silently mis-decode every later record.
    """
    a = adapter(plan)
    a.decode_datagram(ipfix_datagram(ipfix_template_set(256)))
    a.decode_datagram(ipfix_datagram(ipfix_template_set(256, EXTENDED_FIELDS)))

    assert a.cache.stats.templates_replaced == 1
    assert len(a.cache) == 1, "replacement must not create a second entry"

    events = a.decode_datagram(
        ipfix_datagram(data_set(256, [extended_record(flags=0x12)]))
    )
    # Old layout has no TCP_FLAGS field, so decoding a new record with it
    # would leave tcp_flags unset. Seeing SYN|ACK proves replacement took.
    assert events[0].tcp_flags == 0x12
    assert events[0].to_dict()["tcp_flags"] == "SA", "new layout must be in force"


def test_template_scoped_by_exporter_domain(plan):
    """Template 256 from domain 1 must not decode domain 2's records."""
    a = adapter(plan)
    a.decode_datagram(ipfix_datagram(ipfix_template_set(256), domain=1))
    events = a.decode_datagram(ipfix_datagram(data_set(256, [basic_record()]), domain=2))
    assert events == []
    assert a.stats.data_sets_deferred == 1


def test_templates_persist_across_datagrams(plan):
    a = adapter(plan)
    a.decode_datagram(ipfix_datagram(ipfix_template_set(256)))
    events = a.decode_datagram(ipfix_datagram(data_set(256, [basic_record()])))
    assert len(events) == 1


def test_netflow_and_ipfix_share_one_cache(plan):
    """V6.3 2.4: one shared template cache, not two parsers."""
    cache = TemplateCache()
    nf9 = FlowRecordAdapter(address_plan=plan, cache=cache)
    ipfix = FlowRecordAdapter(address_plan=plan, cache=cache)

    nf9.decode_datagram(nf9_datagram(nf9_template_set(256)))
    assert len(cache) == 1
    assert ipfix.cache is cache


def test_template_expiry(plan):
    cache = TemplateCache(idle_timeout=10.0)
    key = TemplateKey("fixture:1", 1, 256)
    cache.register(key, ((8, 4),), now=100.0)
    assert cache.get(key, now=105.0) is not None
    assert cache.get(key, now=200.0) is None
    assert cache.stats.templates_expired == 1


# ------------------------------------------------------- bounded state


def test_template_cache_never_exceeds_its_cap():
    cache = TemplateCache(max_templates=50)
    for i in range(5000):
        cache.register(TemplateKey("fixture:1", 1, 256 + i), ((8, 4),), now=0.0)
        assert len(cache) <= 50
    assert len(cache) == 50
    assert cache.stats.templates_evicted == 4950


def test_hostile_template_stream_stays_bounded(plan):
    """Thousands of distinct template IDs must not grow state without limit."""
    a = FlowRecordAdapter(address_plan=plan, cache=TemplateCache(max_templates=32))
    for i in range(2000):
        a.decode_datagram(ipfix_datagram(ipfix_template_set(256 + i)))
    assert len(a.cache) <= 32
    assert a.cache.stats.templates_evicted > 0


def test_max_templates_must_be_positive():
    with pytest.raises(ValueError, match="at least 1"):
        TemplateCache(max_templates=0)


def test_default_cap_is_a_real_bound():
    assert 0 < DEFAULT_MAX_TEMPLATES < 10**6


def test_template_with_absurd_field_count_is_rejected(plan):
    a = adapter(plan)
    body = struct.pack("!HH", 256, 60000)  # 60k fields claimed
    bad = struct.pack("!HH", 2, 4 + len(body)) + body
    a.decode_datagram(ipfix_datagram(bad))
    assert len(a.cache) == 0
    assert a.stats.records_malformed >= 1


# -------------------------------------------- unknown / malformed input


def test_data_before_template_is_deferred_not_guessed(plan):
    a = adapter(plan)
    events = a.decode_datagram(ipfix_datagram(data_set(256, [basic_record()])))
    assert events == []
    assert a.stats.data_sets_deferred == 1
    assert 256 in a.stats.unknown_templates


def test_decoding_resumes_once_the_template_arrives(plan):
    a = adapter(plan)
    a.decode_datagram(ipfix_datagram(data_set(256, [basic_record()])))
    a.decode_datagram(ipfix_datagram(ipfix_template_set(256)))
    events = a.decode_datagram(ipfix_datagram(data_set(256, [basic_record()])))
    assert len(events) == 1


def test_unknown_template_does_not_stop_other_sets(plan):
    a = adapter(plan)
    dgram = ipfix_datagram(
        ipfix_template_set(300, IPV6_FIELDS),
        data_set(256, [basic_record()]),  # unknown
        data_set(300, [ipv6_record()]),  # known
    )
    events = a.decode_datagram(dgram)
    assert len(events) == 1, "known set must still decode"
    assert a.stats.data_sets_deferred == 1


def test_unsupported_version_is_rejected(plan):
    bad = struct.pack("!HHIII", 5, 16, EXPORT_TIME, 1, 1)
    with pytest.raises(FlowRecordError, match="unsupported flow-record version 5"):
        adapter(plan).decode_datagram(bad)


def test_truncated_ipfix_datagram_is_counted_not_raised(plan):
    a = adapter(plan)
    dgram = ipfix_datagram(ipfix_template_set(256), data_set(256, [basic_record()]))
    events = list(a.decode_stream(dgram[: len(dgram) - 10]))
    assert events == []
    assert a.stats.datagrams_malformed == 1


def test_truncated_set_stops_cleanly(plan):
    a = adapter(plan)
    body = ipfix_template_set(256) + struct.pack("!HH", 256, 400)  # claims 400
    dgram = struct.pack("!HHIII", 10, 16 + len(body), EXPORT_TIME, 1, 1) + body
    a.decode_datagram(dgram)
    assert a.stats.datagrams_malformed >= 1
    assert len(a.cache) == 1, "the valid template before it must survive"


def test_zero_length_set_does_not_loop(plan):
    a = adapter(plan)
    body = struct.pack("!HH", 256, 0)
    dgram = struct.pack("!HHIII", 10, 16 + len(body), EXPORT_TIME, 1, 1) + body
    a.decode_datagram(dgram)
    assert a.stats.datagrams_malformed >= 1


def test_options_template_set_is_skipped_not_misparsed(plan):
    a = adapter(plan)
    body = struct.pack("!HHH", 258, 4, 2) + b"\x00" * 8
    opts = struct.pack("!HH", IPFIX_OPTIONS_SET, 4 + len(body)) + body
    a.decode_datagram(ipfix_datagram(opts))
    assert a.stats.options_sets_skipped == 1
    assert len(a.cache) == 0


def test_record_without_addresses_is_malformed_not_fabricated(plan):
    fields = ((7, 2), (11, 2), (4, 1))  # ports and protocol only
    a = adapter(plan)
    a.decode_datagram(ipfix_datagram(template_set(256, fields, set_id=2)))
    events = a.decode_datagram(
        ipfix_datagram(data_set(256, [struct.pack("!HHB", 1, 2, 6)]))
    )
    assert events == []
    assert a.stats.records_malformed >= 1


def test_missing_fixture_file_is_reported(tmp_path, plan):
    with pytest.raises(FlowRecordError, match="not found"):
        list(adapter(plan).decode_file(tmp_path / "nope.bin"))


# --------------------------------------------------- capability semantics


def test_dns_and_tls_stay_not_observable(plan):
    """Flow records cannot carry names or fingerprints."""
    ev = adapter(plan).decode_datagram(
        ipfix_datagram(ipfix_template_set(256), data_set(256, [basic_record()]))
    )[0]
    cap = ev.to_dict()["capability"]
    for f in (
        "dns_names",
        "dns_responses",
        "tls_handshake",
        "ja3",
        "ja3s",
        "ja4",
        "quic_metadata",
    ):
        assert cap[f] == "NOT_OBSERVABLE", f


def test_flow_records_capability_is_observable(plan):
    ev = adapter(plan).decode_datagram(
        ipfix_datagram(ipfix_template_set(256), data_set(256, [basic_record()]))
    )[0]
    assert ev.to_dict()["capability"]["flow_records"] == "OBSERVABLE"


def test_no_packet_level_fields_are_invented(plan):
    """The adapter must not fabricate shape, dns, tls or quic blocks."""
    ev = adapter(plan).decode_datagram(
        ipfix_datagram(ipfix_template_set(256), data_set(256, [basic_record()]))
    )[0]
    d = ev.to_dict()
    for absent in ("dns", "tls", "quic", "shape", "flow_summary"):
        assert absent not in d, absent


def test_sampling_metadata_is_preserved(plan):
    fields = ((8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (34, 4))
    rec = (
        ipaddress.IPv4Address("10.10.0.5").packed
        + ipaddress.IPv4Address("93.184.216.34").packed
        + struct.pack("!HHB", 44321, 443, 6)
        + struct.pack("!I", 100)
    )
    a = adapter(plan)
    a.decode_datagram(ipfix_datagram(template_set(256, fields, set_id=2)))
    ev = a.decode_datagram(ipfix_datagram(data_set(256, [rec])))[0]

    exporter = ev.to_dict()["exporter"]
    assert exporter["sampling_rate"] == 100
    assert exporter["sampled"] is True
    assert ev.to_dict()["capability"]["flow_sampling"] == "OBSERVABLE"


def test_exporter_identity_is_preserved(plan):
    ev = adapter(plan).decode_datagram(
        ipfix_datagram(
            ipfix_template_set(256), data_set(256, [basic_record()]), domain=42
        )
    )[0]
    assert ev.to_dict()["exporter"]["exporter_id"] == "fixture:42"


def test_capability_state_can_be_supplied(plan):
    cap = CapabilityState(InputMode.IPFIX)
    a = FlowRecordAdapter(address_plan=plan, capability=cap)
    a.decode_datagram(
        ipfix_datagram(ipfix_template_set(256), data_set(256, [basic_record()]))
    )
    assert cap.get("flow_records") is Capability.OBSERVABLE


# ------------------------------------------------------ passive boundary


def test_adapter_module_has_no_network_surface():
    import inspect

    import ingest.flow_record_adapter as mod

    src = inspect.getsource(mod)
    for banned in (
        "socket.",
        "urllib",
        "requests.",
        ".connect(",
        ".sendto(",
        ".bind(",
        ".listen(",
    ):
        assert banned not in src, banned


def test_adapter_never_writes_files():
    import inspect

    import ingest.flow_record_adapter as mod

    src = inspect.getsource(mod)
    for banned in ("write_bytes", "write_text"):
        assert banned not in src, banned
