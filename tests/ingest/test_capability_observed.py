"""raise_from_observed: capability is raised only by what the records carry."""

from __future__ import annotations

from types import SimpleNamespace

from ingest.capability import Capability, CapabilityState, InputMode, raise_from_observed
from scenarios.canonical_campaign import generate_canonical_campaign_events


def test_nothing_is_raised_by_records_without_dns_or_tls():
    state = raise_from_observed(CapabilityState(InputMode.PCAP_REPLAY), [SimpleNamespace(dns=None, tls=None, quic=None)])
    for field in ("dns_names", "dns_responses", "tls_handshake", "quic_metadata", "ja3", "ja3s", "ja4"):
        assert state.get(field) == CapabilityState(InputMode.PCAP_REPLAY).get(field)


def test_only_carried_fields_are_raised():
    event = SimpleNamespace(dns=None, tls={"ja3": "abc"}, quic=None)
    state = raise_from_observed(CapabilityState(InputMode.PCAP_REPLAY), [event])
    assert state.get("tls_handshake") == Capability.OBSERVABLE
    assert state.get("ja3") == Capability.OBSERVABLE
    assert state.get("ja4") != Capability.OBSERVABLE or CapabilityState(InputMode.PCAP_REPLAY).get("ja4") == Capability.OBSERVABLE


def test_canonical_replay_declares_dns_and_fingerprints_it_carries():
    state = raise_from_observed(CapabilityState(InputMode.PCAP_REPLAY), generate_canonical_campaign_events())
    for field in ("dns_names", "dns_responses", "tls_handshake", "ja3", "ja3s", "ja4"):
        assert state.get(field) == Capability.OBSERVABLE, field
