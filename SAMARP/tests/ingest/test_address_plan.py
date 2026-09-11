"""Address plan: direction inference and the RFC 1918 bogon trap.

Two failures in the same family, both fixed by config/address_plan.yaml:

* Reflection reserved-source share is 100% on benign traffic in a pure
  RFC 1918 lab, so the detector fires continuously unless declared lab
  prefixes are excluded from the bogon set.
* Geolocation does not resolve for private lab addressing at all.

Loads the real frozen plan - not a mock - so a change to the plan that would
break direction inference fails here.
"""

from __future__ import annotations

import pytest

from ingest.address_plan import DIRECTIONS, AddressPlan, AddressPlanError

# Declared synthetic lab ranges, from config/address_plan.yaml.
MONITORED = "10.10.0.5"
RESOLVER = "10.10.0.53"
MONITORING = "10.20.0.5"
TRANSPORT = "10.99.0.2"
# RFC 5737 documentation ranges stand in for the external side in direction
# tests, where routability is irrelevant.
EXTERNAL_A = "203.0.113.7"
EXTERNAL_B = "198.51.100.4"

# A genuinely routable public address for bogon tests.
#
# IMPORTANT: Python's ipaddress module classifies the RFC 5737 documentation
# ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) as PRIVATE. They are
# therefore unsuitable for the "external and routable" case, and - more
# importantly - unsuitable for populating external.* in address_plan.yaml.
#
# If the curated external ranges were filled with documentation space, the
# reflection reserved-source share would be ~100% again: exactly the trap
# section 2A.3 exists to prevent, reintroduced one level down. The plan
# already requires "curated public ranges, GeoLite2-resolvable" - this is why.
#
# No traffic is ever sent to this address; it appears only as a string.
EXTERNAL_ROUTABLE = "93.184.216.34"


@pytest.fixture(scope="module")
def plan() -> AddressPlan:
    return AddressPlan.load()


# ------------------------------------------------------------------ loading


def test_loads_the_frozen_plan(plan: AddressPlan):
    assert plan.monitored, "monitored_enclave.prefixes must not be empty"
    assert str(plan.dns_resolver) == RESOLVER


def test_missing_monitored_prefixes_is_a_hard_error():
    # direction, exfil and reflection all depend on this. Failing loudly is
    # correct; silently inferring nothing is not.
    with pytest.raises(AddressPlanError):
        AddressPlan({"monitored_enclave": {"prefixes": []}})


def test_invalid_network_is_rejected():
    with pytest.raises(AddressPlanError):
        AddressPlan({"monitored_enclave": {"prefixes": ["not-a-network"]}})


# ---------------------------------------------------------------- membership


def test_membership_classification(plan: AddressPlan):
    assert plan.is_monitored(MONITORED)
    assert not plan.is_monitored(EXTERNAL_A)
    assert plan.is_monitoring(MONITORING)
    assert plan.is_lab_transport(TRANSPORT)


def test_declared_lab_covers_all_three_ranges(plan: AddressPlan):
    for addr in (MONITORED, MONITORING, TRANSPORT):
        assert plan.is_declared_lab(addr), addr
    assert not plan.is_declared_lab(EXTERNAL_A)


def test_external_is_the_complement_of_declared_lab(plan: AddressPlan):
    assert plan.is_external(EXTERNAL_A)
    assert not plan.is_external(MONITORED)


# ----------------------------------------------------------------- direction


def test_direction_outbound_when_source_in_enclave(plan: AddressPlan):
    assert plan.direction(MONITORED, EXTERNAL_A) == "outbound"


def test_direction_inbound_when_destination_in_enclave(plan: AddressPlan):
    assert plan.direction(EXTERNAL_A, MONITORED) == "inbound"


def test_direction_internal_when_both_in_enclave(plan: AddressPlan):
    assert plan.direction(MONITORED, RESOLVER) == "internal"


def test_direction_external_when_neither_in_enclave(plan: AddressPlan):
    assert plan.direction(EXTERNAL_A, EXTERNAL_B) == "external"


def test_direction_values_are_within_the_frozen_enum(plan: AddressPlan):
    pairs = [
        (MONITORED, EXTERNAL_A),
        (EXTERNAL_A, MONITORED),
        (MONITORED, RESOLVER),
        (EXTERNAL_A, EXTERNAL_B),
    ]
    for src, dst in pairs:
        assert plan.direction(src, dst) in DIRECTIONS


def test_direction_is_none_rather_than_guessed_when_address_missing(plan: AddressPlan):
    # Direction is never inferred from a missing address.
    assert plan.direction(None, MONITORED) is None
    assert plan.direction(MONITORED, None) is None
    assert plan.direction("not-an-ip", MONITORED) is None


# --------------------------------------------------------------- bogon trap


def test_declared_lab_prefixes_are_excluded_from_the_bogon_set(plan: AddressPlan):
    """THE trap this plan exists to fix.

    Without the exclusion, every benign RFC 1918 lab source counts as
    reserved space, the reserved-source share is 100%, and the reflection
    detector fires continuously - destroying false-alerts-per-hour.
    """
    assert plan.bogon_exclude_lab is True
    for addr in (MONITORED, MONITORING, TRANSPORT, RESOLVER):
        assert not plan.is_bogon(addr), f"{addr} must not count as bogon"


def test_reserved_share_is_computed_against_external_space_only(plan: AddressPlan):
    assert plan.bogon_external_only is True
    # A genuinely routable public address is not reserved space.
    assert not plan.is_bogon(EXTERNAL_ROUTABLE)


def test_bogon_detects_genuine_reserved_space_outside_the_lab(plan: AddressPlan):
    # Reserved space that is NOT a declared lab prefix stays eligible for the
    # reserved-source-share feature - that is what makes the feature useful.
    for reserved in ("192.168.7.7", "172.16.0.1", "127.0.0.1", "169.254.1.1"):
        assert plan.is_external(reserved), reserved
        assert plan.is_bogon(reserved), reserved


def test_documentation_ranges_count_as_reserved_not_public(plan: AddressPlan):
    """Guards the trap described at the top of this module.

    Python classifies RFC 5737 documentation space as private. Populating
    external.* with these ranges would drive the reserved-source share back
    to ~100% on benign traffic.
    """
    assert plan.is_bogon(EXTERNAL_A)
    assert not plan.is_bogon(EXTERNAL_ROUTABLE)


def test_bogon_of_missing_address_is_false_not_true(plan: AddressPlan):
    assert plan.is_bogon(None) is False


# ------------------------------------------------------- amplifier and ipv6


def test_amplifier_ports_come_from_the_plan(plan: AddressPlan):
    for port in (53, 123, 389, 1900, 11211):
        assert plan.is_amplifier_port(port), port
    assert not plan.is_amplifier_port(443)
    assert not plan.is_amplifier_port(None)


def test_ipv6_entropy_bucket_uses_the_declared_prefix_length(plan: AddressPlan):
    bucket = plan.ipv6_entropy_bucket("2001:db8:abcd:1234::1")
    assert bucket == "2001:db8:abcd::/48"


def test_ipv6_bucket_is_none_for_ipv4(plan: AddressPlan):
    assert plan.ipv6_entropy_bucket(MONITORED) is None
