"""P1 - Sensor / Infrastructure ingest pipeline.

Passive, read-only. Nothing in this package initiates a connection, completes
a handshake, sends traffic toward an observed host, or decrypts anything.

All input modes converge on ingest.normalized_event.NormalizedEvent, which
conforms to the frozen schemas/normalized_event.schema.json.
"""

from .capability import Capability, CapabilityState, Health, InputMode, baseline_for
from .identity import (
    NOT_OBSERVABLE,
    canonical,
    flow_id_for_aggregate,
    flow_id_for_entity,
    flow_id_for_five_tuple,
    identifier,
)
from .address_plan import AddressPlan, AddressPlanError
from .normalized_event import (
    FLOW_REF_TYPES,
    SCHEMA_VERSION,
    NormalizationError,
    NormalizedEvent,
)

__all__ = [
    "Capability",
    "CapabilityState",
    "Health",
    "InputMode",
    "baseline_for",
    "NOT_OBSERVABLE",
    "canonical",
    "identifier",
    "flow_id_for_five_tuple",
    "flow_id_for_aggregate",
    "flow_id_for_entity",
    "AddressPlan",
    "AddressPlanError",
    "NormalizedEvent",
    "NormalizationError",
    "SCHEMA_VERSION",
    "FLOW_REF_TYPES",
]
