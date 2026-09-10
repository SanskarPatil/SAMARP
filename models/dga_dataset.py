"""Deterministic, offline DGA corpus and leakage-safe holdout definitions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from random import Random
from typing import Iterable


@dataclass(frozen=True)
class DomainExample:
    qname: str
    label: int
    family: str
    entity: str
    observed_time: datetime

    @property
    def canonical_domain(self) -> str:
        """Canonicalise by lower-casing and stripping the terminal TLD."""
        labels = self.qname.lower().strip(".").split(".")
        return ".".join(labels[:-1]) if len(labels) > 1 else labels[0]


BENIGN_DOMAINS = (
    "api.github.com", "cdn.jsdelivr.net", "telemetry.microsoft.com", "updates.mozilla.org", "ocsp.digicert.com",
    "a1b2c3d4-7788-99aa-bbcc.example-cdn.net", "node-3f8d17a1.metrics.example.org",
    "service-v2-us-east-1.api.example.com", "f0e1d2c3b4a5.update.example.net", "assets.cloudflare.com",
)


def _random_label(rng: Random, alphabet: str, length: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(length))


def _malicious_domain(rng: Random, family: str, index: int) -> str:
    if family == "numeric_seed":
        label = _random_label(rng, "abcdefghijklmnopqrstuvwxyz0123456789", 14) + str(index % 10)
    elif family == "hexflux":
        label = _random_label(rng, "0123456789abcdef", 20)
    elif family == "wordmix":
        label = rng.choice(("amber", "briar", "cinder", "dawn")) + _random_label(rng, "0123456789", 8)
    else:
        raise ValueError(f"unknown DGA family: {family}")
    return f"{label}.bad-example.test"


def build_dga_corpus(seed: int = 26145, per_family: int = 24) -> tuple[DomainExample, ...]:
    """Return a reproducible balanced corpus with deliberately hard negatives."""
    rng = Random(seed)
    origin = datetime(2026, 9, 10, tzinfo=UTC)
    examples: list[DomainExample] = []
    for index in range(per_family):
        examples.append(DomainExample(BENIGN_DOMAINS[index % len(BENIGN_DOMAINS)], 0, "benign", f"benign-host-{index % 8}", origin + timedelta(minutes=index)))
    for family_number, family in enumerate(("numeric_seed", "hexflux", "wordmix")):
        for index in range(per_family):
            examples.append(DomainExample(_malicious_domain(rng, family, index), 1, family, f"infected-host-{family_number}-{index % 6}", origin + timedelta(hours=1 + family_number, minutes=index)))
    return tuple(examples)


@dataclass(frozen=True)
class HoldoutDefinition:
    time_cutoff: datetime
    entities: frozenset[str]
    families: frozenset[str]


def default_holdout_definition() -> HoldoutDefinition:
    return HoldoutDefinition(datetime(2026, 9, 10, 1, 12, tzinfo=UTC), frozenset({"infected-host-1-4", "infected-host-2-5"}), frozenset({"wordmix"}))


def deduplicate_examples(examples: Iterable[DomainExample]) -> tuple[DomainExample, ...]:
    """Deduplicate on canonical domain before any split to prevent leakage."""
    by_domain: dict[str, DomainExample] = {}
    for example in sorted(examples, key=lambda item: (item.observed_time, item.qname)):
        by_domain.setdefault(example.canonical_domain, example)
    return tuple(by_domain[key] for key in sorted(by_domain))


def split_holdouts(examples: Iterable[DomainExample], definition: HoldoutDefinition | None = None) -> dict[str, tuple[DomainExample, ...]]:
    """Create mutually exclusive train/time/entity/family partitions."""
    definition = definition or default_holdout_definition()
    partitions: dict[str, list[DomainExample]] = {name: [] for name in ("train", "time", "entity", "family")}
    for example in deduplicate_examples(examples):
        if example.family in definition.families:
            partitions["family"].append(example)
        elif example.entity in definition.entities:
            partitions["entity"].append(example)
        elif example.observed_time >= definition.time_cutoff:
            partitions["time"].append(example)
        else:
            partitions["train"].append(example)
    return {name: tuple(items) for name, items in partitions.items()}
