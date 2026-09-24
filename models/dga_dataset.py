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
        base = BENIGN_DOMAINS[index % len(BENIGN_DOMAINS)]
        qname = base if index < len(BENIGN_DOMAINS) else f"node-{index}.{base}"
        examples.append(DomainExample(qname, 0, "benign", f"benign-host-{index % 8}", origin + timedelta(minutes=index * 8)))
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


# ---------------------------------------------------------------------------
# Extended corpus + group-aware splits (PS-compliance task 1).
#
# The original 96-domain corpus above is kept unchanged for its existing
# tests.  The extended corpus below is what the LightGBM model is trained and
# evaluated on.  It is SYNTHETIC: benign names are generated from generic
# service / brand-like word lists with deliberate hard negatives (hex hashes,
# UUIDs, region codes); DGA names come from five locally reimplemented
# families.  Nothing here is a label-dependent *feature* - labels only decide
# which generator produced the name.
# ---------------------------------------------------------------------------

import hashlib as _hashlib

BENIGN_SERVICE_LABELS = (
    "www", "api", "cdn", "static", "img", "images", "media", "assets", "mail", "smtp", "login", "auth",
    "accounts", "update", "updates", "download", "telemetry", "metrics", "logs", "events", "docs", "help",
    "support", "portal", "shop", "store", "news", "blog", "video", "ws", "push", "sync", "files", "storage",
    "backup", "vpn", "dev", "staging", "m", "app", "edge", "ocsp", "crl", "ntp", "time", "search",
)
BENIGN_WORDS = (
    "green", "river", "data", "cloud", "tech", "soft", "net", "info", "media", "shop", "global", "india",
    "smart", "secure", "health", "learn", "bank", "travel", "food", "games", "music", "sports", "energy",
    "power", "rail", "post", "city", "metro", "star", "sun", "blue", "red", "north", "east", "open", "micro",
    "book", "home", "field", "farm", "trade", "market", "service", "online", "digital", "mobile", "photo",
    "social", "mail", "office", "portal", "science", "labs", "works", "systems", "group", "network", "world",
    "github", "mozilla", "cloudflare", "digicert", "jsdelivr", "microsoft", "akamai", "fastly",
)
BENIGN_TLDS = ("com", "org", "net", "in", "co.in", "gov.in", "io", "edu", "info")
REGIONS = ("us-east-1", "eu-west-1", "ap-south-1", "ap-southeast-2", "in-mum-1")

# Word list for the dictionary-concatenation DGA family is deliberately
# disjoint from BENIGN_WORDS so the model cannot memorise shared tokens.
DGA_DICT_WORDS = (
    "anchor", "bishop", "canyon", "dragon", "eleven", "falcon", "garden", "harbor", "island", "jungle",
    "kettle", "ladder", "marble", "napkin", "orange", "pepper", "quiver", "rocket", "saddle", "tunnel",
    "umbrella", "velvet", "window", "yellow", "zipper", "butter", "candle", "fossil", "goblin", "hollow",
)
EXTENDED_DGA_FAMILIES = ("numeric_seed", "hexflux", "wordmix", "dictcat", "base32")
DGA_TLDS = ("com", "net", "info", "biz", "xyz", "top", "org", "ru")


def _benign_hostname(rng: Random) -> str:
    sld_style = rng.random()
    if sld_style < 0.55:
        sld = rng.choice(BENIGN_WORDS)
    elif sld_style < 0.85:
        sld = rng.choice(BENIGN_WORDS) + rng.choice(BENIGN_WORDS)
    else:
        sld = rng.choice(BENIGN_WORDS) + str(rng.randint(1, 99))
    domain = f"{sld}.{rng.choice(BENIGN_TLDS)}"
    shape = rng.random()
    if shape < 0.30:
        return domain                                     # bare registered domain
    if shape < 0.62:
        return f"{rng.choice(BENIGN_SERVICE_LABELS)}.{domain}"
    if shape < 0.72:
        return f"{rng.choice(BENIGN_SERVICE_LABELS)}.{rng.choice(REGIONS)}.{domain}"
    if shape < 0.84:                                       # hard negative: CDN / object hash
        return f"{_random_label(rng, '0123456789abcdef', rng.choice((8, 12, 16, 20)))}.{rng.choice(BENIGN_SERVICE_LABELS)}.{domain}"
    if shape < 0.92:                                       # hard negative: UUID-like node id
        uuid = "-".join(_random_label(rng, "0123456789abcdef", n) for n in (8, 4, 4, 4, 12))
        return f"{uuid}.{domain}"
    return f"node-{_random_label(rng, '0123456789abcdef', 8)}.{rng.choice(BENIGN_SERVICE_LABELS)}.{domain}"


def _extended_dga_label(rng: Random, family: str, index: int) -> str:
    if family in ("numeric_seed", "hexflux", "wordmix"):
        return _malicious_domain(rng, family, index).split(".")[0]
    if family == "dictcat":
        return "".join(rng.choice(DGA_DICT_WORDS) for _ in range(rng.choice((2, 2, 3))))
    if family == "base32":
        return _random_label(rng, "abcdefghijklmnopqrstuvwxyz234567", rng.randint(16, 24))
    raise ValueError(f"unknown DGA family: {family}")


def registered_domain(qname: str) -> str:
    """eTLD+1 approximation with the two-level Indian suffixes used above."""
    labels = qname.lower().strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in ("co.in", "gov.in"):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def split_group(example: DomainExample) -> str:
    """Grouping key for leakage-safe splits: benign by registered domain, DGA by family."""
    return f"benign:{registered_domain(example.qname)}" if example.label == 0 else f"dga:{example.family}"


def build_extended_dga_corpus(seed: int = 26145, benign_count: int = 1500, per_family: int = 300) -> tuple[DomainExample, ...]:
    """Deterministic synthetic corpus: ``benign_count`` benign + 5 x ``per_family`` DGA names."""
    rng = Random(seed)
    origin = datetime(2026, 9, 10, tzinfo=UTC)
    examples: list[DomainExample] = [DomainExample(q, 0, "benign", "", origin) for q in BENIGN_DOMAINS]
    seen = {q for q in BENIGN_DOMAINS}
    while len(examples) < benign_count:
        qname = _benign_hostname(rng)
        if qname not in seen:
            seen.add(qname)
            examples.append(DomainExample(qname, 0, "benign", f"benign-host-{len(examples) % 40}", origin + timedelta(seconds=len(examples))))
    for family_number, family in enumerate(EXTENDED_DGA_FAMILIES):
        produced = 0
        while produced < per_family:
            qname = f"{_extended_dga_label(rng, family, produced)}.{rng.choice(DGA_TLDS)}"
            if qname in seen:
                continue
            seen.add(qname)
            examples.append(DomainExample(qname, 1, family, f"infected-host-{family_number}-{produced % 6}", origin + timedelta(hours=1 + family_number, seconds=produced)))
            produced += 1
    return deduplicate_examples(examples)


def _bucket(key: str, buckets: int) -> int:
    return int(_hashlib.sha256(key.encode("utf-8")).hexdigest()[:8], 16) % buckets


def grouped_train_validation_split(examples: Iterable[DomainExample], validation_buckets: tuple[int, ...] = (0, 1, 2), buckets: int = 10) -> dict[str, tuple[DomainExample, ...]]:
    """~30 % validation split with no registered domain on both sides.

    Benign names are grouped by registered domain; DGA names (each its own
    registered domain) are bucketed per name so every family appears in both
    partitions.  Unseen-family generalisation is measured separately by
    :func:`family_holdout_splits`.
    """
    train: list[DomainExample] = []
    validation: list[DomainExample] = []
    for example in examples:
        key = registered_domain(example.qname)
        (validation if _bucket(key, buckets) in validation_buckets else train).append(example)
    return {"train": tuple(train), "validation": tuple(validation)}


def family_holdout_splits(examples: Iterable[DomainExample], families: Iterable[str] = EXTENDED_DGA_FAMILIES) -> list[tuple[str, tuple[DomainExample, ...], tuple[DomainExample, ...]]]:
    """Leave-one-DGA-family-out folds.

    Fold k tests on DGA family k (never seen in training) plus the benign
    registered-domain bucket k; it trains on the other families and the other
    benign buckets.  No registered domain and no family crosses the split.
    """
    examples = tuple(examples)
    families = tuple(families)
    folds = []
    for index, family in enumerate(families):
        train, test = [], []
        for example in examples:
            if example.label == 1:
                (test if example.family == family else train).append(example)
            else:
                (test if _bucket(registered_domain(example.qname), len(families)) == index else train).append(example)
        folds.append((family, tuple(train), tuple(test)))
    return folds
