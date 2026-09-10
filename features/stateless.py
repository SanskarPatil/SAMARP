"""Pure, deterministic feature primitives owned by P2.

These helpers intentionally use only Python's standard library and fields
permitted by ``normalized_event.schema.json``.  They do not inspect payload
content and do not retain streaming state; P1 owns rolling/window state.
"""

from __future__ import annotations

from collections import Counter
from math import log2, sqrt
from statistics import median
from typing import Iterable, Mapping, Sequence


def shannon_entropy(values: Iterable[object]) -> float:
    """Return Shannon entropy in bits, with an empty input scored as zero."""
    counts = Counter(values)
    total = sum(counts.values())
    if not total:
        return 0.0
    return -sum((count / total) * log2(count / total) for count in counts.values())


def quantile(values: Sequence[float], probability: float) -> float:
    """Deterministic linear-interpolated quantile for ``0 <= probability <= 1``."""
    if not 0.0 <= probability <= 1.0:
        raise ValueError("probability must be between zero and one")
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return 0.0
    if len(ordered) == 1:
        return ordered[0]
    index = probability * (len(ordered) - 1)
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = index - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def median_absolute_deviation(values: Sequence[float]) -> float:
    """Return unscaled MAD; the caller chooses any statistical scaling."""
    if not values:
        return 0.0
    centre = float(median(values))
    return float(median(abs(float(value) - centre) for value in values))


def robust_z_score(value: float, baseline: Sequence[float]) -> float:
    """Return a MAD-based robust z score, safely handling a flat baseline."""
    if not baseline:
        return 0.0
    centre = float(median(baseline))
    mad = median_absolute_deviation(baseline)
    if mad == 0.0:
        return 0.0 if value == centre else (float("inf") if value > centre else float("-inf"))
    return 0.67448975 * (float(value) - centre) / mad


def coefficient_of_variation(values: Sequence[float]) -> float:
    """Population CV; zero for fewer than two intervals or a zero mean."""
    if len(values) < 2:
        return 0.0
    mean = sum(float(value) for value in values) / len(values)
    if mean == 0.0:
        return 0.0
    variance = sum((float(value) - mean) ** 2 for value in values) / len(values)
    return sqrt(variance) / abs(mean)


def qtype_distribution(qtypes: Iterable[str | None]) -> dict[str, float]:
    """Return normalised qtype shares with PS-required qtypes always present."""
    values = [str(qtype).upper() for qtype in qtypes if qtype]
    counts = Counter(values)
    total = sum(counts.values())
    distribution = {
        qtype: (count / total if total else 0.0)
        for qtype, count in sorted(counts.items())
    }
    for required in ("TXT", "NULL", "CNAME"):
        distribution.setdefault(required, 0.0)
    return distribution


def qtype_entropy(distribution: Mapping[str, float]) -> float:
    return -sum(share * log2(share) for share in distribution.values() if share > 0.0)
