"""Streaming and static Shannon entropy calculations.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md section 6.4, 10.3, 10.4.
Frozen contracts: schemas/alert.schema.json, features/feature_order.py.

Bounded memory guarantees:
- StreamingEntropy maintains a bounded frequency counter with LRU/frequency eviction.
- Never allocates unbounded state on arbitrary attacker-controlled strings or tokens.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Any, Iterable, Mapping, Sequence

DEFAULT_MAX_DISTINCT = 1024


def shannon_entropy_from_counts(
    counts: Mapping[Any, int | float],
    total: float | None = None,
) -> float:
    """Calculate base-2 Shannon entropy from an item-to-frequency mapping.

    Returns 0.0 if total is 0 or all counts are non-positive.
    """
    if total is None:
        total = sum(c for c in counts.values() if c > 0)
    if total <= 0:
        return 0.0

    entropy = 0.0
    for count in counts.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def shannon_entropy(data: str | bytes | Sequence[Any]) -> float:
    """Calculate base-2 Shannon entropy of a sequence (string, bytes, or list).

    Example:
        shannon_entropy("aaaa") == 0.0
        shannon_entropy("ab") == 1.0
    """
    if not data:
        return 0.0
    counts = Counter(data)
    return shannon_entropy_from_counts(counts, len(data))


class StreamingEntropy:
    """Bounded-memory streaming Shannon entropy estimator.

    Maintains frequency counts of observed elements up to ``max_distinct``.
    When ``max_distinct`` is reached, the least frequent entries are evicted
    to prevent memory exhaustion from arbitrary attacker keys.
    """

    __slots__ = ("_counts", "_total", "_max_distinct")

    def __init__(self, max_distinct: int = DEFAULT_MAX_DISTINCT) -> None:
        if max_distinct < 1:
            raise ValueError("max_distinct must be >= 1")
        self._counts: dict[Any, int] = {}
        self._total: int = 0
        self._max_distinct: int = max_distinct

    @property
    def total(self) -> int:
        return self._total

    @property
    def distinct_count(self) -> int:
        return len(self._counts)

    def add(self, item: Any, count: int = 1) -> None:
        """Add an observation of ``item`` with multiplicity ``count``."""
        if count <= 0:
            return

        if item in self._counts:
            self._counts[item] += count
        else:
            if len(self._counts) >= self._max_distinct:
                # Evict the minimum-frequency item to maintain hard bound
                min_key = min(self._counts, key=self._counts.get)  # type: ignore[arg-type]
                self._total -= self._counts.pop(min_key)
            self._counts[item] = count

        self._total += count

    def add_batch(self, items: Iterable[Any]) -> None:
        """Add multiple items in batch."""
        for item in items:
            self.add(item)

    def entropy(self) -> float:
        """Return the current Shannon entropy in bits (base-2)."""
        return shannon_entropy_from_counts(self._counts, self._total)

    def counts(self) -> dict[Any, int]:
        """Return a copy of the current counts."""
        return dict(self._counts)

    def reset(self) -> None:
        """Reset the estimator to empty state."""
        self._counts.clear()
        self._total = 0
