"""Feature extraction from the frozen normalised-event contract.

The functions are deliberately stateless so offline training and streaming
inference use identical transformations.  Window grouping remains external
and bounded by the P1-owned window service.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from math import log
from typing import Any

from .feature_order import FEATURE_ORDER
from .stateless import coefficient_of_variation, qtype_distribution, qtype_entropy, quantile, shannon_entropy


def _labels(domain: str | None) -> list[str]:
    return [label for label in (domain or "").lower().strip(".").split(".") if label]


def _primary_label(domain: str | None) -> str:
    labels = _labels(domain)
    return labels[0] if labels else ""


def character_ratio(value: str, predicate) -> float:
    return sum(bool(predicate(character)) for character in value) / len(value) if value else 0.0


def _mean(values: Iterable[float]) -> float:
    values = [float(value) for value in values]
    return sum(values) / len(values) if values else 0.0


def _language_score(label: str, n: int, language_model: Mapping[str, float] | None) -> float:
    """Average log likelihood of n-grams; unseen grams receive a fixed floor."""
    if not label or len(label) < n or not language_model:
        return 0.0
    grams = [label[index : index + n] for index in range(len(label) - n + 1)]
    floor = float(language_model.get("__floor__", -12.0))
    return _mean(log(max(float(language_model.get(gram, 0.0)), 1e-12)) if gram in language_model else floor for gram in grams)


def domain_features(
    qname: str | None,
    *,
    nxdomain_rate: float = 0.0,
    language_model: Mapping[str, float] | None = None,
) -> dict[str, float]:
    """Extract lexical DGA features from an observable DNS name only."""
    labels = _labels(qname)
    label = _primary_label(qname)
    alpha = "".join(character for character in label if character.isalnum())
    return {
        "length": float(len(label)),
        "entropy": shannon_entropy(alpha),
        "digit_ratio": character_ratio(label, str.isdigit),
        "vowel_ratio": character_ratio(label, lambda character: character in "aeiou"),
        "label_count": float(len(labels)),
        "lm_bigram": _language_score(alpha, 2, language_model),
        "lm_trigram": _language_score(alpha, 3, language_model),
        "nxdomain_rate": float(nxdomain_rate),
    }


def dns_window_features(events: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Compute deterministic DNS window features and visible qtype distribution."""
    events = list(events)
    qtypes = [((event.get("dns") or {}).get("qtype")) for event in events]
    distribution = qtype_distribution(qtypes)
    return {
        "qtype_distribution": distribution,
        "qtype_txt_ratio": distribution["TXT"],
        "qtype_null_ratio": distribution["NULL"],
        "qtype_cname_ratio": distribution["CNAME"],
        "qtype_entropy": qtype_entropy(distribution),
        "query_count": len(events),
        "unique_qname_count": len({(event.get("dns") or {}).get("qname") for event in events if (event.get("dns") or {}).get("qname")}),
    }


def shape_features(event: Mapping[str, Any]) -> dict[str, Any]:
    """Return TLS/QUIC traffic-shape features without payload inspection."""
    shape = event.get("shape") or {}
    sizes = [float(size) for size in (shape.get("packet_size_first_n") or [])]
    directions = [str(direction) for direction in (shape.get("direction_first_n") or [])]
    return {
        "packet_size_first_n": [int(size) for size in sizes],
        "packet_size_mean": _mean(sizes),
        "packet_size_p95": quantile(sizes, 0.95),
        "direction_first_n": directions,
        "iat_median": float(shape.get("iat_median") or 0.0),
        "iat_p95": float(shape.get("iat_p95") or 0.0),
        "iat_cv": float(shape.get("iat_cv") or 0.0),
        "upstream_packet_ratio": float(shape.get("upstream_packet_ratio") or 0.0),
        "downstream_packet_ratio": float(shape.get("downstream_packet_ratio") or 0.0),
    }


def interarrival_features(timestamps: Iterable[float]) -> dict[str, float]:
    ordered = sorted(float(timestamp) for timestamp in timestamps)
    intervals = [right - left for left, right in zip(ordered, ordered[1:])]
    return {
        "iat_median": quantile(intervals, 0.5),
        "iat_p95": quantile(intervals, 0.95),
        "iat_cv": coefficient_of_variation(intervals),
    }


def feature_record(
    event: Mapping[str, Any],
    *,
    dns_window: Mapping[str, Any] | None = None,
    language_model: Mapping[str, float] | None = None,
) -> dict[str, Any]:
    """Build the complete frozen feature record without mutating ``event``."""
    dns = event.get("dns") or {}
    record: dict[str, Any] = {}
    record.update(domain_features(dns.get("qname"), language_model=language_model))
    record.update(dns_window or dns_window_features([event]))
    record.update(shape_features(event))
    return record


def ordered_feature_vector(record: Mapping[str, Any]) -> tuple[float, ...]:
    """Encode ``FEATURE_ORDER`` deterministically for numeric model input.

    ``packet_size_first_n`` is a contract-visible list; its frozen model-slot
    encoding is the arithmetic mean while the full list remains available as
    evidence.  This avoids altering the frozen feature order.
    """
    vector: list[float] = []
    for name in FEATURE_ORDER:
        value = record.get(name, 0.0)
        if name == "packet_size_first_n":
            value = _mean(value or [])
        vector.append(float(value or 0.0))
    return tuple(vector)
