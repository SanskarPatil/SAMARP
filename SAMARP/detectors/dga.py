"""DGA (Domain Generation Algorithm) rule-based fallback detector.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 7, 10.3, 12, 13, 14.
Kill Ladder Priority 12: Rule-based fallback when LightGBM is not installed.
PS Threat Class: "DGA / DNS tunnelling" (frozen external string).
Internal module: "dga".

Covers:
1. Lexical features: length, entropy, digit_ratio, vowel_ratio, label_count.
2. Character bigram and trigram natural language anomaly scoring.
3. NXDOMAIN response rate tracking.
4. Tranco / benign allowlist filtering.
5. Calibrated=False and model_version="rules-fallback" per frozen contract.
6. Dedup key [ps_class, src_ip] (NEVER keys on domain).
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Any, Iterable

from features.entropy import shannon_entropy
from features.rolling import WindowSummary
from ingest.identity import NOT_OBSERVABLE, canonical, identifier
from ingest.normalized_event import NormalizedEvent

PS_CLASS = "DGA / DNS tunnelling"
DETECTOR_NAME = "dga"
MODEL_VERSION = "rules-fallback"

DEFAULT_SCORE_THRESHOLD = 0.85
DEFAULT_MIN_QUERIES = 5
DEFAULT_NXDOMAIN_RATE_MIN = 0.4
DEFAULT_MAX_SOURCES = 1024

# Default top-level domains to strip when extracting domain core
COMMON_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "io", "co", "ai", "uk",
    "de", "cn", "in", "ru", "jp", "fr", "br", "it", "nl", "ca", "au",
}

# Default top allowlisted benign domains
DEFAULT_TRANCO_ALLOWLIST = {
    "google.com", "youtube.com", "facebook.com", "microsoft.com", "apple.com",
    "amazon.com", "netflix.com", "wikipedia.org", "yahoo.com", "twitter.com",
    "instagram.com", "linkedin.com", "cloudflare.com", "live.com", "bing.com",
    "office.com", "github.com", "reddit.com", "zoom.us", "adobe.com",
    "wordpress.org", "pinterest.com", "dropbox.com", "whatsapp.com", "spotify.com",
    "akamai.net", "fastly.net", "cloudfront.net", "googleapis.com", "gstatic.com",
}

# Common English character bigrams for transition likelihood
COMMON_BIGRAMS = {
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es",
    "or", "te", "of", "ed", "is", "it", "al", "ar", "st", "to", "nt", "ng",
    "se", "ha", "as", "ou", "io", "le", "ve", "co", "me", "de", "hi", "ri",
    "ro", "ic", "ne", "ea", "ra", "ce", "li", "ch", "ll", "be", "ma", "si",
    "om", "ur", "ca", "el", "ta", "la", "ns", "ge", "fa", "wi", "so", "da",
}


def _iso_utc(ts: float | datetime | None = None) -> str:
    if ts is None:
        dt = datetime.now(timezone.utc)
    elif isinstance(ts, (int, float)):
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    else:
        dt = ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def extract_domain_labels(qname: str) -> tuple[str, str, int]:
    """Extract (core_label, registered_domain, label_count) from a query name.

    Example:
        "www.sub.example.com." -> ("example", "example.com", 4)
    """
    clean = qname.strip().rstrip(".").lower()
    labels = clean.split(".")
    label_count = len(labels)
    if not labels or not labels[0]:
        return "", "", 0

    if label_count == 1:
        return labels[0], labels[0], 1

    # Extract core label and registered domain
    if labels[-1] in COMMON_TLDS and label_count >= 2:
        reg_domain = f"{labels[-2]}.{labels[-1]}"
        core_label = labels[-2]
    else:
        reg_domain = ".".join(labels[-2:])
        core_label = labels[0]

    return core_label, reg_domain, label_count


def calculate_lexical_features(qname: str) -> dict[str, float]:
    """Calculate the 5 frozen lexical features for DGA analysis."""
    core_label, _, label_count = extract_domain_labels(qname)
    if not core_label:
        return {
            "length": 0.0,
            "entropy": 0.0,
            "digit_ratio": 0.0,
            "vowel_ratio": 0.0,
            "label_count": 0.0,
        }

    length = len(core_label)
    entropy = shannon_entropy(core_label)
    digits = sum(1 for ch in core_label if ch.isdigit())
    vowels = sum(1 for ch in core_label if ch in "aeiou")

    return {
        "length": float(length),
        "entropy": round(entropy, 4),
        "digit_ratio": round(digits / length, 4),
        "vowel_ratio": round(vowels / length, 4),
        "label_count": float(label_count),
    }


def calculate_ngram_anomaly(label: str) -> float:
    """Calculate character bigram anomaly score between 0.0 (natural) and 1.0 (anomalous)."""
    clean = "".join(ch for ch in label.lower() if ch.isalpha())
    if len(clean) < 2:
        return 0.0

    total_pairs = len(clean) - 1
    uncommon_pairs = 0
    for i in range(total_pairs):
        bigram = clean[i : i + 2]
        if bigram not in COMMON_BIGRAMS:
            uncommon_pairs += 1

    return round(uncommon_pairs / total_pairs, 4)


class _SourceDGAState:
    """Tracks DNS activity for a single source IP."""

    __slots__ = ("src_ip", "first_seen", "last_seen", "queries", "nxdomain_count")

    def __init__(self, src_ip: str, now: float) -> None:
        self.src_ip = src_ip
        self.first_seen = now
        self.last_seen = now
        # List of dicts: {"qname": str, "nxdomain": bool, "score": float, "features": dict}
        self.queries: list[dict[str, Any]] = []
        self.nxdomain_count = 0

    def add_query(self, qname: str, nxdomain: bool, score: float, features: dict[str, float], now: float) -> None:
        self.last_seen = now
        if nxdomain:
            self.nxdomain_count += 1
        if len(self.queries) < 100:
            self.queries.append({
                "qname": qname,
                "nxdomain": nxdomain,
                "score": score,
                "features": features,
            })


class DGADetector:
    """Rule-based fallback DGA detector conforming to Kill Ladder priority 12."""

    def __init__(
        self,
        score_threshold: float = DEFAULT_SCORE_THRESHOLD,
        min_queries: int = DEFAULT_MIN_QUERIES,
        nxdomain_rate_min: float = DEFAULT_NXDOMAIN_RATE_MIN,
        allowlist: Iterable[str] | None = None,
        max_sources: int = DEFAULT_MAX_SOURCES,
    ) -> None:
        self.score_threshold = score_threshold
        self.min_queries = min_queries
        self.nxdomain_rate_min = nxdomain_rate_min
        self.allowlist = set(DEFAULT_TRANCO_ALLOWLIST)
        if allowlist:
            self.allowlist.update(domain.lower().strip() for domain in allowlist)
        self.max_sources = max_sources

        # Map src_ip -> _SourceDGAState
        self._sources: dict[str, _SourceDGAState] = {}
        self._alerted_sources: set[str] = set()

    def is_allowlisted(self, qname: str) -> bool:
        """Check if domain or its registered domain is in the Tranco allowlist."""
        clean = qname.strip().rstrip(".").lower()
        if clean in self.allowlist:
            return True
        _, reg_domain, _ = extract_domain_labels(clean)
        return reg_domain in self.allowlist

    def score_domain(self, qname: str) -> tuple[float, dict[str, float]]:
        """Score a single domain using lexical and n-gram rules.

        Returns (score, features_dict) where score is in [0.0, 1.0].
        """
        if self.is_allowlisted(qname):
            return 0.0, calculate_lexical_features(qname)

        core_label, _, _ = extract_domain_labels(qname)
        if not core_label or len(core_label) < 4:
            return 0.0, calculate_lexical_features(qname)

        feats = calculate_lexical_features(qname)
        length = feats["length"]
        entropy = feats["entropy"]
        digit_ratio = feats["digit_ratio"]
        vowel_ratio = feats["vowel_ratio"]
        ngram_anomaly = calculate_ngram_anomaly(core_label)

        # Component scores
        # 1. Entropy score (entropy > 3.0 is suspicious)
        entropy_score = min(1.0, max(0.0, (entropy - 2.0) / 1.6))

        # 2. Length score (length > 8 increases score)
        length_score = min(1.0, max(0.0, (length - 6.0) / 10.0))

        # 3. Digit score (high digit ratio is characteristic of many hash-based DGAs)
        digit_score = min(1.0, digit_ratio * 2.0)

        # 4. Vowel anomaly score (very low vowels indicates consonant mash)
        if vowel_ratio < 0.20:
            vowel_anomaly = 1.0 - (vowel_ratio / 0.20)
        elif vowel_ratio > 0.65:
            vowel_anomaly = 0.4
        else:
            vowel_anomaly = 0.0

        # Weighted rule aggregation
        composite = (
            0.30 * entropy_score
            + 0.25 * ngram_anomaly
            + 0.20 * vowel_anomaly
            + 0.15 * length_score
            + 0.10 * digit_score
        )

        final_score = min(1.0, max(0.0, composite))
        feats["lm_bigram"] = ngram_anomaly
        return round(final_score, 4), feats

    def evaluate_event(self, ev: NormalizedEvent) -> dict[str, Any] | None:
        """Evaluate a NormalizedEvent containing DNS query metadata."""
        if not ev.dns or not ev.src_ip:
            return None

        qname = ev.dns.get("qname")
        if not qname:
            return None

        nxdomain = bool(ev.dns.get("nxdomain", False))
        now = float(ev.observed_time.timestamp()) if isinstance(ev.observed_time, datetime) else float(ev.observed_time)

        # Update state for this source IP
        state = self._sources.get(ev.src_ip)
        if state is None:
            if len(self._sources) >= self.max_sources:
                oldest_ip = min(self._sources, key=lambda k: self._sources[k].last_seen)
                self._sources.pop(oldest_ip, None)
                self._alerted_sources.discard(oldest_ip)
            state = _SourceDGAState(ev.src_ip, now)
            self._sources[ev.src_ip] = state

        domain_score, feats = self.score_domain(qname)
        state.add_query(qname, nxdomain, domain_score, feats, now)

        return self._check_source_state(state, now, ev)

    def evaluate_window(self, window: WindowSummary) -> list[dict[str, Any]]:
        """Evaluate a closed window containing DNS queries."""
        alerts: list[dict[str, Any]] = []
        for ev in window.sample_events:
            if ev.dns:
                alert = self.evaluate_event(ev)
                if alert:
                    alerts.append(alert)
        return alerts

    def _check_source_state(self, state: _SourceDGAState, now: float, ev: NormalizedEvent) -> dict[str, Any] | None:
        query_count = len(state.queries)
        if query_count < self.min_queries:
            return None

        # Calculate average domain score and nxdomain rate across queries
        avg_score = sum(q["score"] for q in state.queries) / query_count
        nx_rate = state.nxdomain_count / query_count

        # A burst of DGA queries is detected when average score exceeds threshold
        # and/or combined with high NXDOMAIN failure rate
        exceeds_threshold = (avg_score >= self.score_threshold) or (
            avg_score >= 0.70 and nx_rate >= self.nxdomain_rate_min
        )

        if not exceeds_threshold:
            return None

        if state.src_ip in self._alerted_sources:
            return None
        self._alerted_sources.add(state.src_ip)

        # Dedup key: [ps_class, src_ip] per frozen dedup_keys.yaml
        dedup_key = [PS_CLASS, state.src_ip]
        inc_id = identifier(dedup_key)
        fl_id = identifier(state.src_ip)

        sample_domains = [q["qname"] for q in state.queries[-10:]]
        latest_feats = state.queries[-1]["features"] if state.queries else {}

        evidence: dict[str, Any] = {
            "interpretation": (
                f"DGA burst detected from {state.src_ip}: {query_count} queries, "
                f"avg rule score {avg_score:.2f}, NXDOMAIN rate {nx_rate:.1%}"
            ),
            "query_count": query_count,
            "avg_score": round(avg_score, 3),
            "nxdomain_rate": round(nx_rate, 3),
            "sample_domains": sample_domains,
            "latest_features": latest_feats,
            "model_version": MODEL_VERSION,
        }

        input_mode = str(ev.input_mode) if ev.input_mode else "pcap_replay"

        alert: dict[str, Any] = {
            "schema_version": "1.3",
            "timestamp": _iso_utc(now),
            "flow_id": fl_id,
            "flow_ref_type": "entity",
            "ps_class": PS_CLASS,
            "threat_class": "dga_domain",
            "detector": DETECTOR_NAME,
            "confidence": None,  # Rule fallback confidence is null / uncalibrated
            "score": round(avg_score, 3),
            "score_type": "rule_score",
            "calibrated": False,  # MUST be False for rule fallback
            "evidence": evidence,
            "incident_id": inc_id,
            "dedup_key": canonical(dedup_key),
            "capability": {
                "detector_state": "OBSERVABLE",
                "input_mode": input_mode,
                "missing_evidence": [],
            },
            "model_version": MODEL_VERSION,
            "status": "NEW",
            "severity": "HIGH" if avg_score >= 0.90 else "MEDIUM",
            "first_observed": _iso_utc(state.first_seen),
            "last_observed": _iso_utc(state.last_seen),
            "event_count": query_count,
            "window": {
                "start": _iso_utc(state.first_seen),
                "end": _iso_utc(state.last_seen),
                "duration_s": round(max(state.last_seen - state.first_seen, 0.001), 3),
            },
            "threshold": {
                "score_threshold": self.score_threshold,
                "min_queries": self.min_queries,
                "nxdomain_rate_min": self.nxdomain_rate_min,
            },
            "recommendation": f"ADVISORY: DGA resolution patterns observed from {state.src_ip}. Inspect endpoint for malware beaconing and sinkhole resolving names.",
        }
        return alert
