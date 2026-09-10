"""DNS Tunnelling and record-type anomaly detection module.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 7, 9.5, 10.4, 12, 14.
PS Threat Class: "DGA / DNS tunnelling" (frozen external string).
Internal module: "dns".

Covers:
1. DNS tunnelling detection (query length, entropy, volume per registered domain).
2. qtype distribution analysis (TXT, NULL, CNAME shares, qtype entropy).
3. Dedup key [ps_class, src_ip, registered_domain] with NOT_OBSERVABLE sentinel.
4. Bounded state across tracked domains and clients.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from features.entropy import shannon_entropy, shannon_entropy_from_counts
from features.rolling import WindowSummary
from ingest.identity import NOT_OBSERVABLE, canonical, identifier
from ingest.normalized_event import NormalizedEvent

PS_CLASS = "DGA / DNS tunnelling"
DETECTOR_NAME = "dns"

DEFAULT_QNAME_LEN_MIN = 50
DEFAULT_ENTROPY_MIN = 3.5
DEFAULT_QPS_PER_DOMAIN_MIN = 10
DEFAULT_MIN_QUERIES = 5
DEFAULT_WINDOW_S = 60.0
DEFAULT_MAX_DOMAINS = 1024

COMMON_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "io", "co", "ai", "uk",
    "de", "cn", "in", "ru", "jp", "fr", "br", "it", "nl", "ca", "au",
}


def _iso_utc(ts: float | datetime | None = None) -> str:
    if ts is None:
        dt = datetime.now(timezone.utc)
    elif isinstance(ts, (int, float)):
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    else:
        dt = ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def extract_registered_domain(qname: str) -> str:
    """Extract eTLD+1 registered domain from query name, or NOT_OBSERVABLE."""
    clean = qname.strip().rstrip(".").lower()
    if not clean:
        return NOT_OBSERVABLE
    labels = clean.split(".")
    if len(labels) == 1:
        return labels[0]
    if labels[-1] in COMMON_TLDS and len(labels) >= 2:
        return f"{labels[-2]}.{labels[-1]}"
    return ".".join(labels[-2:])


class _DomainTunnelState:
    """Bounded history of DNS queries for a (src_ip, registered_domain) pair."""

    __slots__ = (
        "src_ip",
        "registered_domain",
        "first_seen",
        "last_seen",
        "query_count",
        "lengths",
        "entropies",
        "qtypes",
        "sample_queries",
    )

    def __init__(self, src_ip: str, registered_domain: str, now: float) -> None:
        self.src_ip = src_ip
        self.registered_domain = registered_domain
        self.first_seen = now
        self.last_seen = now
        self.query_count = 0
        self.lengths: list[int] = []
        self.entropies: list[float] = []
        self.qtypes: Counter[str] = Counter()
        self.sample_queries: list[str] = []

    def add(self, qname: str, qtype: str | None, now: float) -> None:
        self.last_seen = now
        self.query_count += 1

        length = len(qname.strip().rstrip("."))
        entropy = shannon_entropy(qname)
        if len(self.lengths) < 100:
            self.lengths.append(length)
            self.entropies.append(entropy)

        qt = (qtype or "UNKNOWN").upper()
        self.qtypes[qt] += 1

        if len(self.sample_queries) < 10:
            self.sample_queries.append(qname)


class DNSTunnelDetector:
    """DNS tunnelling detector analyzing query length, entropy, and qtype distribution."""

    def __init__(
        self,
        qname_len_min: int = DEFAULT_QNAME_LEN_MIN,
        entropy_min: float = DEFAULT_ENTROPY_MIN,
        qps_per_domain_min: float = DEFAULT_QPS_PER_DOMAIN_MIN,
        min_queries: int = DEFAULT_MIN_QUERIES,
        window_s: float = DEFAULT_WINDOW_S,
        max_domains: int = DEFAULT_MAX_DOMAINS,
    ) -> None:
        self.qname_len_min = qname_len_min
        self.entropy_min = entropy_min
        self.qps_per_domain_min = qps_per_domain_min
        self.min_queries = min_queries
        self.window_s = window_s
        self.max_domains = max_domains

        # Map (src_ip, registered_domain) -> _DomainTunnelState
        self._domains: dict[tuple[str, str], _DomainTunnelState] = {}
        self._alerted: set[tuple[str, str]] = set()

    def _prune(self, current_time: float) -> None:
        """Prune domains inactive outside the tracking window."""
        cutoff = current_time - self.window_s
        expired = [k for k, s in self._domains.items() if s.last_seen < cutoff]
        for k in expired:
            self._domains.pop(k, None)
            self._alerted.discard(k)

        if len(self._domains) > self.max_domains:
            oldest = sorted(self._domains.items(), key=lambda kv: kv[1].last_seen)[: len(self._domains) - self.max_domains]
            for k, _ in oldest:
                self._domains.pop(k, None)
                self._alerted.discard(k)

    def evaluate_event(self, ev: NormalizedEvent) -> dict[str, Any] | None:
        """Evaluate a single NormalizedEvent containing DNS data."""
        if not ev.dns or not ev.src_ip:
            return None

        qname = ev.dns.get("qname")
        if not qname:
            return None

        now = float(ev.observed_time.timestamp()) if isinstance(ev.observed_time, datetime) else float(ev.observed_time)
        self._prune(now)

        reg_domain = ev.dns.get("registered_domain") or extract_registered_domain(qname)
        key = (ev.src_ip, reg_domain)

        state = self._domains.get(key)
        if state is None:
            state = _DomainTunnelState(ev.src_ip, reg_domain, now)
            self._domains[key] = state

        qtype = ev.dns.get("qtype")
        state.add(qname, qtype, now)

        return self._check_state(state, now, ev)

    def evaluate_window(self, window: WindowSummary) -> list[dict[str, Any]]:
        """Evaluate a closed window with aggregated DNS events."""
        alerts: list[dict[str, Any]] = []
        for ev in window.sample_events:
            if ev.dns:
                alert = self.evaluate_event(ev)
                if alert:
                    alerts.append(alert)
        return alerts

    def _check_state(self, state: _DomainTunnelState, now: float, ev: NormalizedEvent) -> dict[str, Any] | None:
        if state.query_count < self.min_queries:
            return None

        key = (state.src_ip, state.registered_domain)
        if key in self._alerted:
            return None

        avg_len = sum(state.lengths) / len(state.lengths) if state.lengths else 0.0
        avg_entropy = sum(state.entropies) / len(state.entropies) if state.entropies else 0.0

        duration = max(state.last_seen - state.first_seen, 0.001)
        qps = state.query_count / duration if duration > 0 else float(state.query_count)

        # qtype distribution calculations
        total_qtypes = sum(state.qtypes.values())
        txt_count = state.qtypes.get("TXT", 0)
        null_count = state.qtypes.get("NULL", 0)
        cname_count = state.qtypes.get("CNAME", 0)

        txt_ratio = (txt_count / total_qtypes) if total_qtypes > 0 else 0.0
        null_ratio = (null_count / total_qtypes) if total_qtypes > 0 else 0.0
        cname_ratio = (cname_count / total_qtypes) if total_qtypes > 0 else 0.0
        qtype_entropy_val = shannon_entropy_from_counts(state.qtypes, total_qtypes)

        # Tunnelling conditions:
        # 1. High-payload tunnel (length >= 50 and entropy >= 3.5)
        # 2. Or high frequency query rate (qps >= 10) with elevated length
        # 3. Or significant TXT/NULL ratio (> 20%) with high length
        tunnel_condition = (
            (avg_len >= self.qname_len_min and avg_entropy >= self.entropy_min)
            or (qps >= self.qps_per_domain_min and avg_len >= 30)
            or ((txt_ratio > 0.20 or null_ratio > 0.10) and avg_len >= 25)
        )

        if not tunnel_condition:
            return None

        self._alerted.add(key)

        # Dedup key from frozen config: [ps_class, src_ip, registered_domain]
        # Unavailable components take the exact NOT_OBSERVABLE sentinel
        reg_domain_comp = state.registered_domain if state.registered_domain else NOT_OBSERVABLE
        dedup_key = [PS_CLASS, state.src_ip, reg_domain_comp]
        inc_id = identifier(dedup_key)
        fl_id = identifier([state.src_ip, reg_domain_comp])

        # Evidence matching alert.schema.json properties
        evidence: dict[str, Any] = {
            "interpretation": (
                f"DNS tunnelling activity detected for domain '{state.registered_domain}' from {state.src_ip}: "
                f"{state.query_count} queries, avg length {avg_len:.1f}, entropy {avg_entropy:.2f}, "
                f"qtype shares: TXT={txt_ratio:.1%}, NULL={null_ratio:.1%}, CNAME={cname_ratio:.1%}"
            ),
            "qtype_distribution": dict(state.qtypes),
            "qtype_txt_ratio": round(txt_ratio, 3),
            "qtype_null_ratio": round(null_ratio, 3),
            "qtype_cname_ratio": round(cname_ratio, 3),
            "qtype_entropy": round(qtype_entropy_val, 3),
            "query_count": state.query_count,
            "avg_length": round(avg_len, 2),
            "avg_entropy": round(avg_entropy, 3),
            "qps": round(qps, 2),
            "sample_queries": state.sample_queries,
            "registered_domain": state.registered_domain,
        }

        score_val = min(1.0, max(0.0, (avg_len / self.qname_len_min) * 0.5 + (avg_entropy / self.entropy_min) * 0.5))
        input_mode = str(ev.input_mode) if ev.input_mode else "pcap_replay"

        alert: dict[str, Any] = {
            "schema_version": "1.3",
            "timestamp": _iso_utc(now),
            "flow_id": fl_id,
            "flow_ref_type": "aggregate",
            "ps_class": PS_CLASS,
            "threat_class": "dns_tunnel",
            "detector": DETECTOR_NAME,
            "confidence": None,
            "score": round(score_val, 3),
            "score_type": "anomaly_score",
            "calibrated": False,
            "evidence": evidence,
            "incident_id": inc_id,
            "dedup_key": canonical(dedup_key),
            "capability": {
                "detector_state": "OBSERVABLE",
                "input_mode": input_mode,
                "missing_evidence": [],
            },
            "status": "NEW",
            "severity": "HIGH" if (txt_ratio > 0.3 or null_ratio > 0.2 or avg_len > 70) else "MEDIUM",
            "first_observed": _iso_utc(state.first_seen),
            "last_observed": _iso_utc(state.last_seen),
            "event_count": state.query_count,
            "window": {
                "start": _iso_utc(state.first_seen),
                "end": _iso_utc(state.last_seen),
                "duration_s": round(duration, 3),
            },
            "threshold": {
                "qname_len_min": self.qname_len_min,
                "entropy_min": self.entropy_min,
                "qps_per_domain_min": self.qps_per_domain_min,
            },
            "recommendation": f"ADVISORY: Encapsulated DNS tunnel data detected to {state.registered_domain}. Inspect querying client {state.src_ip} and block unauthorized external DNS resolvers.",
        }
        return alert
