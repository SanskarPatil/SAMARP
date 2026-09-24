"""Botnet C2 beaconing detection module.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 7, 10.7, 12, 14.
PS Threat Class: "Botnet C2 beaconing" (frozen external string).
Internal module: "c2".

Covers:
1. Inter-arrival time (IAT) extraction for repeated connections to (src_ip, dst_ip, dst_port).
2. Coefficient of variation (CV = sigma / mu <= 0.15) and median/MAD timing regularity.
3. Persistence across multiple events / windows.
4. Dedup key [ps_class, src_ip, dst_ip, dst_port].
5. Bounded state across tracked conversations.
"""

from __future__ import annotations

import math
import statistics
from datetime import datetime, timezone
from typing import Any

from features.rolling import WindowSummary
from alerts.confidence import apply_confidence
from ingest.identity import NOT_OBSERVABLE, canonical, identifier
from ingest.normalized_event import NormalizedEvent

PS_CLASS = "Botnet C2 beaconing"
DETECTOR_NAME = "c2"

DEFAULT_CV_MAX = 0.15
DEFAULT_MIN_EVENTS = 8
DEFAULT_WINDOW_S = 300.0
DEFAULT_MAX_TRACKED = 1024
DEFAULT_MAX_HISTORY_PER_FLOW = 64
# Protocols that are periodic by design and owned by other detectors or are
# infrastructure: NTP (UDP/123) and DNS (53, covered by the dns/dga detectors).
DEFAULT_EXEMPT_PORTS: frozenset[tuple[str, int]] = frozenset({("UDP", 123), ("UDP", 53), ("TCP", 53)})
# Fleet prevalence: a destination:port contacted by at least this many distinct
# internal hosts is treated as a shared service (telemetry, updates, backup),
# not a single implant's C2. Known limitation: a botnet with this many infected
# hosts beaconing to one server is suppressed; set 0 to disable.
DEFAULT_FLEET_MIN_HOSTS = 3
DEFAULT_MAX_PREVALENCE_DSTS = 4096
# Flow exporters cut long connections into records at a fixed active timeout
# (5-60 s), which looks periodic. Beacons are small; a record at or above this
# size is a slice of a bulk transfer and is not a beacon.
DEFAULT_MAX_BEACON_BYTES = 1_000_000


def _iso_utc(ts: float | datetime | None = None) -> str:
    if ts is None:
        dt = datetime.now(timezone.utc)
    elif isinstance(ts, (int, float)):
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    else:
        dt = ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


class _C2ConversationState:
    """Bounded history of connection timestamps for a (src_ip, dst_ip, dst_port) tuple."""

    __slots__ = ("src_ip", "dst_ip", "dst_port", "timestamps", "last_seen", "flow_ids")

    def __init__(self, src_ip: str, dst_ip: str, dst_port: int, now: float) -> None:
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.timestamps: list[float] = [now]
        self.last_seen = now
        self.flow_ids: list[str] = []

    def add(self, now: float, flow_id: str | None, max_history: int) -> None:
        self.last_seen = now
        if len(self.timestamps) >= max_history:
            self.timestamps.pop(0)
        self.timestamps.append(now)

        if flow_id and flow_id not in self.flow_ids and len(self.flow_ids) < 16:
            self.flow_ids.append(flow_id)


class C2Detector:
    """Periodic beaconing detector evaluating connection inter-arrival times and jitter."""

    def __init__(
        self,
        cv_max: float = DEFAULT_CV_MAX,
        min_events: int = DEFAULT_MIN_EVENTS,
        window_s: float = DEFAULT_WINDOW_S,
        max_tracked: int = DEFAULT_MAX_TRACKED,
        exempt_ports: frozenset[tuple[str, int]] = DEFAULT_EXEMPT_PORTS,
        fleet_min_hosts: int = DEFAULT_FLEET_MIN_HOSTS,
    ) -> None:
        self.exempt_ports = exempt_ports
        self.fleet_min_hosts = fleet_min_hosts
        # (dst_ip, dst_port) -> distinct source hosts seen (bounded, insertion-ordered LRU)
        self._prevalence: dict[tuple[str, int], set[str]] = {}
        self.cv_max = cv_max
        self.min_events = min_events
        self.window_s = window_s
        self.max_tracked = max_tracked

        # Map (src_ip, dst_ip, dst_port) -> _C2ConversationState
        self._conversations: dict[tuple[str, str, int], _C2ConversationState] = {}
        # Track alerted conversations to avoid duplicate spamming within the same cycle
        self._alerted: set[tuple[str, str, int]] = set()

    def _prune(self, current_time: float) -> None:
        """Evict conversations inactive beyond the tracking window."""
        cutoff = current_time - self.window_s
        expired = [k for k, state in self._conversations.items() if state.last_seen < cutoff]
        for k in expired:
            self._conversations.pop(k, None)
            self._alerted.discard(k)

        while len(self._conversations) >= self.max_tracked:
            oldest_key = min(self._conversations.keys(), key=lambda k: self._conversations[k].last_seen)
            self._conversations.pop(oldest_key, None)
            self._alerted.discard(oldest_key)

    def evaluate_event(self, ev: NormalizedEvent) -> dict[str, Any] | None:
        """Evaluate a NormalizedEvent for periodic beaconing behaviour."""
        if not ev.src_ip or not ev.dst_ip or ev.dst_port is None:
            return None

        if (str(ev.protocol).upper(), int(ev.dst_port)) in self.exempt_ports:
            return None
        if ev.bytes is not None and ev.bytes >= DEFAULT_MAX_BEACON_BYTES:
            return None
        if ev.direction == "inbound":
            return None  # beaconing is an internal host calling out

        now = float(ev.observed_time.timestamp()) if isinstance(ev.observed_time, datetime) else float(ev.observed_time)
        self._prune(now)
        hosts = self._note_prevalence(ev.dst_ip, int(ev.dst_port), ev.src_ip)

        key = (ev.src_ip, ev.dst_ip, ev.dst_port)
        state = self._conversations.get(key)
        if state is None:
            state = _C2ConversationState(ev.src_ip, ev.dst_ip, ev.dst_port, now)
            self._conversations[key] = state
        else:
            state.add(now, ev.flow_id, DEFAULT_MAX_HISTORY_PER_FLOW)

        if self.fleet_min_hosts and hosts >= self.fleet_min_hosts:
            return None  # shared service contacted by many internal hosts
        return self._check_conversation(state, now, ev)

    def _note_prevalence(self, dst_ip: str, dst_port: int, src_ip: str) -> int:
        k = (dst_ip, dst_port)
        srcs = self._prevalence.pop(k, None)
        if srcs is None:
            srcs = set()
            if len(self._prevalence) >= DEFAULT_MAX_PREVALENCE_DSTS:
                self._prevalence.pop(next(iter(self._prevalence)))
        if len(srcs) < 64:
            srcs.add(src_ip)
        self._prevalence[k] = srcs
        return len(srcs)

    def evaluate_window(self, window: WindowSummary) -> list[dict[str, Any]]:
        """Evaluate a closed window by processing sampled events."""
        alerts: list[dict[str, Any]] = []
        for ev in window.sample_events:
            alert = self.evaluate_event(ev)
            if alert:
                alerts.append(alert)
        return alerts

    def _check_conversation(self, state: _C2ConversationState, now: float, ev: NormalizedEvent) -> dict[str, Any] | None:
        count = len(state.timestamps)
        if count < self.min_events:
            return None

        key = (state.src_ip, state.dst_ip, state.dst_port)
        if key in self._alerted:
            return None

        # Compute Inter-Arrival Times (IAT)
        iats = [state.timestamps[i] - state.timestamps[i - 1] for i in range(1, count)]
        # Filter out zero or negative intervals resulting from simultaneous bursts
        valid_iats = [iat for iat in iats if iat > 0.001]
        if len(valid_iats) < self.min_events - 1:
            return None

        mean_iat = statistics.mean(valid_iats)
        if mean_iat < 0.05:
            # Sub-50ms bursts are bulk transfers or scans, not periodic beaconing
            return None

        std_iat = statistics.stdev(valid_iats) if len(valid_iats) > 1 else 0.0
        cv = std_iat / mean_iat
        median_iat = statistics.median(valid_iats)
        mad_iat = statistics.median([abs(x - median_iat) for x in valid_iats])

        # Beaconing condition: coefficient of variation <= cv_max (e.g. 0.15)
        if cv > self.cv_max:
            return None

        self._alerted.add(key)

        # Dedup key: [ps_class, src_ip, dst_ip, dst_port] per frozen config
        dedup_key = [PS_CLASS, state.src_ip, state.dst_ip, state.dst_port]
        inc_id = identifier(dedup_key)
        fl_id = identifier([state.src_ip, state.dst_ip, state.dst_port])

        duration = max(state.timestamps[-1] - state.timestamps[0], 0.001)

        evidence: dict[str, Any] = {
            "interpretation": (
                f"Periodic C2 beaconing observed from {state.src_ip} to {state.dst_ip}:{state.dst_port}: "
                f"{count} events over {duration:.1f}s, mean IAT {mean_iat:.2f}s, CV={cv:.3f} <= {self.cv_max}"
            ),
            "repeated_destination": f"{state.dst_ip}:{state.dst_port}",
            "event_count": count,
            "iat_mean": round(mean_iat, 3),
            "iat_median": round(median_iat, 3),
            "iat_std": round(std_iat, 3),
            "iat_cv": round(cv, 4),
            "iat_mad": round(mad_iat, 3),
            "duration_s": round(duration, 2),
            "sample_iats": [round(x, 3) for x in valid_iats[:10]],
        }

        # Score is inverted CV (higher regularity = higher anomaly score)
        score_val = min(1.0, max(0.0, 1.0 - (cv / self.cv_max) * 0.5))
        input_mode = ev.input_mode.value if hasattr(ev.input_mode, "value") else str(ev.input_mode) if ev.input_mode else "pcap_replay"

        alert: dict[str, Any] = {
            "schema_version": "1.3",
            "timestamp": _iso_utc(now),
            "flow_id": fl_id,
            "flow_ref_type": "aggregate",
            "ps_class": PS_CLASS,
            "threat_class": "c2_beacon",
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
            "severity": "CRITICAL" if cv < 0.08 else "HIGH",
            "first_observed": _iso_utc(state.timestamps[0]),
            "last_observed": _iso_utc(state.timestamps[-1]),
            "event_count": count,
            "contributing_flow_ids": state.flow_ids[:16],
            "window": {
                "start": _iso_utc(state.timestamps[0]),
                "end": _iso_utc(state.timestamps[-1]),
                "duration_s": round(duration, 3),
            },
            "threshold": {
                "cv_max": self.cv_max,
                "min_events": self.min_events,
                "window_s": self.window_s,
            },
            "recommendation": f"ADVISORY: Highly regular beaconing communication detected to {state.dst_ip}:{state.dst_port}. Investigate host for persistent implant or RAT activity.",
        }
        return apply_confidence(alert)
