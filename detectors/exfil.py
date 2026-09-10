"""Data exfiltration detection module.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 7, 10.8, 12, 14.
PS Threat Class: "Data exfiltration" (frozen external string).
Internal module: "exfil".

Covers:
1. Outbound byte and volume anomaly detection.
2. Outbound-to-inbound byte ratio >= 10.0.
3. Address-plan direction semantics (direction == "outbound").
4. Dedup key [ps_class, src_ip, dst_ip].
5. Bounded memory state per conversation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from features.rolling import WindowSummary
from ingest.identity import NOT_OBSERVABLE, canonical, identifier
from ingest.normalized_event import NormalizedEvent

PS_CLASS = "Data exfiltration"
DETECTOR_NAME = "exfil"

DEFAULT_OUTBOUND_RATIO_MIN = 10.0
DEFAULT_ROBUST_Z = 5.0
DEFAULT_MIN_OUTBOUND_BYTES = 250_000  # 250 KB min transfer volume
DEFAULT_WINDOW_S = 300.0
DEFAULT_MAX_CONVERSATIONS = 1024


def _iso_utc(ts: float | datetime | None = None) -> str:
    if ts is None:
        dt = datetime.now(timezone.utc)
    elif isinstance(ts, (int, float)):
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    else:
        dt = ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


class _ExfilConversationState:
    """Tracks directional bytes transferred between a src_ip and dst_ip."""

    __slots__ = (
        "src_ip",
        "dst_ip",
        "first_seen",
        "last_seen",
        "outbound_bytes",
        "inbound_bytes",
        "outbound_packets",
        "inbound_packets",
        "flow_ids",
    )

    def __init__(self, src_ip: str, dst_ip: str, now: float) -> None:
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.first_seen = now
        self.last_seen = now
        self.outbound_bytes = 0
        self.inbound_bytes = 0
        self.outbound_packets = 0
        self.inbound_packets = 0
        self.flow_ids: list[str] = []

    def add(self, bytes_: int, pkts: int, direction: str | None, flow_id: str | None, now: float) -> None:
        self.last_seen = now
        if direction == "inbound":
            self.inbound_bytes += bytes_
            self.inbound_packets += pkts
        else:
            # Default or outbound
            self.outbound_bytes += bytes_
            self.outbound_packets += pkts

        if flow_id and flow_id not in self.flow_ids and len(self.flow_ids) < 16:
            self.flow_ids.append(flow_id)


class ExfilDetector:
    """Data exfiltration detector identifying asymmetric outbound transfer volumes."""

    def __init__(
        self,
        outbound_ratio_min: float = DEFAULT_OUTBOUND_RATIO_MIN,
        robust_z: float = DEFAULT_ROBUST_Z,
        min_outbound_bytes: int = DEFAULT_MIN_OUTBOUND_BYTES,
        window_s: float = DEFAULT_WINDOW_S,
        max_conversations: int = DEFAULT_MAX_CONVERSATIONS,
    ) -> None:
        self.outbound_ratio_min = outbound_ratio_min
        self.robust_z = robust_z
        self.min_outbound_bytes = min_outbound_bytes
        self.window_s = window_s
        self.max_conversations = max_conversations

        # Map (src_ip, dst_ip) -> _ExfilConversationState
        self._conversations: dict[tuple[str, str], _ExfilConversationState] = {}
        self._alerted: set[tuple[str, str]] = set()

    def _prune(self, current_time: float) -> None:
        cutoff = current_time - self.window_s
        expired = [k for k, s in self._conversations.items() if s.last_seen < cutoff]
        for k in expired:
            self._conversations.pop(k, None)
            self._alerted.discard(k)

        if len(self._conversations) > self.max_conversations:
            oldest = sorted(self._conversations.items(), key=lambda kv: kv[1].last_seen)[: len(self._conversations) - self.max_conversations]
            for k, _ in oldest:
                self._conversations.pop(k, None)
                self._alerted.discard(k)

    def evaluate_event(self, ev: NormalizedEvent) -> dict[str, Any] | None:
        """Evaluate a NormalizedEvent for outbound volume asymmetry."""
        if not ev.src_ip or not ev.dst_ip:
            return None

        # Exfiltration is specifically evaluated on outbound traffic
        if ev.direction and ev.direction not in ("outbound", "external"):
            return None

        now = float(ev.observed_time.timestamp()) if isinstance(ev.observed_time, datetime) else float(ev.observed_time)
        self._prune(now)

        key = (ev.src_ip, ev.dst_ip)
        state = self._conversations.get(key)
        if state is None:
            state = _ExfilConversationState(ev.src_ip, ev.dst_ip, now)
            self._conversations[key] = state

        bytes_ = ev.bytes if ev.bytes is not None else 0
        pkts = ev.packets if ev.packets is not None else 1
        state.add(bytes_, pkts, ev.direction, ev.flow_id, now)

        return self._check_state(state, now, ev)

    def evaluate_window(self, window: WindowSummary) -> list[dict[str, Any]]:
        """Evaluate a closed window with flow summaries and sampled events."""
        alerts: list[dict[str, Any]] = []
        for ev in window.sample_events:
            alert = self.evaluate_event(ev)
            if alert:
                alerts.append(alert)
        return alerts

    def _check_state(self, state: _ExfilConversationState, now: float, ev: NormalizedEvent) -> dict[str, Any] | None:
        if state.outbound_bytes < self.min_outbound_bytes:
            return None

        key = (state.src_ip, state.dst_ip)
        if key in self._alerted:
            return None

        ratio = state.outbound_bytes / max(state.inbound_bytes, 1)
        if ratio < self.outbound_ratio_min:
            return None

        self._alerted.add(key)

        # Dedup key from frozen config: [ps_class, src_ip, dst_ip]
        dedup_key = [PS_CLASS, state.src_ip, state.dst_ip]
        inc_id = identifier(dedup_key)
        fl_id = identifier([state.src_ip, state.dst_ip])

        duration = max(state.last_seen - state.first_seen, 0.001)

        evidence: dict[str, Any] = {
            "interpretation": (
                f"Data exfiltration pattern detected: {state.src_ip} -> {state.dst_ip} "
                f"transferred {state.outbound_bytes:,} outbound bytes vs {state.inbound_bytes:,} inbound bytes "
                f"(asymmetry ratio {ratio:.1f} >= {self.outbound_ratio_min})"
            ),
            "outbound_bytes": state.outbound_bytes,
            "inbound_bytes": state.inbound_bytes,
            "outbound_ratio": round(ratio, 2),
            "outbound_packets": state.outbound_packets,
            "inbound_packets": state.inbound_packets,
            "duration_s": round(duration, 2),
            "source": state.src_ip,
            "destination": state.dst_ip,
            "direction": "outbound",
        }

        score_val = min(1.0, max(0.0, (ratio / self.outbound_ratio_min) * 0.4 + (state.outbound_bytes / (self.min_outbound_bytes * 2)) * 0.6))
        input_mode = str(ev.input_mode) if ev.input_mode else "pcap_replay"

        alert: dict[str, Any] = {
            "schema_version": "1.3",
            "timestamp": _iso_utc(now),
            "flow_id": fl_id,
            "flow_ref_type": "aggregate",
            "ps_class": PS_CLASS,
            "threat_class": "data_exfil",
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
            "severity": "CRITICAL" if state.outbound_bytes >= self.min_outbound_bytes * 4 else "HIGH",
            "first_observed": _iso_utc(state.first_seen),
            "last_observed": _iso_utc(state.last_seen),
            "event_count": state.outbound_packets + state.inbound_packets,
            "contributing_flow_ids": state.flow_ids[:16],
            "window": {
                "start": _iso_utc(state.first_seen),
                "end": _iso_utc(state.last_seen),
                "duration_s": round(duration, 3),
            },
            "threshold": {
                "outbound_ratio_min": self.outbound_ratio_min,
                "min_outbound_bytes": self.min_outbound_bytes,
                "window_s": self.window_s,
            },
            "recommendation": f"ADVISORY: Massive outbound data transfer anomaly detected from internal host {state.src_ip} to external endpoint {state.dst_ip}. Check egress DLP and restrict destination IP.",
        }
        return alert
