"""Port scanning and reconnaissance detection module.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 7, 10.5, 12, 14.
PS Threat Class: "Port scanning / reconnaissance" (frozen external string).
Internal module: "scan".

Covers:
1. Destination-host spread (horizontal sweep / network scan).
2. Destination-port spread (vertical port scan).
3. Hybrid multi-host / multi-port scanning.
4. Bounded state across tracked sources and targets.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from features.rolling import WindowSummary
from ingest.identity import NOT_OBSERVABLE, canonical, identifier
from ingest.normalized_event import NormalizedEvent

PS_CLASS = "Port scanning / reconnaissance"
DETECTOR_NAME = "scan"

DEFAULT_UNIQUE_DST_MIN = 50
DEFAULT_UNIQUE_PORT_MIN = 100
DEFAULT_WINDOW_S = 10.0
DEFAULT_MAX_SOURCES = 1024
DEFAULT_MAX_TARGETS_PER_SRC = 512


def _iso_utc(ts: float | datetime | None = None) -> str:
    if ts is None:
        dt = datetime.now(timezone.utc)
    elif isinstance(ts, (int, float)):
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    else:
        dt = ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


class _SourceScanState:
    """Bounded state tracking destinations and ports probed by a single source IP."""

    __slots__ = ("src_ip", "first_seen", "last_seen", "dst_ips", "dst_ports", "packet_count", "bytes_count")

    def __init__(self, src_ip: str, now: float) -> None:
        self.src_ip = src_ip
        self.first_seen = now
        self.last_seen = now
        self.dst_ips: set[str] = set()
        self.dst_ports: set[int] = set()
        self.packet_count = 0
        self.bytes_count = 0

    def add(self, dst_ip: str | None, dst_port: int | None, pkts: int, bytes_: int, now: float, max_targets: int) -> None:
        self.last_seen = now
        self.packet_count += pkts
        self.bytes_count += bytes_
        if dst_ip and len(self.dst_ips) < max_targets:
            self.dst_ips.add(dst_ip)
        if dst_port is not None and len(self.dst_ports) < max_targets:
            self.dst_ports.add(dst_port)


class ScanDetector:
    """Reconnaissance and port scan detector with bounded source/target memory."""

    def __init__(
        self,
        unique_dst_min: int = DEFAULT_UNIQUE_DST_MIN,
        unique_port_min: int = DEFAULT_UNIQUE_PORT_MIN,
        window_s: float = DEFAULT_WINDOW_S,
        max_sources: int = DEFAULT_MAX_SOURCES,
        max_targets_per_src: int = DEFAULT_MAX_TARGETS_PER_SRC,
    ) -> None:
        self.unique_dst_min = unique_dst_min
        self.unique_port_min = unique_port_min
        self.window_s = window_s
        self.max_sources = max_sources
        self.max_targets_per_src = max_targets_per_src

        # Map src_ip -> _SourceScanState
        self._sources: dict[str, _SourceScanState] = {}
        # Track active alerted sources to prevent redundant alerts per sweep
        self._alerted_sources: set[str] = set()

    def _prune_old_sources(self, current_time: float) -> None:
        """Evict sources whose last activity is outside the tracking window."""
        cutoff = current_time - self.window_s
        expired = [ip for ip, state in self._sources.items() if state.last_seen < cutoff]
        for ip in expired:
            self._sources.pop(ip, None)
            self._alerted_sources.discard(ip)

        # Hard LRU bound if still above max_sources
        if len(self._sources) > self.max_sources:
            oldest = sorted(self._sources.items(), key=lambda kv: kv[1].last_seen)[: len(self._sources) - self.max_sources]
            for ip, _ in oldest:
                self._sources.pop(ip, None)
                self._alerted_sources.discard(ip)

    def evaluate_event(self, ev: NormalizedEvent) -> dict[str, Any] | None:
        """Evaluate a single NormalizedEvent and emit an alert if scan threshold exceeded."""
        if not ev.src_ip:
            return None

        now = float(ev.observed_time.timestamp()) if isinstance(ev.observed_time, datetime) else float(ev.observed_time)
        self._prune_old_sources(now)

        state = self._sources.get(ev.src_ip)
        if state is None:
            state = _SourceScanState(ev.src_ip, now)
            self._sources[ev.src_ip] = state

        pkts = ev.packets if ev.packets is not None else 1
        bytes_ = ev.bytes if ev.bytes is not None else 0
        state.add(ev.dst_ip, ev.dst_port, pkts, bytes_, now, self.max_targets_per_src)

        return self._check_state(state, now, ev)

    def evaluate_window(self, window: WindowSummary) -> list[dict[str, Any]]:
        """Evaluate a closed window by checking aggregated events."""
        alerts: list[dict[str, Any]] = []
        now = window.end_time
        self._prune_old_sources(now)

        # Ingest events from window sample
        for ev in window.sample_events:
            alert = self.evaluate_event(ev)
            if alert:
                alerts.append(alert)

        return alerts

    def _check_state(self, state: _SourceScanState, now: float, ev: NormalizedEvent) -> dict[str, Any] | None:
        dst_count = len(state.dst_ips)
        port_count = len(state.dst_ports)

        is_vertical = port_count >= self.unique_port_min
        is_horizontal = dst_count >= self.unique_dst_min

        if not (is_vertical or is_horizontal):
            return None

        # Prevent continuous re-alerting on the same scan source within the same window
        if state.src_ip in self._alerted_sources:
            return None
        self._alerted_sources.add(state.src_ip)

        if is_vertical and is_horizontal:
            pattern = "hybrid"
            threat_class = "network_scan"
            detail = f"Hybrid scan: probed {port_count} ports across {dst_count} hosts"
        elif is_vertical:
            pattern = "vertical"
            threat_class = "port_scan"
            detail = f"Vertical port scan: probed {port_count} ports on target hosts"
        else:
            pattern = "horizontal"
            threat_class = "host_sweep"
            detail = f"Horizontal host sweep: probed {dst_count} distinct destination hosts"

        # Dedup key: [ps_class, src_ip]
        dedup_key = [PS_CLASS, state.src_ip]
        inc_id = identifier(dedup_key)
        # Entity flow id is derived from canonical(src_ip) per FR-6 and design.md section 9.4
        fl_id = identifier(state.src_ip)

        duration = max(now - state.first_seen, 0.001)

        evidence: dict[str, Any] = {
            "interpretation": f"{detail} in {duration:.1f}s",
            "unique_dst_count": dst_count,
            "unique_port_count": port_count,
            "scan_pattern": pattern,
            "packets_sent": state.packet_count,
            "duration_s": round(duration, 2),
            "sample_targets": sorted(list(state.dst_ips))[:10],
            "sample_ports": sorted(list(state.dst_ports))[:10],
        }

        # Score computation (ratio to threshold, capped to 1.0)
        score_val = max(dst_count / self.unique_dst_min, port_count / self.unique_port_min)
        confidence_val = min(1.0, round(score_val * 0.5, 3))

        input_mode = str(ev.input_mode) if ev.input_mode else "pcap_replay"

        alert: dict[str, Any] = {
            "schema_version": "1.3",
            "timestamp": _iso_utc(now),
            "flow_id": fl_id,
            "flow_ref_type": "entity",
            "ps_class": PS_CLASS,
            "threat_class": threat_class,
            "detector": DETECTOR_NAME,
            "confidence": None,  # Statistical detector confidence is null per FR-9
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
            "severity": "HIGH" if (dst_count >= self.unique_dst_min * 2 or port_count >= self.unique_port_min * 2) else "MEDIUM",
            "first_observed": _iso_utc(state.first_seen),
            "last_observed": _iso_utc(state.last_seen),
            "event_count": state.packet_count,
            "window": {
                "start": _iso_utc(state.first_seen),
                "end": _iso_utc(state.last_seen),
                "duration_s": round(duration, 3),
            },
            "threshold": {
                "unique_dst_min": self.unique_dst_min,
                "unique_port_min": self.unique_port_min,
                "window_s": self.window_s,
            },
            "recommendation": f"ADVISORY: Reconnaissance probe detected from {state.src_ip}. Inspect source reputation and restrict perimeter ingress ACLs.",
        }
        return alert
