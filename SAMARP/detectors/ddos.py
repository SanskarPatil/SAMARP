"""DDoS and Slowloris detection module.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 7, 10.1, 10.2, 12, 14.
PS Threat Class: "Volumetric DDoS / flooding" (frozen external string).
Internal module: "ddos".

Covers:
1. Volumetric / protocol flood detection (SYN flood, UDP flood, generic volumetric).
2. Robust z-score / baseline comparison, hysteresis, source entropy, SYN/ACK ratio.
3. Slowloris low-rate connection-exhaustion path inside this module.
   - Requires concurrency AND duration gates to agree.
   - Exposes half_open_concurrency, connection_duration_p95, bytes_per_connection.
"""

from __future__ import annotations

import math
import statistics
from datetime import datetime, timezone
from typing import Any, Sequence

from features.rolling import WindowSummary
from ingest.identity import NOT_OBSERVABLE, canonical, identifier

PS_CLASS = "Volumetric DDoS / flooding"
DETECTOR_NAME = "ddos"

DEFAULT_MIN_PPS = 5000
DEFAULT_ROBUST_Z = 6.0
DEFAULT_HYSTERESIS_WINDOWS = 2
DEFAULT_WARMUP_WINDOWS = 30

# Slowloris thresholds (low-rate, long-duration, high concurrency)
DEFAULT_SLOWLORIS_MIN_CONCURRENCY = 5
DEFAULT_SLOWLORIS_MIN_DURATION_S = 10.0
DEFAULT_SLOWLORIS_MAX_BYTES_PER_CONN = 1500
DEFAULT_SLOWLORIS_MAX_PPS = 100.0


def _iso_utc(ts: float | datetime | None = None) -> str:
    if ts is None:
        dt = datetime.now(timezone.utc)
    elif isinstance(ts, (int, float)):
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    else:
        dt = ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _robust_z_score(value: float, median: float, mad: float) -> float:
    """Compute robust z-score: (value - median) / (1.4826 * MAD)."""
    if mad <= 1e-6:
        return 0.0 if abs(value - median) < 1e-6 else float(value - median)
    return (value - median) / (1.4826 * mad)


class DDoSDetector:
    """Volumetric flood and Slowloris detector operating on WindowSummary observations."""

    def __init__(
        self,
        min_pps: float = DEFAULT_MIN_PPS,
        robust_z_threshold: float = DEFAULT_ROBUST_Z,
        hysteresis_windows: int = DEFAULT_HYSTERESIS_WINDOWS,
        slowloris_min_concurrency: int = DEFAULT_SLOWLORIS_MIN_CONCURRENCY,
        slowloris_min_duration_s: float = DEFAULT_SLOWLORIS_MIN_DURATION_S,
        slowloris_max_bytes_per_conn: float = DEFAULT_SLOWLORIS_MAX_BYTES_PER_CONN,
        slowloris_max_pps: float = DEFAULT_SLOWLORIS_MAX_PPS,
    ) -> None:
        self.min_pps = min_pps
        self.robust_z_threshold = robust_z_threshold
        self.hysteresis_windows = hysteresis_windows

        self.slowloris_min_concurrency = slowloris_min_concurrency
        self.slowloris_min_duration_s = slowloris_min_duration_s
        self.slowloris_max_bytes_per_conn = slowloris_max_bytes_per_conn
        self.slowloris_max_pps = slowloris_max_pps

        # Baseline history of normal window pps (bounded to 100 windows)
        self._pps_history: list[float] = []
        self._consecutive_flood_windows = 0

        # Flow duration / connection tracker for Slowloris
        # Map (dst_ip, dst_port) -> dict of active flow metrics
        self._active_connections: dict[tuple[str, int], list[dict[str, Any]]] = {}

    def update_baseline(self, normal_pps: float) -> None:
        """Update baseline history from verified benign windows."""
        if len(self._pps_history) >= 100:
            self._pps_history.pop(0)
        self._pps_history.append(normal_pps)

    def evaluate_window(self, window: WindowSummary) -> list[dict[str, Any]]:
        """Evaluate a closed window for volumetric DDoS or Slowloris attacks."""
        alerts: list[dict[str, Any]] = []

        # 1. Volumetric flood evaluation
        flood_alert = self._check_volumetric_flood(window)
        if flood_alert:
            alerts.append(flood_alert)

        # 2. Slowloris evaluation
        slowloris_alert = self._check_slowloris(window)
        if slowloris_alert:
            alerts.append(slowloris_alert)

        return alerts

    def _check_volumetric_flood(self, window: WindowSummary) -> dict[str, Any] | None:
        current_pps = window.pps

        # Calculate robust z-score if baseline exists
        if len(self._pps_history) >= 5:
            med = statistics.median(self._pps_history)
            mad = statistics.median([abs(x - med) for x in self._pps_history])
            z_score = _robust_z_score(current_pps, med, mad)
            baseline_dict = {
                "median_pps": med,
                "mad_pps": mad,
                "history_samples": len(self._pps_history),
            }
        else:
            med = None
            mad = None
            z_score = 0.0
            baseline_dict = None

        # A flood condition is triggered if either pps exceeds hard threshold or z_score exceeds gate
        exceeds_threshold = (current_pps >= self.min_pps) or (
            baseline_dict is not None and z_score >= self.robust_z_threshold and current_pps > 100.0
        )

        if exceeds_threshold:
            self._consecutive_flood_windows += 1
        else:
            self._consecutive_flood_windows = 0
            # Record non-flood windows into baseline
            if current_pps > 0:
                self.update_baseline(current_pps)
            return None

        # Hysteresis check
        if self._consecutive_flood_windows < self.hysteresis_windows:
            return None

        # Determine target IP and port from top destination in this window
        top_dst_ip = max(window.dst_ip_counts, key=window.dst_ip_counts.get) if window.dst_ip_counts else "0.0.0.0"
        top_dst_port = max(window.dst_port_counts, key=window.dst_port_counts.get) if window.dst_port_counts else 0

        # Dedup key from frozen config: [ps_class, dst_ip, dst_port]
        dedup_key = [PS_CLASS, top_dst_ip, top_dst_port]
        inc_id = identifier(dedup_key)
        fl_id = identifier(dedup_key)  # Aggregate flow identity matches dedup key

        # Classify specific threat label based on protocol indicators
        syns = window.syn_count
        acks = window.ack_count
        udp_pkts = window.protocols.get("UDP", 0)
        tcp_pkts = window.protocols.get("TCP", 0)

        if syns > 0 and (acks == 0 or (syns / max(acks, 1)) >= 3.0 or (syns / max(window.packet_count, 1)) >= 0.5):
            threat_class = "syn_flood"
            detail = f"High SYN-to-ACK ratio ({syns} SYNs vs {acks} ACKs)"
        elif udp_pkts > 0 and (udp_pkts / max(window.packet_count, 1)) >= 0.6:
            threat_class = "udp_flood"
            detail = f"High UDP traffic volume ({udp_pkts} UDP packets, {window.pps:.1f} pps)"
        else:
            threat_class = "volumetric_flood"
            detail = f"Packet rate anomaly ({current_pps:.1f} pps)"

        # Evidence payload satisfying minimum evidence contract
        evidence: dict[str, Any] = {
            "interpretation": f"{detail} exceeding threshold (z={z_score:.2f})",
            "packet_rate_pps": round(current_pps, 2),
            "byte_rate_bps": round(window.bps, 2),
            "unique_source_count": window.unique_src_count,
            "source_entropy": round(window.src_entropy, 4),
            "syn_count": syns,
            "ack_count": acks,
            "syn_ack_ratio": round(window.syn_ack_ratio, 2),
            "protocol_breakdown": window.protocols,
            "target_ip": top_dst_ip,
            "target_port": top_dst_port,
        }

        # Capability state
        cap_state = "OBSERVABLE"
        input_mode = window.latest_input_mode or "pcap_replay"
        if input_mode in ("netflow_v9", "ipfix") and not window.tcp_flags:
            cap_state = "DEGRADED"

        alert: dict[str, Any] = {
            "schema_version": "1.3",
            "timestamp": _iso_utc(window.end_time),
            "flow_id": fl_id,
            "flow_ref_type": "aggregate",
            "ps_class": PS_CLASS,
            "threat_class": threat_class,
            "detector": DETECTOR_NAME,
            "confidence": None,  # Statistical detector confidence is null per FR-9 / alert schema
            "score": round(z_score if baseline_dict else current_pps / self.min_pps, 3),
            "score_type": "robust_z" if baseline_dict else "anomaly_score",
            "calibrated": False,
            "evidence": evidence,
            "incident_id": inc_id,
            "dedup_key": canonical(dedup_key),
            "capability": {
                "detector_state": cap_state,
                "input_mode": input_mode,
                "missing_evidence": [] if cap_state == "OBSERVABLE" else ["tcp_flags"],
            },
            "status": "ACTIVE" if self._consecutive_flood_windows > self.hysteresis_windows else "NEW",
            "severity": "CRITICAL" if current_pps >= self.min_pps * 2 else "HIGH",
            "first_observed": _iso_utc(window.start_time),
            "last_observed": _iso_utc(window.end_time),
            "event_count": window.event_count,
            "contributing_flow_ids": window.contributing_flow_ids[:32],
            "window": {
                "start": _iso_utc(window.start_time),
                "end": _iso_utc(window.end_time),
                "duration_s": window.duration_s,
            },
            "threshold": {
                "min_pps": self.min_pps,
                "robust_z": self.robust_z_threshold,
                "hysteresis_windows": self.hysteresis_windows,
            },
            "baseline": baseline_dict,
            "recommendation": "ADVISORY: Volumetric traffic flood observed targeting internal host. Recommend perimeter upstream ratelimiting.",
        }
        return alert

    def _check_slowloris(self, window: WindowSummary) -> dict[str, Any] | None:
        """Check for Slowloris low-rate HTTP connection-exhaustion attack."""
        # Update connection tracker from flow summaries
        for fs in window.flow_summaries:
            dst_ip = fs.get("dst_ip")
            if not dst_ip and window.sample_events:
                dst_ip = window.sample_events[0].dst_ip
            dst_port = fs.get("dst_port")
            if dst_port is None and window.sample_events:
                dst_port = window.sample_events[0].dst_port
            if dst_port is None:
                dst_port = 80
            if not dst_ip:
                continue

            target_key = (dst_ip, dst_port or 80)
            if target_key not in self._active_connections:
                self._active_connections[target_key] = []

            entry = {
                "duration_s": fs.get("duration_s", 0.0),
                "bytes": fs.get("bytes", 0),
                "packets": fs.get("packets", 0),
                "last_seen": window.end_time,
            }
            self._active_connections[target_key].append(entry)

        # Inspect connections for each target
        for (dst_ip, dst_port), conns in list(self._active_connections.items()):
            # Prune connections older than 60s
            recent_conns = [c for c in conns if window.end_time - c["last_seen"] <= 60.0]
            self._active_connections[(dst_ip, dst_port)] = recent_conns

            concurrency = len(recent_conns)
            if concurrency < self.slowloris_min_concurrency:
                continue

            # Check duration gate
            durations = [c["duration_s"] for c in recent_conns]
            durations.sort()
            # 95th percentile duration
            p95_idx = int(math.ceil(0.95 * len(durations))) - 1
            duration_p95 = durations[max(0, p95_idx)]

            # Check bytes-per-connection gate
            total_bytes = sum(c["bytes"] for c in recent_conns)
            avg_bytes = total_bytes / concurrency if concurrency > 0 else 0.0

            # Low rate requirement: window pps must be modest (not a volumetric flood)
            target_pps = (sum(c["packets"] for c in recent_conns) / window.duration_s) if window.duration_s > 0 else 0.0

            # GATES MUST AGREE: concurrency >= threshold AND duration_p95 >= threshold AND avg_bytes <= threshold
            concurrency_gate = concurrency >= self.slowloris_min_concurrency
            duration_gate = duration_p95 >= self.slowloris_min_duration_s
            byte_rate_gate = avg_bytes <= self.slowloris_max_bytes_per_conn and target_pps <= self.slowloris_max_pps

            if concurrency_gate and duration_gate and byte_rate_gate:
                dedup_key = [PS_CLASS, dst_ip, dst_port]
                inc_id = identifier(dedup_key)
                fl_id = identifier(dedup_key)

                evidence: dict[str, Any] = {
                    "interpretation": (
                        f"Slowloris low-rate exhaustion pattern against port {dst_port}: "
                        f"{concurrency} long-lived half-open connections (p95 duration {duration_p95:.1f}s, "
                        f"{avg_bytes:.1f} avg bytes/conn)"
                    ),
                    "half_open_concurrency": concurrency,
                    "connection_duration_p95": round(duration_p95, 2),
                    "bytes_per_connection": round(avg_bytes, 2),
                    "packet_rate_pps": round(target_pps, 2),
                    "target_ip": dst_ip,
                    "target_port": dst_port,
                }

                alert: dict[str, Any] = {
                    "schema_version": "1.3",
                    "timestamp": _iso_utc(window.end_time),
                    "flow_id": fl_id,
                    "flow_ref_type": "aggregate",
                    "ps_class": PS_CLASS,
                    "threat_class": "slowloris",
                    "detector": DETECTOR_NAME,
                    "confidence": None,
                    "score": round(min(1.0, (concurrency / self.slowloris_min_concurrency) * 0.5 + (duration_p95 / self.slowloris_min_duration_s) * 0.5), 3),
                    "score_type": "anomaly_score",
                    "calibrated": False,
                    "evidence": evidence,
                    "incident_id": inc_id,
                    "dedup_key": canonical(dedup_key),
                    "capability": {
                        "detector_state": "OBSERVABLE",
                        "input_mode": window.latest_input_mode or "pcap_replay",
                        "missing_evidence": [],
                    },
                    "status": "ACTIVE",
                    "severity": "HIGH",
                    "first_observed": _iso_utc(window.start_time),
                    "last_observed": _iso_utc(window.end_time),
                    "event_count": concurrency,
                    "contributing_flow_ids": window.contributing_flow_ids[:32],
                    "window": {
                        "start": _iso_utc(window.start_time),
                        "end": _iso_utc(window.end_time),
                        "duration_s": window.duration_s,
                    },
                    "threshold": {
                        "slowloris_min_concurrency": self.slowloris_min_concurrency,
                        "slowloris_min_duration_s": self.slowloris_min_duration_s,
                        "slowloris_max_bytes_per_conn": self.slowloris_max_bytes_per_conn,
                    },
                    "recommendation": "ADVISORY: Low-rate Slowloris connection starvation detected. Recommend tuning server keep-alive timeouts and connection limits per client IP.",
                }
                return alert

        return None
