"""TLS and QUIC metadata / traffic shape anomaly detection module.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 7, 8.1, 10.6, 12, 14, 15.
PS Threat Class: "Malware in encrypted sessions" (frozen external string).
Internal module: "tls_quic".

Hard Constraints:
- NO PAYLOAD DECRYPTION. Analyzes handshake metadata (JA3/JA3S/JA4), SNI, and traffic shape only.
- Output wording: "Suspicious Encrypted Session" / anomaly - never claims malware family attribution.
- Missing JA3/JA3S/JA4 takes NOT_OBSERVABLE capability state / dedup sentinel.
- Dedup key: [ps_class, src_ip, ja3, dst_ip].
"""

from __future__ import annotations

import statistics
from datetime import datetime, timezone
from typing import Any

from features.rolling import WindowSummary
from ingest.identity import NOT_OBSERVABLE, canonical, identifier
from ingest.normalized_event import NormalizedEvent

PS_CLASS = "Malware in encrypted sessions"
DETECTOR_NAME = "tls_quic"

DEFAULT_NOVELTY_DAYS = 7
DEFAULT_WINDOW_S = 300.0
DEFAULT_MAX_SESSIONS = 1024

# Known suspicious JA3 fingerprints (e.g. CobaltStrike, Metasploit, Trickbot defaults)
KNOWN_SUSPICIOUS_JA3 = {
    "a0e9f5d64349fb13191bc781f81f42e1",  # Metasploit default
    "72a589da586844d7f0818ce684948eea",  # CobaltStrike
    "6734f37431670b3ab4292b8f60f29984",  # Trickbot
    "51c64c77e60f3980eea90869b68c58a8",  # Emotet
    "b32309a26951912be7dba376398abc3b",  # Generic suspicious implant
}


def _iso_utc(ts: float | datetime | None = None) -> str:
    if ts is None:
        dt = datetime.now(timezone.utc)
    elif isinstance(ts, (int, float)):
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    else:
        dt = ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


class _TLSSessionState:
    """Tracks traffic shape and metadata for an encrypted session."""

    __slots__ = (
        "src_ip",
        "dst_ip",
        "dst_port",
        "ja3",
        "ja3s",
        "ja4",
        "sni",
        "packet_sizes",
        "directions",
        "timestamps",
        "first_seen",
        "last_seen",
        "flow_ids",
    )

    def __init__(self, src_ip: str, dst_ip: str, dst_port: int, now: float) -> None:
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.ja3: str | None = None
        self.ja3s: str | None = None
        self.ja4: str | None = None
        self.sni: str | None = None
        self.packet_sizes: list[int] = []
        self.directions: list[str] = []
        self.timestamps: list[float] = [now]
        self.first_seen = now
        self.last_seen = now
        self.flow_ids: list[str] = []

    def update_metadata(self, tls: dict[str, Any] | None, quic: dict[str, Any] | None) -> None:
        if tls:
            if not self.ja3 and tls.get("ja3"):
                self.ja3 = str(tls["ja3"])
            if not self.ja3s and tls.get("ja3s"):
                self.ja3s = str(tls["ja3s"])
            if not self.ja4 and tls.get("ja4"):
                self.ja4 = str(tls["ja4"])
            if not self.sni and tls.get("sni"):
                self.sni = str(tls["sni"])
        if quic:
            if not self.ja3 and quic.get("ja3"):
                self.ja3 = str(quic["ja3"])
            if not self.ja4 and quic.get("ja4"):
                self.ja4 = str(quic["ja4"])

    def add_packet(self, size: int | None, direction: str | None, flow_id: str | None, now: float) -> None:
        self.last_seen = now
        if size is not None and len(self.packet_sizes) < 32:
            self.packet_sizes.append(size)
        if direction and len(self.directions) < 32:
            self.directions.append(direction)
        if len(self.timestamps) < 32:
            self.timestamps.append(now)
        if flow_id and flow_id not in self.flow_ids and len(self.flow_ids) < 16:
            self.flow_ids.append(flow_id)


class TLSQuicDetector:
    """Detects suspicious encrypted sessions using handshake metadata and traffic shape without decryption."""

    def __init__(
        self,
        known_suspicious_ja3: set[str] | None = None,
        window_s: float = DEFAULT_WINDOW_S,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
    ) -> None:
        self.known_suspicious_ja3 = set(KNOWN_SUSPICIOUS_JA3)
        if known_suspicious_ja3:
            self.known_suspicious_ja3.update(known_suspicious_ja3)
        self.window_s = window_s
        self.max_sessions = max_sessions

        # Map (src_ip, dst_ip, dst_port) -> _TLSSessionState
        self._sessions: dict[tuple[str, str, int], _TLSSessionState] = {}
        self._alerted: set[tuple[str, str, int]] = set()

    def _prune(self, current_time: float) -> None:
        cutoff = current_time - self.window_s
        expired = [k for k, s in self._sessions.items() if s.last_seen < cutoff]
        for k in expired:
            self._sessions.pop(k, None)
            self._alerted.discard(k)

        if len(self._sessions) > self.max_sessions:
            oldest = sorted(self._sessions.items(), key=lambda kv: kv[1].last_seen)[: len(self._sessions) - self.max_sessions]
            for k, _ in oldest:
                self._sessions.pop(k, None)
                self._alerted.discard(k)

    def evaluate_event(self, ev: NormalizedEvent) -> dict[str, Any] | None:
        """Evaluate a NormalizedEvent for encrypted session anomalies."""
        if not ev.src_ip or not ev.dst_ip or ev.dst_port is None:
            return None

        # Check if event has TLS or QUIC metadata, or is on standard TLS/QUIC ports
        is_encrypted = (
            bool(ev.tls)
            or bool(ev.quic)
            or ev.dst_port in (443, 8443, 4433, 9443)
            or (ev.protocol in ("TCP", "UDP") and ev.dst_port in (443, 8443))
        )
        if not is_encrypted:
            return None

        now = float(ev.observed_time.timestamp()) if isinstance(ev.observed_time, datetime) else float(ev.observed_time)
        self._prune(now)

        key = (ev.src_ip, ev.dst_ip, ev.dst_port)
        state = self._sessions.get(key)
        if state is None:
            state = _TLSSessionState(ev.src_ip, ev.dst_ip, ev.dst_port, now)
            self._sessions[key] = state

        state.update_metadata(ev.tls, ev.quic)

        # Ingest shape from event if available
        size = ev.bytes or (ev.shape.get("packet_size_first_n", [None])[0] if ev.shape else None)
        state.add_packet(size, ev.direction, ev.flow_id, now)

        return self._check_state(state, now, ev)

    def evaluate_window(self, window: WindowSummary) -> list[dict[str, Any]]:
        """Evaluate a closed window for encrypted session anomalies."""
        alerts: list[dict[str, Any]] = []
        for ev in window.sample_events:
            if ev.tls or ev.quic or (ev.dst_port and ev.dst_port in (443, 8443)):
                alert = self.evaluate_event(ev)
                if alert:
                    alerts.append(alert)
        return alerts

    def _check_state(self, state: _TLSSessionState, now: float, ev: NormalizedEvent) -> dict[str, Any] | None:
        key = (state.src_ip, state.dst_ip, state.dst_port)
        if key in self._alerted:
            return None

        # Calculate shape statistics from timing and packet sequences
        iats: list[float] = []
        if len(state.timestamps) > 1:
            iats = [state.timestamps[i] - state.timestamps[i - 1] for i in range(1, len(state.timestamps))]
            valid_iats = [x for x in iats if x > 0.001]
        else:
            valid_iats = []

        iat_median = statistics.median(valid_iats) if valid_iats else 0.0
        if valid_iats:
            s_iats = sorted(valid_iats)
            p95_idx = int(len(s_iats) * 0.95)
            iat_p95 = s_iats[min(p95_idx, len(s_iats) - 1)]
            mean_iat = statistics.mean(valid_iats)
            std_iat = statistics.stdev(valid_iats) if len(valid_iats) > 1 else 0.0
            iat_cv = (std_iat / mean_iat) if mean_iat > 0 else 0.0
        else:
            iat_p95 = 0.0
            iat_cv = 0.0

        # Check suspicion conditions:
        # 1. Matching known suspicious JA3 fingerprint
        is_suspicious_ja3 = bool(state.ja3 and state.ja3.lower() in self.known_suspicious_ja3)

        # 2. IP-direct TLS without SNI to non-standard or unusual port
        no_sni = (state.sni is None or state.sni == "") and state.dst_port not in (443, 8443)

        # 3. Fixed size beaconing shape (e.g. identical small packets with low jitter)
        fixed_size_shape = (
            len(state.packet_sizes) >= 5
            and len(set(state.packet_sizes)) == 1
            and 0 < state.packet_sizes[0] < 500
            and iat_cv < 0.20
        )

        suspicious = is_suspicious_ja3 or no_sni or fixed_size_shape
        if not suspicious:
            return None

        self._alerted.add(key)

        # Unavailable JA3 takes the exact NOT_OBSERVABLE sentinel per Phase 0 decision DOC-007
        ja3_comp = state.ja3 if state.ja3 else NOT_OBSERVABLE
        dedup_key = [PS_CLASS, state.src_ip, ja3_comp, state.dst_ip]
        inc_id = identifier(dedup_key)
        fl_id = identifier([state.src_ip, ja3_comp, state.dst_ip])

        reasons = []
        if is_suspicious_ja3:
            reasons.append(f"Matching suspicious JA3 fingerprint ({state.ja3})")
        if no_sni:
            reasons.append(f"Direct IP TLS connection without SNI on port {state.dst_port}")
        if fixed_size_shape:
            reasons.append(f"Stealth periodic shape: uniform packet size ({state.packet_sizes[0]}B) with low timing jitter")

        duration = max(state.last_seen - state.first_seen, 0.001)

        evidence: dict[str, Any] = {
            "interpretation": (
                f"Suspicious encrypted session from {state.src_ip} to {state.dst_ip}:{state.dst_port}. "
                + "; ".join(reasons)
                + ". Suspicion based on handshake metadata and traffic shape only; no decrypted payload bytes inspected."
            ),
            "ja3": state.ja3,
            "ja3s": state.ja3s,
            "ja4": state.ja4,
            "packet_size_first_n": state.packet_sizes[:10] if state.packet_sizes else None,
            "direction_first_n": state.directions[:10] if state.directions else None,
            "iat_median": round(iat_median, 3),
            "iat_p95": round(iat_p95, 3),
            "iat_cv": round(iat_cv, 4),
            "target_ip": state.dst_ip,
            "target_port": state.dst_port,
            "sni": state.sni,
        }

        cap_state = "OBSERVABLE" if state.ja3 else "DEGRADED"
        missing_ev = [] if state.ja3 else ["ja3"]
        input_mode = str(ev.input_mode) if ev.input_mode else "pcap_replay"

        alert: dict[str, Any] = {
            "schema_version": "1.3",
            "timestamp": _iso_utc(now),
            "flow_id": fl_id,
            "flow_ref_type": "aggregate",
            "ps_class": PS_CLASS,
            "threat_class": "suspicious_encrypted_session",
            "detector": DETECTOR_NAME,
            "confidence": None,
            "score": 0.90 if is_suspicious_ja3 else 0.75,
            "score_type": "anomaly_score",
            "calibrated": False,
            "evidence": evidence,
            "incident_id": inc_id,
            "dedup_key": canonical(dedup_key),
            "capability": {
                "detector_state": cap_state,
                "input_mode": input_mode,
                "missing_evidence": missing_ev,
            },
            "status": "NEW",
            "severity": "HIGH" if is_suspicious_ja3 else "MEDIUM",
            "first_observed": _iso_utc(state.first_seen),
            "last_observed": _iso_utc(state.last_seen),
            "event_count": len(state.packet_sizes),
            "contributing_flow_ids": state.flow_ids[:16],
            "window": {
                "start": _iso_utc(state.first_seen),
                "end": _iso_utc(state.last_seen),
                "duration_s": round(duration, 3),
            },
            "recommendation": f"ADVISORY: Anomalous encrypted session detected to {state.dst_ip}:{state.dst_port}. Inspect destination certificate validity and host process lineage.",
        }
        return alert
