"""Incident Deduplication and Lifecycle Engine.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 13.1, 17, design.md section 17.
Keys: config/dedup_keys.yaml (FROZEN).
Schema: schemas/alert.schema.json (v1.3).

Lifecycle transitions:
    NEW -> ACTIVE -> UPDATED -> RESOLVED

Guarantees:
- Deduplication against frozen dedup_keys.yaml.
- Unavailable components use the exact sentinel string NOT_OBSERVABLE.
- Deterministic 16-hex incident_id: sha256(canonical(key)).hexdigest()[:16].
- A high-rate flood (e.g. 50,000 pps) yields ONE evolving incident, not an alert storm.
- Bounded incident capacity and state.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from alerts.scorer import AlertScorer, aggregate_scores, escalate_severity
from ingest.identity import NOT_OBSERVABLE, canonical, identifier

# Frozen deduplication keys from config/dedup_keys.yaml
DEDUP_KEY_DEFINITIONS: dict[str, list[str]] = {
    "ddos": ["ps_class", "dst_ip", "dst_port"],
    "reflection": ["ps_class", "dst_ip", "amplifier_port"],
    "scan": ["ps_class", "src_ip"],
    "dga": ["ps_class", "src_ip"],
    "dns_tunnel": ["ps_class", "src_ip", "registered_domain"],
    "dns": ["ps_class", "src_ip", "registered_domain"],
    "c2": ["ps_class", "src_ip", "dst_ip", "dst_port"],
    "exfil": ["ps_class", "src_ip", "dst_ip"],
    "tls_quic": ["ps_class", "src_ip", "ja3", "dst_ip"],
}

DEFAULT_ACTIVE_WINDOW_S = 60.0
DEFAULT_RESOLVE_TIMEOUT_S = 120.0
DEFAULT_MAX_INCIDENTS = 1024


def _parse_ts(ts_val: Any) -> float:
    """Parse ISO date-time string or float/int timestamp into float epoch seconds."""
    if ts_val is None:
        return datetime.now(timezone.utc).timestamp()
    if isinstance(ts_val, (int, float)):
        return float(ts_val)
    if isinstance(ts_val, datetime):
        return ts_val.timestamp()
    try:
        dt = datetime.fromisoformat(str(ts_val).replace("Z", "+00:00"))
        return dt.timestamp()
    except Exception:
        return datetime.now(timezone.utc).timestamp()


def _iso_utc(ts: float | datetime | None = None) -> str:
    """Format timestamp as ISO-8601 UTC string."""
    if ts is None:
        dt = datetime.now(timezone.utc)
    elif isinstance(ts, (int, float)):
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    else:
        dt = ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def extract_dedup_key(alert: dict[str, Any]) -> list[Any]:
    """Extract canonical deduplication key components for an alert per frozen dedup_keys.yaml.

    Unavailable components carry the exact sentinel string NOT_OBSERVABLE per Phase 0 DOC-007.
    """
    det = alert.get("detector") or alert.get("threat_class") or "ddos"
    fields = DEDUP_KEY_DEFINITIONS.get(str(det), ["ps_class", "dst_ip", "dst_port"])

    key: list[Any] = []
    evidence = alert.get("evidence", {}) or {}

    for field in fields:
        val = None
        if field == "ps_class":
            val = alert.get("ps_class")
        elif field in alert:
            val = alert.get(field)
        elif field in evidence:
            val = evidence.get(field)

        if val is None or str(val).strip() == "" or str(val) == "None":
            key.append(NOT_OBSERVABLE)
        else:
            key.append(val)

    return key


class Deduplicator:
    """Stateful alert deduplicator and incident lifecycle manager."""

    def __init__(
        self,
        active_window_s: float = DEFAULT_ACTIVE_WINDOW_S,
        resolve_timeout_s: float = DEFAULT_RESOLVE_TIMEOUT_S,
        max_incidents: int = DEFAULT_MAX_INCIDENTS,
        scorer: AlertScorer | None = None,
    ) -> None:
        self.active_window_s = active_window_s
        self.resolve_timeout_s = resolve_timeout_s
        self.max_incidents = max_incidents
        self.scorer = scorer or AlertScorer()

        # Map incident_id -> incident dict
        self._incidents: dict[str, dict[str, Any]] = {}
        # Map incident_id -> last observed float epoch seconds
        self._last_seen: dict[str, float] = {}

    def _prune(self) -> None:
        """Enforce strict capacity bound by evicting oldest incidents."""
        while len(self._incidents) >= self.max_incidents:
            # Prefer evicting resolved incidents first
            resolved_keys = [k for k, inc in self._incidents.items() if inc.get("status") == "RESOLVED"]
            if resolved_keys:
                oldest_k = min(resolved_keys, key=lambda k: self._last_seen.get(k, 0.0))
            else:
                oldest_k = min(self._incidents.keys(), key=lambda k: self._last_seen.get(k, 0.0))

            self._incidents.pop(oldest_k, None)
            self._last_seen.pop(oldest_k, None)

    def process_alert(self, raw_alert: dict[str, Any]) -> dict[str, Any]:
        """Process an incoming alert, deduplicate it into an incident, and evolve its lifecycle.

        Transitions:
        - First alert -> NEW
        - Second alert within active window -> ACTIVE
        - Subsequent alerts within active window -> UPDATED
        - Reopened alert after resolution -> UPDATED
        """
        # Score and validate alert properties
        alert = self.scorer.score_alert(raw_alert)
        now_ts = _parse_ts(alert.get("timestamp") or alert.get("last_observed"))

        # Determine incident_id and canonical dedup_key
        inc_id = alert.get("incident_id")
        dedup_key_str = alert.get("dedup_key")

        if not inc_id or not dedup_key_str:
            key_comps = extract_dedup_key(alert)
            dedup_key_str = canonical(key_comps)
            inc_id = identifier(key_comps)

        existing = self._incidents.get(inc_id)

        if existing is None:
            # New incident entry
            self._prune()
            incident = deepcopy(alert)
            incident["incident_id"] = inc_id
            incident["dedup_key"] = dedup_key_str
            incident["status"] = "NEW"

            first_obs = alert.get("first_observed") or alert.get("timestamp") or _iso_utc(now_ts)
            last_obs = alert.get("last_observed") or alert.get("timestamp") or _iso_utc(now_ts)
            incident["first_observed"] = first_obs
            incident["last_observed"] = last_obs
            incident["event_count"] = alert.get("event_count") or 1

            self._incidents[inc_id] = incident
            self._last_seen[inc_id] = now_ts
            return deepcopy(incident)

        # Incident already exists: Evolve lifecycle and aggregate evidence
        curr_status = existing.get("status", "NEW")
        if curr_status == "NEW":
            next_status = "ACTIVE"
        elif curr_status in ("ACTIVE", "UPDATED", "RESOLVED"):
            next_status = "UPDATED"
        else:
            next_status = "UPDATED"

        existing["status"] = next_status

        # Accumulate event count
        new_events = alert.get("event_count") or 1
        existing["event_count"] = (existing.get("event_count") or 0) + new_events

        # Update last_observed and timestamp
        last_obs_raw = alert.get("last_observed") or alert.get("timestamp")
        last_obs_ts = _parse_ts(last_obs_raw)
        if last_obs_ts >= _parse_ts(existing.get("last_observed")):
            existing["last_observed"] = _iso_utc(last_obs_ts)
            existing["timestamp"] = _iso_utc(now_ts)

        # Aggregate score preserving peak anomaly/risk
        existing["score"] = aggregate_scores(
            existing.get("score"),
            alert.get("score"),
            score_type=existing.get("score_type", "anomaly_score"),
        )

        # Escalate severity if incoming alert has higher severity
        existing["severity"] = escalate_severity(
            existing.get("severity", "MEDIUM"),
            alert.get("severity", "MEDIUM"),
        )

        # Preserve confidence if present in incoming alert
        if alert.get("confidence") is not None:
            existing["confidence"] = alert["confidence"]

        # Merge contributing flow IDs (capped at 32 per schema line 51)
        raw_flows = alert.get("contributing_flow_ids") or []
        existing_flows = existing.get("contributing_flow_ids") or []
        combined_flows = list(dict.fromkeys(existing_flows + raw_flows))[:32]
        if combined_flows:
            existing["contributing_flow_ids"] = combined_flows

        # Update window duration
        first_ts = _parse_ts(existing.get("first_observed"))
        last_ts = _parse_ts(existing.get("last_observed"))
        duration = max(last_ts - first_ts, 0.001)

        if existing.get("window"):
            existing["window"]["end"] = existing["last_observed"]
            existing["window"]["duration_s"] = round(duration, 3)
        else:
            existing["window"] = {
                "start": existing["first_observed"],
                "end": existing["last_observed"],
                "duration_s": round(duration, 3),
            }

        # Update evidence fields with latest observations
        raw_evidence = alert.get("evidence")
        if raw_evidence:
            existing["evidence"].update(raw_evidence)

        self._last_seen[inc_id] = now_ts
        return deepcopy(existing)

    def sweep_resolved(self, current_time: float | None = None) -> list[dict[str, Any]]:
        """Transition inactive incidents beyond resolve_timeout_s to RESOLVED."""
        now = current_time if current_time is not None else datetime.now(timezone.utc).timestamp()
        resolved_incidents: list[dict[str, Any]] = []

        for inc_id, inc in self._incidents.items():
            if inc.get("status") in ("NEW", "ACTIVE", "UPDATED"):
                last_seen = self._last_seen.get(inc_id, 0.0)
                if now - last_seen >= self.resolve_timeout_s:
                    inc["status"] = "RESOLVED"
                    resolved_incidents.append(deepcopy(inc))

        return resolved_incidents

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        """Retrieve an incident by incident_id."""
        inc = self._incidents.get(incident_id)
        return deepcopy(inc) if inc else None

    def get_all_incidents(self) -> list[dict[str, Any]]:
        """Retrieve all tracked incidents."""
        return [deepcopy(inc) for inc in self._incidents.values()]

    def get_active_incidents(self) -> list[dict[str, Any]]:
        """Retrieve incidents that are not yet RESOLVED."""
        return [deepcopy(inc) for inc in self._incidents.values() if inc.get("status") != "RESOLVED"]

    def clear(self) -> None:
        """Clear all incident tracking state."""
        self._incidents.clear()
        self._last_seen.clear()
