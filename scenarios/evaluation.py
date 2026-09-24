"""Ground-truth evaluation harness (PS-compliance task 5).

Runs a labelled stream (benign background + attack suite) through the real
DetectionPipeline and Deduplicator and scores every raw alert:

* TP        - alert attributed to an attack of the SAME PS class
* overlap   - alert attributed to an attack of a DIFFERENT class (one attack raising another class)
* false     - alert attributed to no attack (fired on benign background)

Attribution: an alert belongs to an attack when they share an address
(attacker / victim / C2 server, found in the alert's dedup key and evidence)
and the alert's observed span overlaps the attack window (+ ``grace_s``).

All numbers produced here describe SYNTHETIC data and must be labelled
"synthetic benign replay" / "synthetic attack suite".
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

from alerts.deduplicator import Deduplicator
from detectors.pipeline import DetectionPipeline
from scenarios.attack_suite import LETTER_OF, PS_CLASSES, AttackLabel

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RESOLVERS = {"1.1.1.1", "8.8.8.8"}


def _ts(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return datetime.fromisoformat(str(value)).timestamp()


def alert_ips(alert: dict[str, Any]) -> set[str]:
    text = json.dumps([alert.get("dedup_key"), alert.get("evidence")], default=str)
    return set(_IPV4.findall(text)) - RESOLVERS


def alert_span(alert: dict[str, Any]) -> tuple[float, float]:
    t_last = _ts(alert.get("last_observed")) or _ts(alert.get("timestamp")) or 0.0
    t_first = _ts(alert.get("first_observed")) or t_last
    return t_first, t_last


def attribute(alert: dict[str, Any], labels: Iterable[AttackLabel], grace_s: float = 120.0) -> AttackLabel | None:
    ips = alert_ips(alert)
    t_first, t_last = alert_span(alert)
    best = None
    for label in labels:
        if ips & label.key_ips and t_first <= label.t_end + grace_s and t_last >= label.t_start - 5.0:
            if best is None or label.ps_letter == LETTER_OF.get(alert.get("ps_class"), "?"):
                best = label
    return best


@dataclass
class RunResult:
    stream_label: str
    duration_s: float
    events: int
    alerts: list[dict[str, Any]] = field(default_factory=list)
    outcomes: list[tuple[str, str | None]] = field(default_factory=list)   # (TP|overlap|false, attack_id)
    incidents_false: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))


def run_stream(events: list, labels: list[AttackLabel], stream_label: str, duration_s: float) -> RunResult:
    pipeline = DetectionPipeline()
    dedup = Deduplicator()
    result = RunResult(stream_label, duration_s, len(events))
    raw: list[dict[str, Any]] = []
    for ev in events:
        raw.extend(pipeline.process_event(ev))
    raw.extend(pipeline.flush())
    for alert in raw:
        incident = dedup.process_alert(alert)
        label = attribute(alert, labels)
        if label is None:
            kind = "false"
            result.incidents_false[alert["ps_class"]].add(incident["incident_id"])
        elif label.ps_letter == LETTER_OF[alert["ps_class"]]:
            kind = "TP"
        else:
            kind = "overlap"
        result.alerts.append(alert)
        result.outcomes.append((kind, label.attack_id if label else None))
    return result


def score(runs: list[RunResult], labels_per_run: list[list[AttackLabel]]) -> dict[str, Any]:
    """Aggregate per-class metrics over one or more runs."""
    per_class: dict[str, dict[str, Any]] = {}
    per_attack: list[dict[str, Any]] = []
    overlap = Counter()
    hours = sum(r.duration_s for r in runs) / 3600.0
    for letter, name in PS_CLASSES.items():
        attacks = detected = 0
        tp = ov = fp = 0
        fp_incidents = 0
        for run, labels in zip(runs, labels_per_run):
            detected_ids = {aid for (kind, aid) in run.outcomes if kind == "TP"}
            for label in labels:
                if label.ps_letter == letter:
                    attacks += 1
                    detected += label.attack_id in detected_ids
            for alert, (kind, aid) in zip(run.alerts, run.outcomes):
                if alert["ps_class"] != name:
                    continue
                tp += kind == "TP"
                ov += kind == "overlap"
                fp += kind == "false"
            fp_incidents += len(run.incidents_false.get(name, ()))
        class_alerts = tp + ov + fp
        per_class[letter] = {
            "ps_class": name, "attacks": attacks, "detected": detected, "missed": attacks - detected,
            "recall": round(detected / attacks, 3) if attacks else None,
            "alerts": class_alerts, "tp_alerts": tp, "overlap_alerts": ov, "false_alerts": fp,
            "precision": round(tp / class_alerts, 3) if class_alerts else None,
            "false_incidents": fp_incidents,
            "false_incidents_per_hour": round(fp_incidents / hours, 3) if hours else None,
        }
    for run, labels in zip(runs, labels_per_run):
        by_attack: dict[str, Counter] = defaultdict(Counter)
        for alert, (kind, aid) in zip(run.alerts, run.outcomes):
            if aid:
                by_attack[aid][alert["detector"]] += 1
                if kind == "overlap":
                    overlap[(LETTER_OF[alert["ps_class"]], next(l.ps_letter for l in labels if l.attack_id == aid))] += 1
        for label in labels:
            det = by_attack.get(label.attack_id, Counter())
            same = any(kind == "TP" and aid == label.attack_id for kind, aid in run.outcomes)
            per_attack.append({"run": run.stream_label, "attack_id": label.attack_id, "ps_letter": label.ps_letter, "variant": label.variant,
                               "expected_hard": label.expected_hard, "detected": same, "alerts_by_detector": dict(det)})
    return {"hours_of_background": round(hours, 3), "per_class": per_class, "per_attack": per_attack,
            "overlap_matrix": [{"alert_class": a, "attack_class": b, "alerts": n} for (a, b), n in sorted(overlap.items())]}


def false_alerts_benign_only(events: list, stream_label: str, duration_s: float) -> dict[str, Any]:
    run = run_stream(events, [], stream_label, duration_s)
    hours = duration_s / 3600.0
    by_class = Counter(a["ps_class"] for a in run.alerts)
    by_detector = Counter(a["detector"] for a in run.alerts)
    return {
        "stream": stream_label, "hours": round(hours, 3), "events": run.events,
        "false_alerts": len(run.alerts),
        "false_alerts_per_hour": round(len(run.alerts) / hours, 3) if hours else None,
        "false_incidents": sum(len(v) for v in run.incidents_false.values()),
        "false_incidents_per_hour": round(sum(len(v) for v in run.incidents_false.values()) / hours, 3) if hours else None,
        "by_ps_class": {LETTER_OF[k]: {"alerts": v, "incidents": len(run.incidents_false.get(k, ())),
                                        "incidents_per_hour": round(len(run.incidents_false.get(k, ())) / hours, 3)} for k, v in sorted(by_class.items())},
        "by_detector": dict(by_detector),
        "examples": [{"detector": a["detector"], "threat_class": a["threat_class"], "interpretation": a["evidence"].get("interpretation", "")[:160]}
                     for a in run.alerts[:8]],
    }
