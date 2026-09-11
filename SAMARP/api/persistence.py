"""SQLite persistence layer and Incident Store for PS26145.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 17, 18, 19, design.md section 18.
Schema: schemas/alert.schema.json.

Persists:
- incidents (latest active/resolved incident state);
- incident updates (full historical update sequence chained by HashChainWriter);
- evidence (both scalar-flattened queryable fields and full evidence_json);
- timestamps (first_observed, last_observed, timestamp);
- hash-chain metadata (seq, prev_hash, entry_hash, payload_hash);
- scenario/replay metadata.
"""

from __future__ import annotations

import csv
import io
import json
import sqlite3
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from alerts.hash_chain import GENESIS_PREV_HASH, HashChainWriter, canonical_json

SQL_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    dedup_key TEXT NOT NULL,
    ps_class TEXT NOT NULL,
    threat_class TEXT NOT NULL,
    detector TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    score REAL NOT NULL,
    confidence REAL,
    score_type TEXT NOT NULL,
    calibrated INTEGER NOT NULL,
    flow_id TEXT NOT NULL,
    flow_ref_type TEXT NOT NULL,
    first_observed TEXT NOT NULL,
    last_observed TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incident_updates (
    update_id INTEGER PRIMARY KEY AUTOINCREMENT,
    seq INTEGER UNIQUE NOT NULL,
    incident_id TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    score REAL NOT NULL,
    confidence REAL,
    timestamp TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_ps_class ON incidents(ps_class);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_last_observed ON incidents(last_observed);
CREATE INDEX IF NOT EXISTS idx_updates_seq ON incident_updates(seq);
CREATE INDEX IF NOT EXISTS idx_updates_incident_id ON incident_updates(incident_id);

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def flatten_dict(d: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    """Recursively flatten dictionary keys using dotted paths for scalar values."""
    items: dict[str, Any] = {}
    for k, v in d.items():
        key = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, Mapping):
            items.update(flatten_dict(v, key))
        elif isinstance(v, (str, int, float, bool)) or v is None:
            items[key] = v
        else:
            items[key] = json.dumps(v, separators=(",", ":"))
    return items


class SQLiteIncidentStore:
    """Thread-safe and restart-resilient SQLite storage for incidents and hash chain."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            isolation_level=None,  # Autocommit mode
        )
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        cursor = self._conn.cursor()
        cursor.executescript(SQL_SCHEMA)

    def close(self) -> None:
        """Close SQLite connection safely."""
        try:
            self._conn.close()
        except Exception:
            pass

    def get_latest_chain_state(self) -> tuple[int, str]:
        """Return the highest recorded (seq, entry_hash) to resume the hash chain across restarts.

        Returns (0, GENESIS_PREV_HASH) if the store has no recorded entries.
        """
        cursor = self._conn.cursor()
        cursor.execute("SELECT seq, entry_hash FROM incident_updates ORDER BY seq DESC LIMIT 1")
        row = cursor.fetchone()
        if row is None:
            return 0, GENESIS_PREV_HASH
        return int(row["seq"]), str(row["entry_hash"])

    def save_incident(
        self,
        incident: dict[str, Any],
        chain_writer: HashChainWriter | None = None,
    ) -> dict[str, Any]:
        """Persist an incident or incident update.

        If chain fields are missing and a HashChainWriter is supplied, the incident
        will be signed before writing.
        """
        record = dict(incident)
        if record.get("entry_hash") is None and chain_writer is not None:
            record = chain_writer.append(record)

        inc_id = str(record["incident_id"])
        seq = int(record.get("seq") or 0)
        prev_hash = str(record.get("prev_hash") or GENESIS_PREV_HASH)
        entry_hash = str(record.get("entry_hash") or "")
        payload_hash = str(record.get("payload_hash") or "")

        payload_json = canonical_json(record)
        evidence_dict = record.get("evidence", {}) or {}
        evidence_json = canonical_json(evidence_dict)

        now = _iso_now()
        cursor = self._conn.cursor()

        # 1. Upsert into `incidents` table (state snapshot)
        cursor.execute(
            """
            INSERT INTO incidents (
                incident_id, dedup_key, ps_class, threat_class, detector,
                status, severity, score, confidence, score_type, calibrated,
                flow_id, flow_ref_type, first_observed, last_observed,
                event_count, seq, prev_hash, entry_hash, payload_hash,
                payload_json, evidence_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(incident_id) DO UPDATE SET
                status = excluded.status,
                severity = excluded.severity,
                score = excluded.score,
                confidence = excluded.confidence,
                last_observed = excluded.last_observed,
                event_count = excluded.event_count,
                seq = excluded.seq,
                prev_hash = excluded.prev_hash,
                entry_hash = excluded.entry_hash,
                payload_hash = excluded.payload_hash,
                payload_json = excluded.payload_json,
                evidence_json = excluded.evidence_json,
                updated_at = excluded.updated_at
            """,
            (
                inc_id,
                str(record.get("dedup_key") or ""),
                str(record.get("ps_class") or ""),
                str(record.get("threat_class") or ""),
                str(record.get("detector") or ""),
                str(record.get("status") or "NEW"),
                str(record.get("severity") or "INFO"),
                float(record.get("score") if record.get("score") is not None else 0.0),
                float(record["confidence"]) if record.get("confidence") is not None else None,
                str(record.get("score_type") or "anomaly_score"),
                1 if record.get("calibrated") else 0,
                str(record.get("flow_id") or ""),
                str(record.get("flow_ref_type") or "aggregate"),
                str(record.get("first_observed") or record.get("timestamp") or now),
                str(record.get("last_observed") or record.get("timestamp") or now),
                int(record.get("event_count") or 1),
                seq,
                prev_hash,
                entry_hash,
                payload_hash,
                payload_json,
                evidence_json,
                now,
                now,
            ),
        )

        # 2. Append into `incident_updates` table (tamper-evident history)
        cursor.execute(
            """
            INSERT INTO incident_updates (
                seq, incident_id, status, severity, score, confidence,
                timestamp, prev_hash, entry_hash, payload_hash,
                evidence_json, payload_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                seq,
                inc_id,
                str(record.get("status") or "NEW"),
                str(record.get("severity") or "INFO"),
                float(record.get("score") if record.get("score") is not None else 0.0),
                float(record["confidence"]) if record.get("confidence") is not None else None,
                str(record.get("last_observed") or record.get("timestamp") or now),
                prev_hash,
                entry_hash,
                payload_hash,
                evidence_json,
                payload_json,
                now,
            ),
        )

        return record

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        """Fetch latest incident state by incident_id."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT payload_json FROM incidents WHERE incident_id = ?", (incident_id,))
        row = cursor.fetchone()
        if row is None:
            return None
        return json.loads(row["payload_json"])

    def list_incidents(
        self,
        status: str | None = None,
        ps_class: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List latest incidents with optional filtering and pagination."""
        query = "SELECT payload_json FROM incidents WHERE 1=1"
        params: list[Any] = []

        if status:
            query += " AND status = ?"
            params.append(status)
        if ps_class:
            query += " AND ps_class = ?"
            params.append(ps_class)
        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY last_observed DESC, seq DESC LIMIT ? OFFSET ?"
        params.extend([max(1, min(limit, 1000)), max(0, offset)])

        cursor = self._conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def get_incident_history(self, incident_id: str) -> list[dict[str, Any]]:
        """Fetch chronological update sequence for a single incident."""
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT payload_json FROM incident_updates WHERE incident_id = ? ORDER BY seq ASC",
            (incident_id,),
        )
        rows = cursor.fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def get_all_signed_entries(self) -> list[dict[str, Any]]:
        """Fetch complete chronological hash chain sequence for export / verification."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT payload_json FROM incident_updates ORDER BY seq ASC")
        rows = cursor.fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def count_incidents(self) -> int:
        """Return total number of distinct active/resolved incidents."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT COUNT(*) AS c FROM incidents")
        return int(cursor.fetchone()["c"])

    def count_updates(self) -> int:
        """Return total number of chained incident update events."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT COUNT(*) AS c FROM incident_updates")
        return int(cursor.fetchone()["c"])

    def set_metadata(self, key: str, value: Any) -> None:
        """Persist scenario or operational metadata."""
        val_str = json.dumps(value) if not isinstance(value, str) else value
        now = _iso_now()
        cursor = self._conn.cursor()
        cursor.execute(
            """
            INSERT INTO metadata (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, val_str, now),
        )

    def get_metadata(self, key: str) -> Any | None:
        """Retrieve persisted metadata."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT value FROM metadata WHERE key = ?", (key,))
        row = cursor.fetchone()
        if row is None:
            return None
        val_str = str(row["value"])
        try:
            return json.loads(val_str)
        except Exception:
            return val_str

    def export_csv(self) -> str:
        """Generate CSV export formatted according to V6.3 section 18 flattening rules.

        Rule:
        - One row per incident (latest state).
        - Core incident columns.
        - evidence.<key> scalar values, dotted path, one column each.
        - evidence_json: full evidence object, JSON-encoded, single column.
        """
        incidents = self.list_incidents(limit=100000)
        if not incidents:
            return "incident_id,seq,prev_hash,entry_hash,payload_hash,ps_class,threat_class,detector,status,severity,score,confidence,score_type,calibrated,flow_id,flow_ref_type,first_observed,last_observed,event_count,evidence_json\r\n"

        evidence_dotted_keys: set[str] = set()
        flattened_evidence_list: list[dict[str, Any]] = []

        for inc in incidents:
            ev = inc.get("evidence") or {}
            flat = flatten_dict(ev, prefix="evidence")
            flattened_evidence_list.append(flat)
            evidence_dotted_keys.update(flat.keys())

        sorted_evidence_cols = sorted(evidence_dotted_keys)

        core_headers = [
            "incident_id",
            "seq",
            "prev_hash",
            "entry_hash",
            "payload_hash",
            "ps_class",
            "threat_class",
            "detector",
            "status",
            "severity",
            "score",
            "confidence",
            "score_type",
            "calibrated",
            "flow_id",
            "flow_ref_type",
            "first_observed",
            "last_observed",
            "event_count",
            "evidence_json",
        ]
        all_headers = core_headers + sorted_evidence_cols

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=all_headers, lineterminator="\r\n")
        writer.writeheader()

        for inc, flat_ev in zip(incidents, flattened_evidence_list):
            row: dict[str, Any] = {
                "incident_id": inc.get("incident_id", ""),
                "seq": inc.get("seq", ""),
                "prev_hash": inc.get("prev_hash", ""),
                "entry_hash": inc.get("entry_hash", ""),
                "payload_hash": inc.get("payload_hash", ""),
                "ps_class": inc.get("ps_class", ""),
                "threat_class": inc.get("threat_class", ""),
                "detector": inc.get("detector", ""),
                "status": inc.get("status", ""),
                "severity": inc.get("severity", ""),
                "score": inc.get("score", ""),
                "confidence": inc.get("confidence", ""),
                "score_type": inc.get("score_type", ""),
                "calibrated": inc.get("calibrated", ""),
                "flow_id": inc.get("flow_id", ""),
                "flow_ref_type": inc.get("flow_ref_type", ""),
                "first_observed": inc.get("first_observed", ""),
                "last_observed": inc.get("last_observed", ""),
                "event_count": inc.get("event_count", ""),
                "evidence_json": json.dumps(inc.get("evidence", {}), ensure_ascii=False),
            }
            for col in sorted_evidence_cols:
                row[col] = flat_ev.get(col, "")
            writer.writerow(row)

        return output.getvalue()
