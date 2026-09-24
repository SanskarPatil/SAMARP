"""Deterministic end-to-end replay launcher and demo runner for PS26145.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 17, 18, 19, 24, testing.md section 19.

Executes the complete passive detection pipeline:
Normalized Events -> Feature Extraction -> Detectors -> Deduplication/Scoring ->
SQLite Persistence / Hash Chain -> FastAPI / WebSocket -> Dashboard.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
import time
from pathlib import Path
from typing import Any

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import uvicorn

from alerts.hash_chain import verify_hash_chain
from api.main import create_app
from api.state import AppState
from detectors.pipeline import DetectionPipeline
from ingest.capability import raise_from_observed
from scenarios.canonical_campaign import generate_canonical_campaign_events


def reset_demo_db(db_path: str | Path) -> list[str]:
    """Delete a demo database file and its SQLite side files. Returns what was removed."""
    if str(db_path) == ":memory:":
        return []
    base = Path(db_path)
    removed = []
    for candidate in (base, Path(f"{base}-wal"), Path(f"{base}-shm"), Path(f"{base}-journal")):
        if candidate.is_file():
            try:
                candidate.unlink()
            except PermissionError as exc:   # Windows: the file is open in another process
                raise RuntimeError(
                    f"cannot reset {candidate}: it is open in another process "
                    "(is 'run_demo.py --serve' still running?). Stop it, or pass --keep-db to append."
                ) from exc
            removed.append(str(candidate))
    return removed


def run_campaign_replay(
    db_path: str = "sentinel_demo.db",
    export_dir: str | Path | None = None,
    verbose: bool = True,
    fresh_db: bool = True,
) -> tuple[AppState, dict[str, Any]]:
    """Execute the canonical campaign through the live detection and persistence pipeline.

    ``fresh_db`` (default) deletes the demo SQLite file and its WAL/SHM/journal
    side files first, so the export holds exactly one replay and its hash chain
    starts at sequence 1. Without it, AppState resumes the previous chain and
    every run appends to the last export.
    """
    export_path = Path(export_dir) if export_dir else PROJECT_ROOT / "export"
    export_path.mkdir(parents=True, exist_ok=True)
    removed = reset_demo_db(db_path) if fresh_db else []

    if verbose:
        print("=" * 72)
        print("  SAMARP - PS26145 CANONICAL CAMPAIGN REPLAY")
        print("=" * 72)
        print(f"[*] Target SQLite Database: {db_path}" + (" (fresh: previous file removed)" if removed else " (fresh)" if fresh_db else " (appending to existing chain)"))

    # 1. Initialize State & Store
    app_state = AppState(db_path=db_path)
    pipeline = DetectionPipeline()

    # 2. Generate Deterministic Normalized Events
    t0 = time.perf_counter()
    if verbose:
        print("[*] Generating canonical campaign normalized events...")
    events = generate_canonical_campaign_events()
    if verbose:
        print(f"[*] Generated {len(events)} events across 7 campaign beats.")

    # 3. Process Events through Pipeline
    if verbose:
        print("[*] Replaying events through detection pipeline and alert deduplicator...")

    # Declare what this replay actually carries (DNS names, TLS/JA3/JA4, ...) so the
    # capability banner matches the evidence on screen. Only fields present in the
    # records are raised; nothing is claimed optimistically.
    raise_from_observed(app_state.capability_state, events)

    raw_alert_count = 0
    for ev in events:
        ingest_ns = time.perf_counter_ns()
        alerts = pipeline.process_event(ev, ingest_perf_ns=ingest_ns)
        for a in alerts:
            raw_alert_count += 1
            app_state.ingest_alert(a, ingest_perf_ns=ingest_ns)

    # Flush any remaining tumbling windows
    flush_ns = time.perf_counter_ns()
    flushed_alerts = pipeline.flush(ingest_perf_ns=flush_ns)
    for a in flushed_alerts:
        raw_alert_count += 1
        app_state.ingest_alert(a, ingest_perf_ns=flush_ns)

    elapsed = time.perf_counter() - t0

    # 4. Persistence and Hash Chain Statistics
    total_incidents = app_state.store.count_incidents()
    total_updates = app_state.store.count_updates()
    latest_seq = app_state.chain_writer.seq

    # 5. Export JSON & CSV
    json_export = app_state.store.get_all_signed_entries()
    json_export_file = export_path / "canonical_campaign_export.json"
    with open(json_export_file, "w", encoding="utf-8") as f:
        json.dump(json_export, f, indent=2)

    csv_export_text = app_state.store.export_csv()
    csv_export_file = export_path / "canonical_campaign_export.csv"
    with open(csv_export_file, "w", encoding="utf-8") as f:
        f.write(csv_export_text)

    # 6. Cryptographic Hash Chain Verification
    is_valid_chain, chain_err = verify_hash_chain(json_export)

    # 7. Collect Threat Class Breakdown
    incidents = app_state.store.list_incidents(limit=1000)
    class_counts: dict[str, int] = {}
    for inc in incidents:
        cls_name = inc.get("ps_class", "Unknown")
        class_counts[cls_name] = class_counts.get(cls_name, 0) + 1

    stats = {
        "events_processed": len(events),
        "raw_alerts": raw_alert_count,
        "distinct_incidents": total_incidents,
        "total_updates": total_updates,
        "chain_seq": latest_seq,
        "elapsed_seconds": elapsed,
        "hash_chain_valid": is_valid_chain,
        "hash_chain_error": chain_err,
        "class_breakdown": class_counts,
        "json_export_file": str(json_export_file),
        "csv_export_file": str(csv_export_file),
    }

    if verbose:
        print("\n" + "-" * 72)
        print("  REPLAY EXECUTION SUMMARY")
        print("-" * 72)
        print(f"  Events Processed:    {stats['events_processed']:,}")
        print(f"  Raw Alerts Emitted:  {stats['raw_alerts']:,}")
        print(f"  Incidents Persisted: {stats['distinct_incidents']}")
        print(f"  Chain Entries:       {stats['chain_seq']}")
        print(f"  Elapsed Time:        {stats['elapsed_seconds']:.2f}s")
        print(f"  Hash Chain Status:   {'[PASS] VERIFIED' if is_valid_chain else f'[FAIL] {chain_err}'}")
        print("-" * 72)
        print("  DEMONSTRATED PS26145 THREAT CLASSES:")
        for cls_name, count in sorted(class_counts.items()):
            print(f"    &bull; {cls_name:<36} : {count} incident(s)")
        print("-" * 72)
        print(f"  Lossless JSON Export : {json_export_file}")
        print(f"  Flattened CSV Export : {csv_export_file}")
        print("=" * 72 + "\n")

    return app_state, stats


def main() -> int:
    parser = argparse.ArgumentParser(description="SAMARP PS26145 Demo Launcher")
    parser.add_argument("--replay-only", action="store_true", help="Execute canonical campaign and exit")
    parser.add_argument("--serve", action="store_true", default=False, help="Launch read-only Plane B API server")
    parser.add_argument("--db-path", default="sentinel_demo.db", help="Path to SQLite database")
    parser.add_argument("--keep-db", action="store_true", help="Append to the existing database instead of starting from an empty one")
    parser.add_argument("--host", default="127.0.0.1", help="API server host")
    parser.add_argument("--port", type=int, default=8000, help="API server port")
    parser.add_argument("--verify-only", type=str, default=None, help="Verify an exported JSON file")

    args = parser.parse_args()

    # Handle verify-only flag
    if args.verify_only:
        with open(args.verify_only, "r", encoding="utf-8") as f:
            data = json.load(f)
        entries = data if isinstance(data, list) else data.get("incidents", [])
        ok, err = verify_hash_chain(entries)
        if ok:
            print(f"[PASS] Hash chain intact for {args.verify_only}")
            return 0
        else:
            print(f"[FAIL] Hash chain verification failed: {err}", file=sys.stderr)
            return 1

    # Run campaign replay
    app_state, stats = run_campaign_replay(db_path=args.db_path, fresh_db=not args.keep_db)

    if not stats["hash_chain_valid"]:
        print(f"FATAL: Hash chain verification failed: {stats['hash_chain_error']}", file=sys.stderr)
        return 1

    if args.replay_only or not args.serve:
        print("[*] Replay verification complete. To serve live API, pass --serve.")
        return 0

    # Serve API via uvicorn
    print(f"[*] Starting Plane B Read-Only Monitoring API on http://{args.host}:{args.port}")
    print("    GET  /health")
    print("    GET  /capabilities")
    print("    GET  /incidents")
    print("    GET  /export/json")
    print("    GET  /export/csv")
    print("    WS   /ws/incidents")
    print("[*] Monitoring Dashboard can be opened at http://localhost:5173")

    app = create_app(service_state=app_state)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
