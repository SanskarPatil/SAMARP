"""Streaming throughput + latency benchmark (PS26145 constraint d, and c).

Replays normalized flow events at a fixed target rate for a fixed duration per
step, over a ladder of increasing rates, through the SAME path the demo uses:

    producer thread (the sensor side)  --bounded buffer-->  consumer thread
    events arrive at the target rate       (drop when full)    DetectionPipeline.process_event
                                                               + AppState.ingest_alert
                                                                 (dedup, scoring, SHA-256 chain, SQLite)

A one-way link cannot slow the sender down, so when the consumer falls behind
and the buffer is full, events are DROPPED and counted - never back-pressured.

Reported per step
  offered rate, sustained processed rate, worst 1-second processed rate,
  dropped events (and %), process CPU (% of one core), peak RSS,
  event->alert latency p50/p95/p99 (arrival in buffer -> incident signed in chain),
  event->processed latency p50/p95/p99 over every event.

Usage (project root, venv active):
    python scripts/bench_throughput.py                       # default ladder, 60 s per step
    python scripts/bench_throughput.py --rates 1000 5000 --duration 60
    python scripts/bench_throughput.py --duration 5 --rates 1000   # smoke run (label says so)

Writes benchmarks/throughput_<UTC>.json and .md with the machine spec + command.
Event mix: the canonical 7-beat campaign (scenarios/canonical_campaign.py),
time-shifted per loop.  It is attack-heavy (12,000 of 12,137 events are the SYN
flood); a mixed benign stream is added in task 5.  Excludes packet capture,
NIC and WebSocket transport.
"""

from __future__ import annotations

import argparse
import copy
import gc
import json
import os
import platform
import queue
import statistics
import sys
import tempfile
import threading
import time
import types
from array import array
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
if "api" not in sys.modules:  # api/__init__ imports FastAPI; AppState does not need it
    _pkg = types.ModuleType("api"); _pkg.__path__ = [str(ROOT / "api")]; sys.modules["api"] = _pkg

from api.state import AppState  # noqa: E402
from detectors.pipeline import DetectionPipeline  # noqa: E402
from machine_spec import machine_spec, spec_markdown  # noqa: E402
from scenarios.canonical_campaign import generate_canonical_campaign_events  # noqa: E402

DEFAULT_RATES = (1_000, 2_000, 5_000, 10_000, 20_000, 40_000)
LOSS_CEILING_PCT = 1.0     # config/thresholds.yaml throughput.loss_ceiling_pct
TICK_S = 0.001             # producer pacing tick


# --------------------------------------------------------------------------- process stats
def peak_rss_mb() -> float | None:
    try:
        if platform.system() == "Windows":
            import ctypes
            from ctypes import wintypes

            class _PMC(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD), ("PeakWorkingSetSize", ctypes.c_size_t),
                            ("WorkingSetSize", ctypes.c_size_t), ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                            ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]

            counters = _PMC(); counters.cb = ctypes.sizeof(_PMC)
            handle = ctypes.windll.kernel32.GetCurrentProcess()  # type: ignore[attr-defined]
            ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb)  # type: ignore[attr-defined]
            return round(counters.PeakWorkingSetSize / 2**20, 1)
        import resource

        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(peak / 1024 / (1024 if platform.system() == "Darwin" else 1), 1)
    except Exception:
        return None


def pct(values, q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, max(0, int(round(q * len(ordered))) - 1))], 4)


# --------------------------------------------------------------------------- one step
def run_step(rate: int, duration_s: float, capacity: int, db_mode: str, base_events: list) -> dict:
    span = max(float(e.observed_time) for e in base_events) - min(float(e.observed_time) for e in base_events) + 60.0
    buf: queue.Queue = queue.Queue()          # holds (arrival_ns, [events]) chunks
    depth = [0]                               # events currently buffered
    depth_lock = threading.Lock()
    stats = {"offered": 0, "dropped": 0, "backlog_at_end": 0}
    stop = threading.Event()

    def producer() -> None:
        loop, idx, n = 0, 0, len(base_events)
        start = time.perf_counter()
        sent = 0
        while True:
            elapsed = time.perf_counter() - start
            if elapsed >= duration_s:
                break
            due = int(rate * elapsed) - sent
            if due > 0:
                chunk = []
                for _ in range(due):
                    ev = copy.copy(base_events[idx])
                    ev.observed_time = float(base_events[idx].observed_time) + loop * span
                    chunk.append(ev)
                    idx += 1
                    if idx == n:
                        idx, loop = 0, loop + 1
                sent += due
                stats["offered"] += due
                with depth_lock:
                    room = capacity - depth[0]
                    if room < len(chunk):             # one-way link: no back-pressure, drop the overflow
                        stats["dropped"] += len(chunk) - max(room, 0)
                        chunk = chunk[: max(room, 0)]
                    depth[0] += len(chunk)
                if chunk:
                    buf.put((time.perf_counter_ns(), chunk))
            time.sleep(TICK_S)
        with depth_lock:
            stats["backlog_at_end"] = depth[0]    # events still waiting when the sender stopped
        stop.set()

    db_dir = tempfile.mkdtemp(prefix="samarp_bench_")
    db_path = ":memory:" if db_mode == "memory" else str(Path(db_dir) / "bench.db")
    state = AppState(db_path=db_path)
    pipeline = DetectionPipeline()
    alert_lat = array("d")
    event_lat = array("d")
    per_second: list[int] = []
    processed = 0

    gc.collect()
    cpu0, wall0 = time.process_time(), time.perf_counter()
    prod = threading.Thread(target=producer, name="producer", daemon=True)
    prod.start()
    sec_start, sec_count = time.perf_counter(), 0
    first_done = last_done = None
    while True:
        try:
            arrival_ns, chunk = buf.get(timeout=0.05)
        except queue.Empty:
            if stop.is_set() and buf.empty():
                break
            continue
        for ev in chunk:
            for alert in pipeline.process_event(ev, ingest_perf_ns=arrival_ns):
                incident = state.ingest_alert(alert, ingest_perf_ns=arrival_ns)
                alert_lat.append(incident["latency_ms"])
            done = time.perf_counter_ns()
            event_lat.append((done - arrival_ns) / 1e6)
            processed += 1
            sec_count += 1
        with depth_lock:
            depth[0] -= len(chunk)
        state.flush_batch()                       # stands in for the 250 ms WebSocket push
        now = time.perf_counter()
        first_done = first_done or now
        last_done = now
        if now - sec_start >= 1.0:
            per_second.append(int(sec_count / (now - sec_start)))
            sec_start, sec_count = now, 0
    for alert in pipeline.flush(ingest_perf_ns=time.perf_counter_ns()):
        state.ingest_alert(alert)
    wall = time.perf_counter() - wall0
    cpu = time.process_time() - cpu0
    prod.join()
    incidents = state.store.count_incidents()
    chain = state.chain_writer.seq
    state.close() if hasattr(state, "close") else None

    offered = stats["offered"]
    backlog_ok = stats["backlog_at_end"] <= rate          # at most ~1 s of traffic still queued
    active = (last_done - first_done) if first_done and last_done and last_done > first_done else wall
    return {
        "target_rate_eps": rate,
        "duration_s": duration_s,
        "offered_events": offered,
        "processed_events": processed,
        "dropped_events": stats["dropped"],
        "dropped_pct": round(100.0 * stats["dropped"] / offered, 3) if offered else 0.0,
        "sustained_processed_eps": round(processed / active, 1),
        "worst_1s_processed_eps": min(per_second[1:-1] or per_second or [0]),
        "median_1s_processed_eps": int(statistics.median(per_second)) if per_second else 0,
        "cpu_pct_of_one_core": round(100.0 * cpu / wall, 1),
        "peak_rss_mb_process": peak_rss_mb(),
        "alerts_emitted": len(alert_lat),
        "incidents": incidents,
        "hash_chain_entries": chain,
        "event_to_alert_latency_ms": {"p50": pct(alert_lat, .50), "p95": pct(alert_lat, .95), "p99": pct(alert_lat, .99), "max": round(max(alert_lat), 4) if alert_lat else None, "n": len(alert_lat)},
        "event_to_processed_latency_ms": {"p50": pct(event_lat, .50), "p95": pct(event_lat, .95), "p99": pct(event_lat, .99), "max": round(max(event_lat), 4) if event_lat else None, "n": len(event_lat)},
        "backlog_at_end_events": stats["backlog_at_end"],
        "keeps_up": backlog_ok,
        "passes_loss_ceiling": ((100.0 * stats["dropped"] / offered if offered else 0.0) < LOSS_CEILING_PCT) and backlog_ok,
    }



def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rates", type=int, nargs="+", default=list(DEFAULT_RATES), help="offered events/s per step")
    parser.add_argument("--duration", type=float, default=60.0, help="seconds per step (PS/KPI: >= 60)")
    parser.add_argument("--buffer", type=int, default=50_000, help="sensor buffer capacity in events (drops beyond)")
    parser.add_argument("--db", choices=("file", "memory"), default="file", help="SQLite on disk (default) or in memory")
    parser.add_argument("--stop-on-loss", action="store_true", help="stop the ladder after the first step above the 1%% loss ceiling")
    parser.add_argument("--out-dir", default=str(ROOT / "benchmarks"))
    args = parser.parse_args()

    base = generate_canonical_campaign_events()
    result = {
        "machine": machine_spec(),
        "config": {"rates": args.rates, "duration_s_per_step": args.duration, "buffer_events": args.buffer, "db": args.db,
                   "loss_ceiling_pct": LOSS_CEILING_PCT, "pass_rule": "dropped < 1 % AND backlog when the sender stops <= 1 s of traffic (the consumer kept up)", "event_source": "scenarios/canonical_campaign.py (attack-heavy, time-shifted per loop)",
                   "metric": "normalized flow events per second", "scope": "pipeline + dedup + scoring + hash chain + SQLite; excludes capture, NIC, WebSocket",
                   "smoke_run": args.duration < 60},
        "steps": [],
    }
    for rate in args.rates:
        print(f"step: {rate} events/s for {args.duration:.0f} s ...", flush=True)
        step = run_step(rate, args.duration, args.buffer, args.db, base)
        result["steps"].append(step)
        print(f"  processed {step['sustained_processed_eps']:.0f}/s (worst 1 s {step['worst_1s_processed_eps']}), dropped {step['dropped_pct']}%, "
              f"alert latency p95 {step['event_to_alert_latency_ms']['p95']} ms, CPU {step['cpu_pct_of_one_core']}%", flush=True)
        if args.stop_on_loss and not step["passes_loss_ceiling"]:
            break
    passing = [s for s in result["steps"] if s["passes_loss_ceiling"]]
    result["summary"] = {"max_offered_rate_with_loss_below_ceiling": max((s["target_rate_eps"] for s in passing), default=None),
                         "kpi_1000_eps_60s_below_1pct_loss": any(s["target_rate_eps"] >= 1000 and s["duration_s"] >= 60 for s in passing)}

    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    (out / f"throughput_{stamp}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    lines = [f"# Throughput benchmark ({stamp})", "",
             ("**SMOKE RUN (< 60 s per step) - not a KPI result.**\n" if args.duration < 60 else ""),
             f"Metric: normalized flow events/s. Scope: {result['config']['scope']}. Events: {result['config']['event_source']}. "
             f"Buffer {args.buffer} events, SQLite {args.db}, {args.duration:.0f} s per step. One-way link: overflow is dropped, never back-pressured.", "",
             "## Machine", "| key | value |", "|---|---|", spec_markdown(result["machine"]), "",
             "## Results", "",
             "| Offered /s | Sustained /s | Worst 1 s /s | Dropped (%) | CPU % 1 core | Peak RSS MB | Alerts | Event→alert p50 / p95 / p99 ms | Event→processed p50 / p95 / p99 ms | Backlog at end | Pass |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for s in result["steps"]:
        a, e = s["event_to_alert_latency_ms"], s["event_to_processed_latency_ms"]
        lines.append(f"| {s['target_rate_eps']:,} | {s['sustained_processed_eps']:,.0f} | {s['worst_1s_processed_eps']:,} | {s['dropped_events']:,} ({s['dropped_pct']}) | "
                     f"{s['cpu_pct_of_one_core']} | {s['peak_rss_mb_process']} | {s['alerts_emitted']} | {a['p50']} / {a['p95']} / {a['p99']} | {e['p50']} / {e['p95']} / {e['p99']} | "
                     f"{s['backlog_at_end_events']:,} | {'yes' if s['passes_loss_ceiling'] else 'no'} |")
    lines += ["", f"Pass rule: {result['config']['pass_rule']}.",
              f"Highest offered rate that passes: **{result['summary']['max_offered_rate_with_loss_below_ceiling']}** events/s.",
              "Peak RSS is the process high-water mark, so it never decreases across steps."]
    (out / f"throughput_{stamp}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[-(len(result['steps']) + 5):]))
    print(f"\nwrote {out / f'throughput_{stamp}.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
