"""Final verification (task 10): run every check, save raw output + machine spec.

Usage (project root, venv active, plugged in):
    python scripts/verify_all.py

Checks
  1. full pytest suite                    python -m pytest -q
  2. API + integration tests only         python -m pytest -q tests/api tests/integration
  3. read-only proof (405 on writes)      python -m pytest -q tests/api -k read_only
  4. static scan: no write routes         regex over api/*.py for POST/PUT/PATCH/DELETE route decorators
  5. canonical replay from an empty DB    python scripts/run_demo.py --replay-only --db-path <temp>
  6. hash-chain verification of export    python scripts/run_demo.py --verify-only export/canonical_campaign_export.json
  7. dashboard unit tests                 npm test          (in dashboard/)
  8. dashboard production build           npm run build     (in dashboard/)
Writes benchmarks/verify_<UTC>.json, .md and .log (full stdout/stderr of every step).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from machine_spec import machine_spec, spec_markdown  # noqa: E402

PY = sys.executable


def _pytest_counts(text: str) -> dict[str, int]:
    tail = "\n".join(text.strip().splitlines()[-3:])
    return {k: int(v) for v, k in re.findall(r"(\d+) (passed|failed|errors?|skipped|xfailed|xpassed|deselected)", tail)}


def _write_route_scan() -> tuple[int, str]:
    hits = []
    for path in sorted((ROOT / "api").glob("*.py")):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"@\w+\.(post|put|patch|delete)\s*\(", line) or re.search(r"methods\s*=\s*\[[^\]]*(POST|PUT|PATCH|DELETE)", line, re.I):
                hits.append(f"{path.relative_to(ROOT)}:{n}: {line.strip()}")
    return (1 if hits else 0), ("write routes found:\n" + "\n".join(hits)) if hits else "no POST/PUT/PATCH/DELETE route decorators in api/*.py"


def main() -> int:
    npm = shutil.which("npm") or shutil.which("npm.cmd")
    tmp_db = Path(tempfile.mkdtemp(prefix="samarp_verify_")) / "verify.db"
    steps = [
        ("full pytest suite", [PY, "-m", "pytest", "-q", "-p", "no:cacheprovider"], ROOT, "pytest"),
        ("API + integration tests", [PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/api", "tests/integration"], ROOT, "pytest"),
        ("read-only proof (405 on writes)", [PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/api", "-k", "read_only"], ROOT, "pytest"),
        ("static scan: no write routes", None, ROOT, "scan"),
        ("canonical replay from empty DB", [PY, "scripts/run_demo.py", "--replay-only", "--db-path", str(tmp_db)], ROOT, "replay"),
        ("hash-chain verification of export", [PY, "scripts/run_demo.py", "--verify-only", "export/canonical_campaign_export.json"], ROOT, "plain"),
        ("dashboard unit tests (vitest)", [npm, "test"] if npm else None, ROOT / "dashboard", "npm"),
        ("dashboard production build", [npm, "run", "build"] if npm else None, ROOT / "dashboard", "npm"),
    ]
    results, log = [], []
    for name, cmd, cwd, kind in steps:
        t0 = time.perf_counter()
        if kind == "scan":
            code, out = _write_route_scan()
            shown = "(built-in scan of api/*.py)"
        elif cmd is None or cmd[0] is None:
            code, out, shown = 2, "npm not found on PATH - dashboard step not run", "npm (missing)"
        else:
            proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace")
            code, out = proc.returncode, (proc.stdout or "") + (("\n[stderr]\n" + proc.stderr) if proc.stderr.strip() else "")
            shown = " ".join(Path(c).name if i == 0 else c for i, c in enumerate(cmd)) + (f"   (cwd: {cwd.relative_to(ROOT)})" if cwd != ROOT else "")
        row = {"step": name, "command": shown, "exit_code": code, "passed": code == 0, "seconds": round(time.perf_counter() - t0, 1)}
        if kind == "pytest":
            row["counts"] = _pytest_counts(out)
        if kind == "replay":
            m = {k: re.search(p, out) for k, p in (("events", r"Events Processed:\s+([\d,]+)"), ("raw_alerts", r"Raw Alerts Emitted:\s+(\d+)"),
                                                   ("incidents", r"Incidents Persisted:\s+(\d+)"), ("chain", r"Hash Chain Status:\s+(.+)"))}
            row["replay"] = {k: (v.group(1).strip() if v else None) for k, v in m.items()}
        results.append(row)
        log += [f"===== {name} =====", f"$ {shown}", f"exit {code}  ({row['seconds']} s)", out.rstrip(), ""]
        print(f"[{'PASS' if row['passed'] else 'FAIL'}] {name}  ({row['seconds']} s)  {row.get('counts', row.get('replay', ''))}", flush=True)

    spec = machine_spec()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = ROOT / "benchmarks"
    (out_dir / f"verify_{stamp}.log").write_text("\n".join(log), encoding="utf-8")
    all_ok = all(r["passed"] for r in results)
    (out_dir / f"verify_{stamp}.json").write_text(json.dumps({"machine": spec, "all_passed": all_ok, "steps": results}, indent=2), encoding="utf-8")
    lines = [f"# Final verification ({stamp})", "", f"**Result: {'ALL CHECKS PASSED' if all_ok else 'SOME CHECKS FAILED'}**", "",
             "## Machine", "| key | value |", "|---|---|", spec_markdown(spec), "",
             "## Checks", "| # | Check | Command | Result | Detail | Time (s) |", "|---|---|---|---|---|---|"]
    for i, r in enumerate(results, 1):
        detail = ", ".join(f"{v} {k}" for k, v in r.get("counts", {}).items()) or ", ".join(f"{k} {v}" for k, v in r.get("replay", {}).items())
        lines.append(f"| {i} | {r['step']} | `{r['command']}` | {'PASS' if r['passed'] else '**FAIL** (exit %d)' % r['exit_code']} | {detail} | {r['seconds']} |")
    lines += ["", f"Full output of every step: `benchmarks/verify_{stamp}.log`."]
    (out_dir / f"verify_{stamp}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[4:]))
    print(f"\nwrote benchmarks/verify_{stamp}.json / .md / .log")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
