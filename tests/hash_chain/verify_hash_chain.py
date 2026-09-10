"""Standalone hash chain verification script for exported JSON files.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md section 19, design.md section 18.

Runs in a clean process against the exported JSON only, with no import of writer runtime state.
"""

import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from alerts.hash_chain import verify_hash_chain


def verify_exported_file(json_file_path: str | Path) -> tuple[bool, str | None]:
    """Load an exported hash chain JSON file and verify its cryptographic integrity."""
    path = Path(json_file_path)
    if not path.exists():
        return False, f"File not found: {path}"

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return False, f"Failed to parse JSON file {path}: {e}"

    if isinstance(data, dict):
        # Support either direct list or {"incidents": [...]} / {"entries": [...]}
        entries = data.get("incidents") or data.get("entries") or [data]
    elif isinstance(data, list):
        entries = data
    else:
        return False, f"Unexpected JSON root type: {type(data).__name__}"

    return verify_hash_chain(entries)


def main() -> int:
    """CLI entrypoint for hash chain verification."""
    if len(sys.argv) < 2:
        print("Usage: python verify_hash_chain.py <export_file.json>", file=sys.stderr)
        return 2

    file_path = sys.argv[1]
    is_valid, err_msg = verify_exported_file(file_path)

    if is_valid:
        print(f"[PASS] Hash chain integrity verified: {file_path}")
        return 0
    else:
        print(f"[FAIL] Hash chain integrity check failed: {err_msg}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
