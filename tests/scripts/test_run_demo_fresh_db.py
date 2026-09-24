"""Task 9: every replay export starts from an empty database."""

import json
import sqlite3

import pytest

pytest.importorskip("fastapi")   # scripts/run_demo.py imports the API app

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from run_demo import reset_demo_db, run_campaign_replay  # noqa: E402


def _replay(db, tmp_path, **kw):
    """One replay, closed afterwards like a finished CLI run (Windows cannot delete an open SQLite file)."""
    state, stats = run_campaign_replay(db_path=str(db), export_dir=tmp_path, verbose=False, **kw)
    state.close()
    return stats


def _export(tmp_path):
    return json.loads((tmp_path / "canonical_campaign_export.json").read_text(encoding="utf-8"))


def test_two_replays_give_identical_exports_starting_at_one(tmp_path):
    db = tmp_path / "demo.db"
    first_stats = _replay(db, tmp_path)
    first = _export(tmp_path)
    second_stats = _replay(db, tmp_path)
    second = _export(tmp_path)
    assert first_stats["hash_chain_valid"] and second_stats["hash_chain_valid"]
    assert len(first) == len(second) > 0
    seq_key = next(k for k in ("seq", "sequence", "chain_seq") if k in first[0])
    assert [e[seq_key] for e in second] == list(range(1, len(second) + 1))


def test_keep_db_appends(tmp_path):
    db = tmp_path / "demo.db"
    _replay(db, tmp_path)
    n = len(_export(tmp_path))
    _replay(db, tmp_path, fresh_db=False)
    assert len(_export(tmp_path)) > n


def test_reset_demo_db_removes_side_files_only(tmp_path):
    db = tmp_path / "demo.db"
    sqlite3.connect(db).close()
    for suffix in ("-wal", "-shm"):
        (tmp_path / f"demo.db{suffix}").write_bytes(b"x")
    keep = tmp_path / "other.db"
    keep.write_bytes(b"x")
    removed = reset_demo_db(db)
    assert len(removed) == 3 and not db.exists() and keep.exists()
    assert reset_demo_db(":memory:") == []


def test_locked_db_gives_a_clear_error(tmp_path, monkeypatch):
    db = tmp_path / "demo.db"
    db.write_bytes(b"x")

    def locked(self, missing_ok=False):
        raise PermissionError(32, "The process cannot access the file because it is being used by another process")

    monkeypatch.setattr(Path, "unlink", locked)
    with pytest.raises(RuntimeError, match="--keep-db"):
        reset_demo_db(db)
