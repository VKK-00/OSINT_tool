"""Tests for data minimization, retention and case-store schema guards."""
from __future__ import annotations

import sqlite3

import pytest

from osint_toolkit.case_store import CaseStore, CaseStoreError


def test_leak_import_minimizes_raw_lines_by_default(tmp_path, monkeypatch):
    from osintkit import store

    monkeypatch.delenv("OSINTKIT_KEEP_RAW", raising=False)
    monkeypatch.chdir(tmp_path)
    leak = tmp_path / "dump.txt"
    leak.write_text("someone@example.com:SuperSecret123\n", encoding="utf-8")

    stats = store.import_leaks(str(leak))
    assert stats["tokens_indexed"] >= 1
    hits = store.search_leaks("someone@example.com")
    assert hits and hits[0]["kind"] == "email"
    # the password-bearing raw line must not be stored by default
    conn = sqlite3.connect(store.DB_PATH)
    stored_lines = [row[0] for row in conn.execute("SELECT line FROM leaks")]
    conn.close()
    assert all(line is None for line in stored_lines)


def test_leak_import_keeps_raw_only_with_opt_in(tmp_path, monkeypatch):
    from osintkit import store

    monkeypatch.setenv("OSINTKIT_KEEP_RAW", "1")
    monkeypatch.chdir(tmp_path)
    leak = tmp_path / "dump.txt"
    leak.write_text("someone2@example.com:pw\n", encoding="utf-8")
    store.import_leaks(str(leak))
    conn = sqlite3.connect(store.DB_PATH)
    stored = [row[0] for row in conn.execute("SELECT line FROM leaks")]
    conn.close()
    assert any(line and "someone2" in line for line in stored)


def test_leak_purge_modes(tmp_path, monkeypatch):
    from osintkit import store

    monkeypatch.setenv("OSINTKIT_KEEP_RAW", "1")
    monkeypatch.chdir(tmp_path)
    leak = tmp_path / "dump.txt"
    leak.write_text("a@b.example:x\nc@d.example:y\n", encoding="utf-8")
    store.import_leaks(str(leak))

    removed_lines = store.purge_leaks_raw_lines()
    assert removed_lines >= 2
    conn = sqlite3.connect(store.DB_PATH)
    remaining_rows = conn.execute("SELECT COUNT(*) FROM leaks").fetchone()[0]
    null_lines = conn.execute("SELECT COUNT(*) FROM leaks WHERE line IS NULL").fetchone()[0]
    conn.close()
    assert remaining_rows >= 2 and null_lines == remaining_rows

    removed_all = store.purge_leaks_all()
    assert removed_all == remaining_rows


def test_case_store_rejects_newer_schema_version(tmp_path):
    db_path = tmp_path / "cases.sqlite"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.execute("INSERT INTO metadata VALUES ('schema_version', '999')")
    conn.commit()
    conn.close()

    store = CaseStore(db_path)
    with pytest.raises(CaseStoreError, match="newer"):
        # any operation that opens the DB must refuse a future schema
        store.list_cases()


def test_case_store_creates_lookup_indexes(tmp_path):
    db_path = tmp_path / "cases.sqlite"
    CaseStore(db_path).list_cases()  # triggers _ensure_schema
    conn = sqlite3.connect(db_path)
    indexes = {row[1] for row in conn.execute("PRAGMA index_list('entities')")}
    edge_indexes = {row[1] for row in conn.execute("PRAGMA index_list('edges')")}
    conn.close()
    assert "idx_entities_kind_value" in indexes
    assert "idx_edges_case_source" in edge_indexes
