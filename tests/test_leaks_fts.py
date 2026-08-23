"""FTS5 leak-search tests (fallback-safe)."""
from __future__ import annotations

import sqlite3


def test_leak_search_finds_token_via_fts(tmp_path, monkeypatch):
    from osintkit import store

    monkeypatch.chdir(tmp_path)
    leak = tmp_path / "dump.txt"
    leak.write_text("ivan.petrenko@gmail.com:pw\n", encoding="utf-8")
    store.import_leaks(str(leak))

    hits = store.search_leaks("ivan.petrenko")
    assert hits and hits[0]["kind"] == "email"

    conn = sqlite3.connect(store.DB_PATH)
    tables = {row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE name LIKE 'leaks_fts%'")}
    conn.close()
    assert "leaks_fts" in tables  # fts5 present on stock CPython sqlite


def test_purge_keeps_fts_consistent(tmp_path, monkeypatch):
    from osintkit import store

    monkeypatch.chdir(tmp_path)
    leak = tmp_path / "dump.txt"
    leak.write_text("keep@x.example:1\n", encoding="utf-8")
    store.import_leaks(str(leak))
    store.purge_leaks_all()
    assert store.search_leaks("keep@x.example") == []
