"""Storage consolidation: legacy index.db migrates into the shared DB."""
from __future__ import annotations

import sqlite3


def test_legacy_index_db_migrates_into_shared_db(tmp_path, monkeypatch):
    from osintkit import store

    monkeypatch.delenv("OSINTKIT_DB_PATH", raising=False)
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "out"
    out.mkdir()

    # simulate a pre-consolidation install: data lives in the legacy file
    conn = sqlite3.connect(out / "index.db")
    conn.execute(
        "CREATE TABLE leaks (value TEXT NOT NULL, kind TEXT NOT NULL,"
        " line TEXT, source TEXT)"
    )
    conn.execute("INSERT INTO leaks VALUES ('old@leak.example', 'email', NULL, 'legacy')")
    conn.execute(
        "CREATE TABLE sanctions (name TEXT NOT NULL, schema TEXT, countries TEXT,"
        " topics TEXT, birth_date TEXT, notes TEXT, sources TEXT)"
    )
    conn.execute("INSERT INTO sanctions VALUES ('Ivan Test', 'person', 'ua', '', '', '', '')")
    conn.commit()
    conn.close()

    # touching the store must migrate both tables into out/cases.sqlite
    hits = store.search_leaks("old@leak.example")
    assert hits and hits[0]["value"] == "old@leak.example"

    shared = sqlite3.connect(out / "cases.sqlite")
    leaks_count = shared.execute("SELECT COUNT(*) FROM leaks").fetchone()[0]
    sanctions_count = shared.execute("SELECT COUNT(*) FROM sanctions").fetchone()[0]
    shared.close()
    assert leaks_count == 1
    assert sanctions_count == 1
    # legacy file is kept untouched as a backup
    assert (out / "index.db").exists()


def test_explicit_db_path_override_skips_migration(tmp_path, monkeypatch):
    from osintkit import store

    out = tmp_path / "out"
    out.mkdir()
    (out / "index.db").write_bytes(b"not a real db")
    custom = tmp_path / "custom.sqlite"
    monkeypatch.setenv("OSINTKIT_DB_PATH", str(custom))

    store.search_leaks("anything")  # triggers connect + schema creation
    # no migration attempt against the bogus legacy file
    assert custom.exists() and (out / "index.db").read_bytes() == b"not a real db"
