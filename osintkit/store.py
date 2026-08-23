"""Local data stores: leak-dataset index + sanctions index (sqlite).

Both are opt-in: the researcher supplies their own leak files, and the
sanctions index is built from OpenSanctions' public simplecsv export.
Nothing is downloaded or indexed automatically.
"""
from __future__ import annotations

import os
import pathlib
import re
import sqlite3

DB_DIR = pathlib.Path("out")
DB_PATH = DB_DIR / "index.db"

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\+?\d[\d\s\-()]{8,}\d")
HANDLE_RE = re.compile(r"(?<![\w@])@[A-Za-z0-9_]{4,32}")

SANCTIONS_CSV_URL = "https://data.opensanctions.org/datasets/latest/default/targets.simple.csv"


def _connect() -> sqlite3.Connection:
    DB_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS leaks(
        value TEXT NOT NULL,
        kind  TEXT NOT NULL,
        line  TEXT,
        source TEXT)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_leaks_value ON leaks(value)")
    conn.execute("""CREATE TABLE IF NOT EXISTS sanctions(
        name TEXT NOT NULL,
        schema TEXT, countries TEXT, topics TEXT, birth_date TEXT,
        notes TEXT, sources TEXT)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sanctions_name ON sanctions(name)")
    return conn


# ---------------------------------------------------------------- leaks ----

def _insert_batch(conn: sqlite3.Connection, batch: list[tuple]) -> None:
    conn.executemany("INSERT INTO leaks(value,kind,line,source) VALUES(?,?,?,?)", batch)


def import_leaks(path: str) -> dict:
    """Stream-import any text-ish dataset; extract emails/phones/handles.

    Data minimization (default): the raw source line - which routinely
    contains passwords, tokens and third-party data - is NOT stored. Only the
    extracted token plus the source file path are kept. Opt in to raw context
    with OSINTKIT_KEEP_RAW=1 when you genuinely need surrounding text.
    """
    keep_raw = os.environ.get("OSINTKIT_KEEP_RAW", "").strip() not in {"", "0", "false"}
    p = pathlib.Path(path)
    if p.is_dir():
        files = [f for f in sorted(p.rglob("*")) if f.is_file()]
    elif p.is_file():
        files = [p]
    else:
        raise FileNotFoundError(path)

    conn = _connect()
    total_rows = total_tokens = 0
    try:
        for f in files:
            # decode leniently; leaks come in every encoding imaginable
            rows = tokens = 0
            batch: list[tuple] = []

            def flush(b=batch):
                if b:
                    _insert_batch(conn, b)
                    b.clear()

            with open(f, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    rows += 1
                    stored_line = line[:500] if keep_raw else None
                    before = len(batch)
                    for m in EMAIL_RE.findall(line):
                        batch.append((m.lower(), "email", stored_line, str(f)))
                    for m in PHONE_RE.findall(line):
                        digits = re.sub(r"\D", "", m)
                        if 10 <= len(digits) <= 15:
                            batch.append((digits, "phone", stored_line, str(f)))
                    for m in HANDLE_RE.findall(line):
                        h = m.lstrip("@").lower()
                        batch.append((h, "handle", stored_line, str(f)))
                    tokens += len(batch) - before
                    if len(batch) >= 5000:
                        flush()
            flush()
            total_rows += rows
            total_tokens += tokens
        conn.commit()
    finally:
        conn.close()
    return {"files": len(files), "rows": total_rows, "tokens_indexed": total_tokens}


def purge_leaks_raw_lines() -> int:
    """Drop all stored raw leak lines (data-minimization / retention helper)."""
    conn = _connect()
    try:
        cur = conn.execute("UPDATE leaks SET line = NULL WHERE line IS NOT NULL")
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def purge_leaks_all() -> int:
    """Delete every indexed leak row (full retention wipe)."""
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM leaks")
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def search_leaks(term: str, limit: int = 50) -> list[dict]:
    conn = _connect()
    try:
        t = term.strip().lstrip("@").lower()
        esc_t = t.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_" )
        cur = conn.execute(
            """SELECT DISTINCT kind, value, source FROM leaks
               WHERE value = ? OR value LIKE ? ESCAPE '\\'
               LIMIT ?""",
            (t, f"%{esc_t}%", limit))
        hits = [{"kind": k, "value": v, "source": s}
                for k, v, s in cur.fetchall()]
        if not hits:
            # fall back to substring search across raw lines
            cur = conn.execute(
                """SELECT DISTINCT kind, value, source FROM leaks
                   WHERE line LIKE ? ESCAPE '\\' LIMIT ?""",
                (f"%{esc_t}%", limit))
            hits = [{"kind": k, "value": v, "source": s}
                    for k, v, s in cur.fetchall()]
        return hits
    finally:
        conn.close()


# ------------------------------------------------------------- sanctions ----

def update_sanctions(url: str = SANCTIONS_CSV_URL, local_file: str | None = None) -> dict:
    csv_path = pathlib.Path(local_file) if local_file else None
    if csv_path is None:
        import httpx
        DB_DIR.mkdir(exist_ok=True)
        csv_path = DB_DIR / "sanctions.simple.csv"
        with httpx.Client(follow_redirects=True, timeout=120) as client:
            with client.stream("GET", url) as resp:
                resp.raise_for_status()
                with open(csv_path, "wb") as fh:
                    for chunk in resp.iter_bytes(1 << 20):
                        fh.write(chunk)

    conn = _connect()
    try:
        conn.execute("DELETE FROM sanctions")
        import csv as csv_mod
        with open(csv_path, encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv_mod.DictReader(fh)
            cols = {c.lower().strip(): c for c in (reader.fieldnames or [])}

            def col(row, *names):
                for nm in names:
                    c = cols.get(nm)
                    if c and row.get(c):
                        return row[c]
                return ""

            batch: list[tuple] = []
            for row in reader:
                name = col(row, "name").strip()
                if not name:
                    continue
                batch.append((
                    name.lower(), col(row, "schema"),
                    col(row, "countries"), col(row, "topics"),
                    col(row, "birth_date"), col(row, "notes")[:800],
                    col(row, "source")))
                if len(batch) >= 5000:
                    conn.executemany("INSERT INTO sanctions VALUES(?,?,?,?,?,?,?)", batch)
                    batch.clear()
            if batch:
                conn.executemany("INSERT INTO sanctions VALUES(?,?,?,?,?,?,?)", batch)
        conn.commit()
        n = conn.execute("SELECT COUNT(*) FROM sanctions").fetchone()[0]
    finally:
        conn.close()
    return {"indexed": n}


def search_sanctions(name: str, limit: int = 30) -> list[dict]:
    conn = _connect()
    try:
        q = name.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_" )
        cur = conn.execute(
            """SELECT name, schema, countries, topics, birth_date, notes
               FROM sanctions WHERE name LIKE ? ESCAPE '\\'
               ORDER BY LENGTH(name) LIMIT ?""", (f"%{q}%", limit))
        return [dict(zip(("name", "schema", "countries", "topics",
                          "birth_date", "notes"), r, strict=False))
                for r in cur.fetchall()]
    finally:
        conn.close()


def sanctions_ready() -> bool:
    if not DB_PATH.exists():
        return False
    conn = _connect()
    try:
        return conn.execute("SELECT COUNT(*) FROM sanctions").fetchone()[0] > 0
    finally:
        conn.close()
