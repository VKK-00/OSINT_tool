"""Smoke tests: no network required."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_transliterate_bidirectional():
    from osintkit.core import transliterate
    out = transliterate("ivanov")
    assert "ivanov" in out
    assert any("іван" in v for v in out)


def test_phone_parsing():
    import asyncio
    from osintkit.modules.phone_info import PhoneModule
    from osintkit.core import HttpClient

    async def go():
        http = HttpClient()
        try:
            res = await PhoneModule().safe_run("+380501234567", http)
        finally:
            await http.aclose()
        return res

    res = asyncio.run(go())
    assert res.ok and res.findings
    assert res.findings[0].extra["country"] == "UA"


def test_store_roundtrip(tmp_path):
    import pathlib
    from osintkit import store

    f = tmp_path / "leak.txt"
    f.write_text("someone@example.com:pass123\n+380501234567 ok\n", encoding="utf-8")
    stats = store.import_leaks(str(f))
    assert stats["tokens_indexed"] >= 2
    hits = store.search_leaks("someone@example.com")
    assert hits and hits[0]["kind"] == "email"


def test_all_modules_registered():
    from osintkit.modules.base import get_all
    names = {m.name for m in get_all()}
    expected = {"username", "email", "phone", "net", "tg",
                "archive", "geo", "leaks", "sanctions", "dorks", "image"}
    assert expected <= names


def test_html_report_renders():
    from osintkit.report_html import render_html_report
    results = [{
        "module": "phone", "target": "+380501234567", "ok": True,
        "error": "", "elapsed_s": 0.1,
        "findings": [{"kind": "phone", "source": "phone",
                      "value": "+380501234567", "confidence": "high",
                      "url": "", "extra": {"country": "UA"}}],
    }]
    path = render_html_report("test_target", results,
                              generated="2025-01-01T00:00:00Z",
                              outdir=str(tmp_dir()))
    text = open(path, encoding="utf-8").read()
    assert "__DATA__" not in text and "const DATA" in text


def tmp_dir():
    import tempfile
    return tempfile.mkdtemp()
