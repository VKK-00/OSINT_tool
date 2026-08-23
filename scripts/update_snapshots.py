"""Refresh bundled Sherlock + WhatsMyName snapshots from upstream.

Usage: python scripts/update_snapshots.py

Downloads the current upstream data files, validates that the existing
loaders can parse them, swaps the package resources in place, and prints
the new dataset statistics for docs updates. Maigret is intentionally NOT
refreshed here: its packaged file is a sanitized projection and the
sanitizer has not been ported into this repo yet.
"""
from __future__ import annotations

import json
import subprocess
import sys
import urllib.request
from pathlib import Path

RESOURCES = Path(__file__).resolve().parents[1] / "osint_toolkit" / "resources"

TARGETS = [
    {
        "name": "Sherlock",
        "raw_url": "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json",
        "api_url": "https://api.github.com/repos/sherlock-project/sherlock/commits?path=sherlock_project/resources/data.json&per_page=1",
        "file": RESOURCES / "sherlock_data.json",
        "notice_line": "Snapshot commit: 206068d",
    },
    {
        "name": "WhatsMyName",
        "raw_url": "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json",
        "api_url": "https://api.github.com/repos/WebBreacher/WhatsMyName/commits?path=wmn-data.json&per_page=1",
        "file": RESOURCES / "whatsmyname_wmn_data.json",
        "notice_line": "Snapshot commit: 7c44595",
    },
]

UA = {"User-Agent": "osint-toolkit-snapshot-updater"}


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def latest_commit_sha(api_url: str) -> str:
    payload = json.loads(fetch(api_url))
    return str(payload[0]["sha"])[:7]


def validate(name: str, raw: bytes) -> None:
    payload = json.loads(raw)
    if name == "Sherlock":
        if not isinstance(payload, dict) or not payload:
            raise SystemExit(f"{name}: unexpected JSON shape")
    if name == "WhatsMyName":
        sites = payload.get("sites") if isinstance(payload, dict) else None
        if not isinstance(sites, list) or not sites:
            raise SystemExit(f"{name}: unexpected JSON shape")


def loader_stats() -> str:
    code = (
        "from osint_toolkit.sites import (\n"
        "    USERNAME_SITES, SHERLOCK_IMPORTED_SITE_COUNT,\n"
        "    WHATSMYNAME_IMPORTED_SITE_COUNT, MAIGRET_IMPORTED_SITE_COUNT)\n"
        "post = sum(1 for s in USERNAME_SITES if s.request_method == 'POST')\n"
        "rurl = sum(1 for s in USERNAME_SITES if s.not_found_url_template)\n"
        "print('total=%d sherlock=%d wmn=%d maigret=%d post=%d rurl=%d' % (\n"
        "    len(USERNAME_SITES), SHERLOCK_IMPORTED_SITE_COUNT,\n"
        "    WHATSMYNAME_IMPORTED_SITE_COUNT, MAIGRET_IMPORTED_SITE_COUNT, post, rurl))\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    return out.stdout.strip()


def main() -> None:
    print("before:", loader_stats())
    notices = (RESOURCES.parent.parent / "THIRD_PARTY_NOTICES.txt")
    if not notices.exists():
        notices = Path("osint_toolkit/resources/THIRD_PARTY_NOTICES.txt")
    notices_text = notices.read_text(encoding="utf-8")

    for target in TARGETS:
        raw = fetch(target["raw_url"])
        validate(target["name"], raw)
        sha = latest_commit_sha(target["api_url"])
        old = target["file"].read_bytes()
        if json.loads(old) == json.loads(raw):
            print(f"{target['name']}: already up to date ({sha})")
            continue
        target["file"].write_bytes(raw)
        old_line = target["notice_line"]
        new_line = old_line.rsplit(" ", 1)[0] + " " + sha
        notices_text = notices_text.replace(old_line, new_line)
        print(f"{target['name']}: updated -> commit {sha}")

    notices.write_text(notices_text, encoding="utf-8", newline="\n")
    print("after:", loader_stats())


if __name__ == "__main__":
    main()
