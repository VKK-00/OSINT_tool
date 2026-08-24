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
    {
        "name": "Maigret",
        "raw_url": "https://raw.githubusercontent.com/soxoj/maigret/main/maigret/resources/data.json",
        "api_url": "https://api.github.com/repos/soxoj/maigret/commits?path=maigret/resources/data.json&per_page=1",
        "file": RESOURCES / "maigret_sites.json",
        "notice_line": "Snapshot commit: 2484509",
        # Maigret ships a raw runtime database; the packaged resource is a
        # sanitized projection produced by sanitize_maigret() below.
        "sanitize": True,
    },
]

# Headers that must never be copied into the packaged projection: anything
# credential-like would leak session material into the repository.
UNSAFE_HEADER_MARKERS = ("auth", "cookie", "token", "session", "csrf", "api")


def sanitize_maigret(raw: bytes) -> bytes:
    """Ported sanitizer: upstream runtime DB -> safe check-template projection.

    Keeps only fields the native loader consumes (url templates, markers,
    regex rules, region tags, plain headers) and drops activation-dependent
    and credential-like data.
    """
    payload = json.loads(raw)
    sites = payload.get("sites") if isinstance(payload, dict) else None
    if not isinstance(sites, dict):
        raise SystemExit("Maigret: upstream JSON has no 'sites' object")
    projection = []
    for name, entry in sites.items():
        if not isinstance(entry, dict):
            continue
        # upstream templates already carry the named {username} field that
        # _template_uses_only_username requires
        url = entry.get("url")
        if not isinstance(url, str) or "{username}" not in url:
            continue
        projected: dict[str, object] = {"name": name, "url": url}
        profile_url = entry.get("urlProbe") or entry.get("urlProfile")
        if isinstance(profile_url, str) and "{username}" in profile_url:
            projected["profile_url"] = profile_url
        if isinstance(entry.get("regexCheck"), str) and entry["regexCheck"]:
            projected["regexCheck"] = entry["regexCheck"]
        tags = entry.get("tags")
        if isinstance(tags, list) and tags:
            projected["tags"] = [tag for tag in tags if isinstance(tag, str)]
        error_type = entry.get("errorType")
        if entry.get("checkType") == "status_code" or error_type == "status_code":
            projected["checkType"] = "status_code"
        presence = entry.get("presenseStrs") or entry.get("presenceStrs")
        if isinstance(presence, list) and presence:
            projected["presenceStrs"] = [s for s in presence if isinstance(s, str)]
        absence = entry.get("absenceStrs")
        if not isinstance(absence, list) and isinstance(entry.get("errorMsg"), str):
            absence = [entry["errorMsg"]]
        if isinstance(absence, list) and absence:
            projected["absenceStrs"] = [s for s in absence if isinstance(s, str)]
        headers = entry.get("headers")
        if isinstance(headers, dict):
            safe_headers = {
                key: value
                for key, value in headers.items()
                if isinstance(key, str)
                and isinstance(value, str)
                and not any(marker in key.lower() for marker in UNSAFE_HEADER_MARKERS)
            }
            if safe_headers:
                projected["headers"] = safe_headers
        projection.append(projected)
    return json.dumps({"sites": projection}, ensure_ascii=False, indent=1).encode("utf-8")

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
        if target.get("sanitize"):
            raw = sanitize_maigret(raw)
        else:
            validate(target["name"], raw)
        sha = latest_commit_sha(target["api_url"])
        old = target["file"].read_bytes() if target["file"].exists() else b""
        try:
            unchanged = json.loads(old) == json.loads(raw)
        except json.JSONDecodeError:
            unchanged = False
        if unchanged:
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
