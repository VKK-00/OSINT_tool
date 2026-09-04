#!/usr/bin/env python3
"""Collect and normalize public UVB-76 logs without claiming decryption.

Primary source: Priyom.org. A public GitHub mirror is used only as a fallback
for pages that cannot be fetched live. Raw HTML and parsing issues are retained.
"""
from __future__ import annotations

import argparse
import hashlib
import html as html_lib
import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urljoin, urlparse, urlunparse

import pandas as pd
import requests
from bs4 import BeautifulSoup
from dateutil import parser as date_parser
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE_URL = "https://priyom.org/military-stations/russia/the-buzzer"
MONTHS = {
    "january": 1, "february": 2, "march": 3, "april": 4,
    "may": 5, "june": 6, "july": 7, "august": 8,
    "september": 9, "october": 10, "november": 11, "december": 12,
}
EXPECTED_MONTHS = {
    2013: [1, 3, 9, 12],
    2014: list(range(1, 13)),
    2015: list(range(1, 13)),
    2016: list(range(1, 13)),
    2017: [1, 2, 3, 4, 5, 6, 9],
    2018: [1, 2, 9, 10, 11],
    2019: [2, 3, 4, 5, 6, 7, 9, 10, 12],
    2020: list(range(1, 13)),
    2021: list(range(1, 13)),
    2022: [1, 2, 12],
    2023: [1, 4, 5, 6, 7, 8, 9, 10, 11, 12],
    2024: list(range(1, 13)),
}
MONTH_SLUG = {number: name for name, number in MONTHS.items()}
SPACE_RE = re.compile(r"\s+")
TIME_RE = re.compile(r"\b([01]?\d|2[0-3]):[0-5]\d\b")
FIVE_RE = re.compile(r"(?<!\d)[0-9?]{5}(?!\d)")
ALPHA_RE = re.compile(r"^[A-Za-zА-Яа-яЁёІіЇїЄєҐґ][A-Za-zА-Яа-яЁёІіЇїЄєҐґ'’`?\-]*$")
NUM_RE = re.compile(r"^[0-9?]{2,8}$")
TOKEN_RE = re.compile(r"[A-Za-zА-Яа-яЁёІіЇїЄєҐґ][A-Za-zА-Яа-яЁёІіЇїЄєҐґ'’`?\-]*|[0-9?]{2,8}")
DATE_LINE_RE = re.compile(
    r"(?:\d{1,2}[./]\d{1,2}[./]\d{2,4}|"
    r"(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},\s+\d{4})",
    re.IGNORECASE,
)


def clean_text(value) -> str:
    if value is None:
        return ""
    if hasattr(value, "get_text"):
        value = value.get_text("\n", strip=True)
    text = html_lib.unescape(str(value)).replace("\xa0", " ")
    lines = [SPACE_RE.sub(" ", line).strip() for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def canonicalize_url(url: str) -> str:
    parsed = urlparse(urljoin(BASE_URL + "/", url))
    path = re.sub(r"/+", "/", parsed.path).rstrip("/")
    return urlunparse(("https", "priyom.org", path, "", "", ""))


def expected_pages() -> list[str]:
    pages = [f"{BASE_URL}/pre2010"]
    pages.extend(f"{BASE_URL}/{year}" for year in (2010, 2011, 2012))
    for year, months in EXPECTED_MONTHS.items():
        pages.extend(f"{BASE_URL}/{year}/{MONTH_SLUG[month]}" for month in months)
    return pages


def infer_page_period(title: str, source_url: str) -> tuple[int | None, int | None]:
    combined = f"{title} {source_url}"
    year_match = re.search(r"\b(19\d{2}|20\d{2})\b", combined)
    year = int(year_match.group(1)) if year_match else None
    lower = combined.lower()
    month = next((number for name, number in MONTHS.items() if re.search(rf"\b{name}\b", lower)), None)
    return year, month


def infer_era(callsign: str) -> str:
    upper = callsign.upper().replace("’", "'")
    if "MDZHB" in upper or "МДЖБ" in upper:
        return "MDZhB"
    if "ZHUOZ" in upper or "ЖУОЗ" in upper:
        return "ZhUOZ"
    if "ANVF" in upper or "АНВФ" in upper:
        return "ANVF"
    if "NZHTI" in upper or "НЖТИ" in upper:
        return "NZhTI"
    if not upper:
        return "unknown"
    return "other"


def parse_frequency(text: str) -> tuple[str, str]:
    values: list[str] = []
    modes: list[str] = []
    for number, unit in re.findall(r"(\d+(?:\.\d+)?)\s*(kHz|MHz)", text, flags=re.IGNORECASE):
        khz = float(number) * (1000 if unit.lower() == "mhz" else 1)
        values.append(str(int(khz)) if khz.is_integer() else f"{khz:g}")
    for mode in re.findall(r"\b(?:H3E|J3E|A3E|USB|LSB|AM|CW|NFM|FM)(?:\s*\([^)]*\))?\b", text, flags=re.IGNORECASE):
        modes.append(mode)
    return ";".join(dict.fromkeys(values)), ";".join(dict.fromkeys(modes))


def _payload_from_numeric_tokens(tokens: list[str], start: int) -> tuple[str, str, int] | None:
    remaining = tokens[start:]
    if not remaining:
        return None
    if len(remaining[0]) == 8:
        return remaining[0], remaining[0], 1
    if len(remaining) >= 2 and all(len(token) == 4 for token in remaining[:2]):
        return " ".join(remaining[:2]), "".join(remaining[:2]), 2
    if len(remaining) >= 4 and all(len(token) == 2 for token in remaining[:4]):
        return " ".join(remaining[:4]), "".join(remaining[:4]), 4
    return None


def parse_message_blocks(message: str, transmission_id: str) -> list[dict]:
    tokens = TOKEN_RE.findall(clean_text(message))
    blocks: list[dict] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if ALPHA_RE.match(token):
            numeric: list[str] = []
            cursor = index + 1
            while cursor < len(tokens) and NUM_RE.match(tokens[cursor]) and len(numeric) < 4:
                numeric.append(tokens[cursor])
                cursor += 1
            parsed = _payload_from_numeric_tokens(numeric, 0)
            if parsed:
                payload_raw, normalized, consumed = parsed
                quality = "exact" if normalized.isdigit() and len(normalized) == 8 else (
                    "uncertain" if "?" in normalized and len(normalized) == 8 else "nonstandard"
                )
                blocks.append({
                    "transmission_id": transmission_id,
                    "block_order": len(blocks) + 1,
                    "codeword_latin": token,
                    "payload_raw": payload_raw,
                    "payload_normalized": normalized,
                    "payload_quality": quality,
                    "numeric_grouping": "+".join(str(len(part)) for part in payload_raw.split()),
                    "context_raw": " ".join(tokens[index:index + 1 + consumed]),
                })
                index += 1 + consumed
                continue
        index += 1
    return blocks


def _parse_date(text: str) -> str:
    try:
        value = date_parser.parse(text, fuzzy=False, dayfirst=False)
        return value.date().isoformat()
    except Exception:
        return ""


def _message_text(cell) -> str:
    marked = cell.select(".messageCol")
    if marked:
        return "\n".join(clean_text(item) for item in marked if clean_text(item))
    return clean_text(cell)


def _extract_repeat_references(notes: str, transmission_id: str) -> list[dict]:
    output: list[dict] = []
    for line in notes.splitlines():
        if not DATE_LINE_RE.search(line):
            continue
        blocks = parse_message_blocks(line, transmission_id)
        if not blocks:
            continue
        date_match = DATE_LINE_RE.search(line)
        time_match = TIME_RE.search(line)
        groups = FIVE_RE.findall(line)
        for block in blocks:
            prefix = line[: line.find(block["codeword_latin"])]
            words = [token for token in TOKEN_RE.findall(prefix) if ALPHA_RE.match(token)]
            output.append({
                "transmission_id": transmission_id,
                "reference_raw": line,
                "ref_date_raw": date_match.group(0) if date_match else "",
                "ref_date": _parse_date(date_match.group(0)) if date_match else "",
                "ref_time": time_match.group(0) if time_match else "",
                "ref_callsign_candidate": words[-1] if words else "",
                "ref_key_group": groups[-1] if groups else "",
                "ref_codeword": block["codeword_latin"],
                "ref_payload": block["payload_normalized"],
                "ref_payload_quality": block["payload_quality"],
            })
    return output


def parse_html_page(html: str, source_url: str, retrieved_at: str):
    soup = BeautifulSoup(html, "lxml")
    title = clean_text(soup.title) if soup.title else ""
    page_year, page_month = infer_page_period(title, source_url)
    page_sha = hashlib.sha256(html.encode("utf-8", errors="replace")).hexdigest()
    transmissions: list[dict] = []
    blocks: list[dict] = []
    repeats: list[dict] = []
    issues: list[dict] = []

    row_counter = 0
    for table_index, table in enumerate(soup.find_all("table"), start=1):
        for tr in table.find_all("tr"):
            cells = tr.find_all("td", recursive=False)
            if len(cells) < 6:
                continue
            row_counter += 1
            raw_cells = [clean_text(cell) for cell in cells]
            date_text = raw_cells[0]
            date_iso = _parse_date(date_text)
            time_match = TIME_RE.search(raw_cells[1])
            time_text = time_match.group(0) if time_match else clean_text(raw_cells[1])
            if not date_iso:
                issues.append({
                    "source_url": source_url, "table_index": table_index,
                    "row_index": row_counter, "issue_type": "unparsed_date",
                    "detail": date_text, "raw_cells_json": json.dumps(raw_cells, ensure_ascii=False),
                })
                continue

            transmission_id = hashlib.sha1(
                f"{source_url}|{table_index}|{row_counter}|{date_text}|{time_text}|{raw_cells}".encode("utf-8")
            ).hexdigest()[:20]
            frequency_raw = raw_cells[2] if len(raw_cells) > 2 else ""
            frequency_khz, mode_raw = parse_frequency(frequency_raw)
            callsign_raw = raw_cells[3] if len(raw_cells) > 3 else ""
            key_group_raw = raw_cells[4] if len(raw_cells) > 4 else ""
            latin_raw = _message_text(cells[5]) if len(cells) > 5 else ""
            cyrillic_raw = _message_text(cells[6]) if len(cells) > 6 else ""
            notes_raw = "\n".join(raw_cells[7:]) if len(raw_cells) > 7 else ""
            audio_urls = [urljoin(source_url, anchor.get("href")) for anchor in tr.find_all("a", href=True)
                          if re.search(r"\.(?:ogg|wav|mp3|flac)(?:$|\?)", anchor.get("href"), re.I)]
            row_blocks = parse_message_blocks(latin_raw, transmission_id)
            callsign_tokens = [part for part in re.split(r"[\s,;]+", callsign_raw) if part]
            key_groups = FIVE_RE.findall(key_group_raw)
            timestamp_utc = ""
            if date_iso and re.fullmatch(r"\d{2}:\d{2}", time_text):
                timestamp_utc = f"{date_iso}T{time_text}:00Z"

            confidence = "high" if date_iso and time_text and latin_raw else "medium"
            transmissions.append({
                "transmission_id": transmission_id,
                "source_url": source_url,
                "source_kind": "Priyom live or archived page",
                "page_year": page_year,
                "page_month": page_month,
                "date": date_iso,
                "date_raw": date_text,
                "time_local_text": time_text,
                "time_zone": "UTC",
                "timestamp_utc": timestamp_utc,
                "frequency_raw": frequency_raw,
                "frequency_khz": frequency_khz,
                "mode_raw": mode_raw,
                "callsign_raw": callsign_raw,
                "callsign_tokens": ";".join(callsign_tokens),
                "era": infer_era(callsign_raw),
                "key_group_raw": key_group_raw,
                "key_groups": ";".join(key_groups),
                "message_latin_raw": latin_raw,
                "message_cyrillic_raw": cyrillic_raw,
                "notes_raw": notes_raw,
                "audio_urls": ";".join(audio_urls),
                "n_blocks": len(row_blocks),
                "parser_confidence": confidence,
                "raw_cells_json": json.dumps(raw_cells, ensure_ascii=False),
                "page_html_sha256": page_sha,
            })
            for block in row_blocks:
                block.update({
                    "date": date_iso,
                    "time_local_text": time_text,
                    "time_zone": "UTC",
                    "callsign_raw": callsign_raw,
                    "era": infer_era(callsign_raw),
                    "key_group_raw": key_group_raw,
                    "key_groups": ";".join(key_groups),
                    "source_url": source_url,
                })
                blocks.append(block)
            repeats.extend(_extract_repeat_references(notes_raw, transmission_id))
            if latin_raw and not row_blocks:
                issues.append({
                    "source_url": source_url, "table_index": table_index,
                    "row_index": row_counter, "issue_type": "message_without_parsed_block",
                    "detail": latin_raw, "raw_cells_json": json.dumps(raw_cells, ensure_ascii=False),
                })

    page = {
        "source_url": source_url,
        "retrieved_at_utc": retrieved_at,
        "title": title,
        "page_year": page_year,
        "page_month": page_month,
        "html_sha256": page_sha,
        "html_bytes": len(html.encode("utf-8", errors="replace")),
        "table_count": len(soup.find_all("table")),
        "rows_parsed": len(transmissions),
        "blocks_parsed": len(blocks),
        "active_dates": len({row["date"] for row in transmissions}),
    }
    return page, transmissions, blocks, repeats, issues


def make_session() -> requests.Session:
    retry = Retry(total=4, connect=4, read=4, status=4, backoff_factor=0.8,
                  status_forcelist=[429, 500, 502, 503, 504], allowed_methods=["GET"])
    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.headers.update({
        "User-Agent": "UVB76-open-research/1.0 (+public-data; non-operational analysis)",
        "Accept": "text/html,application/xhtml+xml",
    })
    return session


def discover_live_pages(session: requests.Session) -> tuple[list[str], str]:
    response = session.get(BASE_URL, timeout=45)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "lxml")
    links = set()
    base_path = urlparse(BASE_URL).path
    for anchor in soup.find_all("a", href=True):
        url = canonicalize_url(anchor["href"])
        path = urlparse(url).path
        if not path.startswith(base_path + "/"):
            continue
        suffix = path[len(base_path) + 1:]
        if re.fullmatch(r"pre2010|(?:19\d{2}|20\d{2})(?:/(?:" + "|".join(MONTHS) + r"))?", suffix):
            links.add(url)
    combined = set(expected_pages()) | links
    return sorted(combined, key=_page_sort_key), response.text


def _page_sort_key(url: str):
    suffix = urlparse(url).path.split("/the-buzzer/")[-1]
    if suffix == "pre2010":
        return (0, 0)
    parts = suffix.split("/")
    try:
        year = int(parts[0])
    except Exception:
        return (9999, 99)
    return (year, MONTHS.get(parts[1], 0) if len(parts) > 1 else 0)


def clone_mirror(repository: str, destination: Path) -> list[dict]:
    subprocess.run(
        ["git", "clone", "--depth", "1", f"https://github.com/{repository}.git", str(destination)],
        check=True,
    )
    inventory = []
    for path in sorted((destination / "text_files").glob("*.htm")):
        text = path.read_text(encoding="utf-8", errors="replace")
        soup = BeautifulSoup(text, "lxml")
        title = clean_text(soup.title) if soup.title else ""
        year, month = infer_page_period(title, path.name)
        inventory.append({
            "path": path.relative_to(destination).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "title": title,
            "page_year": year,
            "page_month": month,
        })
    return inventory


def mirror_lookup(mirror_dir: Path, inventory: list[dict]) -> dict[tuple[int | None, int | None], Path]:
    candidates: dict[tuple[int | None, int | None], list[Path]] = {}
    for row in inventory:
        key = (row["page_year"], row["page_month"])
        candidates.setdefault(key, []).append(mirror_dir / row["path"])
    return {key: max(paths, key=lambda path: path.stat().st_size) for key, paths in candidates.items()}


def write_csv(records: list[dict], path: Path) -> None:
    pd.DataFrame(records).to_csv(path, index=False)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--mirror-repository", default="NatanaelAntonioli/UVB-76-Estudo")
    args = parser.parse_args()

    output = Path(args.output)
    if output.exists():
        shutil.rmtree(output)
    raw_dir = output / "raw_pages"
    data_dir = output / "data"
    raw_dir.mkdir(parents=True)
    data_dir.mkdir(parents=True)
    retrieved_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    mirror_dir = output.parent / "_uvb76_mirror_tmp"
    if mirror_dir.exists():
        shutil.rmtree(mirror_dir)
    mirror_inventory: list[dict] = []
    try:
        mirror_inventory = clone_mirror(args.mirror_repository, mirror_dir)
    except Exception as exc:
        mirror_inventory = [{"error": f"mirror clone failed: {type(exc).__name__}: {exc}"}]
    lookup = mirror_lookup(mirror_dir, mirror_inventory) if mirror_dir.exists() else {}
    write_csv(mirror_inventory, data_dir / "mirror_inventory.csv")

    session = make_session()
    index_error = ""
    try:
        pages, index_html = discover_live_pages(session)
        (raw_dir / "station_index.html").write_text(index_html, encoding="utf-8")
    except Exception as exc:
        pages = expected_pages()
        index_error = f"{type(exc).__name__}: {exc}"

    page_records: list[dict] = []
    transmissions: list[dict] = []
    blocks: list[dict] = []
    repeats: list[dict] = []
    issues: list[dict] = []

    for ordinal, url in enumerate(pages, start=1):
        year, month = infer_page_period("", url)
        source_kind = "Priyom live"
        status_code = None
        fetch_error = ""
        html = ""
        try:
            response = session.get(url, timeout=45)
            status_code = response.status_code
            response.raise_for_status()
            html = response.text
        except Exception as exc:
            fetch_error = f"{type(exc).__name__}: {exc}"
            fallback = lookup.get((year, month))
            if fallback and fallback.exists():
                html = fallback.read_text(encoding="utf-8", errors="replace")
                source_kind = f"GitHub mirror fallback: {args.mirror_repository}"
        if not html:
            page_records.append({
                "source_url": url, "source_kind": source_kind,
                "retrieved_at_utc": retrieved_at, "status_code": status_code,
                "fetch_error": fetch_error, "page_year": year, "page_month": month,
                "title": "", "html_sha256": "", "html_bytes": 0,
                "table_count": 0, "rows_parsed": 0, "blocks_parsed": 0,
                "active_dates": 0,
            })
            issues.append({
                "source_url": url, "table_index": "", "row_index": "",
                "issue_type": "page_unavailable", "detail": fetch_error,
                "raw_cells_json": "",
            })
            continue

        suffix = urlparse(url).path.split("/the-buzzer/")[-1].replace("/", "_")
        raw_path = raw_dir / f"{ordinal:03d}_{suffix}.html"
        raw_path.write_text(html, encoding="utf-8")
        page, tx_rows, block_rows, repeat_rows, issue_rows = parse_html_page(html, url, retrieved_at)
        page.update({
            "source_kind": source_kind,
            "status_code": status_code,
            "fetch_error": fetch_error,
            "raw_file": raw_path.relative_to(output).as_posix(),
        })
        for row in tx_rows:
            row["source_kind"] = source_kind
        page_records.append(page)
        transmissions.extend(tx_rows)
        blocks.extend(block_rows)
        repeats.extend(repeat_rows)
        issues.extend(issue_rows)
        time.sleep(0.05)

    if mirror_dir.exists():
        shutil.rmtree(mirror_dir)

    # Deterministic deduplication only on exact source-row identity. No transcription correction.
    tx_df = pd.DataFrame(transmissions)
    block_df = pd.DataFrame(blocks)
    repeat_df = pd.DataFrame(repeats)
    page_df = pd.DataFrame(page_records)
    issue_df = pd.DataFrame(issues)
    if not tx_df.empty:
        tx_df = tx_df.drop_duplicates(subset=["transmission_id"], keep="first")
        tx_df = tx_df.sort_values(["date", "time_local_text", "transmission_id"], kind="stable")
    if not block_df.empty:
        block_df = block_df.drop_duplicates(subset=["transmission_id", "block_order"], keep="first")
        block_df = block_df.sort_values(["date", "time_local_text", "transmission_id", "block_order"], kind="stable")
    if not repeat_df.empty:
        repeat_df = repeat_df.drop_duplicates()

    page_df.to_csv(data_dir / "pages.csv", index=False)
    tx_df.to_csv(data_dir / "transmissions.csv", index=False)
    block_df.to_csv(data_dir / "message_blocks.csv", index=False)
    repeat_df.to_csv(data_dir / "repeat_references.csv", index=False)
    issue_df.to_csv(data_dir / "parse_issues.csv", index=False)

    if not tx_df.empty:
        tx_df["year"] = pd.to_datetime(tx_df["date"]).dt.year
        tx_df["month"] = pd.to_datetime(tx_df["date"]).dt.month
        coverage = tx_df.groupby(["year", "month"], dropna=False).agg(
            transmissions=("transmission_id", "size"),
            active_dates=("date", "nunique"),
            parsed_blocks=("n_blocks", "sum"),
            pages=("source_url", "nunique"),
        ).reset_index()
        era_summary = tx_df.groupby("era", dropna=False).agg(
            first_date=("date", "min"), last_date=("date", "max"),
            transmissions=("transmission_id", "size"), active_dates=("date", "nunique"),
            pages=("source_url", "nunique"),
        ).reset_index()
    else:
        coverage = pd.DataFrame()
        era_summary = pd.DataFrame()
    coverage.to_csv(data_dir / "year_month_coverage.csv", index=False)
    era_summary.to_csv(data_dir / "era_summary.csv", index=False)

    summary = {
        "generated_at_utc": retrieved_at,
        "primary_source": BASE_URL,
        "mirror_fallback": args.mirror_repository,
        "station_index_fetch_error": index_error,
        "pages_targeted": len(pages),
        "pages_with_html": int((page_df.get("html_bytes", pd.Series(dtype=int)) > 0).sum()),
        "pages_live": int((page_df.get("source_kind", pd.Series(dtype=str)) == "Priyom live").sum()),
        "pages_mirror_fallback": int(page_df.get("source_kind", pd.Series(dtype=str)).astype(str).str.startswith("GitHub mirror").sum()),
        "pages_unavailable": int((page_df.get("html_bytes", pd.Series(dtype=int)) == 0).sum()),
        "transmissions": int(len(tx_df)),
        "message_blocks": int(len(block_df)),
        "repeat_references": int(len(repeat_df)),
        "parse_issues": int(len(issue_df)),
        "active_dates": int(tx_df["date"].nunique()) if not tx_df.empty else 0,
        "first_date": str(tx_df["date"].min()) if not tx_df.empty else "",
        "last_date": str(tx_df["date"].max()) if not tx_df.empty else "",
        "exact_payloads": int((block_df.get("payload_quality", pd.Series(dtype=str)) == "exact").sum()),
        "uncertain_payloads": int((block_df.get("payload_quality", pd.Series(dtype=str)) == "uncertain").sum()),
        "interpretive_boundary": "This is transcription and format parsing, not literal decryption.",
        "observation_boundary": "No log entry is not proof that no RF transmission occurred.",
    }
    (data_dir / "coverage_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    readme = f"""# UVB-76 public corpus\n\nGenerated {retrieved_at}.\n\nPrimary source: {BASE_URL}\nMirror fallback: https://github.com/{args.mirror_repository}\n\nPages targeted: {summary['pages_targeted']}\nPages with HTML: {summary['pages_with_html']}\nParsed transmissions: {summary['transmissions']}\nParsed message blocks: {summary['message_blocks']}\nParsed repeat references: {summary['repeat_references']}\nParse issues: {summary['parse_issues']}\n\nThe tables preserve raw fields and flag uncertain payloads. They do not claim\nliteral decryption. A missing log entry is not proof of no transmission.\n"""
    (output / "README.md").write_text(readme, encoding="utf-8")

    # Fail loudly if the build did not retrieve a meaningful corpus.
    assert summary["pages_with_html"] >= 100, summary
    assert summary["transmissions"] >= 500, summary
    assert summary["message_blocks"] >= 500, summary
    assert tx_df["transmission_id"].is_unique

    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
