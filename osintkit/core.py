from __future__ import annotations

import asyncio
import dataclasses
import random
import time
from typing import Any

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]


@dataclasses.dataclass
class Finding:
    """A single piece of evidence produced by a module."""
    kind: str            # e.g. "profile", "phone", "domain", "archive", "geo"
    source: str          # module name
    value: str           # the main payload (URL, number, description...)
    confidence: str = "medium"   # low | medium | high
    url: str = ""
    extra: dict[str, Any] = dataclasses.field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class ModuleResult:
    module: str
    target: str
    ok: bool = True
    error: str = ""
    findings: list[Finding] = dataclasses.field(default_factory=list)
    elapsed_s: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "target": self.target,
            "ok": self.ok,
            "error": self.error,
            "elapsed_s": round(self.elapsed_s, 2),
            "findings": [f.as_dict() for f in self.findings],
        }


class HttpClient:
    """Thin async HTTP layer: UA rotation, timeouts, polite rate limiting."""

    def __init__(self, timeout: float = 15.0, rps: float = 4.0):
        import httpx
        self._httpx = httpx
        self._client = httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(timeout),
        )
        self._min_interval = 1.0 / max(rps, 0.1)
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def _throttle(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self._last + self._min_interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()

    def headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        h = {"User-Agent": random.choice(USER_AGENTS)}
        if extra:
            h.update(extra)
        return h

    async def get_text(self, url: str, *, headers: dict | None = None) -> str:
        await self._throttle()
        r = await self._client.get(url, headers=self.headers(headers))
        r.raise_for_status()
        return r.text

    async def get_json(self, url: str, *, headers: dict | None = None):
        import json
        return json.loads(await self.get_text(url, headers=headers))

    async def head_or_get_status(self, url: str, retries: int = 1,
                                 max_chars: int = 20000) -> tuple[int, str]:
        """Return (status_code, first_bytes_of_body). Never raises.
        One retry on transient failures (connection errors, 429, 5xx)."""
        last_status, body = -1, ""
        for attempt in range(retries + 1):
            await self._throttle()
            try:
                r = await self._client.get(url, headers=self.headers())
                if r.status_code in (429, 500, 502, 503, 504) and attempt < retries:
                    await asyncio.sleep(1.5 * (attempt + 1))
                    continue
                return r.status_code, r.text[:max_chars]
            except Exception:
                last_status, body = -1, ""
                if attempt < retries:
                    await asyncio.sleep(1.5 * (attempt + 1))
            break
        return last_status, body

    async def aclose(self) -> None:
        await self._client.aclose()


_LAT2CYR = {
    "a": "а", "b": "б", "c": "с", "d": "д", "e": "е", "f": "ф", "g": "г",
    "h": "г", "i": "і", "j": "й", "k": "к", "l": "л", "m": "м", "n": "н",
    "o": "о", "p": "р", "r": "р", "s": "с", "t": "т", "u": "у", "v": "в",
    "x": "х", "y": "у", "z": "з",
}
_CYR2LAT = {
    "а": "a", "б": "b", "в": "v", "г": "h", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "y", "ій": "ii", "і": "i", "ї": "yi", "й": "y",
    "к": "k", "л": "l", "м": "m", "н": "n", "о": "o", "п": "p", "р": "r",
    "с": "s", "т": "t", "у": "u", "ф": "f", "х": "kh", "ц": "ts", "ч": "ch",
    "ш": "sh", "щ": "shch", "ы": "y", "э": "e", "ю": "yu", "я": "ya", "ь": "",
}


def _apply(word: str, table: dict[str, str]) -> str:
    out, i = [], 0
    low = word.lower()
    while i < len(low):
        two = low[i:i+2]
        if two in table:
            out.append(table[two]); i += 2; continue
        ch = low[i]
        if ch in table:
            out.append(table[ch])
        else:
            out.append(word[i])
        i += 1
    return "".join(out)


def transliterate(text: str) -> list[str]:
    """Generate latin<->cyrillic variants of a handle — important for UA/RF targets."""
    results = {text, _apply(text, _CYR2LAT), _apply(text, _LAT2CYR)}
    # second pass: latinized form re-mapped to cyrillic
    lat_form = _apply(text, _CYR2LAT)
    results.add(_apply(lat_form, _LAT2CYR))
    return sorted(r for r in results if r)[:12]
