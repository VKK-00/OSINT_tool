"""Shared latin<->cyrillic transliteration variants for handles/names.

Single implementation used by both osint_toolkit modules and the osintkit
compatibility layer (osintkit.core.transliterate re-exports this).
"""
from __future__ import annotations

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
    out: list[str] = []
    i = 0
    low = word.lower()
    while i < len(low):
        two = low[i : i + 2]
        if two in table:
            out.append(table[two])
            i += 2
            continue
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
