from pathlib import Path

print("--- runtime import block ---")
c = Path("osint_toolkit/runtime.py").read_text(encoding="utf-8")
i = c.index("from .modules.person_sources import")
print(c[i : i + 240])

print("--- safe block ---")
s = Path("osint_toolkit/search.py").read_text(encoding="utf-8")
i = s.index('name="safe",')
print(s[i : i + 800])
