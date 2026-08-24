import sys

from .cli import main

if __name__ == "__main__":
    # refreshed upstream datasets contain non-latin site names; legacy Windows
    # consoles default to cp1251 and would crash on report rendering
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - best effort console fix
            pass
    raise SystemExit(main())
