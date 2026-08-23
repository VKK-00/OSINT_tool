from __future__ import annotations

import json
import pathlib
from typing import Any

from rich.console import Console
from rich.table import Table

from osintkit.core import ModuleResult

console = Console()


def print_results(results: list[ModuleResult], verbose: bool = False) -> None:
    for res in results:
        style = "green" if res.ok else "red"
        console.print(f"\n[bold {style}]■ module:[/] {res.module} "
                      f"[dim]({res.elapsed_s:.1f}s)"
                      + (f" ERROR: {res.error}" if not res.ok else "") + "[/]")
        if not res.findings:
            console.print("  [dim]no findings[/]")
            continue
        table = Table(box=None, pad_edge=False, show_header=True)
        table.add_column("kind", style="cyan", max_width=14)
        table.add_column("finding", max_width=90)
        table.add_column("conf.", max_width=8)
        for f in res.findings:
            conf_color = {"high": "green", "medium": "yellow", "low": "dim"}.get(f.confidence, "white")
            table.add_row(f.kind, f.value, f"[{conf_color}]{f.confidence}[/]")
        console.print(table)


def save_report(target: str, results: list[ModuleResult], outdir: str = "out") -> str:
    out = pathlib.Path(outdir)
    out.mkdir(exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "@._-" else "_" for c in target)[:60]
    path = out / f"report_{safe}.json"
    payload: dict[str, Any] = {
        "target": target,
        "generated": _utcnow(),
        "results": [r.as_dict() for r in results],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(path)


def _utcnow() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()
