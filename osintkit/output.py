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


def _sig(module: str, f) -> str:
    return f"{module}|{f.kind}|{f.value}"


def load_previous_signatures(target: str, outdir: str = "out") -> set[str]:
    """Signatures of findings from the last stored report for this target."""
    import json
    safe = "".join(c if c.isalnum() or c in "@._-" else "_" for c in target)[:60]
    path = pathlib.Path(outdir) / f"report_{safe}.json"
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {f"{r['module']}|{fd['kind']}|{fd['value']}"
                for r in data.get("results", []) for fd in r.get("findings", [])}
    except Exception:
        return set()


def annotate_new(target: str, results: list[ModuleResult], outdir: str = "out") -> int:
    """Mark findings absent from the previous report with extra['new']=True.
    Must be called BEFORE save_report overwrites the previous report."""
    prev = load_previous_signatures(target, outdir)
    n_new = 0
    for res in results:
        for f in res.findings:
            if _sig(res.module, f) not in prev:
                f.extra["new"] = True
                n_new += 1
    return n_new
