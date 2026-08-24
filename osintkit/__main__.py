from __future__ import annotations

import argparse
import asyncio
import sys

from rich.console import Console

from osintkit import __version__
from osintkit.core import HttpClient
from osintkit.modules.base import get_all
from osintkit.output import print_results, save_report

console = Console()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osintkit",
        description="Modular OSINT toolkit focused on UA/RF research targets.",
    )
    p.add_argument("-V", "--version", action="version", version=f"osintkit {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    # import side-effects register all modules
    get_all()

    scan = sub.add_parser("scan", help="Run one or more modules against a target")
    scan.add_argument("target", nargs="?", default="",
                      help="Target (username, phone, email, domain, URL or coords)")
    scan.add_argument("-m", "--modules", default="all",
                      help="Comma-separated module names or 'all'")
    scan.add_argument("--list-modules", action="store_true", help="List modules and exit")
    scan.add_argument("-o", "--out", default="out", help="Report output directory")
    scan.add_argument("--no-save", action="store_true", help="Do not write JSON report")
    scan.add_argument("-v", "--verbose", action="store_true")
    scan.add_argument("--csv", action="store_true",
                      help="Also export findings to CSV")

    variants = sub.add_parser("variants", help="Show transliteration variants of a handle")
    variants.add_argument("handle")

    imp = sub.add_parser("leaks-import",
                         help="Index local leak dataset file/dir into out/index.db")
    imp.add_argument("path")

    san = sub.add_parser("sanctions-update",
                         help="Download OpenSanctions simplecsv and build search index")
    san.add_argument("--url", default=None, help="Custom CSV URL")
    san.add_argument("--file", default=None, help="Build from a local CSV instead")

    rep = sub.add_parser("report",
                         help="Regenerate HTML report from an existing JSON report")
    rep.add_argument("json_path")

    return p


async def cmd_scan(args) -> int:
    all_modules = {m.name: m for m in get_all()}
    if args.list_modules:
        for name, m in all_modules.items():
            console.print(f"[cyan]{name:<10}[/] — {m.help}  [dim]{m.target_hint}[/]")
        return 0

    if args.modules == "all":
        chosen = list(all_modules.values())
    else:
        names = [n.strip() for n in args.modules.split(",")]
        bad = [n for n in names if n not in all_modules]
        if bad:
            console.print(f"[red]Unknown modules:[/] {', '.join(bad)}. "
                          f"Available: {', '.join(sorted(all_modules))}")
            return 2
        chosen = [all_modules[n] for n in names]

    http = HttpClient()
    try:
        results = []
        with console.status(f"Scanning '{args.target}' across {len(chosen)} module(s)..."):
            results = await asyncio.gather(*(m.safe_run(args.target, http) for m in chosen))
        results = list(results)
    finally:
        await http.aclose()

    n_new = 0
    try:
        from osintkit.output import annotate_new
        n_new = annotate_new(args.target, results, args.out)
    except Exception:
        pass

    print_results(results, verbose=args.verbose)
    if not args.no_save:
        path = save_report(args.target, results, args.out)
        console.print(f"\n[bold green]Report saved →[/] {path}")
        try:
            import json

            from osintkit.report_html import render_html_report
            data = json.loads(open(path, encoding="utf-8").read())
            html_path = render_html_report(
                args.target, data["results"],
                generated=data.get("generated", ""), outdir=args.out)
            console.print(f"[bold green]HTML report →[/] {html_path}")
        except Exception as exc:
            console.print(f"[yellow]HTML report failed: {exc}[/]")
        if args.csv:
            try:
                import csv as csv_mod
                import pathlib
                csv_path = pathlib.Path(args.out) / (
                    "report_" + "".join(
                        c if c.isalnum() or c in "@._-" else "_"
                        for c in args.target)[:60] + ".csv")
                with open(csv_path, "w", encoding="utf-8-sig", newline="") as fh:
                    wtr = csv_mod.writer(fh, delimiter=";")
                    wtr.writerow(["module", "kind", "value", "confidence",
                                  "url", "new"])
                    for res in results:
                        for f in res.findings:
                            wtr.writerow([res.module, f.kind, f.value,
                                          f.confidence, f.url,
                                          bool(f.extra.get("new"))])
                console.print(f"[bold green]CSV export →[/] {csv_path}")
            except Exception as exc:
                console.print(f"[yellow]CSV failed: {exc}[/]")
    total = sum(len(r.findings) for r in results)
    failed = [r.module for r in results if not r.ok]
    console.print(f"[bold]\n{total} finding(s)[/]" +
                  (f", [bold green]{n_new} NEW[/]" if n_new else "") +
                  (f"  [yellow]module errors: {', '.join(failed)}[/]" if failed else ""))
    return 0


def main(argv: list[str] | None = None) -> int:
    # Windows legacy consoles default to cp1251 — our findings are Unicode
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    if not os.environ.get("OSINTKIT_HIDE_DEPRECATION"):
        console.print(
            "[yellow]note:[/] osintkit CLI is in maintenance mode - new "
            "capabilities land in the unified engine: [bold]python -m osint_toolkit[/] "
            "(set OSINTKIT_HIDE_DEPRECATION=1 to silence)"
        )
    if args.command == "scan":
        return asyncio.run(cmd_scan(args))
    if args.command == "variants":
        from osintkit.core import transliterate
        console.print(", ".join(transliterate(args.handle)))
        return 0
    if args.command == "leaks-import":
        from osintkit import store
        with console.status(f"Indexing {args.path} ..."):
            stats = store.import_leaks(args.path)
        console.print(f"[green]Indexed[/] {stats['files']} file(s), "
                      f"{stats['rows']} rows, {stats['tokens_indexed']} tokens")
        return 0
    if args.command == "sanctions-update":
        from osintkit import store
        with console.status("Building sanctions index (this can take a while)..."):
            stats = store.update_sanctions(url=args.url or store.SANCTIONS_CSV_URL,
                                           local_file=args.file)
        console.print(f"[green]Sanctions index ready:[/] {stats['indexed']} entities")
        return 0
    if args.command == "report":
        import json
        import pathlib

        from osintkit.report_html import render_html_report
        src = pathlib.Path(args.json_path)
        if not src.exists():
            console.print(f"[red]No such report:[/] {src}")
            return 2
        data = json.loads(src.read_text(encoding="utf-8"))
        outdir = str(src.parent)
        html_path = render_html_report(data.get("target", "?"),
                                       data.get("results", []),
                                       generated=data.get("generated", ""),
                                       outdir=outdir)
        console.print(f"[green]HTML report →[/] {html_path}")
        return 0
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
