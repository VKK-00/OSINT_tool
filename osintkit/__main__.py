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

    modules = {m.name: m for m in get_all()}

    scan = sub.add_parser("scan", help="Run one or more modules against a target")
    scan.add_argument("target", nargs="?", default="",
                      help="Target (username, phone, email, domain, URL or coords)")
    scan.add_argument("-m", "--modules", default="all",
                      help="Comma-separated module names or 'all'")
    scan.add_argument("--list-modules", action="store_true", help="List modules and exit")
    scan.add_argument("-o", "--out", default="out", help="Report output directory")
    scan.add_argument("--no-save", action="store_true", help="Do not write JSON report")
    scan.add_argument("-v", "--verbose", action="store_true")

    variants = sub.add_parser("variants", help="Show transliteration variants of a handle")
    variants.add_argument("handle")

    imp = sub.add_parser("leaks-import",
                         help="Index local leak dataset file/dir into out/index.db")
    imp.add_argument("path")

    san = sub.add_parser("sanctions-update",
                         help="Download OpenSanctions simplecsv and build search index")
    san.add_argument("--url", default=None, help="Custom CSV URL")
    san.add_argument("--file", default=None, help="Build from a local CSV instead")

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
    total = sum(len(r.findings) for r in results)
    failed = [r.module for r in results if not r.ok]
    console.print(f"[bold]\n{total} finding(s)[/]" +
                  (f", [bold green]{n_new} NEW[/]" if n_new else "") +
                  (f"  [yellow]module errors: {', '.join(failed)}[/]" if failed else ""))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
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
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
