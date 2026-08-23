"""Web UI backend for osintkit (FastAPI).

Run:  osintkit-web            (serves http://127.0.0.1:8765)
or    python -m osintkit.webapp
"""
from __future__ import annotations

import asyncio
import json
import os
import pathlib
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from osintkit import __version__
from osintkit.core import HttpClient
from osintkit.modules.base import get_all

app = FastAPI(title="osintkit", version=__version__)
STATIC = pathlib.Path(__file__).parent / "static"


def _web_token() -> str:
    """Optional shared token. Set OSINTKIT_WEBAPP_TOKEN (or pass --token)
    to protect /api/* endpoints; leave empty for local-only open access."""
    return os.environ.get("OSINTKIT_WEBAPP_TOKEN", "")


@app.middleware("http")
async def token_guard(request, call_next):
    expected = _web_token()
    if expected and request.url.path.startswith("/api/"):
        provided = (
            request.headers.get("x-osintkit-token")
            or request.query_params.get("token")
            or ""
        )
        if provided != expected:
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return await call_next(request)

# in-memory scan jobs
JOBS: dict[str, dict] = {}


class ScanRequest(BaseModel):
    target: str
    modules: list[str] | None = None   # None => all


@app.get("/api/meta")
async def meta() -> dict:
    modules = [
        {"name": m.name, "help": m.help, "hint": m.target_hint}
        for m in get_all()
    ]
    return {"version": __version__, "modules": modules}


@app.post("/api/scan")
async def start_scan(req: ScanRequest) -> dict:
    req.target = req.target.strip()
    if not req.target:
        raise HTTPException(400, "empty target")
    all_modules = {m.name: m for m in get_all()}
    names = req.modules or list(all_modules)
    unknown = [n for n in names if n not in all_modules]
    if unknown:
        raise HTTPException(400, f"unknown modules: {', '.join(unknown)}")

    job_id = uuid.uuid4().hex[:12]
    JOBS[job_id] = {"status": "running", "target": req.target,
                    "modules": names, "results": []}
    asyncio.create_task(_run_job(job_id, [all_modules[n] for n in names], req.target))
    return {"job_id": job_id}


async def _run_job(job_id: str, modules, target: str) -> None:
    from osintkit.output import annotate_new
    job = JOBS[job_id]
    collected = []
    http = HttpClient()
    try:
        tasks = [asyncio.create_task(m.safe_run(target, http)) for m in modules]
        for coro in asyncio.as_completed(tasks):
            res = await coro
            collected.append(res)
            job["results"].append(res.as_dict())
    finally:
        await http.aclose()
        job["status"] = "done"
        try:
            n_new = annotate_new(target, collected)
        except Exception:
            n_new = 0
        if n_new:
            job["new_count"] = n_new
            job["results"] = [r.as_dict() for r in collected]
        _save_report_files(target, job["results"])
        save_case_from_results(target, collected)


def _save_report_files(target: str, results: list[dict]) -> None:
    try:
        outdir = pathlib.Path("out")
        outdir.mkdir(exist_ok=True)
        safe = "".join(c if c.isalnum() or c in "@._-" else "_" for c in target)[:60]
        path = outdir / f"report_{safe}.json"
        generated = __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat()
        path.write_text(json.dumps(
            {"target": target, "generated": generated,
             "results": results},
            ensure_ascii=False, indent=2), encoding="utf-8")
        from osintkit.report_html import render_html_report
        render_html_report(target, results, generated=generated)
    except Exception:
        pass


def case_db_path() -> pathlib.Path:
    """Shared SQLite case DB (same store the unified CLI writes to)."""
    outdir = pathlib.Path("out")
    outdir.mkdir(exist_ok=True)
    return outdir / "cases.sqlite"


def save_case_from_results(target: str, results: list) -> str | None:
    """Persist a finished scan into the shared osint_toolkit case store.

    Best-effort: a failing case write must never break the scan job itself.
    """
    try:
        from datetime import datetime, timezone

        from osint_toolkit.case_store import CaseStore
        from osint_toolkit.engine import Finding as EngineFinding
        from osint_toolkit.engine import ScanTarget
        from osint_toolkit.entities import (
            entities_from_findings,
            entities_from_targets,
            merge_entities,
        )
        from osint_toolkit.graph import graph_edges_from_case
        from osint_toolkit.investigation import InvestigationResult
        from osintkit.bridge import classify_target, core_to_engine

        engine_findings: list[EngineFinding] = []
        for result in results:
            engine_findings.extend(
                core_to_engine(finding, target=target)
                for finding in result.findings
            )
        targets = (ScanTarget(kind=classify_target(target), value=target),)
        findings = tuple(engine_findings)
        entities = merge_entities(
            entities_from_targets(targets),
            entities_from_findings(findings),
        )
        edges = graph_edges_from_case(targets, findings, entities)
        generated_at = datetime.now(timezone.utc).isoformat()
        case = InvestigationResult(
            title=f"osintkit scan: {target}",
            targets=targets,
            findings=findings,
            adapter_findings=(),
            entities=entities,
            edges=edges,
            generated_at=generated_at,
        )
        case_id = f"osintkit-{uuid.uuid4().hex[:12]}"
        CaseStore(case_db_path()).save(
            case,
            case_id=case_id,
            metadata={
                "source": "osintkit-webapp",
                "workflow": "scan",
                "modules": ",".join(sorted({r.module for r in results})),
            },
        )
        return case_id
    except Exception:
        return None


@app.get("/api/job/{job_id}")
async def job_status(job_id: str) -> dict:
    if job_id not in JOBS:
        raise HTTPException(404, "no such job")
    j = JOBS[job_id]
    return {k: j[k] for k in ("status", "target", "modules", "results")}


@app.get("/api/history")
async def history() -> dict:
    out = []
    reports = sorted(pathlib.Path("out").glob("report_*.json"),
                     key=lambda p: p.stat().st_mtime, reverse=True)
    for p in reports[:30]:
        out.append({"file": p.name, "mtime": int(p.stat().st_mtime)})
    return {"reports": out}


@app.get("/api/report/{name}")
async def get_report(name: str) -> dict:
    if "/" in name or "\\" in name or ".." in name:
        raise HTTPException(400, "bad name")
    p = pathlib.Path("out") / name
    if not p.exists():
        raise HTTPException(404, "not found")
    import json
    return json.loads(p.read_text(encoding="utf-8"))


@app.get("/api/cases")
async def cases_list() -> dict:
    """Saved cases from the shared osint_toolkit case store."""
    from osint_toolkit.case_store import CaseStore

    store = CaseStore(case_db_path())
    summaries = store.list_cases(limit=50)
    return {"cases": [s.to_dict() for s in summaries]}


@app.get("/api/cases/{case_id}")
async def case_detail(case_id: str) -> dict:
    from osint_toolkit.case_store import CaseStore, CaseStoreError

    store = CaseStore(case_db_path())
    try:
        return store.load_case(case_id)
    except CaseStoreError as exc:
        raise HTTPException(404, "no such case") from exc


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


# --------------------------------------------------------------- watches ----

WATCHES: dict[str, dict] = {}
_watch_seq = 0
WATCH_FILE = pathlib.Path("out") / "watches.json"


def persist_watches() -> None:
    try:
        WATCH_FILE.parent.mkdir(exist_ok=True)
        WATCH_FILE.write_text(json.dumps(
            {wid: {k: w[k] for k in ("target", "modules", "interval_min")}
             for wid, w in WATCHES.items()}, ensure_ascii=False),
            encoding="utf-8")
    except Exception:
        pass


def restore_watches() -> None:
    global _watch_seq
    try:
        import json as _json
        data = _json.loads(WATCH_FILE.read_text(encoding="utf-8"))
    except Exception:
        return
    for wid, cfg in data.items():
        WATCHES[wid] = {"id": wid, "target": cfg["target"],
                        "modules": cfg["modules"],
                        "interval_min": cfg["interval_min"],
                        "status": "restored", "last_run": "",
                        "findings": 0, "new": 0, "error": ""}
        try:
            _watch_seq = max(_watch_seq, int(wid.lstrip("w")))
        except ValueError:
            pass
        asyncio.create_task(_watch_loop(wid))


@app.on_event("startup")
async def _startup() -> None:
    restore_watches()


class WatchRequest(BaseModel):
    target: str
    modules: list[str] | None = None
    interval_min: int = 10


@app.post("/api/watch")
async def add_watch(req: WatchRequest) -> dict:
    global _watch_seq
    req.target = req.target.strip()
    if not req.target:
        raise HTTPException(400, "empty target")
    if len(WATCHES) >= 10:
        raise HTTPException(400, "max 10 concurrent watches")
    all_modules = {m.name: m for m in get_all()}
    names = req.modules or list(all_modules)
    unknown = [n for n in names if n not in all_modules]
    if unknown:
        raise HTTPException(400, f"unknown modules: {', '.join(unknown)}")
    if not (1 <= req.interval_min <= 1440):
        raise HTTPException(400, "interval must be 1..1440 minutes")
    _watch_seq += 1
    wid = f"w{_watch_seq}"
    WATCHES[wid] = {"id": wid, "target": req.target, "modules": names,
                    "interval_min": req.interval_min, "status": "starting",
                    "last_run": "", "findings": 0, "new": 0, "error": ""}
    persist_watches()
    asyncio.create_task(_watch_loop(wid))
    return {"watch_id": wid}


async def _watch_loop(wid: str) -> None:
    """Re-scan the target on an interval; diff each run against the last."""
    import datetime

    from osintkit.output import annotate_new
    while wid in WATCHES:
        w = WATCHES[wid]
        all_modules = {m.name: m for m in get_all()}
        mods = [all_modules[n] for n in w["modules"] if n in all_modules]
        collected = []
        http = HttpClient()
        try:
            tasks = [asyncio.create_task(m.safe_run(w["target"], http))
                     for m in mods]
            for coro in asyncio.as_completed(tasks):
                collected.append(await coro)
        except Exception as exc:  # noqa: BLE001
            w["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            await http.aclose()
        try:
            n_new = annotate_new(w["target"], collected)
        except Exception:
            n_new = 0
        w.update(status="ok",
                 findings=sum(len(r.findings) for r in collected),
                 new=n_new,
                 last_run=datetime.datetime.now(
                     datetime.timezone.utc).strftime("%H:%M:%S UTC"),
                 error=w.get("error", ""))
        for _ in range(max(1, int(w["interval_min"] * 12))):
            if wid not in WATCHES:
                return
            await asyncio.sleep(5)


@app.get("/api/watches")
async def list_watches() -> dict:
    keys = ("id", "target", "modules", "interval_min", "status",
            "last_run", "findings", "new", "error")
    return {"watches": [{k: w[k] for k in keys} for w in WATCHES.values()]}


@app.delete("/api/watch/{wid}")
async def del_watch(wid: str) -> dict:
    WATCHES.pop(wid, None)
    persist_watches()
    return {"deleted": True}


# ------------------------------------------------------------ admin ops ----

ADMIN: dict[str, str] = {"state": "idle", "message": ""}


async def _admin_task(fn, *args) -> None:
    ADMIN.update(state="running", message="")
    try:
        stats = await asyncio.to_thread(fn, *args)
        ADMIN.update(state="done", message=str(stats))
    except Exception as exc:  # noqa: BLE001
        ADMIN.update(state="error", message=f"{type(exc).__name__}: {exc}")


@app.post("/api/admin/leaks")
async def admin_leaks(body: dict) -> dict:
    path = (body or {}).get("path", "").strip()
    if not path:
        raise HTTPException(400, "path required")
    from osintkit import store
    asyncio.create_task(_admin_task(store.import_leaks, path))
    return {"started": True}


@app.post("/api/admin/sanctions")
async def admin_sanctions(body: dict | None = None) -> dict:
    from osintkit import store
    file_path = ((body or {}).get("file") or "").strip() or None
    asyncio.create_task(_admin_task(store.update_sanctions, store.SANCTIONS_CSV_URL, file_path))
    return {"started": True}


@app.get("/api/admin/status")
async def admin_status() -> dict:
    return dict(ADMIN)


def main() -> None:
    import argparse

    import uvicorn
    parser = argparse.ArgumentParser(description="osintkit web UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--token",
        default=os.environ.get("OSINTKIT_WEBAPP_TOKEN", ""),
        help="Protect /api/* with a shared token",
    )
    args = parser.parse_args()
    if args.token:
        os.environ["OSINTKIT_WEBAPP_TOKEN"] = args.token
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
