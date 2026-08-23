"""Web UI backend for osintkit (FastAPI).

Run:  osintkit-web            (serves http://127.0.0.1:8765)
or    python -m osintkit.webapp
"""
from __future__ import annotations

import asyncio
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
        try:
            import json
            outdir = pathlib.Path("out")
            outdir.mkdir(exist_ok=True)
            safe = "".join(c if c.isalnum() or c in "@._-" else "_" for c in target)[:60]
            path = outdir / f"report_{safe}.json"
            generated = __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc).isoformat()
            path.write_text(json.dumps(
                {"target": target, "generated": generated,
                 "results": job["results"]},
                ensure_ascii=False, indent=2), encoding="utf-8")
            from osintkit.report_html import render_html_report
            render_html_report(target, job["results"], generated=generated)
        except Exception:
            pass


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


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


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
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="warning")


if __name__ == "__main__":
    main()
