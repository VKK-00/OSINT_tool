"""Standalone HTML report generator: findings + interactive link graph.

The output file is fully self-contained (no CDN, no JS libs) and can be
shared as-is — useful when attaching reports to investigation notes.
"""
from __future__ import annotations

import html
import json
import pathlib

from osintkit.core import ModuleResult  # noqa: F401 (typing only)

_CONF_COLOR = {"high": "#3fb950", "medium": "#d29922", "low": "#8b949e"}

_TEMPLATE = r"""<!DOCTYPE html>
<html lang="uk"><head><meta charset="utf-8">
<title>osintkit report</title>
<style>
  :root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--text:#e6edf3;
        --dim:#8b949e;--accent:#2f81f7}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:"Segoe UI",system-ui,sans-serif;
       font-size:14px;padding:28px 36px;max-width:1200px;margin:0 auto}
  h1{font-size:20px}.meta{color:var(--dim);font-size:12.5px;margin:6px 0 22px}
  .stats{display:flex;gap:14px;margin-bottom:22px;flex-wrap:wrap}
  .stat{background:var(--panel);border:1px solid var(--border);border-radius:8px;
        padding:10px 18px}.stat b{display:block;font-size:22px}
  .card{background:var(--panel);border:1px solid var(--border);
        border-radius:10px;padding:14px 16px;margin-bottom:14px}
  .card h3{font-size:14px;margin-bottom:8px}
  .f{display:flex;gap:10px;padding:6px 0;border-top:1px solid #21262d;align-items:baseline}
  .kind{font-family:Consolas,monospace;font-size:11px;color:var(--accent);min-width:84px}
  .val{flex:1;white-space:pre-wrap;word-break:break-word;font-size:13px}
  .conf{font-size:10.5px;border-radius:9px;padding:1px 8px}
  .new{background:var(--accent);color:#fff;font-size:10px;font-weight:700;
       border-radius:8px;padding:1px 7px}
  #graph{width:100%;height:520px;background:var(--panel);border:1px solid var(--border);
         border-radius:10px;margin-bottom:24px;cursor:grab;display:block}
  .legend{color:var(--dim);font-size:12px;margin-bottom:24px}
  .legend i{display:inline-block;width:10px;height:10px;border-radius:50%;margin:0 5px 0 16px}
</style></head><body>
<h1>osintkit report</h1>
<div class="meta">target: <b>__TARGET__</b> &middot; generated: __GENERATED__ &middot; new findings: __NEWCOUNT__</div>
<div class="stats">
  <div class="stat"><b>__NFIND__</b>findings</div>
  <div class="stat"><b>__NMODS__</b>modules run</div>
  <div class="stat"><b>__NHIGH__</b>high confidence</div>
</div>
<canvas id="graph"></canvas>
<div class="legend">
  <i style="background:#e6edf3"></i>target
  <i style="background:#2f81f7"></i>module
  <i style="background:#d29922"></i>entity
</div>
<div id="cards">__CARDS__</div>
<script>
const DATA = __DATA__;
const cv = document.getElementById('graph'), ctx = cv.getContext('2d');
let W, H;
function resize(){ W = cv.width = cv.offsetWidth; H = cv.height = 520; }
resize(); addEventListener('resize', resize);
const nodes = DATA.nodes.map(function(n){
  return Object.assign({}, n,
    { x: W/2 + (Math.random()-.5)*300, y: H/2 + (Math.random()-.5)*260,
      vx: 0, vy: 0, drag: false,
      r: n.type === 'target' ? 26 : n.type === 'module' ? 15 : 9 });
});
const idx = {};
DATA.nodes.forEach(function(n,i){ idx[n.id] = i; });
const links = DATA.links.map(function(l){
  return { s: idx[l.source], t: idx[l.target] };
}).filter(function(l){ return l.s !== undefined && l.t !== undefined && l.s !== l.t; });
function step(){
  for (let i = 0; i < nodes.length; i++)
    for (let j = i+1; j < nodes.length; j++){
      const a = nodes[i], b = nodes[j];
      let dx = b.x - a.x, dy = b.y - a.y;
      let d2 = dx*dx + dy*dy || 1, d = Math.sqrt(d2);
      if (d > 340) continue;
      const f = 2200 / d2; dx /= d; dy /= d;
      a.vx -= dx*f; a.vy -= dy*f; b.vx += dx*f; b.vy += dy*f;
    }
  for (const l of links){
    const a = nodes[l.s], b = nodes[l.t];
    let dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx*dx + dy*dy) || 1;
    const want = (a.type === 'target' || b.type === 'target') ? 130 : 90;
    const f = (d - want) * 0.004; dx /= d; dy /= d;
    a.vx += dx*f*d*0.06; a.vy += dy*f*d*0.06;
    b.vx -= dx*f*d*0.06; b.vy -= dy*f*d*0.06;
  }
  for (const n of nodes){
    n.vx *= .85; n.vy *= .85;
    if (!n.drag){ n.x += n.vx; n.y += n.vy; }
    n.x = Math.max(n.r, Math.min(W-n.r, n.x));
    n.y = Math.max(n.r, Math.min(H-n.r, n.y));
  }
}
const COL = { target:'#e6edf3', module:'#2f81f7', entity:'#d29922' };
function draw(){
  ctx.clearRect(0,0,W,H);
  ctx.strokeStyle = '#30363d';
  for (const l of links){
    ctx.beginPath(); ctx.moveTo(nodes[l.s].x, nodes[l.s].y);
    ctx.lineTo(nodes[l.t].x, nodes[l.t].y); ctx.stroke();
  }
  for (const n of nodes){
    ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, 7);
    ctx.fillStyle = COL[n.type] || '#888'; ctx.fill();
    if (n.r >= 15){
      ctx.fillStyle = '#0d1117';
      ctx.font = 'bold ' + Math.max(9, n.r*.55) + 'px sans-serif';
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.fillText(n.label.slice(0, n.r > 20 ? 12 : 6), n.x, n.y);
    } else {
      ctx.fillStyle = '#8b949e'; ctx.font = '10px sans-serif';
      ctx.textAlign = 'center'; ctx.fillText(n.label.slice(0,22), n.x, n.y - n.r - 5);
    }
  }
}
let drag = null;
cv.addEventListener('mousedown', function(e){
  const b = cv.getBoundingClientRect();
  const mx = e.clientX - b.left, my = e.clientY - b.top;
  drag = nodes.find(function(n){ return (mx-n.x)*(mx-n.x)+(my-n.y)*(my-n.y) < n.r*n.r + 40; }) || null;
  if (drag) drag.drag = true;
});
cv.addEventListener('mousemove', function(e){
  if (!drag) return;
  const b = cv.getBoundingClientRect();
  drag.x = e.clientX - b.left; drag.y = e.clientY - b.top;
});
addEventListener('mouseup', function(){ if (drag) drag.drag = false; drag = null; });
(function loop(){ step(); draw(); requestAnimationFrame(loop); })();
</script></body></html>"""


def _extract_entities(results: list[dict], cap: int = 36) -> list[dict]:
    """Pick the most valuable findings to show as graph entities."""
    prio = ("profile", "channel", "sanctions", "exposure", "identity",
            "subdomains", "whois", "phone")
    ents: list[dict] = []
    seen: set[str] = set()
    for res in sorted(results, key=lambda r: r["module"]):
        for f in res.get("findings", []):
            if len(ents) >= cap:
                return ents
            if f["kind"] not in prio:
                continue
            label = f["value"].splitlines()[0][:60]
            eid = f"{res['module']}|{label}"
            if eid in seen or not label:
                continue
            seen.add(eid)
            ents.append({"id": eid, "label": label, "type": "entity"})
    return ents


def render_html_report(target: str, results_dicts: list[dict],
                       generated: str = "", outdir: str = "out") -> str:
    safe = "".join(c if c.isalnum() or c in "@._-" else "_" for c in target)[:60]
    path = pathlib.Path(outdir) / f"report_{safe}.html"

    cards: list[str] = []
    n_find = n_high = n_new = 0
    for res in sorted(results_dicts, key=lambda r: r["module"]):
        fs = res.get("findings") or []
        n_find += len(fs)
        n_high += sum(1 for f in fs if f.get("confidence") == "high")
        rows = []
        for f in fs:
            val = html.escape(f["value"])
            if f.get("url"):
                u = html.escape(f["url"])
                val += (f'<br><a style="color:var(--accent)" href="{u}" '
                        f'target="_blank" rel="noopener">{u[:90]}</a>')
            badge = ('<span class="new">NEW</span>'
                     if (f.get("extra") or {}).get("new") else "")
            color = _CONF_COLOR.get(f.get("confidence"), "#8b949e")
            rows.append(
                '<div class="f"><span class="kind">' + html.escape(f["kind"]) +
                '</span><span class="val">' + val + '</span>' + badge +
                '<span class="conf" style="color:' + color +
                ';border:1px solid ' + color + '">' +
                html.escape(f.get("confidence", "")) + '</span></div>')
            if (f.get("extra") or {}).get("new"):
                n_new += 1
        err = ""
        if not res.get("ok"):
            err = ('<div style="color:#f85149;font-size:12px">&#9888; '
                   + html.escape(res.get("error", "")) + '</div>')
        empty = ('<div style="color:var(--dim);font-size:12px">&mdash; nothing found</div>'
                 if not fs else "")
        cards.append(
            '<div class="card"><h3>' + html.escape(res["module"]) +
            ' <span style="float:right;color:var(--dim);font-weight:400;font-size:12px">'
            + str(len(fs)) + ' findings &middot; ' + str(res.get("elapsed_s", 0)) +
            's</span></h3>' + err + empty + "".join(rows) + '</div>')

    nodes = [{"id": "__target__", "label": target[:24], "type": "target"}]
    links: list[dict[str, str]] = []
    ents = _extract_entities(results_dicts)
    for res_d in results_dicts:
        mod = res_d["module"]
        nodes.append({"id": f"m|{mod}", "label": mod, "type": "module"})
        links.append({"source": "__target__", "target": f"m|{mod}"})
        for e in ents:
            if e["id"].split("|", 1)[0] == mod:
                if all(n["id"] != e["id"] for n in nodes):
                    nodes.append(e)
                links.append({"source": f"m|{mod}", "target": e["id"]})

    doc = (_TEMPLATE
           .replace("__TARGET__", html.escape(target))
           .replace("__GENERATED__", html.escape(generated))
           .replace("__NEWCOUNT__", str(n_new))
           .replace("__NFIND__", str(n_find))
           .replace("__NMODS__", str(len(results_dicts)))
           .replace("__NHIGH__", str(n_high))
           .replace("__CARDS__", "".join(cards))
           .replace("__DATA__", json.dumps({"nodes": nodes, "links": links},
                                           ensure_ascii=False)))
    path.parent.mkdir(exist_ok=True)
    path.write_text(doc, encoding="utf-8")
    return str(path)
