"""Guardian Dashboard backend (FastAPI).

Serves the React dashboard (guardian/web, prebuilt) and a JSON API over the Guardian's run folders
(out/, out-tampered/, out-*/). Actions (scan, plan, approve, validate) run the same CLI commands as the
terminal, in background jobs whose logs stream to the UI. Binds to 127.0.0.1 only.

    python -m guardian.cli dashboard            # http://127.0.0.1:8765
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import networkx as nx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from networkx.readwrite import json_graph
from pydantic import BaseModel

from .ledger import Ledger

ROOT = Path.cwd()                       # project folder (where out*/ live)
WEB = Path(__file__).resolve().parent / "web"
RUN_RE = re.compile(r"^out[\w.-]*$")
ID_RE = re.compile(r"^F-\d{3,}$")

app = FastAPI(title="Supply Chain Guardian", docs_url="/api/docs", openapi_url="/api/openapi.json")
JOBS: dict[str, dict] = {}


# ------------------------------------------------------------------ helpers
def run_dir(run: str) -> Path:
    if not RUN_RE.match(run):
        raise HTTPException(400, "invalid run name")
    d = ROOT / run
    if not (d / "state.json").exists():
        raise HTTPException(404, f"no Guardian run in {run}/ (run a scan first)")
    return d


def load_state(run: str) -> dict:
    return json.loads((run_dir(run) / "state.json").read_text(encoding="utf-8"))


def start_job(kind: str, args: list[str], run: str | None) -> dict:
    jid = uuid.uuid4().hex[:10]
    job = {"id": jid, "kind": kind, "run": run, "args": args, "status": "running", "log": [],
           "started": time.time(), "ended": None, "exit": None}
    JOBS[jid] = job

    def worker():
        try:
            p = subprocess.Popen([sys.executable, "-m", "guardian.cli", *args], cwd=ROOT,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                 encoding="utf-8", errors="replace", env={**__import__("os").environ,
                                                                         "PYTHONUNBUFFERED": "1"})
            for line in p.stdout:
                job["log"].append(line.rstrip("\n"))
            job["exit"] = p.wait()
            job["status"] = "done" if job["exit"] == 0 else "failed"
        except Exception as e:  # pragma: no cover
            job["log"].append(f"error: {e}")
            job["status"] = "failed"
        job["ended"] = time.time()

    threading.Thread(target=worker, daemon=True).start()
    return job


# ------------------------------------------------------------------ read API
@app.get("/api/runs")
def runs():
    out = []
    for d in sorted(ROOT.glob("out*")):
        sf = d / "state.json"
        if d.is_dir() and RUN_RE.match(d.name) and sf.exists():
            s = json.loads(sf.read_text(encoding="utf-8"))
            f = s.get("findings", [])
            out.append({"run": d.name, "app": s["inventory"]["app"], "target": s.get("target"),
                        "ai_mode": s.get("ai_mode"), "findings": len(f),
                        "critical": sum(x["priority"] == "Critical" for x in f),
                        "high": sum(x["priority"] == "High" for x in f),
                        "build_allowed": s.get("policy", {}).get("build_allowed"),
                        "updated": sf.stat().st_mtime})
    out.sort(key=lambda r: -r["updated"])
    return out


@app.get("/api/runs/{run}/state")
def state(run: str):
    s = load_state(run)
    ok, msg = Ledger(run_dir(run) / "ledger.jsonl").verify()
    s["ledger_status"] = {"ok": ok, "message": msg}
    for v in s.get("validations", []):
        v.pop("resolution", None)
    return s


@app.get("/api/runs/{run}/evidence")
def evidence(run: str, ids: str):
    led = Ledger(run_dir(run) / "ledger.jsonl")
    return {i: led.get(i) for i in ids.split(",")[:40] if re.match(r"^E-\d+$", i)}


@app.get("/api/runs/{run}/ledger")
def ledger_tail(run: str, limit: int = 80):
    led = Ledger(run_dir(run) / "ledger.jsonl")
    recs = list(led.records.values())
    kinds: dict[str, int] = {}
    for r in recs:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    tail = [{k: r[k] for k in ("id", "ts", "kind", "source", "actor", "hash")} for r in recs[-limit:]][::-1]
    ok, msg = led.verify()
    return {"total": len(recs), "kinds": kinds, "records": tail, "ok": ok, "message": msg}


@app.get("/api/runs/{run}/riskmap")
def riskmap(run: str, max_nodes: int = 160):
    """Union of root->package paths for every finding tied to a package: the app's 'attack surface map'."""
    d = run_dir(run)
    s = json.loads((d / "state.json").read_text(encoding="utf-8"))
    G = json_graph.node_link_graph(json.loads((d / "graph.json").read_text(encoding="utf-8")), edges="links")
    sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    flagged: dict[str, dict] = {}
    for f in s["findings"]:
        for n in f.get("nodes") or []:
            cur = flagged.get(n)
            if cur is None or sev_rank[f["priority"]] > sev_rank[cur["priority"]]:
                flagged[n] = {"priority": f["priority"], "finding": f["id"], "type": f["type"]}
    keep, edges = set(), set()
    for n in sorted(flagged, key=lambda x: -sev_rank[flagged[x]["priority"]]):
        if n not in G:
            continue
        proj = G.nodes[n].get("project", ".")
        root = (f"py:{proj}::<root>" if G.nodes[n].get("ecosystem") == "pypi" else f"{proj}::<root>")
        try:
            path = nx.shortest_path(G, root, n)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue
        if len(keep | set(path)) > max_nodes:
            break
        keep |= set(path)
        edges |= set(zip(path, path[1:]))
    nodes = []
    for n in keep:
        a = G.nodes[n]
        nodes.append({"id": n, "name": a.get("name"), "version": a.get("version"), "kind": a.get("kind"),
                      "project": a.get("project"), "direct": bool(a.get("direct")), "dev": bool(a.get("dev")),
                      **({"flag": flagged[n]} if n in flagged else {})})
    return {"nodes": nodes, "edges": [{"source": u, "target": v} for u, v in edges],
            "total_packages": sum(1 for _, a in G.nodes(data=True) if a.get("kind") == "package")}


@app.get("/api/runs/{run}/patch/{fid}")
def patch(run: str, fid: str):
    if not ID_RE.match(fid):
        raise HTTPException(400, "bad id")
    d = run_dir(run) / "prs"
    p, md = d / f"{fid}.patch", d / f"{fid}.md"
    if not md.exists():
        raise HTTPException(404, "not validated yet")
    return {"patch": p.read_text(encoding="utf-8") if p.exists() else "", "pr": md.read_text(encoding="utf-8")}


@app.get("/api/runs/{run}/download/{name}")
def download(run: str, name: str):
    allowed = {"sbom.cdx.json", "report.json", "report.md", "report.html", "ledger.jsonl"}
    if name not in allowed:
        raise HTTPException(400, "not downloadable")
    return FileResponse(run_dir(run) / name, filename=f"{run}-{name}")


# ------------------------------------------------------------------ actions
class ScanReq(BaseModel):
    target: str
    out: str = "out"
    prepare: bool = False
    investigate: int = 8


class PlanReq(BaseModel):
    ids: list[str]


class ApproveReq(BaseModel):
    id: str
    by: str
    target: str | None = None
    note: str = ""


class ValidateReq(BaseModel):
    id: str
    run_tests: bool = False


@app.post("/api/scan")
def scan(req: ScanReq):
    if not RUN_RE.match(req.out):
        raise HTTPException(400, "output name must start with 'out' (e.g. out-myrepo)")
    args = ["--out", req.out, "day1", "--target", req.target, "--investigate", str(max(0, min(req.investigate, 30)))]
    if req.prepare:
        args.append("--prepare")
    return start_job("scan", args, req.out)


@app.post("/api/runs/{run}/plan")
def plan(run: str, req: PlanReq):
    run_dir(run)
    ids = [i for i in req.ids if ID_RE.match(i)]
    if not ids:
        raise HTTPException(400, "no valid finding ids")
    return start_job("plan", ["--out", run, "plan", "--ids", *ids, "--top", str(len(ids))], run)


@app.post("/api/runs/{run}/approve")
def approve(run: str, req: ApproveReq):
    run_dir(run)
    name = req.by.strip()
    if not ID_RE.match(req.id) or not re.match(r"^[\w .@'-]{2,60}$", name):
        raise HTTPException(400, "enter your name (2-60 characters) to approve")
    args = ["--out", run, "approve", req.id, "--by", name]
    if req.target:
        args += ["--target", req.target]
    if req.note:
        args += ["--note", req.note[:200]]
    r = subprocess.run([sys.executable, "-m", "guardian.cli", *args], cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise HTTPException(400, (r.stderr or r.stdout).strip()[-300:])
    return {"ok": True, "message": r.stdout.strip()}


@app.post("/api/runs/{run}/validate")
def validate(run: str, req: ValidateReq):
    run_dir(run)
    if not ID_RE.match(req.id):
        raise HTTPException(400, "bad id")
    args = ["--out", run, "validate", req.id] + (["--run-tests"] if req.run_tests else [])
    return start_job("validate", args, run)


@app.post("/api/runs/{run}/report")
def rebuild_report(run: str):
    run_dir(run)
    return start_job("report", ["--out", run, "report"], run)


@app.get("/api/jobs/{jid}")
def job(jid: str):
    j = JOBS.get(jid)
    if not j:
        raise HTTPException(404, "unknown job")
    return j


@app.get("/api/jobs")
def jobs():
    return sorted(({k: v for k, v in j.items() if k != "log"} for j in JOBS.values()), key=lambda j: -j["started"])


@app.get("/api/health")
def health():
    from . import agents
    return {"ok": True, "brain": agents.backend_label(), "root": str(ROOT)}


# ------------------------------------------------------------------ static frontend
if (WEB / "index.html").exists():
    app.mount("/assets", StaticFiles(directory=WEB / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        f = WEB / path
        if path and f.is_file() and WEB in f.resolve().parents:
            return FileResponse(f)
        return FileResponse(WEB / "index.html")
else:
    @app.get("/", include_in_schema=False)
    def no_ui():
        return PlainTextResponse("Dashboard UI not built. Run: cd dashboard && npm install && npm run build")


def serve(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    import uvicorn
    url = f"http://{host}:{port}"
    print(f"[guardian] dashboard on {url}  (Ctrl+C to stop)")
    if open_browser:
        threading.Timer(1.2, lambda: __import__("webbrowser").open(url)).start()
    uvicorn.run(app, host=host, port=port, log_level="warning")
