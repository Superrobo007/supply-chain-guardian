"""Supply Chain Guardian — orchestrator CLI.

  python -m guardian.cli day1     --target targets/juice-shop [--base-lock old.json] [--investigate 8]
  python -m guardian.cli plan     --top 5                    # Day 2: remediation plans (pending approval)
  python -m guardian.cli approve  F-011 --by alice           # human-in-the-loop gate
  python -m guardian.cli validate F-011 [--run-tests]        # sandbox apply -> re-resolve -> rescan -> diff
  python -m guardian.cli report                              # JSON + Markdown + HTML
  python -m guardian.cli monitor                             # continuous: re-check SBOM for new advisories
  python -m guardian.cli verify-ledger
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from networkx.readwrite import json_graph

from . import agents, policy, registry, report, semver
from .detect import detect, lockfile_diff, lockfile_diff_findings
from .discover import discover
from .ledger import Ledger
from .risk import score_findings
from .sbom import to_cyclonedx
from .validate import validate as run_validation

OUT = Path("out")


def _state_path(out: Path) -> Path:
    return out / "state.json"


def load(out: Path) -> dict:
    return json.loads(_state_path(out).read_text(encoding="utf-8"))


def save(out: Path, state: dict) -> None:
    _state_path(out).write_text(json.dumps(state, indent=1, default=str), encoding="utf-8")


def _log(msg: str) -> None:
    print(f"[guardian] {msg}", flush=True)


def _policy(state: dict) -> dict:
    inp = {"findings": state["findings"], "plans": state.get("plans", [])}
    return policy.evaluate(inp)


def resolve_target(t: str) -> Path:
    """Accept a local folder or a git URL (cloned read-only into ./targets/<name>)."""
    import re
    import subprocess
    if re.match(r"^(https?://|git@)", t):
        name = re.sub(r"\.git$", "", t.rstrip("/").rsplit("/", 1)[-1])
        dest = Path("targets") / name
        if not dest.exists():
            _log(f"cloning {t} -> {dest}")
            subprocess.run(["git", "clone", "--depth", "1", t, str(dest)], check=True)
        return dest.resolve()
    p = Path(t).resolve()
    if not p.is_dir():
        raise SystemExit(f"target not found: {t}")
    return p


def prepare_lockfiles(target: Path) -> None:
    """Generate missing package-lock.json files WITHOUT executing any package code (--ignore-scripts)."""
    import shutil
    import subprocess
    npm = shutil.which("npm")
    skip = {"node_modules", ".git", "dist", "build", "test", "tests", "fixtures", "examples", "vendor"}
    manifests = [m for m in target.rglob("package.json")
                 if not any(s in m.relative_to(target).parts for s in skip)][:20]
    for m in manifests:
        if (m.parent / "package-lock.json").exists() or (m.parent / "yarn.lock").exists() or \
                (m.parent / "pnpm-lock.yaml").exists():
            continue
        if not npm:
            _log("npm not found: cannot generate lockfiles (install Node.js)")
            return
        base = [npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]
        rel = m.parent.relative_to(target).as_posix() or "."
        r = subprocess.run(base, cwd=m.parent, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if r.returncode != 0:
            r = subprocess.run(base + ["--legacy-peer-deps"], cwd=m.parent, capture_output=True, text=True,
                               encoding="utf-8", errors="replace")
        _log(f"  lockfile for {rel}: {'generated' if r.returncode == 0 else 'FAILED (' + r.stderr.strip()[-120:] + ')'}")


def cmd_day1(a) -> None:
    out, target = Path(a.out), resolve_target(a.target)
    if a.prepare:
        _log("PREPARE: generating missing lockfiles (no install scripts run)")
        prepare_lockfiles(target)
    out.mkdir(parents=True, exist_ok=True)
    ledger = Ledger(out / "ledger.jsonl")
    _log(f"DISCOVER {target}")
    inv = discover(target, ledger)
    G = inv["graph"]
    pkgs = [d for _, d in G.nodes(data=True) if d["kind"] == "package"]
    sbom = to_cyclonedx(G, target.name, inv["containers"], inv["workflows"])
    (out / "sbom.cdx.json").write_text(json.dumps(sbom, indent=1), encoding="utf-8")
    (out / "graph.json").write_text(json.dumps(json_graph.node_link_data(G, edges="links"), default=str), encoding="utf-8")
    _log(f"  {len(pkgs)} packages, {sum(1 for d in pkgs if d.get('direct'))} direct, "
         f"{len(inv['containers'])} Dockerfiles, {len(inv['workflows'])} workflows -> sbom.cdx.json")
    _log("DETECT vulnerabilities + supply-chain anomalies")
    findings = detect(inv, ledger)
    if a.base_lock:
        head_lock = target / (a.lock_rel or "package-lock.json")
        changes = lockfile_diff(json.loads(Path(a.base_lock).read_text(encoding="utf-8")), json.loads(head_lock.read_text(encoding="utf-8")))
        (out / "lockfile_diff.json").write_text(json.dumps(changes, indent=1), encoding="utf-8")
        _log(f"  lockfile diff vs {a.base_lock}: {len(changes)} changes")
        lockfile_diff_findings(changes, ledger, findings, f"diff {a.base_lock} -> {head_lock}")
    _log("ANALYZE: reachability + explainable risk score")
    findings = score_findings(findings, inv, ledger)
    ai_mode = agents.backend_label()
    _log(f"INVESTIGATE top {a.investigate} with agents ({ai_mode}) -> skeptic verification")
    tb = agents.Toolbox(inv, findings, ledger)
    # investigate the highest-risk finding of each type first (diverse coverage), then by score
    seen, queue = set(), []
    for f in findings:
        if f["type"] not in seen:
            queue.append(f)
            seen.add(f["type"])
    queue = sorted(queue, key=lambda f: -f["risk_score"])
    queue += [f for f in findings if f not in queue]
    for f in queue[:a.investigate]:
        asmt = agents.skeptic(agents.investigate(f, tb), ledger)
        f["assessment"] = asmt
        ledger.add("assessment", f"agent:investigator/{f['id']}", asmt, actor=f"ai:{asmt.get('mode')}")
        _log(f"  {f['id']} {f['type']:<20} -> {asmt['verdict']} ({asmt['verified_claims']} verified, "
             f"{asmt['inferred_claims']} inferred)")
    state = {"target": str(target), "ai_mode": ai_mode, "findings": findings, "plans": [], "validations": [],
             "inventory": {"app": target.name, "components": len(pkgs),
                           "direct": sum(1 for d in pkgs if d.get("direct")),
                           "projects": inv["projects"],
                           "images": [i["ref"] for c in inv["containers"] for i in c["base_images"]],
                           "workflows": len(inv["workflows"]),
                           "actions": sum(len(w["actions"]) for w in inv["workflows"])},
             "sbom_file": str(out / "sbom.cdx.json")}
    state["policy"] = _policy(state)
    save(out, state)
    report.build(state, out, ledger.verify()[1])
    _log(f"Build gate: {'PASS' if state['policy']['build_allowed'] else 'BLOCKED'} "
         f"({len(state['policy']['deny'])} deny, {len(state['policy']['warn'])} warn, engine={state['policy']['engine']})")
    _log(f"Day 1 done -> {out}/report.md, report.html, report.json, sbom.cdx.json, ledger.jsonl")


def cmd_plan(a) -> None:
    out = Path(a.out)
    state, ledger = load(out), Ledger(out / "ledger.jsonl")
    chosen = [f for f in state["findings"] if f["type"] != "install_script"
              or (f.get("assessment") or {}).get("verdict") != "likely_benign"]
    if a.ids:
        chosen = [f for f in state["findings"] if f["id"] in a.ids]
    existing = {p["finding_id"] for p in state["plans"]}
    for f in chosen[:a.top]:
        if f["id"] in existing:
            continue
        r = agents.remediate(f, f.get("assessment") or {})
        eid = ledger.add("remediation_plan", f"agent:remediator/{f['id']}", r, actor=f"ai:{r['mode']}")
        state["plans"].append({"finding_id": f["id"], "remediation": r, "approval": None, "evidence_id": eid})
        _log(f"{f['id']} {f['title'][:60]} -> {r['action']} {r['target']} [{r['mode']}] (awaiting approval)")
    state["policy"] = _policy(state)
    save(out, state)


def cmd_approve(a) -> None:
    out = Path(a.out)
    state, ledger = load(out), Ledger(out / "ledger.jsonl")
    for p in state["plans"]:
        if p["finding_id"] == a.id:
            if a.target:
                if a.target not in {c["target"] for c in p["remediation"]["candidates"]}:
                    raise SystemExit("target must be one of the plan's candidates")
                p["remediation"]["target"] = a.target
                p["remediation"]["action"] = next(c["action"] for c in p["remediation"]["candidates"]
                                                  if c["target"] == a.target)
            p["approval"] = {"approved": True, "by": f"human:{a.by}", "at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                             "note": a.note}
            p["approval"]["evidence_id"] = ledger.add("approval", "cli", {"finding": a.id, **p["approval"],
                                                      "target": p["remediation"]["target"]}, actor=f"human:{a.by}")
            state["policy"] = _policy(state)
            save(out, state)
            _log(f"approved {a.id} -> {p['remediation']['target']} by {a.by} (ledger {p['approval']['evidence_id']})")
            return
    raise SystemExit(f"no plan for {a.id}; run `plan` first")


def cmd_validate(a) -> None:
    out = Path(a.out)
    state, ledger = load(out), Ledger(out / "ledger.jsonl")
    pol = _policy(state)
    if a.id not in pol["remediation_allowed"]:
        raise SystemExit(f"policy gate: {a.id} is not approved by a human (or target not in candidate set). "
                         f"Run: python -m guardian.cli approve {a.id} --by <name>")
    plan = next(p for p in state["plans"] if p["finding_id"] == a.id)
    finding = next(f for f in state["findings"] if f["id"] == a.id)
    before_sbom = json.loads(Path(state["sbom_file"]).read_text(encoding="utf-8"))
    _log(f"VALIDATE {a.id}: sandbox apply '{plan['remediation']['target']}' -> re-resolve -> rescan -> diff")
    v = run_validation(plan, finding, Path(state["target"]), out, ledger, state["findings"], before_sbom, a.run_tests)
    (out / "prs").mkdir(exist_ok=True)
    (out / "prs" / f"{a.id}.patch").write_text(v["patch"], encoding="utf-8")
    (out / "prs" / f"{a.id}.md").write_text(pr_body(finding, plan, v), encoding="utf-8")
    state["validations"] = [x for x in state["validations"] if x["finding_id"] != a.id] + [v]
    save(out, state)
    _log(f"  status={v['status']} target_resolved={v['target_finding_resolved']} new={len(v['new_findings'])} "
         f"risk {v['risk_before']} -> {v['risk_after']}")
    if v.get("api_probe"):
        _log(f"  API probe: {v['api_probe'].get('verdict', v['api_probe'].get('error'))}")
    _log(f"  PR-ready (NOT pushed/merged): {out}/prs/{a.id}.patch + .md")


def pr_body(f: dict, plan: dict, v: dict) -> str:
    r = plan["remediation"]
    return "\n".join([
        f"## Guardian remediation: {f['title']}", "",
        f"**Action:** {r['action']} → `{r['target']}`  ", f"**Approved by:** {plan['approval']['by']}  ",
        f"**Validation:** {v['status']}", "", "### Why", r["rationale"], "",
        "### Evidence", *[f"- {e}" for e in f["evidence"][:8]], "",
        "### Changes", *[f"- {c}" for c in v["changes"]], f"- lockfile: {v['lockfile_diffstat'] or 'unchanged'}", "",
        "### Validation results",
        f"- Dependency resolution: {'ok' if v['resolution_ok'] else 'FAILED'}",
        f"- Target finding resolved on rescan: {v['target_finding_resolved']}",
        f"- Findings resolved: {len(v['resolved_findings'])}; newly introduced: {len(v['new_findings'])}",
        f"- Total risk score: {v['risk_before']} → {v['risk_after']}",
        f"- API compatibility probe: {(v.get('api_probe') or {}).get('verdict', 'n/a')}",
        f"- Unit/integration tests: {'run' if v.get('tests') else 'not run in sandbox (run `npm ci && npm test` in CI)'}",
        "", "### Compatibility impact", r["compatibility_impact"], "", "### Rollback", r["rollback"], "",
        "_Generated by Supply Chain Guardian. Must be reviewed and merged by a human._"])


def cmd_report(a) -> None:
    out = Path(a.out)
    state, ledger = load(out), Ledger(out / "ledger.jsonl")
    state["policy"] = _policy(state)
    save(out, state)
    report.build(state, out, ledger.verify()[1])
    _log(f"report -> {out}/report.md, report.html, report.json")


def cmd_monitor(a) -> None:
    """Re-check every SBOM component against the advisory DB; report advisories not seen before."""
    out = Path(a.out)
    state, ledger = load(out), Ledger(out / "ledger.jsonl")
    sbom = json.loads(Path(state["sbom_file"]).read_text(encoding="utf-8"))
    q = {}
    for c in sbom["components"]:
        if c["type"] == "library" and c.get("version"):
            q.setdefault(c["name"], []).append(c["version"])
    import os
    os.environ["GUARDIAN_NO_CACHE"] = "1"
    advs = registry.bulk_advisories(q)
    known = {adv["id"] for f in state["findings"] for adv in f.get("advisories", [])}
    new = []
    for name, al in advs.items():
        for adv in al:
            gid = adv["url"].rsplit("/", 1)[-1]
            if gid not in known and any(semver.satisfies(v, adv["vulnerable_versions"]) for v in q[name]):
                new.append({"package": name, "advisory": gid, "title": adv["title"], "severity": adv["severity"]})
    eid = ledger.add("monitor", "bulk-advisory-recheck", {"checked": len(q), "new": new})
    _log(f"monitor: {len(q)} packages re-checked, {len(new)} new advisories (ledger {eid})")
    for n in new:
        _log(f"  NEW {n['severity']}: {n['package']} {n['advisory']} {n['title']}")


def cmd_dashboard(a) -> None:
    try:
        from .server import serve
    except ImportError:
        raise SystemExit("Dashboard needs fastapi + uvicorn:  pip install fastapi uvicorn  (or: uv pip install fastapi uvicorn)")
    serve(a.host, a.port, not a.no_browser)


def cmd_verify(a) -> None:
    ok, msg = Ledger(Path(a.out) / "ledger.jsonl").verify()
    _log(("OK " if ok else "TAMPERED ") + msg)


def main() -> None:
    import sys
    for stream in (sys.stdout, sys.stderr):      # Windows consoles default to cp1252
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    p = argparse.ArgumentParser(prog="guardian")
    p.add_argument("--out", default=str(OUT))
    sp = p.add_subparsers(dest="cmd", required=True)
    d1 = sp.add_parser("day1")
    d1.add_argument("--target", required=True)
    d1.add_argument("--base-lock", help="previous package-lock.json to diff against ('what changed?')")
    d1.add_argument("--lock-rel", help="lockfile path inside target for the diff (default package-lock.json)")
    d1.add_argument("--investigate", type=int, default=8)
    d1.add_argument("--prepare", action="store_true", help="generate missing npm lockfiles first (scripts disabled)")
    d1.set_defaults(fn=cmd_day1)
    pl = sp.add_parser("plan")
    pl.add_argument("--top", type=int, default=6)
    pl.add_argument("--ids", nargs="*")
    pl.set_defaults(fn=cmd_plan)
    ap = sp.add_parser("approve")
    ap.add_argument("id")
    ap.add_argument("--by", required=True)
    ap.add_argument("--target", help="choose a different candidate target")
    ap.add_argument("--note", default="")
    ap.set_defaults(fn=cmd_approve)
    va = sp.add_parser("validate")
    va.add_argument("id")
    va.add_argument("--run-tests", action="store_true")
    va.set_defaults(fn=cmd_validate)
    sp.add_parser("report").set_defaults(fn=cmd_report)
    sp.add_parser("monitor").set_defaults(fn=cmd_monitor)
    sp.add_parser("verify-ledger").set_defaults(fn=cmd_verify)
    db = sp.add_parser("dashboard", help="open the web dashboard")
    db.add_argument("--port", type=int, default=8765)
    db.add_argument("--host", default="127.0.0.1")
    db.add_argument("--no-browser", action="store_true")
    db.set_defaults(fn=cmd_dashboard)
    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
