"""Stage 5 — VALIDATE: apply an APPROVED remediation in an isolated sandbox copy, rebuild the dependency
resolution, rescan, diff SBOMs/findings, probe API compatibility, and emit a PR-ready patch (never merged)."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from .detect import detect
from .discover import discover
from .ledger import Ledger
from .risk import score_findings
from .sbom import diff as sbom_diff, to_cyclonedx

IGNORE = shutil.ignore_patterns("node_modules", ".git", "dist", ".angular", "build", "coverage")


def _run(cmd: list[str], cwd: Path, timeout: int = 600) -> dict:
    exe = shutil.which(cmd[0]) or cmd[0]          # Windows: npm -> npm.cmd, node -> node.exe
    r = subprocess.run([exe, *cmd[1:]], cwd=cwd, capture_output=True, text=True, timeout=timeout,
                       encoding="utf-8", errors="replace")
    return {"cmd": " ".join(cmd), "exit": r.returncode, "tail": (r.stdout + r.stderr)[-1500:]}


def _force_rmtree(path: Path) -> None:
    """rmtree that also works on Windows, where git marks object files read-only."""
    import os
    import stat
    def onerror(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    if path.exists():
        shutil.rmtree(path, onerror=onerror)


def make_sandbox(src: Path, dest: Path) -> Path:
    _force_rmtree(dest)
    shutil.copytree(src, dest, ignore=IGNORE)
    for cmd in (["git", "init", "-q", "-b", "main"], ["git", "add", "-A"],
                ["git", "-c", "user.name=guardian", "-c", "user.email=guardian@localhost", "commit", "-qm", "baseline"]):
        subprocess.run(cmd, cwd=dest, capture_output=True)
    subprocess.run(["git", "checkout", "-q", "-b", f"guardian/fix"], cwd=dest, capture_output=True)
    return dest


def apply_change(sb: Path, finding: dict, target: str) -> list[str]:
    """Edit manifests/Dockerfiles in the sandbox. Returns human-readable change notes."""
    notes = []
    proj_dir = sb / (finding.get("project") or ".")
    if finding.get("ecosystem") == "pypi" and "@" in target and not target.startswith(("parent:", "mitigate:")):
        return _apply_pypi(sb, finding, target)
    pkg_file = proj_dir / "package.json"
    if target.startswith("overrides:"):
        name, ver = target[len("overrides:"):].rsplit("@", 1)
        pkg = json.loads(pkg_file.read_text(encoding="utf-8"))
        pkg.setdefault("overrides", {})[name] = ver
        pkg_file.write_text(json.dumps(pkg, indent=2) + "\n", encoding="utf-8")
        notes.append(f"{pkg_file.relative_to(sb).as_posix()}: overrides.{name} = {ver}")
    elif "->" in target:                                  # replace look-alike with the legitimate package
        bad, good = target.split("->")
        pkg = json.loads(pkg_file.read_text(encoding="utf-8"))
        from .registry import packument
        good_ver = packument(good).get("dist-tags", {}).get("latest")
        for sect in ("dependencies", "devDependencies"):
            if bad in pkg.get(sect, {}):
                pkg[sect].pop(bad)
                pkg[sect][good] = f"^{good_ver}"
                pkg[sect] = dict(sorted(pkg[sect].items()))
        pkg_file.write_text(json.dumps(pkg, indent=2) + "\n", encoding="utf-8")
        notes.append(f"{pkg_file.relative_to(sb).as_posix()}: removed {bad}, added {good}@^{good_ver}")
        for f in proj_dir.rglob("*.ts"):
            if "node_modules" in f.parts:
                continue
            t = f.read_text(errors="ignore", encoding="utf-8")
            if f"'{bad}'" in t or f'"{bad}"' in t:
                f.write_text(t.replace(f"'{bad}'", f"'{good}'").replace(f'"{bad}"', f'"{good}"'), encoding="utf-8")
                notes.append(f"{f.relative_to(sb).as_posix()}: import '{bad}' -> '{good}'")
    elif target.startswith("exact:") and finding["type"] == "unpinned_build_tool":
        spec = target[len("exact:"):]
        name = spec.rsplit("@", 1)[0] if spec.count("@") > (1 if spec.startswith("@") else 0) else spec
        from .registry import packument
        latest = packument(name).get("dist-tags", {}).get("latest")
        df = sb / finding["file"]
        t = df.read_text(encoding="utf-8")
        t = re.sub(r"ARG CYCLONEDX_NPM_VERSION=.*", f"ARG CYCLONEDX_NPM_VERSION='{latest}'", t) \
            if "$CYCLONEDX" in spec else t.replace(spec, f"{name}@{latest}")
        df.write_text(t, encoding="utf-8")
        notes.append(f"{finding['file']}: {spec} -> {name}@{latest}")
    elif "@" in target and not target.startswith(("digest:", "parent:", "mitigate:", "block:")):
        name, ver = target.rsplit("@", 1)
        pkg = json.loads(pkg_file.read_text(encoding="utf-8"))
        for sect in ("dependencies", "devDependencies"):
            if name in pkg.get(sect, {}):
                old = pkg[sect][name]
                pkg[sect][name] = ver            # exact pin: reproducible + reviewable
                notes.append(f"{pkg_file.relative_to(sb).as_posix()}: {sect}.{name} {old} -> {ver}")
        pkg_file.write_text(json.dumps(pkg, indent=2) + "\n", encoding="utf-8")
    else:
        notes.append(f"action '{target}' is a process/config change; no automated edit (documented in PR body)")
    return notes


def _apply_pypi(sb: Path, finding: dict, target: str) -> list[str]:
    """Rewrite `name==old` -> `name==new` in requirements files (or add a constraint for transitive deps)."""
    import re as _re
    from .eco_pypi import norm
    name, ver = target.replace("overrides:", "").rsplit("@", 1)
    notes = []
    req_files = sorted(p for p in sb.rglob("requirements*.txt") if ".git" not in p.parts)
    for rf in req_files:
        lines = rf.read_text(encoding="utf-8").splitlines()
        changed = False
        for i, line in enumerate(lines):
            m = _re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(==|>=|~=)?\s*([^;#\s]*)(.*)$", line)
            if m and norm(m.group(1)) == norm(name):
                lines[i] = f"{m.group(1)}{m.group(2) or ''}=={ver}{m.group(5)}"
                notes.append(f"{rf.relative_to(sb).as_posix()}: {line.strip()} -> {lines[i].strip()}")
                changed = True
        if changed:
            rf.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if not notes and req_files:   # transitive: add an explicit floor so the resolver can't pick the bad version
        rf = req_files[0]
        rf.write_text(rf.read_text(encoding="utf-8").rstrip("\n") + f"\n{name}>={ver}  # guardian: security floor\n",
                      encoding="utf-8")
        notes.append(f"{rf.relative_to(sb).as_posix()}: added {name}>={ver}")
    for lock in ("poetry.lock", "uv.lock", "Pipfile.lock"):
        if list(sb.rglob(lock)):
            notes.append(f"{lock} present: run `poetry update {name}` / `uv lock --upgrade-package {name}` / "
                         f"`pipenv update {name}` to refresh it")
    return notes


def api_probe(pkg: str, old: str, new: str, used: list[str], workdir: Path) -> dict:
    """Install old & new versions side by side (scripts disabled) and compare exported API surface."""
    out = {}
    for tag, ver in (("old", old), ("new", new)):
        d = workdir / f"probe-{tag}"
        d.mkdir(parents=True, exist_ok=True)
        (d / "package.json").write_text('{"name":"probe","version":"1.0.0"}', encoding="utf-8")
        r = _run(["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", f"{pkg}@{ver}"], d, 300)
        if r["exit"] != 0:
            return {"error": f"install {pkg}@{ver} failed", "detail": r["tail"][-300:]}
        js = (f"try{{const m=require('{pkg}');const k=new Set(Object.keys(m));"
              f"if(typeof m==='function')k.add('<callable>');"
              f"if(m&&m.default)Object.keys(m.default).forEach(x=>k.add(x));console.log(JSON.stringify([...k]))}}"
              f"catch(e){{console.log(JSON.stringify({{error:String(e).slice(0,200)}}))}}")
        r = _run(["node", "-e", js], d, 60)
        try:
            out[tag] = json.loads(r["tail"].strip().splitlines()[-1])
        except Exception:
            out[tag] = {"error": r["tail"][-200:]}
    if isinstance(out.get("old"), dict) or isinstance(out.get("new"), dict):
        return {"error": "could not load module", "old": out.get("old"), "new": out.get("new")}
    old_k, new_k = set(out["old"]), set(out["new"])
    missing_used = [s for s in used if s in old_k and s not in new_k]
    return {"removed_exports": sorted(old_k - new_k)[:30], "added_exports": sorted(new_k - old_k)[:30],
            "used_symbols": used, "used_symbols_missing_in_new": missing_used,
            "callable_changed": ("<callable>" in old_k) != ("<callable>" in new_k),
            "verdict": "BREAKING for this app" if missing_used or (("<callable>" in old_k) and "<callable>" not in new_k)
            else "no removed symbols used by this app (behavioural changes still possible)"}


def validate(plan: dict, finding: dict, target_root: Path, out_dir: Path, ledger: Ledger,
             before_findings: list[dict], before_sbom: dict, run_tests: bool = False) -> dict:
    fid = finding["id"]
    sb = make_sandbox(target_root, out_dir / "sandbox" / fid)
    target = plan["remediation"]["target"]
    notes = apply_change(sb, finding, target)
    steps = []
    # rebuild dependency resolution (no install scripts executed — safe by construction)
    for proj in {finding.get("project") or "."}:
        if (sb / proj / "package.json").exists() and finding.get("ecosystem", "npm") == "npm" and \
                finding["type"] not in ("unpinned_image", "unpinned_build_tool"):
            extra = ["--legacy-peer-deps"] if proj == "frontend" else []
            steps.append(_run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
                               *extra], sb / proj, 600))
    resolution_ok = all(s["exit"] == 0 for s in steps)
    # rescan the sandbox
    tmp_ledger = Ledger(Path(tempfile.mkdtemp()) / "ledger.jsonl")
    inv2 = discover(sb, tmp_ledger)
    after = score_findings(detect(inv2, tmp_ledger), inv2, tmp_ledger)
    after_sbom = to_cyclonedx(inv2["graph"], "sandbox", inv2["containers"], inv2["workflows"])
    key = lambda f: (f["type"], f.get("component"), f.get("version"), f.get("file"), f.get("line"))
    bkeys, akeys = {key(f) for f in before_findings}, {key(f) for f in after}
    target_resolved = key(finding) not in akeys
    new_findings = [f for f in after if key(f) not in bkeys]
    resolved = [f for f in before_findings if key(f) not in akeys]
    # API compatibility probe for package upgrades
    probe = None
    if finding["type"] == "vulnerability" and finding.get("ecosystem", "npm") == "npm" and "@" in target \
            and not target.startswith(("overrides:", "parent:", "mitigate:")):
        name, ver = target.rsplit("@", 1)
        used = (finding.get("reachability") or {}).get("symbols_used", [])
        probe = api_probe(name, finding["version"], ver, used, out_dir / "sandbox" / f"{fid}-probe")
    tests = None
    if run_tests:
        tests = [_run(["npm", "ci", "--ignore-scripts"], sb, 1800), _run(["npm", "test"], sb, 1800)]
    patch = subprocess.run(["git", "diff", "--", ".", ":(exclude)*package-lock.json"], cwd=sb,
                           capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    lock_stat = subprocess.run(["git", "diff", "--stat", "--", "*package-lock.json"], cwd=sb,
                               capture_output=True, text=True, encoding="utf-8", errors="replace").stdout.strip()
    result = {
        "finding_id": fid, "sandbox": str(sb), "branch": "guardian/fix", "target": target, "changes": notes,
        "resolution": steps, "resolution_ok": resolution_ok, "target_finding_resolved": target_resolved,
        "resolved_findings": [f"{f['id']} {f['title'][:80]}" for f in resolved],
        "new_findings": [f"{f['type']}: {f['title'][:100]}" for f in new_findings],
        "risk_before": round(sum(f["risk_score"] for f in before_findings), 1),
        "risk_after": round(sum(f["risk_score"] for f in after), 1),
        "sbom_diff": sbom_diff(before_sbom, after_sbom), "api_probe": probe, "tests": tests,
        "lockfile_diffstat": lock_stat, "patch": patch,
    }
    result["status"] = ("VERIFIED" if resolution_ok and target_resolved and not new_findings and
                        not (probe and "BREAKING" in str(probe.get("verdict"))) else "NEEDS_REVIEW")
    result["evidence_id"] = ledger.add("validation", f"sandbox:{sb}", {k: v for k, v in result.items()
                                       if k not in ("patch", "resolution")} | {"resolution_exit": [s["exit"] for s in steps]},
                                       actor="tool:validator")
    return result
