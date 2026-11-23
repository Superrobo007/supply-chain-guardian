"""Stage 1 — DISCOVER: manifests + lockfiles + Dockerfiles + CI workflows -> inventory & dependency graph."""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import networkx as nx

from .ledger import Ledger

SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".angular", "coverage"}


def _find(root: Path, name: str) -> list[Path]:
    out = []
    for p in root.rglob(name):
        if not any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            out.append(p)
    return sorted(out)


def _git_tracked(root: Path, rel: str) -> bool | None:
    try:
        r = subprocess.run(["git", "-C", str(root), "ls-files", "--error-unmatch", rel],
                           capture_output=True, text=True)
        return r.returncode == 0
    except FileNotFoundError:
        return None


def _resolve(packages: dict, from_path: str, name: str) -> str | None:
    """npm node_modules resolution: walk up from `from_path` looking for node_modules/<name>."""
    base = from_path
    while True:
        cand = f"{base}/node_modules/{name}" if base else f"node_modules/{name}"
        if cand in packages:
            return cand
        if not base:
            return None
        idx = base.rfind("/node_modules/")
        base = base[:idx] if idx != -1 else ""


def discover_npm_project(root: Path, manifest: Path, ledger: Ledger, G: nx.DiGraph) -> dict:
    proj = manifest.parent.relative_to(root).as_posix() or "."
    pkg = json.loads(manifest.read_text(encoding="utf-8"))
    lock_path = manifest.parent / "package-lock.json"
    rel_manifest = manifest.relative_to(root).as_posix()
    rel_lock = lock_path.relative_to(root).as_posix()
    direct = {**{k: ("prod", v) for k, v in pkg.get("dependencies", {}).items()},
              **{k: ("dev", v) for k, v in pkg.get("devDependencies", {}).items()}}
    manifest_eid = ledger.add("manifest", rel_manifest, {
        "name": pkg.get("name"), "version": pkg.get("version"),
        "dependencies": pkg.get("dependencies", {}), "devDependencies": pkg.get("devDependencies", {}),
        "scripts": {k: v for k, v in (pkg.get("scripts") or {}).items() if "install" in k or k == "prepare"}})
    root_node = f"{proj}::<root>"
    G.add_node(root_node, kind="project", name=pkg.get("name", proj), version=pkg.get("version"),
               project=proj, evidence=[manifest_eid])
    info = {"project": proj, "manifest": rel_manifest, "lockfile": None, "lock_committed": None,
            "direct": {k: {"scope": s, "range": r} for k, (s, r) in direct.items()}}

    if not lock_path.exists():
        # No lockfile: only direct deps with declared ranges are knowable.
        for name, (scope, rng) in direct.items():
            nid = f"{proj}::node_modules/{name}"
            G.add_node(nid, kind="package", ecosystem="npm", name=name, version=None, range=rng, project=proj,
                       dev=scope == "dev", direct=True, evidence=[manifest_eid])
            G.add_edge(root_node, nid, range=rng)
        return info

    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    info["lockfile"] = rel_lock
    info["lock_committed"] = _git_tracked(root, rel_lock)
    packages = lock.get("packages", {})
    lock_eid = ledger.add("lockfile", rel_lock, {
        "lockfileVersion": lock.get("lockfileVersion"), "package_count": len(packages) - 1,
        "committed_to_git": info["lock_committed"]})
    for path, meta in packages.items():
        if path == "" or meta.get("link"):
            continue
        name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
        G.add_node(f"{proj}::{path}", kind="package", ecosystem="npm", name=name, version=meta.get("version"),
                   project=proj, dev=bool(meta.get("dev")), optional=bool(meta.get("optional")),
                   resolved=meta.get("resolved"), integrity=meta.get("integrity"),
                   has_install_script=bool(meta.get("hasInstallScript")), license=meta.get("license"),
                   direct=False, lock_path=path, evidence=[lock_eid])
    for name, (scope, rng) in direct.items():
        tgt = _resolve(packages, "", name)
        if tgt:
            G.add_edge(root_node, f"{proj}::{tgt}", range=rng)
            G.nodes[f"{proj}::{tgt}"]["direct"] = True
            G.nodes[f"{proj}::{tgt}"]["declared_range"] = rng
    for path, meta in packages.items():
        if path == "" or meta.get("link"):
            continue
        for dep, rng in {**meta.get("dependencies", {}), **meta.get("optionalDependencies", {})}.items():
            tgt = _resolve(packages, path, dep)
            if tgt:
                G.add_edge(f"{proj}::{path}", f"{proj}::{tgt}", range=rng)
    return info


FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.I | re.M)
NPM_G_RE = re.compile(r"npm\s+(?:install|i)\s+-g\s+([^\s&;]+)")


def discover_dockerfiles(root: Path, ledger: Ledger) -> list[dict]:
    out = []
    for df in _find(root, "Dockerfile"):
        text = df.read_text(errors="ignore", encoding="utf-8")
        rel = df.relative_to(root).as_posix()
        stages = [m.group(2) for m in FROM_RE.finditer(text) if m.group(2)]
        images = []
        for m in FROM_RE.finditer(text):
            ref = m.group(1)
            if ref in stages:
                continue
            line = text[:m.start()].count("\n") + 1
            digest = ref.split("@", 1)[1] if "@" in ref else None
            name_tag = ref.split("@")[0]
            tag = name_tag.rsplit(":", 1)[1] if ":" in name_tag.split("/")[-1] else "latest"
            images.append({"ref": ref, "image": name_tag.rsplit(":", 1)[0] if tag != "latest" or ":" in name_tag else name_tag,
                           "tag": tag, "digest": digest, "line": line,
                           "evidence": ledger.add("container", f"{rel}:{line}", {"from": ref, "tag": tag, "digest": digest})})
        tools = []
        for m in NPM_G_RE.finditer(text):
            line = text[:m.start()].count("\n") + 1
            spec = m.group(1)
            tools.append({"spec": spec, "line": line,
                          "evidence": ledger.add("container", f"{rel}:{line}", {"global_install": spec})})
        user = re.findall(r"^\s*USER\s+(\S+)", text, re.M)
        out.append({"file": rel, "base_images": images, "build_tools": tools, "final_user": user[-1] if user else "root",
                    "exposes": re.findall(r"^\s*EXPOSE\s+(\d+)", text, re.M)})
    return out


USES_RE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)(?:\s*#\s*(.*))?$", re.M)


def discover_workflows(root: Path, ledger: Ledger) -> list[dict]:
    out = []
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.exists():
        return out
    for wf in sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml"))):
        text = wf.read_text(errors="ignore", encoding="utf-8")
        rel = wf.relative_to(root).as_posix()
        actions = []
        for m in USES_RE.finditer(text):
            ref = m.group(1)
            if ref.startswith("./"):
                continue
            line = text[:m.start()].count("\n") + 1
            pinned = bool(re.search(r"@[0-9a-f]{40}$", ref)) or "@sha256:" in ref
            actions.append({"uses": ref, "comment": (m.group(2) or "").strip(), "line": line, "sha_pinned": pinned,
                            "evidence": ledger.add("cicd", f"{rel}:{line}", {"uses": ref, "sha_pinned": pinned})})
        triggers_prt = "pull_request_target" in text
        perms = re.findall(r"^\s*permissions:\s*(.*)$", text, re.M)
        curl_pipe = [text[:m.start()].count("\n") + 1 for m in re.finditer(r"(curl|wget)[^\n|]*\|\s*(ba)?sh", text)]
        out.append({"file": rel, "actions": actions, "pull_request_target": triggers_prt,
                    "permissions": perms, "curl_pipe_sh_lines": curl_pipe,
                    "evidence": ledger.add("cicd", rel, {"actions": len(actions), "pull_request_target": triggers_prt,
                                                         "permissions": perms, "curl_pipe_sh_lines": curl_pipe})})
    return out


def discover(root: Path, ledger: Ledger) -> dict:
    root = Path(root).resolve()
    G = nx.DiGraph()
    projects = [discover_npm_project(root, m, ledger, G) for m in _find(root, "package.json")
                if (m.parent / "package-lock.json").exists() or m.parent == root]
    from .eco_pypi import discover_pypi
    projects += discover_pypi(root, ledger, G)
    return {"root": str(root), "graph": G, "projects": projects,
            "containers": discover_dockerfiles(root, ledger), "workflows": discover_workflows(root, ledger)}


def dependency_paths(G: nx.DiGraph, node: str, limit: int = 3) -> list[list[str]]:
    """Up to `limit` shortest paths from the project root to `node`, rendered as name@version."""
    proj = G.nodes[node]["project"]
    root = f"py:{proj}::<root>" if G.nodes[node].get("ecosystem") == "pypi" else f"{proj}::<root>"
    try:
        paths = nx.all_shortest_paths(G, root, node)
        out = []
        for p in paths:
            out.append([f"{G.nodes[n]['name']}@{G.nodes[n].get('version') or G.nodes[n].get('range')}" for n in p])
            if len(out) >= limit:
                break
        return out
    except nx.NetworkXNoPath:
        return []
