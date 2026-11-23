"""Reachability analysis: is a package actually imported by application code, and which symbols are used?

Static, import-level reachability (a fast, explainable approximation of call-graph reachability):
  reachable_direct   -> imported from production source
  reachable_test     -> only imported from tests/specs
  transitive         -> not imported, but pulled in by a reachable parent
  unreferenced       -> not imported anywhere and no reachable parent
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

import networkx as nx

EXTS = {".ts", ".js", ".mjs", ".cjs", ".tsx", ".jsx"}
SKIP = {"node_modules", ".git", "dist", "build", ".angular", "coverage"}
TEST_HINT = re.compile(r"(\.spec\.|\.test\.|/test/|/tests/|cypress|/e2e/)")


@lru_cache(maxsize=4)
def _sources(root: str) -> tuple[tuple[str, str], ...]:
    out = []
    for p in Path(root).rglob("*"):
        if p.suffix in EXTS and p.is_file() and not any(s in p.parts for s in SKIP):
            try:
                out.append((p.relative_to(root).as_posix(), p.read_text(errors="ignore", encoding="utf-8")))
            except OSError:
                pass
    return tuple(out)


def import_sites(root: str, pkg: str) -> dict:
    q = re.escape(pkg)
    pat = re.compile(
        rf"""(?:require\(\s*['"]{q}(?:/[^'"]*)?['"]\s*\)|from\s+['"]{q}(?:/[^'"]*)?['"]|import\(\s*['"]{q}['"]\s*\)|import\s+['"]{q}['"])""")
    prod, test, symbols = [], [], set()
    for rel, text in _sources(root):
        if pkg not in text:
            continue
        for m in pat.finditer(text):
            line_no = text[:m.start()].count("\n") + 1
            line = text.splitlines()[line_no - 1].strip()[:200]
            (test if TEST_HINT.search("/" + rel) else prod).append({"file": rel, "line": line_no, "code": line})
            nm = re.search(r"import\s*\{([^}]*)\}", line)
            if nm:
                symbols |= {s.strip().split(" as ")[0].replace("type ", "") for s in nm.group(1).split(",") if s.strip()}
            alias = re.search(r"(?:import\s+\*\s+as\s+|import\s+|const\s+|let\s+|var\s+)(\w+)\s*(?:=|from)", line)
            if alias:
                for c in re.finditer(rf"\b{alias.group(1)}\.(\w+)", text):
                    symbols.add(c.group(1))
                if re.search(rf"(?<![\w.]){alias.group(1)}\s*\(", text[m.end():]):
                    symbols.add("<callable>")      # the module itself is invoked as a function
    return {"prod": prod, "test": test, "symbols_used": sorted(symbols)}


def classify(G: nx.DiGraph, root: str, node: str) -> dict:
    d = G.nodes[node]
    proj_root = str(Path(root) / d["project"]) if d["project"] != "." else root
    if d.get("ecosystem") == "pypi":
        from .eco_pypi import import_sites as py_sites
        sites = py_sites(proj_root, d["name"])   # scan the sub-project that declares the requirement
        status = "reachable_direct" if sites["prod"] else ("dev_or_test_only" if sites["test"] or d.get("dev")
                                                          else "unreferenced")
        if status == "unreferenced":
            for anc in nx.ancestors(G, node):
                ad = G.nodes[anc]
                if ad["kind"] == "package" and ad.get("direct") and py_sites(proj_root, ad["name"])["prod"]:
                    status, sites["via"] = "transitive_of_reachable", ad["name"]
                    break
        return {"status": status, **sites}
    sites = import_sites(proj_root, d["name"])
    nested = (d.get("lock_path") or "").count("node_modules/") > 1
    if nested and not d.get("direct"):
        # app code's `require(name)` resolves to the top-level copy, not this nested one
        sites = {"prod": [], "test": [], "symbols_used": [], "shadowed_by_top_level_import": bool(sites["prod"])}
    if sites["prod"]:
        status = "reachable_direct"
    elif sites["test"] or d.get("dev"):
        status = "dev_or_test_only"
    else:
        # transitive: reachable if any ancestor chain leads to a prod-imported direct dependency
        status = "unreferenced"
        for anc in nx.ancestors(G, node):
            ad = G.nodes[anc]
            if ad["kind"] == "package" and ad.get("direct") and not ad.get("dev"):
                if import_sites(proj_root, ad["name"])["prod"]:
                    status = "transitive_of_reachable"
                    sites["via"] = ad["name"]
                    break
    return {"status": status, **sites}
