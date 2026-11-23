"""CycloneDX 1.6 SBOM generation + SBOM diff (used for before/after validation)."""
from __future__ import annotations

import time
import uuid

import networkx as nx


def purl(name: str, version: str | None, eco: str = "npm") -> str:
    n = name.replace("@", "%40", 1) if name.startswith("@") else name
    return f"pkg:{eco}/{n}@{version}" if version else f"pkg:{eco}/{n}"


def to_cyclonedx(G: nx.DiGraph, app_name: str, containers: list[dict], workflows: list[dict]) -> dict:
    comps, deps, seen = [], [], set()
    for nid, d in G.nodes(data=True):
        if d["kind"] != "package":
            continue
        ref = purl(d["name"], d.get("version"), d.get("ecosystem", "npm"))
        if ref in seen:
            continue
        seen.add(ref)
        c = {"type": "library", "bom-ref": ref, "name": d["name"], "purl": ref,
             "scope": "optional" if d.get("dev") else "required",
             "properties": [{"name": "guardian:project", "value": d["project"]},
                            {"name": "guardian:direct", "value": str(bool(d.get("direct"))).lower()}]}
        if d.get("version"):
            c["version"] = d["version"]
        if d.get("license"):
            c["licenses"] = [{"license": {"id": d["license"]}}] if isinstance(d["license"], str) else []
        if d.get("integrity"):
            algo, _, val = d["integrity"].partition("-")
            c["hashes"] = [{"alg": {"sha512": "SHA-512", "sha1": "SHA-1", "sha256": "SHA-256"}.get(algo, algo), "content": val}]
        if d.get("resolved"):
            c["externalReferences"] = [{"type": "distribution", "url": d["resolved"]}]
        if d.get("has_install_script"):
            c["properties"].append({"name": "guardian:hasInstallScript", "value": "true"})
        comps.append(c)
    for nid, d in G.nodes(data=True):
        if d["kind"] != "package":
            continue
        ref = purl(d["name"], d.get("version"), d.get("ecosystem", "npm"))
        children = sorted({purl(G.nodes[s]["name"], G.nodes[s].get("version"), G.nodes[s].get("ecosystem", "npm")) for s in G.successors(nid)})
        deps.append({"ref": ref, "dependsOn": children})
    for c in containers:
        for img in c["base_images"]:
            comps.append({"type": "container", "bom-ref": f"oci:{img['ref']}", "name": img["image"],
                          "version": img["digest"] or img["tag"],
                          "properties": [{"name": "guardian:dockerfile", "value": c["file"]}]})
    for w in workflows:
        for a in w["actions"]:
            name, _, ver = a["uses"].partition("@")
            comps.append({"type": "application", "bom-ref": f"gha:{a['uses']}", "name": name, "version": ver,
                          "properties": [{"name": "guardian:workflow", "value": w["file"]}]})
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                     "tools": {"components": [{"type": "application", "name": "supply-chain-guardian", "version": "0.1"}]},
                     "component": {"type": "application", "name": app_name, "bom-ref": "app"}},
        "components": comps, "dependencies": deps,
    }


def diff(before: dict, after: dict) -> dict:
    def index(b):
        out = {}
        for c in b.get("components", []):
            if c["type"] == "library":
                out.setdefault(c["name"], set()).add(c.get("version"))
        return out
    a, b = index(before), index(after)
    added = sorted(f"{n}@{v}" for n in b for v in b[n] - a.get(n, set()) if n not in a)
    removed = sorted(f"{n}@{v}" for n in a for v in a[n] - b.get(n, set()) if n not in b)
    changed = sorted(f"{n}: {sorted(a[n] - b[n])} -> {sorted(b[n] - a[n])}" for n in a.keys() & b.keys() if a[n] != b[n])
    return {"added": added, "removed": removed, "changed": changed,
            "count_before": sum(len(v) for v in a.values()), "count_after": sum(len(v) for v in b.values())}
