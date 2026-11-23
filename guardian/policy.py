"""Policy gate. Uses the real OPA binary on policy/guardian.rego when `opa` is on PATH;
otherwise a Python evaluator that mirrors the same rules (kept deliberately 1:1 with the Rego)."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

POLICY_DIR = Path(__file__).resolve().parent.parent / "policy"


def _python_eval(inp: dict) -> dict:
    deny, warn, allowed = [], [], []
    for f in inp["findings"]:
        a = f.get("assessment") or {}
        if f["type"] == "typosquat" and a.get("verdict") != "likely_benign":
            deny.append(f"{f['id']}: typosquat-suspect dependency '{f['component']}' (looks like '{f.get('lookalike_of')}')")
        if f["type"] == "lockfile_drift":
            deny.append(f"{f['id']}: suspicious lockfile change for '{f['component']}'")
        if f["type"] == "vulnerability" and f["priority"] == "Critical" and f["reachability"]["status"] == "reachable_direct":
            deny.append(f"{f['id']}: critical reachable vulnerability in {f['component']}@{f['version']}")
        if f["type"] == "install_script" and f.get("suspicious"):
            deny.append(f"{f['id']}: install script with suspicious behaviour in {f['component']}")
        if f["type"] in {"unpinned_image", "unpinned_action", "unpinned_build_tool", "lockfile_uncommitted", "ci_curl_pipe"}:
            warn.append(f"{f['id']}: {f['title']}")
    for p in inp.get("plans", []):
        ap = p.get("approval") or {}
        if ap.get("approved") and str(ap.get("by", "")).startswith("human:") and \
                any(c["target"] == p["remediation"]["target"] for c in p["remediation"]["candidates"]):
            allowed.append(p["finding_id"])
    return {"deny": sorted(set(deny)), "warn": sorted(set(warn)), "remediation_allowed": sorted(set(allowed)),
            "auto_merge_allowed": False, "build_allowed": not deny, "engine": "python-mirror"}


def evaluate(inp: dict) -> dict:
    opa = shutil.which("opa")
    if opa:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as t:
            json.dump(inp, t, default=str)
        r = subprocess.run([opa, "eval", "-f", "json", "-d", str(POLICY_DIR), "-i", t.name, "data.guardian"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            v = json.loads(r.stdout)["result"][0]["expressions"][0]["value"]
            return {"deny": sorted(v.get("deny", [])), "warn": sorted(v.get("warn", [])),
                    "remediation_allowed": sorted(v.get("remediation_allowed", [])),
                    "auto_merge_allowed": v.get("auto_merge_allowed", False),
                    "build_allowed": v.get("build_allowed", False), "engine": "opa"}
    return _python_eval(inp)
