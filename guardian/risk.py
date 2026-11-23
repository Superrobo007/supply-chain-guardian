"""Stage 3a — deterministic, explainable risk scoring (the AI may adjust it, but must justify with evidence).

score = base_severity x reachability x exposure x environment x provenance, clipped to [0, 10]
Each factor is recorded so the score can be explained line by line.
"""
from __future__ import annotations

from .ledger import Ledger
from .reachability import classify

REACH_W = {"reachable_direct": 1.0, "transitive_of_reachable": 0.85, "unreferenced": 0.55,
           "dev_or_test_only": 0.3, "n/a": 1.0}
NON_PACKAGE = {"unpinned_image", "unpinned_build_tool", "container_root", "unpinned_action",
               "ci_risky_trigger", "ci_curl_pipe", "lockfile_uncommitted", "lockfile_drift"}


def bucket(score: float) -> str:
    return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low"


def score_findings(findings: list[dict], inv: dict, ledger: Ledger) -> list[dict]:
    G, root = inv["graph"], inv["root"]
    exposed = any(c["exposes"] for c in inv["containers"])
    for f in findings:
        factors = {"base": f["severity_base"]}
        if f["type"] in NON_PACKAGE or not f.get("nodes"):
            reach = {"status": "n/a"}
        else:
            reach = classify(G, root, f["nodes"][0])
            reach_e = ledger.add("reachability", f"static-import-scan:{f['component']}",
                                 {"package": f["component"], "status": reach["status"],
                                  "prod_sites": reach["prod"][:6], "test_sites": len(reach["test"]),
                                  "symbols_used": reach["symbols_used"][:20], "via": reach.get("via")})
            f["evidence"].append(reach_e)
        f["reachability"] = reach
        factors["reachability"] = REACH_W[reach["status"]]
        # exposure: network-exposed server code vs browser bundle vs build-only
        if f.get("project") == "frontend":
            factors["exposure"] = 0.8        # runs in users' browsers
        elif f["type"] in NON_PACKAGE:
            factors["exposure"] = 1.0
        else:
            factors["exposure"] = 1.0 if exposed else 0.8
        factors["environment"] = 0.4 if f.get("dev_only") else 1.0
        # malicious-package classes are dangerous at install time regardless of reachability
        if f["type"] in ("typosquat", "lockfile_drift") or (f["type"] == "install_script" and f.get("suspicious")):
            factors["reachability"] = max(factors["reachability"], 1.0)
            factors["environment"] = 1.0
            factors["exposure"] = 1.0       # executes at install time on dev/CI machines and in every build
        s = factors["base"]
        for k in ("reachability", "exposure", "environment"):
            s *= factors[k]
        f["risk_score"] = round(min(10.0, s), 2)
        f["priority"] = bucket(f["risk_score"])
        known = sum([reach["status"] != "n/a", bool(f.get("version")), bool(f.get("evidence"))])
        f["confidence"] = round(0.5 + 0.15 * known, 2)
        f["score_factors"] = factors
    findings.sort(key=lambda x: -x["risk_score"])
    return findings
