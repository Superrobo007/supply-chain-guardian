"""Guardian Report — machine-readable JSON + human-readable Markdown + standalone HTML."""
from __future__ import annotations

import html
import json
import time
from pathlib import Path


def _md_table(rows, headers):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    for r in rows:
        out.append("| " + " | ".join(str(c).replace("|", "\\|").replace("\n", " ") for c in r) + " |")
    return "\n".join(out)


def build(state: dict, out: Path, ledger_status: str) -> dict:
    fs = state["findings"]
    plans = {p["finding_id"]: p for p in state.get("plans", [])}
    vals = {v["finding_id"]: v for v in state.get("validations", [])}
    pol = state.get("policy", {})
    inv = state["inventory"]
    counts = {}
    for f in fs:
        counts[f["priority"]] = counts.get(f["priority"], 0) + 1
    md = [f"# Supply Chain Guardian Report — {inv['app']}",
          f"_Generated {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())} · AI mode: {state.get('ai_mode')} · "
          f"Ledger: {ledger_status}_", "",
          "## 1. Inventory",
          f"- Projects: {', '.join(p['project'] + ' (' + str(p['lockfile']) + ')' for p in inv['projects'])}",
          f"- Components: **{inv['components']}** ({inv['direct']} direct, {inv['components'] - inv['direct']} transitive)",
          f"- Container base images: {', '.join(inv['images'])}",
          f"- CI workflows: {inv['workflows']} ({inv['actions']} third-party action references)",
          "- SBOM: `sbom.cdx.json` (CycloneDX 1.6) · graph: `graph.json`", "",
          "## 2. Risk summary",
          " · ".join(f"**{k}**: {counts.get(k, 0)}" for k in ("Critical", "High", "Medium", "Low")), "",
          f"**Build gate ({pol.get('engine', 'n/a')}):** {'PASS' if pol.get('build_allowed') else 'BLOCKED'}", ""]
    for d in pol.get("deny", []):
        md.append(f"- ⛔ {d}")
    md += ["", "## 3. Prioritised findings", _md_table(
        [(f["id"], f["priority"], f["risk_score"], f["type"], f["title"][:90], f["reachability"]["status"],
          (f.get("assessment") or {}).get("verdict", "-")) for f in fs[:40]],
        ["ID", "Priority", "Score", "Type", "Finding", "Reachability", "AI verdict"]), ""]
    md.append("## 4. Evidence for top findings")
    for f in [x for x in fs if x.get("assessment")][:12]:
        a = f["assessment"]
        md += [f"### {f['id']} · {f['title']}",
               f"- Component: `{f.get('component')}` {f.get('version') or ''} · project `{f.get('project')}`",
               f"- Score {f['risk_score']} = " + " × ".join(f"{k} {v}" for k, v in f["score_factors"].items()),
               f"- Dependency path: {' → '.join(f['dependency_paths'][0]) if f.get('dependency_paths') else 'n/a'}",
               f"- Reachability: **{f['reachability']['status']}** " +
               (f"(e.g. `{f['reachability']['prod'][0]['file']}:{f['reachability']['prod'][0]['line']}`)"
                if f["reachability"].get("prod") else ""),
               f"- Assessment ({a.get('mode')}): **{a['verdict']}**, priority {a['adjusted_priority']}, "
               f"confidence {a['confidence']} — {a['rationale']}"]
        for c in a["claims"]:
            tag = "✅ VERIFIED" if c["kind"] == "verified_fact" else "💭 INFERENCE"
            md.append(f"  - {tag}: {c['statement']} {c['evidence_ids'] or ''}"
                      + (f" _(downgraded: {c['downgraded']})_" if c.get("downgraded") else ""))
        if a.get("skeptic_note"):
            md.append(f"  - Skeptic: {a['skeptic_note']}")
        md.append("")
    if plans:
        md.append("## 5. Remediation plans (human approval required)")
        for fid, p in plans.items():
            r = p["remediation"]
            ap = p.get("approval") or {}
            md += [f"### {fid} → {r['action'].upper()} `{r['target']}` ({r.get('mode')})",
                   f"- Why: {r['rationale']}", f"- Expected risk reduction: {r['expected_risk_reduction']}",
                   f"- Compatibility: {r['compatibility_impact']}", f"- Rollback: {r['rollback']}",
                   f"- Approval: {'✅ ' + ap.get('by', '') + ' at ' + ap.get('at', '') if ap.get('approved') else '⏳ pending'}"]
            v = vals.get(fid)
            if v:
                md += [f"- **Validation: {v['status']}** — target resolved: {v['target_finding_resolved']}, "
                       f"lock resolution ok: {v['resolution_ok']}, new findings: {len(v['new_findings'])}, "
                       f"total risk {v['risk_before']} → {v['risk_after']}",
                       f"- SBOM diff: +{len(v['sbom_diff']['added'])} / -{len(v['sbom_diff']['removed'])} / "
                       f"~{len(v['sbom_diff']['changed'])}"]
                if v.get("api_probe"):
                    md.append(f"- API probe: {v['api_probe'].get('verdict', v['api_probe'].get('error'))}")
                if v["new_findings"]:
                    md.append("- Newly introduced: " + "; ".join(v["new_findings"][:5]))
                md.append(f"- Patch: `prs/{fid}.patch` · PR description: `prs/{fid}.md`")
            md.append("")
    md += ["## 6. Remaining / accepted risk",
           f"{sum(1 for f in fs if f['id'] not in vals)} findings not yet remediated; see `findings.json`. "
           "Accepted risks must be recorded with `guardian accept <id> --by <name> --reason ...`.", "",
           "## 7. Responsible AI note",
           "- AI is used for triage, adversarial verification and choosing among pre-computed remediations; "
           "all facts come from deterministic tools and are stored in a hash-chained evidence ledger.",
           "- Each AI claim is typed VERIFIED (cites ledger evidence that exists and supports it) or INFERENCE.",
           "- The remediator cannot invent versions: its choice must match a registry-computed candidate.",
           "- No change is merged, deployed or released automatically; validation runs only after human approval, "
           "in a sandbox copy, with install scripts disabled.",
           "- Secrets/key files are never readable by the model; tool output is fenced as untrusted data."]
    text = "\n".join(md)
    (out / "report.md").write_text(text, encoding="utf-8")
    machine = {"generated": time.time(), "ai_mode": state.get("ai_mode"), "inventory": inv, "policy": pol,
               "findings": fs, "plans": list(plans.values()),
               "validations": [{k: v for k, v in x.items() if k != "patch"} for x in vals.values()],
               "ledger": ledger_status}
    (out / "report.json").write_text(json.dumps(machine, indent=1, default=str), encoding="utf-8")
    (out / "report.html").write_text(_html(text, inv["app"]), encoding="utf-8")
    return machine


def _html(md: str, title: str) -> str:
    """Tiny markdown->HTML renderer (headings, lists, tables, code) so the report needs no dependencies."""
    import re
    lines, out, in_table, in_list = md.splitlines(), [], False, False
    def inline(s):
        s = html.escape(s)
        s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        s = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", s)
        return re.sub(r"_([^_]+)_", r"<i>\1</i>", s)
    for ln in lines:
        if ln.startswith("|"):
            cells = [c.strip() for c in ln.strip("|").split(" | ")]
            if set(ln) <= set("|-"):
                continue
            if not in_table:
                out.append("<table><tr>" + "".join(f"<th>{inline(c)}</th>" for c in cells) + "</tr>")
                in_table = True
            else:
                cls = cells[1].lower() if len(cells) > 1 else ""
                out.append(f"<tr class='{cls}'>" + "".join(f"<td>{inline(c)}</td>" for c in cells) + "</tr>")
            continue
        if in_table:
            out.append("</table>")
            in_table = False
        m = re.match(r"^(\s*)- (.*)", ln)
        if m:
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li style='margin-left:{len(m.group(1)) * 8}px'>{inline(m.group(2))}</li>")
            continue
        if in_list:
            out.append("</ul>")
            in_list = False
        if ln.startswith("#"):
            n = len(ln) - len(ln.lstrip("#"))
            out.append(f"<h{n}>{inline(ln[n:].strip())}</h{n}>")
        elif ln.strip():
            out.append(f"<p>{inline(ln)}</p>")
    if in_table:
        out.append("</table>")
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Guardian Report</title><style>
:root{{--bg:#fff;--fg:#1d2433;--mut:#5b6475;--line:#e3e6ec;--crit:#fde2e4;--high:#fff0dc;--med:#fff9db}}
@media (prefers-color-scheme:dark){{:root{{--bg:#14171c;--fg:#e6e9ef;--mut:#9aa3b2;--line:#2a2f38;--crit:#4a1f25;--high:#4a3418;--med:#3f3a17}}}}
body{{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:1100px;margin:auto;padding:16px}}
table{{border-collapse:collapse;width:100%;font-size:13px;display:block;overflow-x:auto}}
td,th{{border:1px solid var(--line);padding:4px 8px;text-align:left}} tr.critical{{background:var(--crit)}}
tr.high{{background:var(--high)}} tr.medium{{background:var(--med)}} code{{font-size:12px}} h1{{font-size:24px}}
i{{color:var(--mut)}}</style></head><body>{''.join(out)}</body></html>"""
