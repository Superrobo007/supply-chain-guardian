"""Stage 2 — DETECT: known vulnerabilities + non-CVE supply-chain anomalies. Every finding carries evidence IDs."""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import networkx as nx
from rapidfuzz.distance import DamerauLevenshtein

from . import registry, semver
from .discover import dependency_paths
from .ledger import Ledger

# Well-known packages used as typosquatting reference set (extend with your org's internal list).
POPULAR = """react react-dom vue angular @angular/core @angular/common lodash underscore express koa fastify hapi
moment dayjs date-fns axios request node-fetch got superagent chalk commander yargs minimist debug dotenv uuid
async bluebird q rxjs tslib typescript babel-core @babel/core webpack rollup vite esbuild eslint prettier jest mocha
chai sinon cypress jquery bootstrap socket.io socket.io-client ws mongoose sequelize pg mysql mysql2 sqlite3 redis
ioredis jsonwebtoken express-jwt passport bcrypt bcryptjs helmet cors cookie-parser cookie body-parser multer
morgan winston pino bunyan nodemon pm2 cross-env rimraf mkdirp glob fs-extra graceful-fs semver colors
event-stream through2 readable-stream inherits once wrappy minimatch ms qs mime mime-types js-yaml yaml marked
sanitize-html dompurify xss validator joi zod ajv class-validator handlebars hbs pug ejs nunjucks mustache
core-js regenerator-runtime classnames prop-types ngx-cookie ngx-cookie-service ngx-translate @ngx-translate/core
crypto-js node-forge elliptic ethers web3 bignumber.js big.js decimal.js shelljs execa cross-spawn
electron puppeteer playwright cheerio jsdom htmlparser2 xml2js fast-xml-parser libxmljs libxmljs2 pdfkit
sharp jimp canvas file-type unzipper tar archiver jszip node-gyp prebuild-install nan bindings
epilogue finale-rest finale sequelize-cli config i18n compression serve-index express-rate-limit
""".split()
POPULAR_SET = set(POPULAR)

SUSPICIOUS_SCRIPT = re.compile(
    r"(curl |wget |\|\s*(ba)?sh|base64|eval\(|child_process|https?://(?!registry\.npmjs\.org)|"
    r"\.ssh|/etc/passwd|process\.env|npm_config_|nc -e|powershell)", re.I)
BENIGN_SCRIPT = re.compile(r"^(node-gyp rebuild|prebuild-install|node-pre-gyp|node install\.js|node scripts/|"
                           r"node index\.js --exec install|node dist/index\.js --exec install|node ./dist/|"
                           r"node-gyp-build|patch-package|husky)", re.I)


def _f(findings, ftype, title, sev, evidence, **kw):
    fid = f"F-{len(findings) + 1:03d}"
    findings.append({"id": fid, "type": ftype, "title": title, "severity_base": sev,
                     "evidence": sorted(set(evidence)), **kw})
    return findings[-1]


def _sev_score(adv) -> float:
    if adv.get("cvss", {}).get("score"):
        return float(adv["cvss"]["score"])
    return {"critical": 9.5, "high": 7.5, "moderate": 5.5, "low": 3.0}.get(adv.get("severity"), 5.0)


def fix_candidates(name: str, current: str, advisories: list[dict]) -> dict:
    p = registry.packument(name)
    versions = [v for v, meta in (p.get("versions") or {}).items()
                if not semver.is_prerelease(v) and not meta.get("deprecated")]
    versions.sort(key=lambda v: semver.parse(v)[:3])
    ranges = [a["vulnerable_versions"] for a in advisories]
    # pull every advisory for this package (not just ones hitting `current`) so candidates are truly safe
    allv = registry.bulk_advisories({name: versions[-200:]}).get(name, []) if versions else []
    ranges += [a["vulnerable_versions"] for a in allv]
    safe = [v for v in versions if semver.cmp(v, current) > 0 and not any(semver.satisfies(v, r) for r in ranges)]
    cur_major = semver.parse(current)[0] if semver.parse(current) else None
    same_major = [v for v in safe if semver.parse(v)[0] == cur_major]
    return {"min_safe": safe[0] if safe else None,
            "min_safe_same_major": same_major[0] if same_major else None,
            "latest_safe": safe[-1] if safe else None,
            "latest": p.get("dist-tags", {}).get("latest"),
            "all_known_advisory_ranges": sorted(set(ranges))}


def detect(inv: dict, ledger: Ledger) -> list[dict]:
    G: nx.DiGraph = inv["graph"]
    root = inv["root"]
    findings: list[dict] = []
    pkg_nodes = [n for n, d in G.nodes(data=True) if d["kind"] == "package" and d.get("version")]

    # ---- 1. Known vulnerabilities (GitHub Advisory DB via npm bulk API) ----
    npm_nodes = [n for n in pkg_nodes if G.nodes[n].get("ecosystem", "npm") == "npm"]
    query: dict[str, list[str]] = {}
    for n in npm_nodes:
        query.setdefault(G.nodes[n]["name"], []).append(G.nodes[n]["version"])
    advs = registry.bulk_advisories(query)
    for name, alist in sorted(advs.items()):
        nodes = [n for n in npm_nodes if G.nodes[n]["name"] == name]
        for ver in sorted({G.nodes[n]["version"] for n in nodes}):
            hits = [a for a in alist if semver.satisfies(ver, a["vulnerable_versions"])]
            if not hits:
                continue
            vnodes = [n for n in nodes if G.nodes[n]["version"] == ver]
            eids = [ledger.add("advisory", a["url"], {k: a.get(k) for k in
                    ("id", "url", "title", "severity", "vulnerable_versions", "cwe", "cvss")}) for a in hits]
            fixes = fix_candidates(name, ver, hits)
            eids.append(ledger.add("registry", f"{registry.REGISTRY}/{name}",
                                   {"package": name, "current": ver, "fix_candidates": fixes}))
            paths = [p for vn in vnodes for p in dependency_paths(G, vn, 2)][:4]
            parent_ranges = sorted({f"{G.nodes[u]['name']} wants {G.edges[u, vn]['range']}"
                                    for vn in vnodes for u in G.predecessors(vn)})
            top = max(hits, key=_sev_score)
            _f(findings, "vulnerability", f"{name}@{ver}: {top['title']}", max(_sev_score(a) for a in hits), eids,
               component=name, version=ver, nodes=vnodes, project=G.nodes[vnodes[0]]["project"],
               direct=any(G.nodes[v].get("direct") for v in vnodes), dev_only=all(G.nodes[v].get("dev") for v in vnodes),
               advisories=[{"id": a["url"].rsplit("/", 1)[-1], "title": a["title"], "severity": a["severity"],
                            "range": a["vulnerable_versions"], "cvss": (a.get("cvss") or {}).get("score"),
                            "cwe": a.get("cwe")} for a in hits],
               fix=fixes, dependency_paths=paths, parent_constraints=parent_ranges)

    # ---- 1b. Python (PyPI) vulnerabilities ----
    from . import eco_pypi
    py_nodes = [n for n in pkg_nodes if G.nodes[n].get("ecosystem") == "pypi"]
    for n, hits in eco_pypi.vulnerabilities(G, py_nodes).items():
        d = G.nodes[n]
        eids = [ledger.add("advisory", a["url"], {k: a.get(k) for k in
                ("id", "title", "severity", "fixed_in", "aliases", "cvss")}) for a in hits]
        fixes = eco_pypi.fix_candidates(d["name"], d["version"], hits)
        eids.append(ledger.add("registry", f"{eco_pypi.PYPI}/{d['name']}", {"package": d["name"],
                                                                             "current": d["version"], "fix_candidates": fixes}))
        base = max((_sev_score(a) if a["severity"] != "unknown" else 6.5) for a in hits)
        cves = sorted({x for a in hits for x in a["aliases"] if x.startswith("CVE-")})
        where = "" if d["project"] == "." else f" [{d['project']}]"
        _f(findings, "vulnerability", f"{d['name']}@{d['version']}{where}: {len(hits)} known advisories "
           f"({', '.join(cves[:3]) or hits[0]['id']}{'…' if len(cves) > 3 else ''})", base, eids,
           component=d["name"], version=d["version"], nodes=[n], project=d["project"], ecosystem="pypi",
           direct=bool(d.get("direct")), dev_only=bool(d.get("dev")), manifest=d.get("manifest"),
           advisories=[{"id": a["id"], "title": a["title"], "severity": a["severity"], "range": a["vulnerable_versions"],
                        "cvss": (a.get("cvss") or {}).get("score"), "fixed_in": a["fixed_in"],
                        "aliases": a["aliases"]} for a in hits],
           fix=fixes, dependency_paths=dependency_paths(G, n, 1), parent_constraints=[])

    # ---- 2. Typosquatting / look-alike packages (direct deps) ----
    direct_nodes = [n for n in pkg_nodes if G.nodes[n].get("direct")]
    for n in direct_nodes:
        name = G.nodes[n]["name"]
        if name in POPULAR_SET:
            continue
        bare = name
        eco = G.nodes[n].get("ecosystem", "npm")
        pool = eco_pypi.POPULAR if eco == "pypi" else POPULAR
        if eco == "pypi" and name in pool:
            continue
        for pop in pool:
            pb = pop
            if name.startswith("@") != pop.startswith("@"):
                continue          # compare scoped with scoped, unscoped with unscoped
            d = DamerauLevenshtein.distance(bare, pb)
            if (len(pb) >= 5 and d == 1) or bare in (pb + "-js", pb + "js", "node-" + pb) and bare != pb:
                if eco == "pypi":
                    me, them = eco_pypi.summarize(name), eco_pypi.summarize(pop)
                else:
                    me = registry.summarize_packument(name, G.nodes[n]["version"])
                    them = registry.summarize_packument(pop)
                e1 = ledger.add("registry", f"{registry.REGISTRY}/{name}", me)
                e2 = ledger.add("registry", f"{eco}:{pop}", them)
                e3 = ledger.add("heuristic", "typosquat:damerau-levenshtein",
                                {"candidate": name, "lookalike_of": pop, "edit_distance": d})
                usage = []
                _f(findings, "typosquat", f"'{name}' looks like popular package '{pop}' (edit distance {d})", 8.5,
                   [e1, e2, e3], component=name, version=G.nodes[n]["version"], nodes=[n],
                   project=G.nodes[n]["project"], direct=True, dev_only=bool(G.nodes[n].get("dev")),
                   lookalike_of=pop, signals={"candidate": me, "legit": them}, ecosystem=eco,
                   dependency_paths=dependency_paths(G, n, 1))
                break

    # ---- 3. Anomalous version numbers (dependency-confusion style "6.0.1000") ----
    for n in direct_nodes:
        v = G.nodes[n]["version"]
        segs = [int(x) for x in re.findall(r"\d+", v.split("-")[0])]
        calver = bool(segs) and 1990 <= segs[0] <= 2100       # date-based versions like 2022.12.7 are normal
        if not calver and any(x >= 1000 for x in segs):
            e = ledger.add("heuristic", "version-anomaly", {"package": G.nodes[n]["name"], "version": v,
                           "reason": "a version segment >= 1000 is typical of dependency-confusion / squatting payloads"})
            _f(findings, "suspicious_version", f"{G.nodes[n]['name']}@{v}: anomalous version number", 6.5,
               [e] + G.nodes[n]["evidence"], component=G.nodes[n]["name"], version=v, nodes=[n],
               project=G.nodes[n]["project"], direct=True, dev_only=bool(G.nodes[n].get("dev")))

    # ---- 4. Install scripts (run arbitrary code at `npm install` time) ----
    script_nodes = [n for n in pkg_nodes if G.nodes[n].get("has_install_script")]
    with ThreadPoolExecutor(8) as ex:
        metas = list(ex.map(lambda n: registry.summarize_packument(G.nodes[n]["name"], G.nodes[n]["version"]), script_nodes))
    for n, meta in zip(script_nodes, metas):
        scripts = meta.get("install_scripts") or {}
        sus = {k: s for k, s in scripts.items() if SUSPICIOUS_SCRIPT.search(s)}
        benign = all(BENIGN_SCRIPT.search(s.strip()) for s in scripts.values()) if scripts else False
        e = ledger.add("registry", f"{registry.REGISTRY}/{meta['name']}/{G.nodes[n]['version']}",
                       {"package": meta["name"], "version": G.nodes[n]["version"], "install_scripts": scripts,
                        "suspicious_tokens": bool(sus), "matches_known_build_pattern": benign})
        sev = 8.0 if sus else (2.5 if benign else 4.5)
        _f(findings, "install_script", f"{meta['name']}@{G.nodes[n]['version']} runs an install script", sev,
           [e] + G.nodes[n]["evidence"], component=meta["name"], version=G.nodes[n]["version"], nodes=[n],
           project=G.nodes[n]["project"], direct=bool(G.nodes[n].get("direct")), dev_only=bool(G.nodes[n].get("dev")),
           scripts=scripts, suspicious=sus, dependency_paths=dependency_paths(G, n, 1))

    # ---- 5. Lockfile hygiene & integrity ----
    for proj in inv["projects"]:
        if proj.get("ecosystem") == "pypi" and not proj["lockfile"]:
            unpinned = [n for n in py_nodes if G.nodes[n]["project"] == proj["project"] and not G.nodes[n].get("version")]
            if unpinned:
                e = ledger.add("manifest", ",".join(proj["manifest"]), {"unpinned": [G.nodes[n]["name"] for n in unpinned]})
                _f(findings, "lockfile_uncommitted", f"{proj['project']} (python): {len(unpinned)} requirements are "
                   "not pinned and there is no lockfile — builds are non-reproducible", 5.0, [e],
                   component=",".join(proj["manifest"]), project=proj["project"], direct=True, dev_only=False)
            continue
        if proj["lockfile"] and proj["lock_committed"] is False:
            e = ledger.add("git", f"git ls-files {proj['lockfile']}", {"tracked": False})
            _f(findings, "lockfile_uncommitted", f"{proj['project']}: lockfile is not committed — transitive "
               "versions float on every install (non-reproducible builds)", 6.0, [e], component=proj["lockfile"],
               project=proj["project"], direct=True, dev_only=False)
    for n in npm_nodes:
        d = G.nodes[n]
        bad_src = d.get("resolved") and not d["resolved"].startswith("https://registry.npmjs.org/")
        if bad_src or not d.get("integrity"):
            e = ledger.add("lockfile", f"{d['project']}/package-lock.json#{d.get('lock_path')}",
                           {"resolved": d.get("resolved"), "integrity": d.get("integrity")})
            _f(findings, "lockfile_integrity", f"{d['name']}@{d['version']}: " +
               ("resolved from non-registry source" if bad_src else "no integrity hash"), 7.0 if bad_src else 5.0,
               [e], component=d["name"], version=d["version"], nodes=[n], project=d["project"],
               direct=bool(d.get("direct")), dev_only=bool(d.get("dev")), resolved=d.get("resolved"))

    # ---- 6. Containers ----
    for c in inv["containers"]:
        for img in c["base_images"]:
            if not img["digest"]:
                _f(findings, "unpinned_image", f"{c['file']}:{img['line']} base image '{img['ref']}' is not pinned "
                   "to a digest (mutable tag)", 5.5, [img["evidence"]], component=img["ref"], project=".",
                   direct=True, dev_only=False, file=c["file"], line=img["line"])
        for t in c["build_tools"]:
            spec = t["spec"]
            ver = spec.rsplit("@", 1)[1] if spec.count("@") >= (2 if spec.startswith("@") else 1) else ""
            if not ver or re.search(r"[\^~*|<>x]|latest|\$", ver):
                _f(findings, "unpinned_build_tool", f"{c['file']}:{t['line']} installs '{spec}' with a floating "
                   "version during image build", 5.0, [t["evidence"]], component=spec, project=".", direct=True,
                   dev_only=False, file=c["file"], line=t["line"])
        if c["final_user"] in ("root", "0"):
            e = ledger.add("container", c["file"], {"final_user": c["final_user"]})
            _f(findings, "container_root", f"{c['file']}: container runs as root", 4.0, [e],
               component=c["file"], project=".", direct=True, dev_only=False)

    # ---- 7. CI/CD ----
    for w in inv["workflows"]:
        for a in w["actions"]:
            if not a["sha_pinned"]:
                _f(findings, "unpinned_action", f"{w['file']}:{a['line']} uses '{a['uses']}' (tag, not commit SHA)",
                   5.0, [a["evidence"]], component=a["uses"], project=".", direct=True, dev_only=False,
                   file=w["file"], line=a["line"])
        if w["pull_request_target"]:
            _f(findings, "ci_risky_trigger", f"{w['file']}: uses pull_request_target (runs with secrets on fork PRs)",
               6.0, [w["evidence"]], component=w["file"], project=".", direct=True, dev_only=False, file=w["file"])
        for ln in w["curl_pipe_sh_lines"]:
            _f(findings, "ci_curl_pipe", f"{w['file']}:{ln} pipes a downloaded script into a shell", 6.5,
               [w["evidence"]], component=w["file"], project=".", direct=True, dev_only=False, file=w["file"], line=ln)
    return findings


def lockfile_diff(base: dict, head: dict) -> list[dict]:
    """Compare two package-lock.json documents -> list of change records (for 'what changed?')."""
    bp, hp = base.get("packages", {}), head.get("packages", {})
    changes = []
    for path in sorted(set(bp) | set(hp)):
        if path == "":
            continue
        a, b = bp.get(path), hp.get(path)
        name = path.rsplit("node_modules/", 1)[-1]
        if a and not b:
            changes.append({"change": "removed", "package": name, "path": path, "from": a.get("version")})
        elif b and not a:
            changes.append({"change": "added", "package": name, "path": path, "to": b.get("version"),
                            "resolved": b.get("resolved"), "hasInstallScript": bool(b.get("hasInstallScript")),
                            "integrity": b.get("integrity")})
        else:
            delta = {k: (a.get(k), b.get(k)) for k in ("version", "resolved", "integrity", "hasInstallScript")
                     if a.get(k) != b.get(k)}
            if delta:
                changes.append({"change": "modified", "package": name, "path": path, "delta": delta})
    return changes


def lockfile_diff_findings(changes: list[dict], ledger: Ledger, findings: list[dict], source: str) -> None:
    for c in changes:
        reasons = []
        if c["change"] == "added":
            if c.get("hasInstallScript"):
                reasons.append("new package with an install script")
            if c.get("resolved") and not c["resolved"].startswith("https://registry.npmjs.org/"):
                reasons.append(f"resolved from non-registry URL {c['resolved']}")
            if not c.get("integrity"):
                reasons.append("no integrity hash")
        elif c["change"] == "modified":
            d = c["delta"]
            if "integrity" in d and "version" not in d:
                reasons.append("integrity hash changed WITHOUT a version change (artifact swapped?)")
            if "resolved" in d and d["resolved"][1] and not d["resolved"][1].startswith("https://registry.npmjs.org/"):
                reasons.append(f"resolved URL moved to {d['resolved'][1]}")
            if "hasInstallScript" in d and d["hasInstallScript"][1]:
                reasons.append("version now has an install script")
        if reasons:
            e = ledger.add("lockfile-diff", source, c)
            _f(findings, "lockfile_drift", f"{c['package']}: " + "; ".join(reasons), 8.0, [e],
               component=c["package"], version=(c.get("to") or (c.get("delta", {}).get("version") or [None, None])[1]),
               project=".", direct=False, dev_only=False, change=c)
