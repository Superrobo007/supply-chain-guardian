"""Python / PyPI ecosystem adapter — same pipeline, different "eyes".

Discovers:  requirements*.txt (pinned / ranged), poetry.lock, uv.lock, Pipfile.lock
Vulns:      PyPI JSON API `vulnerabilities` (sourced from the OSV / PyPA advisory DB) + optional GitHub
            advisory API for severity (unauthenticated; silently skipped when unreachable / rate-limited)
Reach:      `import x` / `from x import y` scan of *.py, with distribution->module name mapping
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import networkx as nx

from . import registry
from .ledger import Ledger

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    tomllib = None

PYPI = "https://pypi.org/pypi"
SKIP = {"node_modules", ".git", ".venv", "venv", "env", "site-packages", "dist", "build", "__pycache__"}

# distribution name -> importable module (only where they differ)
MODULE_MAP = {"pyyaml": "yaml", "pillow": "PIL", "beautifulsoup4": "bs4", "scikit-learn": "sklearn",
              "python-dateutil": "dateutil", "opencv-python": "cv2", "protobuf": "google.protobuf",
              "psycopg2-binary": "psycopg2", "pyjwt": "jwt", "python3-openid": "openid", "dj-database-url":
              "dj_database_url", "django-allauth": "allauth", "django-crispy-forms": "crispy_forms",
              "crispy-bootstrap4": "crispy_bootstrap4", "argon2-cffi": "argon2", "pycryptodome": "Crypto",
              "attrs": "attr", "msgpack-python": "msgpack", "python-jose": "jose", "pymysql": "pymysql",
              "requests-oauthlib": "requests_oauthlib", "charset-normalizer": "charset_normalizer"}

POPULAR = """requests urllib3 django flask fastapi numpy pandas scipy matplotlib pillow pyyaml jinja2 werkzeug
cryptography pyjwt sqlalchemy psycopg2 boto3 botocore setuptools pip wheel six certifi idna charset-normalizer
click attrs pytest tox black flake8 mypy pydantic uvicorn gunicorn celery redis lxml beautifulsoup4 selenium
scrapy tensorflow torch scikit-learn colorama python-dateutil pytz tqdm rich typer httpx aiohttp openai anthropic
paramiko fabric ansible docker kubernetes protobuf grpcio markdown pygments sqlparse whitenoise oauthlib
""".split()


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _find(root: Path, pattern: str) -> list[Path]:
    return sorted(p for p in root.rglob(pattern)
                  if not any(part in SKIP for part in p.relative_to(root).parts))


REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(==|~=|>=|<=|!=|>|<)?\s*([^;#\s,]*)")


def parse_requirements(text: str) -> list[tuple[str, str | None, str]]:
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = REQ_LINE.match(line)
        if m:
            name, op, ver = m.group(1), m.group(3), m.group(4)
            out.append((norm(name), ver if op == "==" else None, (op or "") + (ver or "")))
    return out


def discover_pypi(root: Path, ledger: Ledger, G: nx.DiGraph) -> list[dict]:
    projects = []
    dirs: dict[Path, dict] = {}
    for f in _find(root, "requirements*.txt") + _find(root, "poetry.lock") + _find(root, "uv.lock") + \
            _find(root, "Pipfile.lock"):
        dirs.setdefault(f.parent, {}).setdefault("files", []).append(f)
    for d, info in sorted(dirs.items()):
        proj = d.relative_to(root).as_posix() or "."
        proj_id = f"py:{proj}"
        root_node = f"{proj_id}::<root>"
        G.add_node(root_node, kind="project", name=f"{root.name}/{proj} (python)", version=None,
                   project=proj, ecosystem="pypi")
        locked = False
        for f in info["files"]:
            rel = f.relative_to(root).as_posix()
            text = f.read_text(encoding="utf-8", errors="ignore")
            if f.name.startswith("requirements"):
                reqs = parse_requirements(text)
                eid = ledger.add("manifest", rel, {"requirements": [f"{n}{r}" for n, _, r in reqs]})
                dev = any(k in f.name for k in ("dev", "test", "lint", "doc"))
                for name, ver, rng in reqs:
                    nid = f"{proj_id}::{name}"
                    if nid not in G:
                        G.add_node(nid, kind="package", name=name, version=ver, range=rng, project=proj,
                                   ecosystem="pypi", dev=dev, direct=True, manifest=rel, evidence=[eid])
                    G.add_edge(root_node, nid, range=rng)
            elif f.suffix == ".lock" and tomllib and f.name in ("poetry.lock", "uv.lock"):
                locked = True
                data = tomllib.loads(text)
                eid = ledger.add("lockfile", rel, {"packages": len(data.get("package", []))})
                for p in data.get("package", []):
                    nid = f"{proj_id}::{norm(p['name'])}"
                    G.add_node(nid, kind="package", name=norm(p["name"]), version=p.get("version"), project=proj,
                               ecosystem="pypi", dev=p.get("category") == "dev",
                               direct=G.nodes.get(nid, {}).get("direct", False), manifest=rel, evidence=[eid])
                for p in data.get("package", []):
                    deps = p.get("dependencies", {})
                    names = deps.keys() if isinstance(deps, dict) else [x["name"] for x in deps if "name" in x]
                    for dn in names:
                        if f"{proj_id}::{norm(dn)}" in G:
                            G.add_edge(f"{proj_id}::{norm(p['name'])}", f"{proj_id}::{norm(dn)}", range="")
            elif f.name == "Pipfile.lock":
                locked = True
                data = json.loads(text)
                eid = ledger.add("lockfile", rel, {"default": len(data.get("default", {})),
                                                   "develop": len(data.get("develop", {}))})
                for sect, dev in (("default", False), ("develop", True)):
                    for name, meta in data.get(sect, {}).items():
                        nid = f"{proj_id}::{norm(name)}"
                        G.add_node(nid, kind="package", name=norm(name), version=meta.get("version", "").lstrip("="),
                                   project=proj, ecosystem="pypi", dev=dev, direct=True, manifest=rel, evidence=[eid])
                        G.add_edge(root_node, nid, range=meta.get("version", ""))
        # requirements-only projects: deps not reachable from a lock are still direct
        projects.append({"project": proj, "ecosystem": "pypi", "manifest": [f.relative_to(root).as_posix()
                         for f in info["files"]], "lockfile": "yes" if locked else None, "lock_committed": None,
                         "direct": {}})
    return projects


def _pypi_json(name: str, version: str | None = None) -> dict:
    url = f"{PYPI}/{name}/{version}/json" if version else f"{PYPI}/{name}/json"
    try:
        return registry._http(url)
    except Exception as e:
        return {"__error__": str(e)}


_GH_OK = [True]
_OSV_OK = [True]
GHSA_SEV = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "moderate", "MEDIUM": "moderate", "LOW": "low"}


def _osv_severity(vid: str, aliases: list[str]) -> tuple[str | None, float | None]:
    """OSV (osv.dev) record: GHSA-sourced records carry database_specific.severity."""
    if not _OSV_OK[0]:
        return None, None
    for i in [a for a in aliases or [] if a.startswith("GHSA-")] + [vid]:
        try:
            d = registry._http(f"https://api.osv.dev/v1/vulns/{i}", timeout=10)
        except Exception:
            _OSV_OK[0] = False
            return None, None
        sev = GHSA_SEV.get(str((d.get("database_specific") or {}).get("severity", "")).upper())
        if sev:
            return sev, None
    return None, None


def _ghsa_severity(aliases: list[str]) -> tuple[str | None, float | None]:
    for a in aliases or []:
        if a.startswith("GHSA-") and _GH_OK[0]:
            try:
                d = registry._http(f"https://api.github.com/advisories/{a}", timeout=10)
                score = ((d.get("cvss_severities") or {}).get("cvss_v3") or {}).get("score") or \
                        (d.get("cvss") or {}).get("score")
                return d.get("severity"), score
            except Exception:
                _GH_OK[0] = False          # unreachable / rate-limited: severity stays "unknown"
                return None, None
    return None, None


def vulnerabilities(G: nx.DiGraph, nodes: list[str]) -> dict[str, list[dict]]:
    """node -> list of advisories (normalised to the npm-advisory shape the rest of the pipeline uses)."""
    out = {}
    for n in nodes:
        d = G.nodes[n]
        doc = _pypi_json(d["name"], d["version"])
        vulns = [v for v in doc.get("vulnerabilities") or [] if not v.get("withdrawn")]
        advs = []
        for v in vulns:
            sev, score = _osv_severity(v["id"], v.get("aliases"))
            if not sev:
                sev, score = _ghsa_severity(v.get("aliases"))
            cves = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
            advs.append({"id": v["id"], "url": v.get("link") or f"https://osv.dev/vulnerability/{v['id']}",
                         "title": (v.get("summary") or (v.get("details") or "")[:120]).strip().split("\n")[0]
                         or ", ".join(cves) or v["id"],
                         "severity": sev or "unknown", "cvss": {"score": score} if score else {},
                         "vulnerable_versions": f"={d['version']}", "fixed_in": v.get("fixed_in", []),
                         "aliases": v.get("aliases", []), "cwe": []})
        if advs:
            out[n] = advs
    return out


def fix_candidates(name: str, current: str, advs: list[dict]) -> dict:
    from . import semver
    doc = _pypi_json(name)
    releases = [v for v, files in (doc.get("releases") or {}).items()
                if files and not any(f.get("yanked") for f in files) and semver.parse(v) and not semver.is_prerelease(v)]
    releases.sort(key=lambda v: semver.parse(v)[:3])
    # a version is safe if, for every advisory, it is >= some fixed_in on the same release line
    def safe(v):
        for a in advs:
            fx = [x for x in a["fixed_in"] if semver.parse(x)]
            if not fx:
                return False
            same_line = [x for x in fx if semver.parse(x)[:2] == semver.parse(v)[:2]]
            ref = same_line or [x for x in fx if semver.cmp(x, v) <= 0]
            if not ref or not any(semver.cmp(v, x) >= 0 for x in ref):
                return False
        return True
    cands = [v for v in releases if semver.cmp(v, current) > 0 and safe(v)]
    major = semver.parse(current)[0] if semver.parse(current) else None
    same = [v for v in cands if semver.parse(v)[0] == major]
    return {"min_safe": cands[0] if cands else None, "min_safe_same_major": same[0] if same else None,
            "latest_safe": cands[-1] if cands else None, "latest": (doc.get("info") or {}).get("version"),
            "fixed_in": sorted({x for a in advs for x in a["fixed_in"]})}


def summarize(name: str) -> dict:
    doc = _pypi_json(name)
    if "__error__" in doc or not doc.get("info"):
        return {"name": name, "exists": False}
    info = doc["info"]
    rel = doc.get("releases") or {}
    first = min((f["upload_time"] for files in rel.values() for f in files if f.get("upload_time")), default=None)
    return {"name": name, "exists": True, "summary": (info.get("summary") or "")[:300], "author": info.get("author"),
            "home_page": info.get("home_page") or (info.get("project_urls") or {}).get("Homepage"),
            "release_count": len(rel), "first_release": first, "latest": info.get("version")}


def import_sites(root: str, dist: str) -> dict:
    mod = MODULE_MAP.get(dist, dist.replace("-", "_"))
    top = mod.split(".")[0]
    pat = re.compile(rf"^\s*(?:from\s+{re.escape(mod)}(?:\.[\w.]+)?\s+import\s+([\w ,()*]+)|import\s+{re.escape(mod)}\b)",
                     re.M | re.I)
    prod, test, symbols = [], [], set()
    for p in Path(root).rglob("*.py"):
        if any(s in p.parts for s in SKIP):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if top.lower() not in text.lower():
            continue
        rel = p.relative_to(root).as_posix()
        for m in pat.finditer(text):
            line_no = text[:m.start()].count("\n") + 1
            hit = {"file": rel, "line": line_no, "code": text.splitlines()[line_no - 1].strip()[:200]}
            (test if re.search(r"(^|/)(tests?|testing)/|test_|_test\.py", rel) else prod).append(hit)
            if m.group(1):
                symbols |= {s.strip(" ()") for s in m.group(1).split(",") if s.strip(" ()")}
    return {"prod": prod, "test": test, "symbols_used": sorted(symbols)[:30]}
