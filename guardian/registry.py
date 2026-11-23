"""npm registry + GitHub Advisory (via npm bulk advisory API) clients, with an on-disk cache.

Read-only: the Guardian never publishes anything to a registry.
"""
from __future__ import annotations

import hashlib
import json
import os
import ssl
import urllib.error
import urllib.request
from pathlib import Path

REGISTRY = "https://registry.npmjs.org"
BULK_ADVISORY = f"{REGISTRY}/-/npm/v1/security/advisories/bulk"
CACHE = Path(os.environ.get("GUARDIAN_CACHE", Path.home() / ".cache" / "guardian"))


def _ctx():
    ca = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
    if not ca:
        try:  # python.org builds on macOS ship without system CA certs -> use certifi's bundle
            import certifi
            ca = certifi.where()
        except ImportError:
            pass
    return ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()


def _http(url: str, body: dict | None = None, timeout: int = 60):
    key = hashlib.sha256((url + json.dumps(body, sort_keys=True)).encode()).hexdigest()
    cf = CACHE / f"{key}.json"
    if cf.exists() and os.environ.get("GUARDIAN_NO_CACHE") != "1":
        return json.loads(cf.read_text(encoding="utf-8"))
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={
        "content-type": "application/json", "accept": "application/json",
        "user-agent": "supply-chain-guardian/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
            out = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            out = {"__error__": 404}
        else:
            raise
    CACHE.mkdir(parents=True, exist_ok=True)
    cf.write_text(json.dumps(out), encoding="utf-8")
    return out


def packument(name: str) -> dict:
    """Full registry document for a package (all versions, times, maintainers)."""
    return _http(f"{REGISTRY}/{name.replace('/', '%2F')}")


def bulk_advisories(pkgs: dict[str, list[str]], batch: int = 250) -> dict[str, list[dict]]:
    """{name: [versions]} -> {name: [advisory...]} for advisories affecting any listed version."""
    out: dict[str, list[dict]] = {}
    names = sorted(pkgs)
    for i in range(0, len(names), batch):
        chunk = {n: sorted(set(pkgs[n])) for n in names[i:i + batch]}
        res = _http(BULK_ADVISORY, chunk)
        for n, advs in res.items():
            if isinstance(advs, list):
                out.setdefault(n, []).extend(advs)
    return out


def summarize_packument(name: str, version: str | None = None) -> dict:
    """Trust-relevant registry signals for a package (and optionally one version)."""
    p = packument(name)
    if p.get("__error__") == 404:
        return {"name": name, "exists": False}
    times = p.get("time", {})
    versions = p.get("versions", {})
    v = versions.get(version or p.get("dist-tags", {}).get("latest", ""), {})
    scripts = {k: s for k, s in (v.get("scripts") or {}).items()
               if k in ("preinstall", "install", "postinstall", "prepare")}
    return {
        "name": name,
        "exists": True,
        "description": (p.get("description") or "")[:300],
        "created": times.get("created"),
        "modified": times.get("modified"),
        "latest": p.get("dist-tags", {}).get("latest"),
        "version_count": len(versions),
        "maintainers": [m.get("name") for m in p.get("maintainers", [])],
        "repository": (p.get("repository") or {}).get("url") if isinstance(p.get("repository"), dict) else p.get("repository"),
        "deprecated": v.get("deprecated"),
        "install_scripts": scripts,
        "version_published": times.get(version) if version else None,
        "has_provenance": bool((v.get("dist") or {}).get("attestations")),
    }
