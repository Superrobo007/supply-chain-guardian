"""Minimal npm-semver range evaluator (enough for advisory `vulnerable_versions`)."""
from __future__ import annotations

import re

_V = re.compile(r"^v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$")


def parse(v: str):
    m = _V.match(v.strip())
    if not m:
        return None
    major, minor, patch, pre = m.groups()
    def num(x):
        return 0 if x in (None, "x", "*") else int(x)
    pre_t = tuple(int(p) if p.isdigit() else p for p in pre.split(".")) if pre else None
    return (num(major), num(minor), num(patch), pre_t)


def _cmp_pre(a, b):
    if a == b:
        return 0
    if a is None:
        return 1      # release > prerelease
    if b is None:
        return -1
    for x, y in zip(a, b):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, int):
            return -1
        if isinstance(y, int):
            return 1
        return -1 if x < y else 1
    return -1 if len(a) < len(b) else (1 if len(a) > len(b) else 0)


def cmp(a: str, b: str) -> int:
    pa, pb = parse(a), parse(b)
    if pa is None or pb is None:
        return 0
    if pa[:3] != pb[:3]:
        return -1 if pa[:3] < pb[:3] else 1
    return _cmp_pre(pa[3], pb[3])


def _sat(v: str, comp: str) -> bool:
    comp = comp.strip()
    if comp in ("", "*", "x"):
        return True
    m = re.match(r"^(<=|>=|<|>|=)?\s*(.+)$", comp)
    op, ver = m.group(1) or "=", m.group(2)
    c = cmp(v, ver)
    return {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "=": c == 0}[op]


def satisfies(version: str, rng: str) -> bool:
    if parse(version) is None:
        return False
    for alt in rng.split("||"):
        alt = re.sub(r"(<=|>=|<|>|=)\s+", r"\1", alt.strip())
        if " - " in alt:
            lo, hi = alt.split(" - ")
            parts = [f">={lo}", f"<={hi}"]
        else:
            parts = alt.split()
        if all(_sat(version, p) for p in parts):
            return True
    return False


def is_prerelease(v: str) -> bool:
    p = parse(v)
    return bool(p and p[3])
