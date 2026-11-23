"""Evidence Ledger — the backbone of the Guardian.

Every fact any component learns (a manifest entry, an advisory, a registry
metadata field, a grep hit, a test result, a human approval) is written here as
an *evidence record* with a stable ID (E-0001 ...). Records are hash-chained
(each record stores the SHA-256 of the previous one), so the audit trail is
tamper-evident: editing any past record breaks `verify()`.

AI agents never invent facts: every claim they make must cite evidence IDs that
exist in this ledger. Claims that cite nothing are labelled "inference".
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


class Ledger:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.records: dict[str, dict] = {}
        self._last_hash = GENESIS
        self._dedupe: dict[str, str] = {}
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    rec = json.loads(line)
                    self.records[rec["id"]] = rec
                    self._last_hash = rec["hash"]
                    self._dedupe[self._key(rec["kind"], rec["source"], rec["data"])] = rec["id"]

    @staticmethod
    def _key(kind: str, source: str, data: Any) -> str:
        return hashlib.sha256(json.dumps([kind, source, data], sort_keys=True, default=str).encode()).hexdigest()

    def add(self, kind: str, source: str, data: Any, actor: str = "tool") -> str:
        """Append an evidence record and return its ID. Identical facts are de-duplicated."""
        k = self._key(kind, source, data)
        if k in self._dedupe:
            return self._dedupe[k]
        eid = f"E-{len(self.records) + 1:04d}"
        body = {
            "id": eid,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "kind": kind,          # e.g. manifest, lockfile, advisory, registry, reachability, test, approval
            "source": source,      # where the fact came from (file path, URL, command)
            "actor": actor,        # tool | ai:<agent> | human:<name>
            "data": data,
            "prev": self._last_hash,
        }
        body["hash"] = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(body, default=str) + "\n")
        self.records[eid] = body
        self._last_hash = body["hash"]
        self._dedupe[k] = eid
        return eid

    def get(self, eid: str) -> dict | None:
        return self.records.get(eid)

    def exists(self, eid: str) -> bool:
        return eid in self.records

    def verify(self) -> tuple[bool, str]:
        """Re-compute the hash chain. Returns (ok, message)."""
        prev = GENESIS
        for rec in self.records.values():
            body = {k: v for k, v in rec.items() if k != "hash"}
            if body["prev"] != prev:
                return False, f"chain broken before {rec['id']}"
            h = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
            if h != rec["hash"]:
                return False, f"record {rec['id']} was modified"
            prev = rec["hash"]
        return True, f"{len(self.records)} records, chain intact, head={prev[:12]}"
