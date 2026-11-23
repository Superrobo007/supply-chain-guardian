#!/usr/bin/env bash
# Create .venv on Macs where pip/uv fail with an empty platform.mac_ver().
# Usage: scripts/mac_venv.sh [/path/to/python3.12]
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${1:-/opt/homebrew/bin/python3.12}"
export PIP_USER=0 PIP_CONFIG_FILE=/dev/null
rm -rf .venv
"$PY" -m venv --without-pip .venv
SP="$(.venv/bin/python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
cp scripts/macver_fix.py "$SP/_guardian_macver_fix.py"
echo "import _guardian_macver_fix" > "$SP/_guardian_macver_fix.pth"
echo "macOS version seen by Python now: $(.venv/bin/python -c 'import platform; print(platform.mac_ver()[0] or "(empty)")')"
if command -v uv >/dev/null 2>&1; then
  # uv installs into the patched venv without needing pip at all
  uv pip install --python .venv/bin/python -r requirements.txt
else
  # unpack the pip wheel bundled with Python straight into the venv (skips ensurepip's self-install step)
  WHL="$(.venv/bin/python -c 'import ensurepip,os,glob; print(sorted(glob.glob(os.path.join(os.path.dirname(ensurepip.__file__),"_bundled","pip-*.whl")))[-1])')"
  .venv/bin/python -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$WHL" "$SP"
  .venv/bin/python -m pip install -q -r requirements.txt
fi
.venv/bin/python -c "import networkx, rapidfuzz, pydantic, anthropic; print('DEPS-OK')"
