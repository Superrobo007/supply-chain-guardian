#!/usr/bin/env bash
# One-time setup (macOS / Linux). Needs: python3 >= 3.10, node + npm (>= 18), git.
set -euo pipefail
cd "$(dirname "$0")"
command -v npm >/dev/null     || { echo "Install Node.js 18+ (brew install node)"; exit 1; }
command -v git >/dev/null     || { echo "Install git (xcode-select --install)"; exit 1; }

# Pick a STABLE Python 3.10-3.14. Pre-releases (e.g. 3.15 from Homebrew) break ensurepip and have no
# binary wheels for pydantic/rapidfuzz yet. Override with:  PYTHON=/path/to/python3.12 ./setup.sh
PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  for c in python3.13 python3.12 python3.14 python3.11 python3.10 python3 \
           /opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12 /usr/local/bin/python3.12; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; v=sys.version_info; raise SystemExit(0 if (3,10)<=v[:2]<=(3,14) and v.releaselevel=="final" else 1)' 2>/dev/null; then
      PY="$c"; break
    fi
  done
fi
if [ -z "$PY" ]; then
  echo "No stable Python 3.10-3.14 found (python3 is $(python3 --version 2>&1))."
  echo "Fix:  brew install python@3.12   then re-run ./setup.sh"
  exit 1
fi
echo "Using $PY ($("$PY" --version))"

# pip robustness on macOS:
#  - a global pip.conf with `user = true` breaks installs inside a venv
#  - if Python reports an empty macOS version, pip's truststore import crashes -> use certifi instead
export PIP_USER=0
if [ "$(uname)" = "Darwin" ] && [ -z "$("$PY" -c 'import platform; print(platform.mac_ver()[0])')" ]; then
  echo "Note: Python cannot read the macOS version; using pip's legacy certificate handling."
  export PIP_USE_DEPRECATED=legacy-certs
fi

# Reuse a working venv (e.g. one created by uv); otherwise create it.
if [ -x .venv/bin/python ] && .venv/bin/python -c "import networkx, rapidfuzz, pydantic, anthropic" 2>/dev/null; then
  echo "Existing .venv already has the dependencies."
elif [ "$(uname)" = "Darwin" ] && [ -z "$("$PY" -c 'import platform; print(platform.mac_ver()[0])')" ]; then
  # Python reports an empty macOS version here: pip and uv both crash on that. Patch it inside the venv only.
  echo "Python cannot read the macOS version on this Mac; applying the venv-local fix (scripts/mac_venv.sh)."
  scripts/mac_venv.sh "$PY"
elif command -v uv >/dev/null 2>&1; then
  # uv (brew install uv) needs no pip/ensurepip -> immune to the macOS pip bootstrap bugs
  rm -rf .venv
  uv venv --python "$PY" .venv
  VIRTUAL_ENV="$PWD/.venv" uv pip install -r requirements.txt
else
  rm -rf .venv
  if ! "$PY" -m venv .venv; then
    echo
    echo "Creating the venv with pip failed (a known pip bootstrap bug on some Macs)."
    echo "Fix:  brew install uv   then re-run ./setup.sh"
    exit 1
  fi
  .venv/bin/python -m pip install -q --upgrade pip
  .venv/bin/python -m pip install -q -r requirements.txt
fi
. .venv/bin/activate

mkdir -p targets
if [ ! -d targets/juice-shop ]; then
  git clone --depth 1 https://github.com/juice-shop/juice-shop.git targets/juice-shop
fi
# Juice Shop doesn't commit lockfiles: resolve them WITHOUT running any install scripts
(cd targets/juice-shop && npm install --package-lock-only --ignore-scripts --no-audit --no-fund)
(cd targets/juice-shop/frontend && npm install --package-lock-only --ignore-scripts --no-audit --no-fund --legacy-peer-deps)
echo
echo "Setup done. Next:  source .venv/bin/activate && ./run_demo.sh"
