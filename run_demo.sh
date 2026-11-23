#!/usr/bin/env bash
# Day 1 + Day 2 planning + the "what changed?" tamper scenario. Approval/validation stay manual (human gate).
set -euo pipefail
cd "$(dirname "$0")"
[ -d .venv ] && . .venv/bin/activate
[ -z "${ANTHROPIC_API_KEY:-}" ] && echo "(no ANTHROPIC_API_KEY set -> agents run in offline deterministic mode)"
python -m guardian.cli day1 --target targets/juice-shop --investigate 8
python -m guardian.cli plan --top 6
python -m guardian.cli plan --ids F-018
python -m guardian.cli report
python -m guardian.cli verify-ledger
python scenarios/tamper_lockfile.py targets/juice-shop targets/juice-shop-tampered
python -m guardian.cli --out out-tampered day1 --target targets/juice-shop-tampered \
  --base-lock targets/juice-shop.base-package-lock.json --investigate 3
echo
echo "Reports: out/report.html  out-tampered/report.html"
echo "Now approve + validate (you are the human in the loop):"
echo "  python -m guardian.cli approve F-018 --by <your-name> && python -m guardian.cli validate F-018"
echo
echo "Or do it all in the web console:  python -m guardian.cli dashboard"
