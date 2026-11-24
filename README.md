#Bosch 
# Supply Chain Guardian

*Know what you build. Trust what you ship.* An agentic AI system that discovers the software supply chain of an
application, detects vulnerabilities and suspicious changes, prioritises what actually matters, recommends
remediations from a closed candidate set, and validates them in a sandbox. A human approves every action.

**Target app:** OWASP Juice Shop (https://github.com/juice-shop/juice-shop).
**Day 1 / Day 2 explainer:** [`docs/DAY_PLAN.md`](docs/DAY_PLAN.md).

## Quick start

Requirements: a stable Python 3.10–3.14, Node.js 18+, git. On a Mac, `brew install uv` is recommended: setup then uses uv instead of pip, which avoids pip bootstrap failures some Macs hit. **No GPU needed.** A GPU is optional and only used if you choose the local-model brain below.

**macOS / Linux**
```bash
unzip supply-chain-guardian.zip && cd supply-chain-guardian
./setup.sh                       # venv + deps + clone Juice Shop + lockfiles (~2-3 min)
source .venv/bin/activate
./run_demo.sh
open out/report.html             # Linux: xdg-open
```

**Windows 10/11 (PowerShell)**
```powershell
Expand-Archive supply-chain-guardian.zip -DestinationPath . ; cd supply-chain-guardian
powershell -ExecutionPolicy Bypass -File .\setup.ps1
.\.venv\Scripts\Activate.ps1
powershell -ExecutionPolicy Bypass -File .\run_demo.ps1
start out\report.html
```
If `git clone` fails on long paths: `git config --global core.longpaths true` (run as admin once).

## Dashboard (web console)

```bash
python -m guardian.cli dashboard        # opens http://127.0.0.1:8765
```
A bright, interactive console on top of the same pipeline: overview KPIs and charts, a filterable findings table with
evidence, AI claims and score breakdowns, an interactive **risk map** of how each risky package enters the app,
remediation cards where you **approve fixes under your name** and run sandbox validation with live logs, policy/ledger
audit, and a form to scan any repository. It binds to 127.0.0.1 only.

Stack: React 19 + TypeScript, Vite 7, Tailwind CSS 4, TanStack Query and Table, React Flow (@xyflow) with dagre layout,
Recharts, Radix UI primitives, Sonner, served by a FastAPI backend (`guardian/server.py`).
The built UI ships in `guardian/web/`, so Node is not needed to use it. To change the UI:
```bash
cd dashboard && npm ci && npm run dev      # hot reload on :5173 (start the dashboard server too)
npm run build                              # writes guardian/web/
```
Frontend dependencies were installed with `npm install --before=<date>` (only releases at least two weeks old), and the
lockfile is committed, which is the practice the Guardian checks other projects for.

## Choosing the "brain" (who runs the AI agents)

| Mode | How to enable | Runs on | Notes |
|---|---|---|---|
| `claude` | set `ANTHROPIC_API_KEY` | Anthropic's cloud | Strongest reasoning; costs API credits; nothing runs on your GPU |
| `ollama` | install [Ollama](https://ollama.com), `ollama pull qwen2.5:7b`, set `GUARDIAN_LLM=ollama` | **your GPU** (NVIDIA CUDA on Windows/Linux, Metal on Apple Silicon) | Free, private, offline after download; weaker than Claude on multi-step tool use |
| `offline` | default when neither is configured, or `GUARDIAN_LLM=offline` | CPU | Deterministic rules, no AI, but the pipeline still works end to end |

```bash
# local GPU (bash)                     # local GPU (PowerShell)
ollama pull qwen2.5:7b                 # ollama pull qwen2.5:7b
export GUARDIAN_LLM=ollama             # $env:GUARDIAN_LLM="ollama"
./run_demo.sh                          # .\run_demo.ps1
```
Model size guide: 8 GB RAM/VRAM → `qwen2.5:7b` (default). 12–16 GB VRAM → `GUARDIAN_OLLAMA_MODEL=qwen2.5:14b`. 24 GB+ → `qwen2.5:32b`.
The AI only reasons over the top findings. Discovery, detection, scoring, policy and validation are plain code in every mode.

## Scanning any repository
```bash
python -m guardian.cli --out out-myrepo day1 --prepare --target https://github.com/<owner>/<repo>
python -m guardian.cli --out out-myrepo day1 --prepare --target C:\path\to\local\repo
```
`--prepare` generates missing `package-lock.json` files with install scripts disabled.

| Ecosystem / artifact | Supported files |
|---|---|
| JavaScript / TypeScript (npm) | `package.json`, `package-lock.json` (v2/v3); `--prepare` creates missing locks |
| Python (PyPI) | `requirements*.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock` |
| Containers | every `Dockerfile` (base-image pinning, floating tool installs, root user) |
| CI/CD | `.github/workflows/*.yml` (SHA pinning, `pull_request_target`, `curl \| sh`) |
| Not yet | Maven/Gradle, Go, Cargo, NuGet, yarn/pnpm locks: add a `guardian/eco_<name>.py` adapter (see `eco_pypi.py`) |

Python severities come from OSV (osv.dev) or the GitHub advisory API. If both are unreachable or rate-limited, severity shows as "unknown" (base score 6.5).

## Manual setup
```bash
git clone --depth 1 https://github.com/juice-shop/juice-shop targets/juice-shop
# Juice Shop does not commit lockfiles; generate them WITHOUT running install scripts:
(cd targets/juice-shop && npm install --package-lock-only --ignore-scripts)
(cd targets/juice-shop/frontend && npm install --package-lock-only --ignore-scripts --legacy-peer-deps)
pip install -r requirements.txt
export ANTHROPIC_API_KEY=...     # optional; without it the agents run in deterministic offline mode
# optional: install OPA (https://www.openpolicyagent.org/docs/#running-opa) to evaluate policy/guardian.rego natively
```

## Run
```bash
python -m guardian.cli day1 --target targets/juice-shop --investigate 8   # discover → detect → score → AI triage
python -m guardian.cli plan --top 6                                          # remediation plans (pending approval)
python -m guardian.cli approve F-018 --by <your-name>                        # human approval (ledger-recorded)
python -m guardian.cli validate F-018                                        # sandbox apply → rescan → diff → PR patch
python -m guardian.cli report && python -m guardian.cli verify-ledger
python -m guardian.cli monitor                                               # continuous re-check (cron/CI)
```
Finding IDs depend on the run, so take them from `out/report.md`.

Outputs in `out/`: `sbom.cdx.json`, `graph.json`, `report.{md,html,json}`, `ledger.jsonl`, `prs/*.patch|md`.

Configuration: `GUARDIAN_LLM` (`claude`/`ollama`/`offline`), `GUARDIAN_OLLAMA_MODEL` (default `qwen2.5:7b`), `GUARDIAN_OLLAMA_URL`, `GUARDIAN_MODEL` (default `claude-opus-5-5`), `GUARDIAN_EFFORT` (default `medium`),
`GUARDIAN_OFFLINE=1` to force offline mode, `GUARDIAN_CACHE` for the HTTP cache directory.
The agent calls enable server-side refusal fallbacks (`fallbacks="default"`); if a request is still declined,
the Guardian falls back to the deterministic assessment for that finding.

## Layout
```
guardian/ledger.py        hash-chained evidence ledger (E-xxxx IDs)
guardian/discover.py      manifests, lockfiles (npm resolution), Dockerfiles, GitHub Actions → graph
guardian/sbom.py          CycloneDX 1.6 SBOM + SBOM diff
guardian/registry.py      npm registry + GitHub Advisory DB (bulk API), cached, read-only
guardian/semver.py        npm range evaluator
guardian/detect.py        CVEs, typosquats, version anomalies, install scripts, lockfile drift, Docker, CI
guardian/reachability.py  static import reachability + used symbols
guardian/risk.py          explainable risk score
guardian/agents.py        Investigator (tool loop) · Skeptic (verifier) · Remediator (closed action space)
guardian/llm_local.py     local-GPU brain via Ollama (same agents, same guards)
guardian/eco_pypi.py      Python ecosystem adapter (requirements / poetry / uv / Pipfile)
guardian/policy.py        OPA gate (+ Python mirror)      policy/guardian.rego
guardian/validate.py      sandbox apply, re-resolve, rescan, SBOM diff, API-compat probe, patch
guardian/report.py        JSON / Markdown / HTML report
guardian/server.py        FastAPI backend for the dashboard (API + background jobs)
guardian/web/             prebuilt dashboard UI
dashboard/                dashboard source (React + TypeScript)
scenarios/tamper_lockfile.py   local-only simulated lockfile attack for the "what changed?" demo
```

## Responsible AI & security
- The AI never produces facts. Tools write evidence and the AI cites it. Claims are labelled VERIFIED or INFERENCE.
- The Skeptic downgrades unsupported claims. The Remediator cannot invent versions.
- Registry text, install scripts and source code reach the model only inside `<untrusted_data>` fences (prompt-injection defence).
- Model tools are read-only. Key and secret files are refused and secret patterns are redacted.
- No install scripts are executed (`--ignore-scripts` everywhere). Nothing is published, pushed, merged or deployed.
- Validation requires a recorded human approval (OPA `remediation_allowed`). `auto_merge_allowed := false`.
