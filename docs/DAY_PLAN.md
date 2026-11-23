# Supply Chain Guardian — Day 1 / Day 2 build breakdown

> Use this to learn the system and to explain it to the judges.
> Each step lists **what we build → which file → what to say → what to demo**.

---

## 0. The target application: OWASP Juice Shop

**Repo:** https://github.com/juice-shop/juice-shop (MIT, intentionally insecure, maintained by OWASP)

Why this repo fits the problem statement:

| Requirement in the brief | Juice Shop |
|---|---|
| Free, open-source, public | MIT, GitHub |
| Realistic tree of direct and transitive dependencies | **2,111 npm packages** across 2 projects (server `.` and Angular `frontend`), 161 direct |
| Containerised, runs locally | `Dockerfile` (multi-stage node:24 → distroless), `docker run -p 3000:3000 bkimminich/juice-shop` |
| Has a CI/CD pipeline to inspect | 16 GitHub Actions workflows |
| Build, test and scan locally | `npm install && npm test`, `npm run sbom` |

**Supply-chain problems already in the repo** (what the Guardian finds):

| # | Problem | Category from the brief | Where |
|---|---|---|---|
| 1 | `jsonwebtoken@0.4.0` (+ nested `0.1.0` via express-jwt) — verification bypass, **Critical** | Vulnerable direct and transitive dependency | `package.json`, used in `lib/insecurity.ts` |
| 2 | `express-jwt@0.1.3` — authorisation bypass | Vulnerable direct dependency | `lib/insecurity.ts:10` |
| 3 | `sanitize-html@1.4.2` — XSS / ReDoS | Vulnerable direct dependency, **reachable** | `lib/insecurity.ts:13` |
| 4 | `lodash@2.4.2`, `crypto-js`, `moment`, `uuid`, `ws` … | Vulnerable transitive dependencies | pulled in by other packages |
| 5 | `marsdb@0.6.11` command injection, `notevil` sandbox escape | Vulnerable direct dependency | `package.json` |
| 6 | **`ngy-cookie`**, a look-alike of **`ngx-cookie`**, at the odd version `6.0.1000` | Typosquatted / malicious package | `frontend/package.json`, 10 imports |
| 7 | No committed `package-lock.json` | Unexpected lockfile / dependency change | repo root + frontend |
| 8 | `node:24`, `gcr.io/distroless/...`, `alpine` not pinned to a digest | Untrusted container image | `Dockerfile`s |
| 9 | `npm install -g typescript@^6.0.3` and `cyclonedx-npm@^2‖^3‖^4` during the image build | Unpinned CI/CD component | `Dockerfile:4,18` |
| 10 | `curl https://cli-assets.heroku.com/install.sh \| sh` | Unsafe CI/CD component | `ci.yml:353` |
| 11 | `pull_request_target` trigger | Unsafe CI/CD component (needs review) | `pr-compliance.yml` |
| 12 | 17 installed copies of 14 packages with install scripts (`sqlite3`, `esbuild`, `cypress`, `@scarf/scarf`, `@fortawesome/*`…) | Suspicious install script | lockfile `hasInstallScript` |
| 13 | Simulated: integrity hash changed without a version bump, plus an injected `flatmap-stream` from a non-registry URL | Suspicious package update / modified lockfile | `scenarios/tamper_lockfile.py` (local only) |

> ⚠️ The CVEs in Juice Shop are intentional (they are hacking challenges). Our remediation is
> correct security engineering, but it would "fix" the training challenges, so it is only applied in a sandbox copy.

---

## Architecture in one picture

```
              ┌──────────────────────── DETERMINISTIC EVIDENCE PLANE ────────────────────────┐
 repo ──► DISCOVER ──► DETECT ──────────► SCORE ──┐                                         │
 (manifests,  (graph,   (GHSA advisories, (reach ×   │        Evidence Ledger (hash-chained)   │
  locks,       SBOM)     typosquat, lock   exposure  │◄────── every fact = E-xxxx record ────►│
  Docker, CI)            hygiene, Docker,  × env)    │                                         │
                         CI, install scr.)           │                                         │
              └──────────────────────────────────────┼─────────────────────────────────────────┘
                                                     ▼
              ┌──────────────────────── AI REASONING PLANE (Claude) ──────────────────────────┐
              │  Investigator agent ──(read-only tools)──► assessment with typed claims         │
              │        │                                  "verified_fact" must cite E-xxxx      │
              │        ▼                                                                         │
              │  Skeptic agent ── checks IDs exist (code) + evidence really supports (AI)       │
              │        ▼                                                                         │
              │  Remediator agent ── must pick a target from a registry-computed candidate set  │
              └────────────────────────────────────┬─────────────────────────────────────────────┘
                                                   ▼
          OPA policy gate ──► HUMAN APPROVAL ──► sandbox apply ──► re-resolve lock (scripts OFF)
          (deny / warn /        (ledger record)      ──► rescan ──► SBOM diff ──► API-compat probe
           remediation_allowed)                      ──► PR-ready patch + PR body (never merged)
                                                   ▼
                                  Guardian Report (JSON + Markdown + HTML)
```

### Why this is not "the usual" agent framework

We deliberately **don't** use LangChain or CrewAI. The design rests on four ideas that you can defend:

1. **Evidence-ledger architecture.** The LLM never produces facts. Tools produce facts and write them to a
   SHA-256 hash-chained ledger (`guardian/ledger.py`). The AI only reasons over them and must cite IDs.
   Tampering with any record breaks `verify-ledger`, so the audit trail is tamper-evident.
2. **Adversarial agent pair.** An Investigator proposes and a Skeptic attacks, so the agents check each other.
   Hallucinations are caught in two layers: in code (do the cited IDs exist?) and by AI (does the evidence say that?).
3. **Closed action space.** The Remediator picks from options computed in code (safe versions from
   the registry and advisory ranges). It cannot invent a version number, and an invented one is rejected.
4. **Policy-as-code plus a human gate.** OPA/Rego decides what may happen (`policy/guardian.rego`).
   `auto_merge_allowed := false` is hard-coded. Validation runs only after `approve --by <human>`.

The agent loop uses the **raw Claude Messages API with native tool use, strict JSON-schema tools and
structured outputs** (`client.messages.parse`). That gives full control of the loop, which is required for
gating, fencing untrusted data and logging every tool call to the ledger.

---

## DAY 1 — "Build the Guardian's Eyes" (visibility + detection)

Checkpoint question: *"Show us what is in the application, what changed, and what appears risky."*

### Step 1 · Discover components — `guardian/discover.py`
- Parses every `package.json` + `package-lock.json` (v3), every `Dockerfile`, every `.github/workflows/*.yml`.
- Rebuilds the real dependency tree using **npm's node_modules resolution algorithm** (`_resolve`: walk up
  `node_modules` directories). That is how we know which parent pulled in which transitive package.
- **Say:** "We don't just list packages. We rebuild the graph exactly the way npm resolves it, so every
  transitive package can be traced back to the direct dependency that pulled it in."
- **Learn:** direct vs transitive, `dev` flag, `resolved` URL, `integrity` (SRI sha512), `hasInstallScript`.

### Step 2 · Build the supply chain view — `guardian/sbom.py`
- Generates a **CycloneDX 1.6** SBOM (`out/sbom.cdx.json`) with purls, hashes, scope, distribution URL,
  dependency relationships, plus container base images and GitHub Actions as components.
- Dependency graph exported as `out/graph.json` (networkx node-link). `dependency_paths()` = shortest root→package paths.
- Inspects the container (base images, digests, global build tools, USER, EXPOSE) and CI (action pinning,
  `pull_request_target`, `curl | sh`).
- **Say:** "The SBOM includes the build supply chain (images and CI actions), not only libraries."

### Step 3 · Detect vulnerabilities — `guardian/detect.py` (part 1)
- Queries the **GitHub Advisory Database via npm's bulk advisory API** for all 2,111 packages in batches.
- Matches versions against `vulnerable_versions` ranges with our own npm-semver evaluator (`guardian/semver.py`).
- Computes **fix candidates** from the full registry version list: `min_safe_same_major`, `min_safe`, `latest_safe`
  (a version counts as safe only if it falls in no known advisory range).
- Records **parent constraints** (e.g. "express-jwt wants jsonwebtoken ~0.1.0"). These tell us whether a lockfile
  refresh is enough or an `overrides` entry / parent upgrade is needed.

### Step 4 · Detect suspicious changes (non-CVE) — `guardian/detect.py` (part 2)
| Detector | Signal |
|---|---|
| Typosquat | Damerau-Levenshtein distance 1 to a popular package, `-js`/`node-` affixes, scoped vs scoped only. The registry metadata of both packages is stored as evidence |
| Version anomaly | a version segment ≥ 1000 (`6.0.1000`), typical of dependency-confusion payloads |
| Install scripts | registry `scripts.preinstall/install/postinstall`, scanned for `curl`, `\| sh`, `base64`, `eval`, `child_process`, env access… |
| Lockfile hygiene | lockfile not committed; `resolved` not from registry; missing integrity |
| **Lockfile diff** ("what changed?") | added/removed/modified packages; **integrity changed without a version change**; new install script; non-registry URL |
| Containers | tag without `@sha256` digest; floating global tool installs; runs as root |
| CI/CD | action not pinned to a 40-char SHA; `pull_request_target`; `curl \| sh` |

Demo of "what changed":
```bash
python scenarios/tamper_lockfile.py targets/juice-shop targets/juice-shop-tampered
python -m guardian.cli --out out-tampered day1 --target targets/juice-shop-tampered \
       --base-lock targets/juice-shop.base-package-lock.json
```

### Step 5 · Present evidence — `guardian/risk.py`, `guardian/agents.py`, `guardian/report.py`
- Every finding shows: **component, dependency path, evidence IDs, reachability, initial risk level**.
- Reachability (`guardian/reachability.py`) is a static import scan of app source, excluding tests:
  `reachable_direct` / `transitive_of_reachable` / `dev_or_test_only` / `unreferenced`, plus **which symbols are used**
  (e.g. jsonwebtoken: `sign`, `verify`, `decode`).
- Output: `out/report.md|html|json`, `out/ledger.jsonl`.

**Day 1 command:**
```bash
python -m guardian.cli day1 --target targets/juice-shop --investigate 8
```

---

## DAY 2 — "Build the Guardian's Brain & Shield" (reasoning + safe action + verification)

Final demo question: *"Show us how the Guardian takes a finding from detection to verified remediation."*

### Step 1 · Prioritise risks — `guardian/risk.py`
```
risk = base_severity(CVSS) × reachability × exposure × environment        (each factor stored → explainable)
reachability: reachable_direct 1.0 · transitive_of_reachable 0.85 · unreferenced 0.55 · dev/test 0.3
exposure: network-exposed server (EXPOSE 3000) 1.0 · browser bundle 0.8
environment: dev-only 0.4 · production 1.0
malicious classes (typosquat, lockfile drift, suspicious scripts) force all factors to 1.0 (they run at install time)
```
Buckets: Critical ≥ 9, High ≥ 7, Medium ≥ 4, Low. Confidence rises with how much evidence is known.
**Say:** "A CVSS 9.8 bug in a dev-only test helper scores lower than a 7.5 bug in code we actually call."

### Step 2 · Investigate suspicious changes — Investigator agent (`agents.investigate`)
- A Claude tool-use loop with **read-only tools**: `get_evidence`, `dependency_paths`, `find_usages`,
  `registry_metadata`, `read_source` (sandboxed to the repo; refuses `encryptionkeys/`, `*.key`, `.env`; redacts secrets).
- Ends with `submit_assessment` (strict schema): verdict, adjusted priority, confidence, and **typed claims**.
- **Skeptic** (`agents.skeptic`): code layer (cited IDs exist; facts must cite something), then AI layer (does each
  cited record support the claim?). Unsupported facts are downgraded to INFERENCE and the confidence drops.
- The report shows ✅ VERIFIED vs 💭 INFERENCE for every claim. This is the brief's
  "clearly separate verified evidence from AI-generated inference".

### Step 3 · Recommend safe remediation — Remediator agent (`agents.remediate`, `agents.candidates`)
- Candidate set computed in code per finding type: upgrade (same-major / min-safe / latest-safe),
  `overrides` pin for transitive deps, replace look-alike with the legitimate package, block, digest-pin,
  exact-pin, commit lockfile, mitigate, escalate.
- The AI picks one, explains risk reduction, compatibility impact and rollback. A target outside the set is rejected.
```bash
python -m guardian.cli plan --top 6           # writes plans, status "awaiting approval"
```

### Step 4 · Validate the proposed fix — `guardian/validate.py`
Runs **only after a human approves** (`approve F-018 --by <your-name>`); the OPA rule `remediation_allowed` enforces this.
1. Sandbox: a copy of the repo with its own git repo, on branch `guardian/fix`
2. Apply the change (package.json, imports, Dockerfile)
3. Re-resolve: `npm install --package-lock-only --ignore-scripts` (**no third-party code executes**)
4. Rescan the sandbox with the full Day 1 pipeline, then compare: target resolved? new findings introduced? total risk before → after
5. **SBOM diff** (added / removed / changed components)
6. **API-compatibility probe**: install the old and new versions side by side, compare exported symbols against the
   symbols this app actually uses, and flag "BREAKING for this app"
7. Optional `--run-tests`: `npm ci && npm test` in the sandbox
```bash
python -m guardian.cli approve F-018 --by <your-name>
python -m guardian.cli validate F-018
```

### Step 5 · Verify and report — `guardian/report.py`
- `out/prs/<id>.patch` + `out/prs/<id>.md`: a PR-ready change with rationale, evidence, validation results and
  rollback. **Never pushed or merged automatically.**
- The report covers original finding + evidence, approved action, build/test results, before/after risk,
  remaining/accepted risk, confidence and the audit trail (`verify-ledger`).

---

## Stretch goals → where they are

| Stretch goal | Status |
|---|---|
| Reachability analysis | ✅ import-level + used symbols (`reachability.py`); call-graph level is future work |
| Automated remediation PR | ✅ patch + PR body generated; pushing is left to a human by design |
| Provenance verification | ◐ registry `dist.attestations` captured (`has_provenance`); next: `cosign verify` / `npm audit signatures` |
| Advanced package risk | ✅ typosquat, version anomaly, install scripts, integrity swap, non-registry source; ◐ maintainer-change diff |
| Policy-as-code | ✅ `policy/guardian.rego` (OPA), Python mirror when `opa` isn't installed |
| Continuous monitoring | ✅ `guardian monitor` re-queries every SBOM component (schedule it with cron/CI) |

## Questions judges will ask (have these answers ready)

- **"How do you stop hallucinations?"** Facts come only from tools and live in the ledger. Claims are typed and must
  cite IDs. A two-layer Skeptic checks them. Remediation targets come from a closed set. Untrusted text is fenced.
- **"Where do humans come in?"** At plan approval (required before any sandbox change) and at the PR merge
  (always human). The policy has `auto_merge_allowed := false`.
- **"How do you protect secrets?"** Tools are read-only. Key and secret paths are refused and secret patterns are
  redacted before the model sees them. No credentials are needed to scan. Install scripts are never executed.
- **"Why not just run `npm audit`?"** npm audit gives you a list. The Guardian adds reachability, the dependency path,
  non-CVE attacks (typosquats, lockfile tampering, CI/containers), a verified fix with a before/after diff, and an audit trail.
- **"Does it scale?"** Detection is batched (250 packages per advisory call) with an HTTP cache, and the 2,111-package
  scan takes about 5 seconds. The AI only looks at the top-N diverse findings, so cost stays bounded. Monitoring is a cheap re-check of the SBOM.

## Known limitations (say them before the judges find them)
- Reachability is import-level, not function-level call-graph analysis.
- Ecosystem coverage is npm + PyPI + Docker + GitHub Actions. Maven/Go/Cargo would be new `eco_*` adapters.
- Digest pinning needs registry access to resolve `sha256` (`docker buildx imagetools inspect node:24`).
- Full Juice Shop tests need a full `npm install` (Angular build), so they are optional via `--run-tests`.
