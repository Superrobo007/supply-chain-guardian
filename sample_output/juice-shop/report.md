# Supply Chain Guardian Report — juice-shop
_Generated 2026-11-23 08:59 UTC · AI mode: offline-deterministic · Ledger: 261 records, chain intact, head=98d3deb96837_

## 1. Inventory
- Projects: frontend (frontend/package-lock.json), . (package-lock.json)
- Components: **2111** (161 direct, 1950 transitive)
- Container base images: node:24, gcr.io/distroless/nodejs24-debian13, node:20.19.2-bookworm-slim, node:20.19.2-bookworm, alpine
- CI workflows: 16 (94 third-party action references)
- SBOM: `sbom.cdx.json` (CycloneDX 1.6) · graph: `graph.json`

## 2. Risk summary
**Critical**: 2 · **High**: 7 · **Medium**: 27 · **Low**: 22

**Build gate (python-mirror):** BLOCKED

- ⛔ F-011: critical reachable vulnerability in jsonwebtoken@0.4.0
- ⛔ F-014: critical reachable vulnerability in marsdb@0.6.11
- ⛔ F-022: typosquat-suspect dependency 'ngy-cookie' (looks like 'ngx-cookie')

## 3. Prioritised findings
| ID | Priority | Score | Type | Finding | Reachability | AI verdict |
|---|---|---|---|---|---|---|
| F-011 | Critical | 9.5 | vulnerability | jsonwebtoken@0.4.0: Verification Bypass in jsonwebtoken | reachable_direct | true_positive |
| F-014 | Critical | 9.5 | vulnerability | marsdb@0.6.11: Command Injection in marsdb | reachable_direct | - |
| F-012 | High | 8.7 | vulnerability | jws@0.2.6: Forgeable Public/Private Tokens in jws | reachable_direct | - |
| F-022 | High | 8.5 | typosquat | 'ngy-cookie' looks like popular package 'ngx-cookie' (edit distance 1) | reachable_direct | true_positive |
| F-010 | High | 8.07 | vulnerability | jsonwebtoken@0.1.0: Verification Bypass in jsonwebtoken | transitive_of_reachable | - |
| F-004 | High | 7.73 | vulnerability | crypto-js@3.3.0: crypto-js PBKDF2 1,000 times weaker than specified in 1993 and 1.3M times | transitive_of_reachable | - |
| F-013 | High | 7.73 | vulnerability | lodash@2.4.2: Prototype Pollution in lodash | transitive_of_reachable | - |
| F-006 | High | 7.7 | vulnerability | express-jwt@0.1.3: Authorization bypass in express-jwt | reachable_direct | - |
| F-018 | High | 7.5 | vulnerability | sanitize-html@1.4.2: Sanitize-html Vulnerable To REDoS Attacks | reachable_direct | - |
| F-017 | Medium | 6.5 | vulnerability | notevil@1.3.3: Sandbox escape in notevil and argencoders-notevil | reachable_direct | - |
| F-051 | Medium | 6.5 | ci_curl_pipe | .github/workflows/ci.yml:353 pipes a downloaded script into a shell | n/a | true_positive |
| F-016 | Medium | 6.38 | vulnerability | moment@2.0.0: Path Traversal: 'dir/../../filename' in moment.locale | transitive_of_reachable | - |
| F-020 | Medium | 6.38 | vulnerability | uuid@8.3.2: uuid: Missing buffer bounds check in v3/v5/v6 when buf is provided | transitive_of_reachable | - |
| F-041 | Medium | 6.0 | lockfile_uncommitted | .: lockfile is not committed — transitive versions float on every install (non-reproducibl | n/a | true_positive |
| F-058 | Medium | 6.0 | ci_risky_trigger | .github/workflows/pr-compliance.yml: uses pull_request_target (runs with secrets on fork P | n/a | needs_human_review |
| F-042 | Medium | 5.5 | unpinned_image | Dockerfile:1 base image 'node:24' is not pinned to a digest (mutable tag) | n/a | true_positive |
| F-043 | Medium | 5.5 | unpinned_image | Dockerfile:21 base image 'gcr.io/distroless/nodejs24-debian13' is not pinned to a digest ( | n/a | - |
| F-046 | Medium | 5.5 | unpinned_image | infrastructure/Dockerfile:1 base image 'node:20.19.2-bookworm-slim' is not pinned to a dig | n/a | - |
| F-047 | Medium | 5.5 | unpinned_image | infrastructure/Dockerfile:5 base image 'node:20.19.2-bookworm' is not pinned to a digest ( | n/a | - |
| F-048 | Medium | 5.5 | unpinned_image | test/smoke/Dockerfile:1 base image 'alpine' is not pinned to a digest (mutable tag) | n/a | - |
| F-007 | Medium | 5.3 | vulnerability | file-type@16.5.4: file-type affected by infinite loop in ASF parser on malformed input wit | reachable_direct | - |
| F-023 | Medium | 5.2 | suspicious_version | ngy-cookie@6.0.1000: anomalous version number | reachable_direct | true_positive |
| F-021 | Medium | 5.1 | vulnerability | ws@8.18.0: ws: Memory exhaustion DoS from tiny fragments and data chunks | transitive_of_reachable | - |
| F-044 | Medium | 5.0 | unpinned_build_tool | Dockerfile:4 installs 'typescript@^6.0.3' with a floating version during image build | n/a | true_positive |
| F-045 | Medium | 5.0 | unpinned_build_tool | Dockerfile:19 installs '@cyclonedx/cyclonedx-npm@$CYCLONEDX_NPM_VERSION' with a floating v | n/a | - |
| F-050 | Medium | 5.0 | unpinned_action | .github/workflows/ci.yml:198 uses 'coverallsapp/github-action@v2' (tag, not commit SHA) | n/a | - |
| F-052 | Medium | 5.0 | unpinned_action | .github/workflows/codeql-analysis.yml:23 uses 'github/codeql-action/init@v3' (tag, not com | n/a | - |
| F-053 | Medium | 5.0 | unpinned_action | .github/workflows/codeql-analysis.yml:34 uses 'github/codeql-action/autobuild@v3' (tag, no | n/a | - |
| F-054 | Medium | 5.0 | unpinned_action | .github/workflows/codeql-analysis.yml:36 uses 'github/codeql-action/analyze@v3' (tag, not  | n/a | - |
| F-055 | Medium | 5.0 | unpinned_action | .github/workflows/image_actions.yml:30 uses 'actions/checkout@v6' (tag, not commit SHA) | n/a | - |
| F-056 | Medium | 5.0 | unpinned_action | .github/workflows/image_actions.yml:33 uses 'calibreapp/image-actions@main' (tag, not comm | n/a | - |
| F-057 | Medium | 5.0 | unpinned_action | .github/workflows/image_actions.yml:42 uses 'peter-evans/create-pull-request@v8' (tag, not | n/a | - |
| F-019 | Medium | 4.84 | vulnerability | tar@6.2.1: Race Condition in node-tar Path Reservations via Unicode Ligature Collisions on | unreferenced | - |
| F-040 | Medium | 4.8 | lockfile_uncommitted | frontend: lockfile is not committed — transitive versions float on every install (non-repr | n/a | - |
| F-003 | Medium | 4.67 | vulnerability | base64url@0.0.6: Out-of-bounds Read in base64url | transitive_of_reachable | - |
| F-049 | Medium | 4.0 | container_root | test/smoke/Dockerfile: container runs as root | n/a | - |
| F-034 | Low | 3.82 | install_script | @scarf/scarf@1.4.0 runs an install script | transitive_of_reachable | - |
| F-005 | Low | 3.81 | vulnerability | elliptic@6.6.1: Elliptic Uses a Cryptographic Primitive with a Risky Implementation | transitive_of_reachable | - |
| F-025 | Low | 3.6 | install_script | @fortawesome/fontawesome-svg-core@1.2.36 runs an install script | reachable_direct | - |
| F-026 | Low | 3.6 | install_script | @fortawesome/free-brands-svg-icons@5.15.4 runs an install script | reachable_direct | - |

## 4. Evidence for top findings
### F-011 · jsonwebtoken@0.4.0: Verification Bypass in jsonwebtoken
- Component: `jsonwebtoken` 0.4.0 · project `.`
- Score 9.5 = base 9.5 × reachability 1.0 × exposure 1.0 × environment 1.0
- Dependency path: juice-shop@20.4.0-SNAPSHOT → jsonwebtoken@0.4.0
- Reachability: **reachable_direct** (e.g. `lib/insecurity.ts:11`)
- Assessment (offline): **true_positive**, priority Critical, confidence 0.95 — offline deterministic assessment (no LLM configured)
  - ✅ VERIFIED: jsonwebtoken@0.4.0: Verification Bypass in jsonwebtoken ['E-0142', 'E-0143', 'E-0144']
  - ✅ VERIFIED: static import scan classifies jsonwebtoken as reachable_direct ['E-0226']

### F-022 · 'ngy-cookie' looks like popular package 'ngx-cookie' (edit distance 1)
- Component: `ngy-cookie` 6.0.1000 · project `frontend`
- Score 8.5 = base 8.5 × reachability 1.0 × exposure 1.0 × environment 1.0
- Dependency path: frontend@20.4.0-SNAPSHOT → ngy-cookie@6.0.1000
- Reachability: **reachable_direct** (e.g. `src/main.ts:57`)
- Assessment (offline): **true_positive**, priority High, confidence 0.95 — offline deterministic assessment (no LLM configured)
  - ✅ VERIFIED: 'ngy-cookie' looks like popular package 'ngx-cookie' (edit distance 1) ['E-0195', 'E-0196', 'E-0197']
  - ✅ VERIFIED: static import scan classifies ngy-cookie as reachable_direct ['E-0237']
  - ✅ VERIFIED: name is one edit away from popular package ngx-cookie ['E-0195', 'E-0196', 'E-0197', 'E-0237']

### F-051 · .github/workflows/ci.yml:353 pipes a downloaded script into a shell
- Component: `.github/workflows/ci.yml`  · project `.`
- Score 6.5 = base 6.5 × reachability 1.0 × exposure 1.0 × environment 1.0
- Dependency path: n/a
- Reachability: **n/a** 
- Assessment (offline): **true_positive**, priority Medium, confidence 0.65 — offline deterministic assessment (no LLM configured)
  - ✅ VERIFIED: .github/workflows/ci.yml:353 pipes a downloaded script into a shell ['E-0050']

### F-041 · .: lockfile is not committed — transitive versions float on every install (non-reproducible builds)
- Component: `package-lock.json`  · project `.`
- Score 6.0 = base 6.0 × reachability 1.0 × exposure 1.0 × environment 1.0
- Dependency path: n/a
- Reachability: **n/a** 
- Assessment (offline): **true_positive**, priority Medium, confidence 0.65 — offline deterministic assessment (no LLM configured)
  - ✅ VERIFIED: .: lockfile is not committed — transitive versions float on every install (non-reproducible builds) ['E-0214']

### F-058 · .github/workflows/pr-compliance.yml: uses pull_request_target (runs with secrets on fork PRs)
- Component: `.github/workflows/pr-compliance.yml`  · project `.`
- Score 6.0 = base 6.0 × reachability 1.0 × exposure 1.0 × environment 1.0
- Dependency path: n/a
- Reachability: **n/a** 
- Assessment (offline): **needs_human_review**, priority Medium, confidence 0.65 — offline deterministic assessment (no LLM configured)
  - ✅ VERIFIED: .github/workflows/pr-compliance.yml: uses pull_request_target (runs with secrets on fork PRs) ['E-0087']
  - 💭 INFERENCE: pull_request_target is only dangerous if the job checks out and runs PR code 

### F-042 · Dockerfile:1 base image 'node:24' is not pinned to a digest (mutable tag)
- Component: `node:24`  · project `.`
- Score 5.5 = base 5.5 × reachability 1.0 × exposure 1.0 × environment 1.0
- Dependency path: n/a
- Reachability: **n/a** 
- Assessment (offline): **true_positive**, priority Medium, confidence 0.65 — offline deterministic assessment (no LLM configured)
  - ✅ VERIFIED: Dockerfile:1 base image 'node:24' is not pinned to a digest (mutable tag) ['E-0005']

### F-023 · ngy-cookie@6.0.1000: anomalous version number
- Component: `ngy-cookie` 6.0.1000 · project `frontend`
- Score 5.2 = base 6.5 × reachability 1.0 × exposure 0.8 × environment 1.0
- Dependency path: n/a
- Reachability: **reachable_direct** (e.g. `src/main.ts:57`)
- Assessment (offline): **true_positive**, priority Medium, confidence 0.95 — offline deterministic assessment (no LLM configured)
  - ✅ VERIFIED: ngy-cookie@6.0.1000: anomalous version number ['E-0002', 'E-0198', 'E-0237']
  - ✅ VERIFIED: static import scan classifies ngy-cookie as reachable_direct ['E-0237']

### F-044 · Dockerfile:4 installs 'typescript@^6.0.3' with a floating version during image build
- Component: `typescript@^6.0.3`  · project `.`
- Score 5.0 = base 5.0 × reachability 1.0 × exposure 1.0 × environment 1.0
- Dependency path: n/a
- Reachability: **n/a** 
- Assessment (offline): **true_positive**, priority Medium, confidence 0.65 — offline deterministic assessment (no LLM configured)
  - ✅ VERIFIED: Dockerfile:4 installs 'typescript@^6.0.3' with a floating version during image build ['E-0007']

## 6. Remaining / accepted risk
58 findings not yet remediated; see `findings.json`. Accepted risks must be recorded with `guardian accept <id> --by <name> --reason ...`.

## 7. Responsible AI note
- AI is used for triage, adversarial verification and choosing among pre-computed remediations; all facts come from deterministic tools and are stored in a hash-chained evidence ledger.
- Each AI claim is typed VERIFIED (cites ledger evidence that exists and supports it) or INFERENCE.
- The remediator cannot invent versions: its choice must match a registry-computed candidate.
- No change is merged, deployed or released automatically; validation runs only after human approval, in a sandbox copy, with install scripts disabled.
- Secrets/key files are never readable by the model; tool output is fenced as untrusted data.