# Supply Chain Guardian Report — pygoat
_Generated 2026-11-23 08:59 UTC · AI mode: offline-deterministic · Ledger: 568 records, chain intact, head=63a7c6954f32_

## 1. Inventory
- Projects: . (None), challenge/labs/bopla_lab (None), challenge/labs/business_logic_lab (None), challenge/labs/security_headers_lab (None), dockerized_labs/a9_uckv_lab (None), dockerized_labs/auth_failure_lab (None), dockerized_labs/broken_access_lab (None), dockerized_labs/broken_auth_lab (None), dockerized_labs/command_injection_lab (None), dockerized_labs/crypto_failure_lab (None), dockerized_labs/dependency_attack_lab (None), dockerized_labs/insec_des_lab (None), dockerized_labs/insecure_design_lab (None), dockerized_labs/insufficient_logging_lab (None), dockerized_labs/open_source_library_attack_lab (None), dockerized_labs/package_injection_lab (None), dockerized_labs/sde (None), dockerized_labs/sec_misconfig (None), dockerized_labs/sensitive_data_exposure (None), dockerized_labs/software_integrity_lab (None), dockerized_labs/sql_injection_lab (None), dockerized_labs/ssrf_lab (None), dockerized_labs/template_injection_lab (None), dockerized_labs/xss_lab (None), dockerized_labs/xxe_lab (None)
- Components: **123** (123 direct, 0 transitive)
- Container base images: python:3.11-slim-bookworm, python:3.11-slim-bookworm, python:3.9-alpine, python:3.9-alpine, python:3.9-alpine, python:3.8-slim, python:3.9-alpine, python:3.9-alpine, python:3.9-alpine, python:3.9-alpine, python:3.9-alpine, python:3.9-alpine, python:3.9-alpine, python:3.9-alpine, python:3.9-alpine, python:3.9-alpine, python:3.9-alpine, python:3.9-alpine, python:3.9-alpine, python:3.9-alpine, python:3.9-alpine, python:3.9-alpine, python:3.9-alpine, python:3.9-alpine, python:3.9-alpine, python:3.9-alpine
- CI workflows: 3 (6 third-party action references)
- SBOM: `sbom.cdx.json` (CycloneDX 1.6) · graph: `graph.json`

## 2. Risk summary
**Critical**: 0 · **High**: 0 · **Medium**: 87 · **Low**: 46

**Build gate (python-mirror):** PASS


## 3. Prioritised findings
| ID | Priority | Score | Type | Finding | Reachability | AI verdict |
|---|---|---|---|---|---|---|
| F-004 | Medium | 6.5 | vulnerability | django@4.2: 96 known advisories (CVE-2023-31047, CVE-2023-36053, CVE-2023-41164…) | reachable_direct | true_positive |
| F-008 | Medium | 6.5 | vulnerability | pillow@12.1.0: 95 known advisories (CVE-2026-112390, CVE-2026-112391, CVE-2026-112392…) | reachable_direct | - |
| F-009 | Medium | 6.5 | vulnerability | pyjwt@2.4.0: 25 known advisories (CVE-2025-45768, CVE-2026-101917, CVE-2026-101918…) | reachable_direct | - |
| F-010 | Medium | 6.5 | vulnerability | pyyaml@5.1: 6 known advisories (CVE-2019-20477, CVE-2020-14343, CVE-2020-1747…) | reachable_direct | - |
| F-011 | Medium | 6.5 | vulnerability | requests@2.28.2: 8 known advisories (CVE-2023-32681, CVE-2024-35195, CVE-2024-47081…) | reachable_direct | - |
| F-016 | Medium | 6.5 | vulnerability | flask@2.3.3 [challenge/labs/bopla_lab]: 2 known advisories (CVE-2026-27205) | reachable_direct | - |
| F-018 | Medium | 6.5 | vulnerability | flask@2.3.3 [challenge/labs/business_logic_lab]: 2 known advisories (CVE-2026-27205) | reachable_direct | - |
| F-021 | Medium | 6.5 | vulnerability | flask@2.3.3 [challenge/labs/security_headers_lab]: 2 known advisories (CVE-2026-27205) | reachable_direct | - |
| F-024 | Medium | 6.5 | vulnerability | flask@2.0.1 [dockerized_labs/a9_uckv_lab]: 4 known advisories (CVE-2023-30861, CVE-2026-27 | reachable_direct | - |
| F-025 | Medium | 6.5 | vulnerability | pyyaml@5.1 [dockerized_labs/a9_uckv_lab]: 6 known advisories (CVE-2019-20477, CVE-2020-143 | reachable_direct | - |
| F-026 | Medium | 6.5 | vulnerability | pillow@8.0.0 [dockerized_labs/a9_uckv_lab]: 123 known advisories (CVE-2020-35653, CVE-2020 | reachable_direct | - |
| F-030 | Medium | 6.5 | vulnerability | flask@3.0.2 [dockerized_labs/broken_access_lab]: 2 known advisories (CVE-2026-27205) | reachable_direct | - |
| F-032 | Medium | 6.5 | vulnerability | flask@2.3.3 [dockerized_labs/broken_auth_lab]: 2 known advisories (CVE-2026-27205) | reachable_direct | - |
| F-035 | Medium | 6.5 | vulnerability | flask@2.0.1 [dockerized_labs/command_injection_lab]: 4 known advisories (CVE-2023-30861, C | reachable_direct | - |
| F-038 | Medium | 6.5 | vulnerability | flask@2.0.1 [dockerized_labs/crypto_failure_lab]: 4 known advisories (CVE-2023-30861, CVE- | reachable_direct | - |
| F-040 | Medium | 6.5 | vulnerability | flask@2.3.3 [dockerized_labs/dependency_attack_lab]: 2 known advisories (CVE-2026-27205) | reachable_direct | - |
| F-043 | Medium | 6.5 | vulnerability | flask@3.0.0 [dockerized_labs/insec_des_lab]: 2 known advisories (CVE-2026-27205) | reachable_direct | - |
| F-045 | Medium | 6.5 | vulnerability | flask@2.2.5 [dockerized_labs/insecure_design_lab]: 2 known advisories (CVE-2026-27205) | reachable_direct | - |
| F-047 | Medium | 6.5 | vulnerability | flask@2.3.3 [dockerized_labs/insufficient_logging_lab]: 2 known advisories (CVE-2026-27205 | reachable_direct | - |
| F-050 | Medium | 6.5 | vulnerability | flask@2.0.1 [dockerized_labs/open_source_library_attack_lab]: 4 known advisories (CVE-2023 | reachable_direct | - |
| F-053 | Medium | 6.5 | vulnerability | flask@2.0.1 [dockerized_labs/package_injection_lab]: 4 known advisories (CVE-2023-30861, C | reachable_direct | - |
| F-056 | Medium | 6.5 | vulnerability | flask@2.0.3 [dockerized_labs/sde]: 4 known advisories (CVE-2023-30861, CVE-2026-27205) | reachable_direct | - |
| F-058 | Medium | 6.5 | vulnerability | flask@2.2.5 [dockerized_labs/sec_misconfig]: 2 known advisories (CVE-2026-27205) | reachable_direct | - |
| F-059 | Medium | 6.5 | vulnerability | pyjwt@2.8.0 [dockerized_labs/sec_misconfig]: 27 known advisories (CVE-2025-45768, CVE-2026 | reachable_direct | - |
| F-061 | Medium | 6.5 | vulnerability | django@3.2.18 [dockerized_labs/sensitive_data_exposure]: 30 known advisories (CVE-2023-310 | reachable_direct | - |
| F-063 | Medium | 6.5 | vulnerability | flask@2.0.1 [dockerized_labs/software_integrity_lab]: 4 known advisories (CVE-2023-30861,  | reachable_direct | - |
| F-066 | Medium | 6.5 | vulnerability | flask@2.0.1 [dockerized_labs/sql_injection_lab]: 4 known advisories (CVE-2023-30861, CVE-2 | reachable_direct | - |
| F-069 | Medium | 6.5 | vulnerability | flask@2.3.3 [dockerized_labs/template_injection_lab]: 2 known advisories (CVE-2026-27205) | reachable_direct | - |
| F-072 | Medium | 6.5 | vulnerability | flask@2.3.3 [dockerized_labs/xss_lab]: 2 known advisories (CVE-2026-27205) | reachable_direct | - |
| F-075 | Medium | 6.5 | vulnerability | flask@2.2.5 [dockerized_labs/xxe_lab]: 2 known advisories (CVE-2026-27205) | reachable_direct | - |
| F-077 | Medium | 5.5 | unpinned_image | Dockerfile:2 base image 'python:3.11-slim-bookworm' is not pinned to a digest (mutable tag | n/a | true_positive |
| F-078 | Medium | 5.5 | unpinned_image | Dockerfile:24 base image 'python:3.11-slim-bookworm' is not pinned to a digest (mutable ta | n/a | - |
| F-080 | Medium | 5.5 | unpinned_image | challenge/labs/bopla_lab/Dockerfile:1 base image 'python:3.9-alpine' is not pinned to a di | n/a | - |
| F-082 | Medium | 5.5 | unpinned_image | challenge/labs/business_logic_lab/Dockerfile:1 base image 'python:3.9-alpine' is not pinne | n/a | - |
| F-084 | Medium | 5.5 | unpinned_image | challenge/labs/security_headers_lab/Dockerfile:1 base image 'python:3.9-alpine' is not pin | n/a | - |
| F-086 | Medium | 5.5 | unpinned_image | dockerized_labs/a9_uckv_lab/Dockerfile:1 base image 'python:3.8-slim' is not pinned to a d | n/a | - |
| F-088 | Medium | 5.5 | unpinned_image | dockerized_labs/auth_failure_lab/Dockerfile:1 base image 'python:3.9-alpine' is not pinned | n/a | - |
| F-090 | Medium | 5.5 | unpinned_image | dockerized_labs/broken_access_lab/Dockerfile:1 base image 'python:3.9-alpine' is not pinne | n/a | - |
| F-092 | Medium | 5.5 | unpinned_image | dockerized_labs/broken_auth_lab/Dockerfile:1 base image 'python:3.9-alpine' is not pinned  | n/a | - |
| F-094 | Medium | 5.5 | unpinned_image | dockerized_labs/command_injection_lab/Dockerfile:1 base image 'python:3.9-alpine' is not p | n/a | - |

## 4. Evidence for top findings
### F-004 · django@4.2: 96 known advisories (CVE-2023-31047, CVE-2023-36053, CVE-2023-41164…)
- Component: `django` 4.2 · project `.`
- Score 6.5 = base 6.5 × reachability 1.0 × exposure 1.0 × environment 1.0
- Dependency path: pygoat/. (python)@None → django@4.2
- Reachability: **reachable_direct** (e.g. `manage.py:11`)
- Assessment (offline): **true_positive**, priority Medium, confidence 0.95 — offline deterministic assessment (no LLM configured)
  - ✅ VERIFIED: django@4.2: 96 known advisories (CVE-2023-31047, CVE-2023-36053, CVE-2023-41164…) ['E-0093', 'E-0094', 'E-0095']
  - ✅ VERIFIED: static import scan classifies django as reachable_direct ['E-0533']

### F-077 · Dockerfile:2 base image 'python:3.11-slim-bookworm' is not pinned to a digest (mutable tag)
- Component: `python:3.11-slim-bookworm`  · project `.`
- Score 5.5 = base 5.5 × reachability 1.0 × exposure 1.0 × environment 1.0
- Dependency path: n/a
- Reachability: **n/a** 
- Assessment (offline): **true_positive**, priority Medium, confidence 0.65 — offline deterministic assessment (no LLM configured)
  - ✅ VERIFIED: Dockerfile:2 base image 'python:3.11-slim-bookworm' is not pinned to a digest (mutable tag) ['E-0026']

### F-128 · .github/workflows/flake8.yml:22 uses 'actions/checkout@v4' (tag, not commit SHA)
- Component: `actions/checkout@v4`  · project `.`
- Score 5.0 = base 5.0 × reachability 1.0 × exposure 1.0 × environment 1.0
- Dependency path: n/a
- Reachability: **n/a** 
- Assessment (offline): **true_positive**, priority Medium, confidence 0.65 — offline deterministic assessment (no LLM configured)
  - ✅ VERIFIED: .github/workflows/flake8.yml:22 uses 'actions/checkout@v4' (tag, not commit SHA) ['E-0052']

## 6. Remaining / accepted risk
133 findings not yet remediated; see `findings.json`. Accepted risks must be recorded with `guardian accept <id> --by <name> --reason ...`.

## 7. Responsible AI note
- AI is used for triage, adversarial verification and choosing among pre-computed remediations; all facts come from deterministic tools and are stored in a hash-chained evidence ledger.
- Each AI claim is typed VERIFIED (cites ledger evidence that exists and supports it) or INFERENCE.
- The remediator cannot invent versions: its choice must match a registry-computed candidate.
- No change is merged, deployed or released automatically; validation runs only after human approval, in a sandbox copy, with install scripts disabled.
- Secrets/key files are never readable by the model; tool output is fenced as untrusted data.