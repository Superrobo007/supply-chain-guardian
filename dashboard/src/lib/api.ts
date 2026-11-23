export type Priority = "Critical" | "High" | "Medium" | "Low";

export interface Claim { statement: string; kind: "verified_fact" | "inference"; evidence_ids: string[]; downgraded?: string }
export interface Assessment {
  verdict: string; adjusted_priority: Priority; confidence: number; rationale: string; mode?: string;
  claims: Claim[]; skeptic_note?: string; verified_claims?: number; inferred_claims?: number; ai_error?: string;
}
export interface Site { file: string; line: number; code: string }
export interface Advisory { id: string; title: string; severity: string; range?: string; cvss?: number | null; fixed_in?: string[]; aliases?: string[] }
export interface Finding {
  id: string; type: string; title: string; component?: string; version?: string | null; project?: string;
  ecosystem?: string; direct?: boolean; dev_only?: boolean; priority: Priority; risk_score: number; confidence: number;
  score_factors: Record<string, number>; evidence: string[];
  reachability: { status: string; prod?: Site[]; test?: Site[]; symbols_used?: string[]; via?: string };
  advisories?: Advisory[]; fix?: Record<string, unknown>; dependency_paths?: string[][]; parent_constraints?: string[];
  lookalike_of?: string; file?: string; line?: number; assessment?: Assessment; scripts?: Record<string, string>;
}
export interface Candidate { action: string; target: string; kind: string }
export interface Plan {
  finding_id: string; evidence_id?: string;
  remediation: { action: string; target: string; rationale: string; expected_risk_reduction: string;
    compatibility_impact: string; rollback: string; mode: string; candidates: Candidate[] };
  approval: null | { approved: boolean; by: string; at: string; note?: string; evidence_id?: string };
}
export interface Validation {
  finding_id: string; status: "VERIFIED" | "NEEDS_REVIEW"; target: string; changes: string[];
  resolution_ok: boolean; target_finding_resolved: boolean; resolved_findings: string[]; new_findings: string[];
  risk_before: number; risk_after: number; lockfile_diffstat?: string;
  sbom_diff: { added: string[]; removed: string[]; changed: string[]; count_before: number; count_after: number };
  api_probe?: { verdict?: string; error?: string; used_symbols_missing_in_new?: string[]; removed_exports?: string[] } | null;
}
export interface State {
  target: string; ai_mode: string; findings: Finding[]; plans: Plan[]; validations: Validation[];
  inventory: { app: string; components: number; direct: number; images: string[]; workflows: number; actions: number;
    projects: { project: string; lockfile: string | null; ecosystem?: string }[] };
  policy: { deny: string[]; warn: string[]; remediation_allowed: string[]; build_allowed: boolean; engine: string };
  ledger_status: { ok: boolean; message: string };
}
export interface RunInfo { run: string; app: string; target: string; ai_mode: string; findings: number; critical: number; high: number; build_allowed: boolean; updated: number }
export interface Job { id: string; kind: string; run: string | null; status: "running" | "done" | "failed"; log: string[]; exit: number | null; started: number; ended: number | null }
export interface RiskNode { id: string; name: string; version: string | null; kind: string; project: string; direct: boolean; dev: boolean; flag?: { priority: Priority; finding: string; type: string } }
export interface RiskMap { nodes: RiskNode[]; edges: { source: string; target: string }[]; total_packages: number }
export interface LedgerView { total: number; kinds: Record<string, number>; ok: boolean; message: string;
  records: { id: string; ts: string; kind: string; source: string; actor: string; hash: string }[] }

async function req<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, { headers: { "content-type": "application/json" }, ...init });
  if (!r.ok) {
    let msg = r.statusText;
    try { msg = (await r.json()).detail ?? msg; } catch { /* not json */ }
    throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
  }
  return r.json() as Promise<T>;
}

export const api = {
  health: () => req<{ brain: string; root: string }>("/api/health"),
  runs: () => req<RunInfo[]>("/api/runs"),
  state: (run: string) => req<State>(`/api/runs/${run}/state`),
  evidence: (run: string, ids: string[]) => req<Record<string, Record<string, unknown> | null>>(`/api/runs/${run}/evidence?ids=${ids.join(",")}`),
  ledger: (run: string) => req<LedgerView>(`/api/runs/${run}/ledger`),
  riskmap: (run: string) => req<RiskMap>(`/api/runs/${run}/riskmap`),
  patch: (run: string, id: string) => req<{ patch: string; pr: string }>(`/api/runs/${run}/patch/${id}`),
  job: (id: string) => req<Job>(`/api/jobs/${id}`),
  scan: (body: { target: string; out: string; prepare: boolean; investigate: number }) =>
    req<Job>("/api/scan", { method: "POST", body: JSON.stringify(body) }),
  plan: (run: string, ids: string[]) => req<Job>(`/api/runs/${run}/plan`, { method: "POST", body: JSON.stringify({ ids }) }),
  approve: (run: string, body: { id: string; by: string; target?: string; note?: string }) =>
    req<{ ok: boolean; message: string }>(`/api/runs/${run}/approve`, { method: "POST", body: JSON.stringify(body) }),
  validate: (run: string, id: string, run_tests = false) =>
    req<Job>(`/api/runs/${run}/validate`, { method: "POST", body: JSON.stringify({ id, run_tests }) }),
  report: (run: string) => req<Job>(`/api/runs/${run}/report`, { method: "POST" }),
};
