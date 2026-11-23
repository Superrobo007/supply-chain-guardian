# Supply Chain Guardian — policy-as-code (Open Policy Agent / Conftest compatible, Rego v1)
# Evaluate with:  opa eval -d policy/ -i out/policy_input.json "data.guardian"
package guardian

import rego.v1

# ---------- Build gate: findings that BLOCK a build ----------
deny contains msg if {
	some f in input.findings
	f.type == "typosquat"
	f.assessment.verdict != "likely_benign"
	msg := sprintf("%s: typosquat-suspect dependency '%s' (looks like '%s')", [f.id, f.component, f.lookalike_of])
}

deny contains msg if {
	some f in input.findings
	f.type == "lockfile_drift"
	msg := sprintf("%s: suspicious lockfile change for '%s'", [f.id, f.component])
}

deny contains msg if {
	some f in input.findings
	f.type == "vulnerability"
	f.priority == "Critical"
	f.reachability.status == "reachable_direct"
	msg := sprintf("%s: critical reachable vulnerability in %s@%s", [f.id, f.component, f.version])
}

deny contains msg if {
	some f in input.findings
	f.type == "install_script"
	count(f.suspicious) > 0
	msg := sprintf("%s: install script with suspicious behaviour in %s", [f.id, f.component])
}

# ---------- Warnings: allowed, but reported ----------
warn contains msg if {
	some f in input.findings
	f.type in {"unpinned_image", "unpinned_action", "unpinned_build_tool", "lockfile_uncommitted", "ci_curl_pipe"}
	msg := sprintf("%s: %s", [f.id, f.title])
}

# ---------- Remediation gate: what the Guardian may do on its own ----------
# Nothing is ever merged/deployed automatically. A change may enter a sandbox branch only with human approval
# and only if the chosen target came from the deterministic candidate set.
remediation_allowed contains fid if {
	some p in input.plans
	fid := p.finding_id
	p.approval.approved == true
	startswith(p.approval.by, "human:")
	some c in p.remediation.candidates
	c.target == p.remediation.target
}

auto_merge_allowed := false

build_allowed if count(deny) == 0
