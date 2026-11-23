import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, CheckCircle2, ClipboardCheck, FileDiff, FlaskConical, Hourglass, ShieldAlert, UserCheck, Wand2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api, type Finding, type Plan, type State, type Validation } from "../lib/api";
import { cn } from "../lib/utils";
import { Badge, Button, Card, Empty, Input, Mono, PriorityBadge, Sheet } from "../components/ui";
import { JobLog } from "../components/JobLog";

type Go = (p: "findings", id?: string) => void;

export default function Remediation({ s, run, go }: { s: State; run: string; go: Go }) {
  const [planJob, setPlanJob] = useState<string | null>(null);
  const unplanned = s.findings.filter((f) => !s.plans.some((p) => p.finding_id === f.id) &&
    !(f.type === "install_script" && f.assessment?.verdict === "likely_benign")).slice(0, 5);
  const mPlan = useMutation({ mutationFn: () => api.plan(run, unplanned.map((f) => f.id)), onSuccess: (j) => setPlanJob(j.id), onError: (e) => toast.error(String(e)) });
  const order = (p: Plan) => (p.approval ? (s.validations.some((v) => v.finding_id === p.finding_id) ? 2 : 1) : 0);
  const plans = [...s.plans].sort((a, b) => order(a) - order(b));

  return (
    <div className="mx-auto max-w-[1200px] space-y-5">
      <Card className="flex flex-wrap items-center gap-4 p-4">
        <div className="flex items-center gap-2 text-sm">
          {[["Plan", Wand2, "AI picks from safe options"], ["Approve", UserCheck, "you, by name"], ["Validate", FlaskConical, "sandbox rescan"], ["Review patch", FileDiff, "merge is yours"]].map(([t, Icon, d], i) => {
            const I = Icon as typeof Wand2;
            return (
              <span key={t as string} className="flex items-center gap-2">
                {i > 0 && <ArrowRight className="size-4 text-ink-3" />}
                <span className={cn("flex items-center gap-1.5 rounded-lg px-2.5 py-1.5", i === 1 ? "bg-amber-50 text-human" : "bg-slate-50 text-ink-2")}>
                  <I className="size-4" /><b className="font-semibold">{t as string}</b><span className="hidden text-xs lg:inline">{d as string}</span>
                </span>
              </span>);
          })}
        </div>
        <Button className="ml-auto" variant="primary" disabled={!unplanned.length || mPlan.isPending || !!planJob} onClick={() => mPlan.mutate()}>
          <Wand2 className="size-4" />Plan next {unplanned.length} fixes
        </Button>
      </Card>
      {planJob && <JobLog jobId={planJob} onDone={() => setPlanJob(null)} />}

      {!plans.length ? <Card><Empty icon={<ClipboardCheck className="size-6" />} title="No remediation plans yet">Use “Plan next fixes”, or open a finding and choose “Plan a fix”.</Empty></Card>
        : plans.map((p) => <PlanCard key={p.finding_id} p={p} f={s.findings.find((x) => x.id === p.finding_id)!}
          v={s.validations.find((x) => x.finding_id === p.finding_id)} run={run} go={go} />)}
    </div>
  );
}

function PlanCard({ p, f, v, run, go }: { p: Plan; f: Finding; v?: Validation; run: string; go: Go }) {
  const qc = useQueryClient();
  const [target, setTarget] = useState(p.remediation.target);
  const [name, setName] = useState(() => { try { return localStorage.getItem("guardian.approver") ?? ""; } catch { return ""; } });
  const [job, setJob] = useState<string | null>(null);
  const [showPatch, setShowPatch] = useState(false);
  const r = p.remediation;
  const approved = !!p.approval?.approved;

  const mApprove = useMutation({
    mutationFn: () => api.approve(run, { id: p.finding_id, by: name.trim(), target: target !== r.target ? target : undefined }),
    onSuccess: () => { try { localStorage.setItem("guardian.approver", name.trim()); } catch { /* ignore */ }
      toast.success(`Approved ${p.finding_id} as ${name.trim()}. Recorded in the evidence ledger.`); qc.invalidateQueries({ queryKey: ["state"] }); },
    onError: (e) => toast.error(String(e)),
  });
  const mValidate = useMutation({ mutationFn: () => api.validate(run, p.finding_id), onSuccess: (j) => setJob(j.id), onError: (e) => toast.error(String(e)) });

  return (
    <Card className={cn(approved ? "" : "ring-2 ring-amber-200")}>
      <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3.5">
        {f && <PriorityBadge p={f.priority} />}
        <button onClick={() => go("findings", p.finding_id)} className="min-w-0 flex-1 truncate text-left font-semibold hover:text-brand">
          <span className="mr-2 font-mono text-xs text-ink-3">{p.finding_id}</span>{f?.title}
        </button>
        {v ? <Badge className={v.status === "VERIFIED" ? "bg-emerald-50 text-emerald-700 ring-emerald-200" : "bg-amber-50 text-amber-800 ring-amber-200"}>
          {v.status === "VERIFIED" ? <CheckCircle2 className="size-3.5" /> : <ShieldAlert className="size-3.5" />}{v.status.replace("_", " ")}</Badge>
          : approved ? <Badge className="bg-indigo-50 text-brand ring-indigo-200"><UserCheck className="size-3.5" />Approved by {p.approval!.by.replace("human:", "")}</Badge>
            : <Badge className="bg-amber-50 text-amber-800 ring-amber-200"><Hourglass className="size-3.5" />Awaiting approval</Badge>}
      </div>

      <div className="grid gap-5 p-5 lg:grid-cols-[1.25fr_1fr]">
        <div className="space-y-3 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-md bg-ink px-2 py-0.5 text-xs font-semibold uppercase tracking-wide text-white">{r.action}</span>
            <Mono className="text-[13px]">{r.target}</Mono>
            <Badge className="bg-violet-50 text-violet-700 ring-violet-200">chosen by {r.mode}</Badge>
          </div>
          <dl className="grid grid-cols-[150px_1fr] gap-x-3 gap-y-2">
            <dt className="text-ink-3">Why</dt><dd>{r.rationale}</dd>
            <dt className="text-ink-3">Risk reduction</dt><dd>{r.expected_risk_reduction}</dd>
            <dt className="text-ink-3">Compatibility</dt><dd className={cn(/MAJOR|BREAK/i.test(r.compatibility_impact) && "font-medium text-high")}>{r.compatibility_impact}</dd>
            <dt className="text-ink-3">Rollback</dt><dd>{r.rollback}</dd>
          </dl>
        </div>

        <div className="space-y-3">
          <fieldset disabled={approved} className="space-y-1.5">
            <legend className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-ink-3">Options computed by code</legend>
            {r.candidates.map((c) => (
              <label key={c.target} className={cn("flex cursor-pointer items-center gap-2.5 rounded-lg border px-3 py-2 text-sm",
                target === c.target ? "border-brand bg-brand-soft" : "border-line bg-white hover:bg-slate-50", approved && "cursor-default opacity-80")}>
                <input type="radio" name={`t-${p.finding_id}`} id={`t-${p.finding_id}-${c.target}`} checked={target === c.target} onChange={() => setTarget(c.target)} className="accent-indigo-600" />
                <span className="w-16 text-xs font-semibold uppercase text-ink-2">{c.action}</span>
                <span className="min-w-0 flex-1 truncate font-mono text-xs">{c.target}</span>
                <span className="text-[11px] text-ink-3">{c.kind}</span>
              </label>))}
          </fieldset>

          {!approved ? (
            <div className="rounded-lg bg-amber-50 p-3 ring-1 ring-amber-200">
              <label htmlFor={`name-${p.finding_id}`} className="text-xs font-semibold text-human">Approve as (your name is written to the audit ledger)</label>
              <div className="mt-1.5 flex gap-2">
                <Input id={`name-${p.finding_id}`} placeholder="Your name" value={name} onChange={(e) => setName(e.target.value)} />
                <Button variant="human" disabled={name.trim().length < 2 || mApprove.isPending} onClick={() => mApprove.mutate()}><UserCheck className="size-4" />Approve</Button>
              </div>
            </div>
          ) : (
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-ink-3">Approved {p.approval!.at} · ledger {p.approval!.evidence_id}</span>
              <Button className="ml-auto" variant="primary" disabled={mValidate.isPending || !!job} onClick={() => mValidate.mutate()}>
                <FlaskConical className="size-4" />{v ? "Re-validate" : "Validate in sandbox"}
              </Button>
              {v && <Button onClick={() => setShowPatch(true)}><FileDiff className="size-4" />Patch & PR</Button>}
            </div>
          )}
        </div>
      </div>

      {job && <div className="px-5 pb-5"><JobLog jobId={job} onDone={() => setJob(null)} /></div>}
      {v && <ValidationPanel v={v} />}
      <PatchSheet open={showPatch} onOpenChange={setShowPatch} run={run} id={p.finding_id} />
    </Card>
  );
}

function ValidationPanel({ v }: { v: Validation }) {
  const drop = v.risk_before ? Math.max(0, (v.risk_before - v.risk_after) / v.risk_before) : 0;
  const checks: [string, boolean, string][] = [
    ["Dependencies re-resolved", v.resolution_ok, "npm --package-lock-only --ignore-scripts"],
    ["Original finding gone on rescan", v.target_finding_resolved, "same Day 1 detectors"],
    ["No new problems introduced", v.new_findings.length === 0, `${v.new_findings.length} new`],
    ["App's used API still present", !(v.api_probe?.verdict ?? "").includes("BREAKING"), v.api_probe?.verdict ?? "not applicable"],
  ];
  return (
    <div className="grid gap-5 border-t border-line bg-slate-50/60 p-5 lg:grid-cols-3">
      <div className="space-y-2">
        <div className="text-xs font-semibold uppercase tracking-wide text-ink-3">Checks</div>
        {checks.map(([t, ok, d]) => (
          <div key={t} className="flex items-start gap-2 text-sm">
            {ok ? <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-ok" /> : <ShieldAlert className="mt-0.5 size-4 shrink-0 text-high" />}
            <div><div className="font-medium">{t}</div><div className="text-xs text-ink-3">{d}</div></div>
          </div>))}
      </div>
      <div>
        <div className="text-xs font-semibold uppercase tracking-wide text-ink-3">Total risk, before → after</div>
        <div className="mt-2 flex items-baseline gap-2 tnum"><span className="text-2xl font-semibold">{v.risk_before}</span><ArrowRight className="size-4 text-ink-3" />
          <span className="text-2xl font-semibold text-ok">{v.risk_after}</span><span className="text-sm text-ok">−{(drop * 100).toFixed(1)}%</span></div>
        <div className="mt-3 h-2.5 rounded-full bg-slate-200"><div className="h-2.5 rounded-full bg-ok" style={{ width: `${(1 - drop) * 100}%` }} /></div>
        <p className="mt-3 text-xs text-ink-3">Resolved on rescan: {v.resolved_findings.length} finding{v.resolved_findings.length === 1 ? "" : "s"}</p>
        {!!v.new_findings.length && <ul className="mt-2 space-y-1 text-xs text-high">{v.new_findings.slice(0, 4).map((n) => <li key={n}>+ {n}</li>)}</ul>}
      </div>
      <div>
        <div className="text-xs font-semibold uppercase tracking-wide text-ink-3">SBOM diff</div>
        <div className="mt-2 grid grid-cols-3 gap-2 text-center">
          {([["added", v.sbom_diff.added.length, "text-ok"], ["removed", v.sbom_diff.removed.length, "text-crit"], ["changed", v.sbom_diff.changed.length, "text-brand"]] as const).map(([k, n, c]) => (
            <div key={k} className="rounded-lg bg-white p-2 ring-1 ring-line"><div className={cn("text-xl font-semibold tnum", c)}>{n}</div><div className="text-[11px] text-ink-3">{k}</div></div>))}
        </div>
        <ul className="mt-2 max-h-24 space-y-0.5 overflow-auto font-mono text-[11px] text-ink-2">
          {v.sbom_diff.changed.slice(0, 6).map((c) => <li key={c} className="truncate">~ {c}</li>)}
          {v.sbom_diff.removed.slice(0, 4).map((c) => <li key={c} className="truncate text-crit">− {c}</li>)}
          {v.sbom_diff.added.slice(0, 4).map((c) => <li key={c} className="truncate text-ok">+ {c}</li>)}
        </ul>
      </div>
    </div>
  );
}

function PatchSheet({ open, onOpenChange, run, id }: { open: boolean; onOpenChange: (o: boolean) => void; run: string; id: string }) {
  const q = useQuery({ queryKey: ["patch", run, id], queryFn: () => api.patch(run, id), enabled: open });
  return (
    <Sheet open={open} onOpenChange={onOpenChange} wide title={`Pull request for ${id}`} sub="Generated for human review. The Guardian never pushes or merges.">
      {q.data && (
        <div className="space-y-4">
          <Card className="p-4"><pre className="whitespace-pre-wrap font-sans text-sm leading-relaxed">{q.data.pr}</pre></Card>
          <Card className="overflow-x-auto">
            <pre className="p-4 font-mono text-[12px] leading-relaxed">
              {(q.data.patch || "(no manifest diff — lockfile-only or process change)").split("\n").map((l, i) => (
                <div key={i} className={cn(l.startsWith("+") && !l.startsWith("+++") && "bg-emerald-50 text-emerald-800",
                  l.startsWith("-") && !l.startsWith("---") && "bg-rose-50 text-rose-800", l.startsWith("@@") && "text-brand")}>{l || " "}</div>))}
            </pre>
          </Card>
        </div>)}
    </Sheet>
  );
}
