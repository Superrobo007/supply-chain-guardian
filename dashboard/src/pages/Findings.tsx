import { useMutation, useQuery } from "@tanstack/react-query";
import {
  createColumnHelper, flexRender, getCoreRowModel, getFilteredRowModel, getSortedRowModel, useReactTable, type SortingState,
} from "@tanstack/react-table";
import { ArrowDown, ArrowUp, ChevronRight, FileSearch, Lightbulb, Search, ShieldCheck, Wrench } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { api, type Finding, type State } from "../lib/api";
import { PRIORITIES, REACH_LABEL, cn, typeLabel } from "../lib/utils";
import { Badge, Button, Card, Empty, Input, Mono, PriorityBadge, Sheet, Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui";
import { JobLog } from "../components/JobLog";

const col = createColumnHelper<Finding>();
// AI confidence is stored 0-1, but older local-model results may be 0-100
const pct = (c: number) => Math.round(Math.min(100, c > 1 ? c : c * 100));
type Go = (p: "remediation" | "graph", id?: string) => void;

export default function Findings({ s, run, focus, clearFocus, go }: { s: State; run: string; focus: string | null; clearFocus: () => void; go: Go }) {
  const [q, setQ] = useState("");
  const [prio, setPrio] = useState<string[]>([]);
  const [type, setType] = useState("all");
  const [reach, setReach] = useState("all");
  const [sorting, setSorting] = useState<SortingState>([{ id: "risk_score", desc: true }]);
  const [open, setOpen] = useState<Finding | null>(null);

  useEffect(() => {
    if (focus) { setOpen(s.findings.find((f) => f.id === focus) ?? null); clearFocus(); }
  }, [focus, s.findings, clearFocus]);

  const data = useMemo(() => s.findings.filter((f) =>
    (!prio.length || prio.includes(f.priority)) && (type === "all" || f.type === type) &&
    (reach === "all" || f.reachability.status === reach) &&
    (!q || `${f.id} ${f.title} ${f.component ?? ""}`.toLowerCase().includes(q.toLowerCase()))), [s.findings, prio, type, reach, q]);

  const columns = useMemo(() => [
    col.accessor("id", { header: "ID", cell: (c) => <span className="font-mono text-xs text-ink-3">{c.getValue()}</span>, size: 70 }),
    col.accessor("priority", {
      header: "Priority", cell: (c) => <PriorityBadge p={c.getValue()} />,
      sortingFn: (a, b) => PRIORITIES.indexOf(b.original.priority) - PRIORITIES.indexOf(a.original.priority),
    }),
    col.accessor("risk_score", { header: "Score", cell: (c) => <span className="font-semibold tnum">{c.getValue().toFixed(1)}</span> }),
    col.accessor("title", { header: "Finding", cell: (c) => (
      <div className="min-w-0">
        <div className="truncate font-medium">{c.getValue()}</div>
        <div className="text-xs text-ink-3">{typeLabel(c.row.original.type)}{c.row.original.project && c.row.original.project !== "." ? ` · ${c.row.original.project}` : ""}</div>
      </div>) }),
    col.accessor((r) => r.reachability.status, { id: "reach", header: "Reachability", cell: (c) => (
      <span className={cn("text-xs", c.getValue() === "reachable_direct" ? "font-semibold text-crit" : "text-ink-2")}>{REACH_LABEL[c.getValue()] ?? c.getValue()}</span>) }),
    col.accessor((r) => r.assessment?.verdict ?? "", { id: "verdict", header: "AI verdict", cell: (c) => c.getValue()
      ? <Badge className={c.getValue() === "true_positive" ? "bg-violet-50 text-violet-700 ring-violet-200" : "bg-slate-50 text-ink-2 ring-line"}>{c.getValue().replace(/_/g, " ")}</Badge>
      : <span className="text-xs text-ink-3">–</span> }),
    col.display({ id: "go", cell: () => <ChevronRight className="size-4 text-ink-3" /> }),
  ], []);

  const table = useReactTable({ data, columns, state: { sorting }, onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(), getSortedRowModel: getSortedRowModel(), getFilteredRowModel: getFilteredRowModel() });

  const types = [...new Set(s.findings.map((f) => f.type))];
  return (
    <div className="mx-auto max-w-[1400px] space-y-4">
      <Card className="flex flex-wrap items-center gap-3 p-3">
        <div className="relative min-w-[220px] flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-ink-3" />
          <Input id="q" className="pl-9" placeholder="Search package, title or ID" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="flex gap-1">
          {PRIORITIES.map((p) => (
            <button key={p} onClick={() => setPrio((x) => x.includes(p) ? x.filter((y) => y !== p) : [...x, p])}
              className={cn("rounded-lg px-3 py-1.5 text-sm font-medium ring-1 ring-inset", prio.includes(p) ? "bg-ink text-white ring-ink" : "bg-white text-ink-2 ring-line hover:bg-slate-50")}>
              {p} <span className="tnum opacity-60">{s.findings.filter((f) => f.priority === p).length}</span>
            </button>))}
        </div>
        <select id="type" value={type} onChange={(e) => setType(e.target.value)} className="h-9 rounded-lg border border-line bg-white px-2.5 text-sm">
          <option value="all">All types</option>{types.map((t) => <option key={t} value={t}>{typeLabel(t)}</option>)}
        </select>
        <select id="reach" value={reach} onChange={(e) => setReach(e.target.value)} className="h-9 rounded-lg border border-line bg-white px-2.5 text-sm">
          <option value="all">Any reachability</option>{Object.entries(REACH_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <span className="text-sm text-ink-3 tnum">{data.length} shown</span>
      </Card>

      <Card className="overflow-x-auto">
        <table className="w-full min-w-[860px] text-sm">
          <thead>
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id} className="border-b border-line bg-slate-50/70 text-left text-xs font-semibold uppercase tracking-wide text-ink-3">
                {hg.headers.map((h) => (
                  <th key={h.id} className="px-4 py-2.5">
                    {h.column.getCanSort() ? (
                      <button className="inline-flex items-center gap-1 uppercase" onClick={h.column.getToggleSortingHandler()}>
                        {flexRender(h.column.columnDef.header, h.getContext())}
                        {h.column.getIsSorted() === "asc" ? <ArrowUp className="size-3" /> : h.column.getIsSorted() === "desc" ? <ArrowDown className="size-3" /> : null}
                      </button>) : flexRender(h.column.columnDef.header, h.getContext())}
                  </th>))}
              </tr>))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map((r) => (
              <tr key={r.id} onClick={() => setOpen(r.original)} className="cursor-pointer border-b border-line last:border-0 hover:bg-indigo-50/40">
                {r.getVisibleCells().map((c) => <td key={c.id} className="max-w-[520px] px-4 py-2.5 align-middle">{flexRender(c.column.columnDef.cell, c.getContext())}</td>)}
              </tr>))}
          </tbody>
        </table>
        {!data.length && <Empty icon={<FileSearch className="size-6" />} title="No findings match these filters" />}
      </Card>

      <Sheet open={!!open} onOpenChange={(o) => !o && setOpen(null)} wide
        title={open?.title} sub={open && <div className="flex flex-wrap items-center gap-2"><PriorityBadge p={open.priority} /><span className="font-mono">{open.id}</span>·<span>{typeLabel(open.type)}</span>·<span>score {open.risk_score.toFixed(2)}</span></div>}>
        {open && <FindingDetail f={open} s={s} run={run} go={go} />}
      </Sheet>
    </div>
  );
}

function FindingDetail({ f, s, run, go }: { f: Finding; s: State; run: string; go: Go }) {
  const [job, setJob] = useState<string | null>(null);
  const plan = s.plans.find((p) => p.finding_id === f.id);
  const mPlan = useMutation({ mutationFn: () => api.plan(run, [f.id]), onSuccess: (j) => setJob(j.id), onError: (e) => toast.error(String(e)) });
  const ev = useQuery({ queryKey: ["evidence", run, f.id], queryFn: () => api.evidence(run, f.evidence.slice(0, 20)) });
  const factors = Object.entries(f.score_factors);
  const fix = f.fix as Record<string, string | null> | undefined;

  return (
    <Tabs defaultValue="summary">
      <TabsList>
        <TabsTrigger value="summary">Summary</TabsTrigger>
        <TabsTrigger value="ai">AI assessment</TabsTrigger>
        <TabsTrigger value="evidence">Evidence ({f.evidence.length})</TabsTrigger>
      </TabsList>

      <TabsContent value="summary">
        <div className="space-y-4">
          <Card className="p-4">
            <div className="mb-3 text-sm font-semibold">Why this score</div>
            <div className="flex flex-wrap items-center gap-2 font-mono text-[13px]">
              {factors.map(([k, v], i) => (
                <span key={k} className="flex items-center gap-2">
                  {i > 0 && <span className="text-ink-3">×</span>}
                  <span className="rounded-md bg-slate-100 px-2 py-1"><span className="text-ink-3">{k}</span> <b>{v}</b></span>
                </span>))}
              <span className="text-ink-3">=</span><span className="rounded-md bg-ink px-2 py-1 font-semibold text-white">{f.risk_score.toFixed(2)}</span>
            </div>
            <p className="mt-3 text-xs text-ink-3">Confidence {Math.round(f.confidence * 100)}%. Priority buckets: Critical ≥ 9, High ≥ 7, Medium ≥ 4.</p>
          </Card>

          {!!f.dependency_paths?.length && (
            <Card className="p-4">
              <div className="mb-3 flex items-center justify-between text-sm font-semibold">How it got into the app
                <button className="text-xs font-medium text-brand hover:underline" onClick={() => go("graph")}>Open risk map</button></div>
              {f.dependency_paths.slice(0, 3).map((p, i) => (
                <div key={i} className="mb-2 flex flex-wrap items-center gap-1.5">
                  {p.map((n, j) => (
                    <span key={j} className="flex items-center gap-1.5">
                      {j > 0 && <ChevronRight className="size-3.5 text-ink-3" />}
                      <span className={cn("rounded-md px-2 py-1 font-mono text-xs ring-1 ring-inset",
                        j === p.length - 1 ? "bg-rose-50 text-rose-700 ring-rose-200" : j === 0 ? "bg-brand-soft text-brand ring-indigo-200" : "bg-white ring-line")}>{n}</span>
                    </span>))}
                </div>))}
              {!!f.parent_constraints?.length && <p className="mt-2 text-xs text-ink-3">Parent constraints: {f.parent_constraints.join("; ")}</p>}
            </Card>)}

          {f.reachability.status !== "n/a" && (
            <Card className="p-4">
              <div className="mb-2 text-sm font-semibold">Where the app uses it · <span className="font-normal text-ink-2">{REACH_LABEL[f.reachability.status]}</span></div>
              {f.reachability.prod?.length ? (
                <ul className="space-y-1.5">
                  {f.reachability.prod.slice(0, 6).map((site, i) => (
                    <li key={i} className="overflow-x-auto rounded-md bg-slate-50 px-3 py-2 font-mono text-xs">
                      <span className="text-brand">{site.file}:{site.line}</span> <span className="text-ink-2">{site.code}</span>
                    </li>))}
                </ul>) : <p className="text-sm text-ink-3">{f.reachability.via ? `Not imported directly; pulled in by ${f.reachability.via}, which the app imports.` : "No production imports found."}</p>}
              {!!f.reachability.symbols_used?.length && <p className="mt-2 text-xs text-ink-3">Symbols used: {f.reachability.symbols_used.map((x) => <Mono key={x} className="mr-1">{x}</Mono>)}</p>}
            </Card>)}

          {!!f.advisories?.length && (
            <Card className="overflow-x-auto">
              <table className="w-full min-w-[560px] text-sm">
                <thead><tr className="border-b border-line text-left text-xs uppercase tracking-wide text-ink-3"><th className="px-4 py-2">Advisory</th><th className="px-4 py-2">Severity</th><th className="px-4 py-2">Affected</th></tr></thead>
                <tbody>{f.advisories.slice(0, 12).map((a) => (
                  <tr key={a.id} className="border-b border-line last:border-0">
                    <td className="px-4 py-2"><div className="font-mono text-xs">{a.id}</div><div className="text-ink-2">{a.title}</div></td>
                    <td className="px-4 py-2 whitespace-nowrap">{a.severity}{a.cvss ? ` · ${a.cvss}` : ""}</td>
                    <td className="px-4 py-2 font-mono text-xs">{a.range ?? a.fixed_in?.join(", ")}</td>
                  </tr>))}</tbody>
              </table>
            </Card>)}

          {fix && (fix.min_safe || fix.latest_safe) && (
            <Card className="flex flex-wrap items-center gap-x-6 gap-y-2 p-4 text-sm">
              <Lightbulb className="size-5 text-human" />
              <span>Smallest safe version: <Mono>{fix.min_safe_same_major ?? fix.min_safe ?? "none"}</Mono></span>
              <span>Latest safe: <Mono>{fix.latest_safe ?? "none"}</Mono></span>
            </Card>)}

          <Card className="flex flex-wrap items-center gap-3 p-4">
            <Wrench className="size-5 text-brand" />
            <div className="flex-1 text-sm">{plan ? <>A fix is planned: <b>{plan.remediation.action}</b> <Mono>{plan.remediation.target}</Mono></> : "No fix planned yet. The Remediator proposes one from a computed list of safe options."}</div>
            {plan ? <Button variant="primary" onClick={() => go("remediation", f.id)}>Review plan</Button>
              : <Button variant="primary" disabled={mPlan.isPending || !!job} onClick={() => mPlan.mutate()}>Plan a fix</Button>}
          </Card>
          {job && <JobLog jobId={job} onDone={() => toast.success("Plan created. Review it in Remediation.")} />}
        </div>
      </TabsContent>

      <TabsContent value="ai">
        {f.assessment ? (
          <div className="space-y-3">
            <Card className="p-4 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <Badge className="bg-violet-50 text-violet-700 ring-violet-200">{f.assessment.mode}</Badge>
                <span className="font-semibold">{f.assessment.verdict.replace(/_/g, " ")}</span>
                <span className="text-ink-3">· priority {f.assessment.adjusted_priority} · confidence {pct(f.assessment.confidence)}%</span>
              </div>
              <p className="mt-2 text-ink-2">{f.assessment.rationale}</p>
              {f.assessment.skeptic_note && <p className="mt-2 text-xs text-ink-3">Skeptic: {f.assessment.skeptic_note}</p>}
              {f.assessment.ai_error && <p className="mt-2 text-xs text-human">{f.assessment.ai_error}</p>}
            </Card>
            {f.assessment.claims.map((c, i) => (
              <Card key={i} className={cn("flex gap-3 p-3.5 text-sm", c.kind === "verified_fact" ? "border-emerald-200" : "border-violet-200")}>
                {c.kind === "verified_fact" ? <ShieldCheck className="mt-0.5 size-4 shrink-0 text-ok" /> : <Lightbulb className="mt-0.5 size-4 shrink-0 text-ai" />}
                <div className="min-w-0">
                  <div className="text-[11px] font-semibold uppercase tracking-wide">{c.kind === "verified_fact" ? <span className="text-ok">Verified fact</span> : <span className="text-ai">Inference</span>}</div>
                  <div className="mt-0.5">{c.statement}</div>
                  {!!c.evidence_ids.length && <div className="mt-1 flex flex-wrap gap-1">{c.evidence_ids.map((e) => <Mono key={e}>{e}</Mono>)}</div>}
                  {c.downgraded && <div className="mt-1 text-xs text-crit">Downgraded: {c.downgraded}</div>}
                </div>
              </Card>))}
          </div>
        ) : <Empty icon={<Lightbulb className="size-6" />} title="Not AI-assessed in this run">The AI looks at the top finding of each type. Raise <Mono>--investigate</Mono> to cover more.</Empty>}
      </TabsContent>

      <TabsContent value="evidence">
        <div className="space-y-2">
          {ev.isLoading && <p className="text-sm text-ink-3">Loading ledger records…</p>}
          {Object.entries(ev.data ?? {}).map(([id, rec]) => rec && (
            <details key={id} className="rounded-lg border border-line bg-white">
              <summary className="flex cursor-pointer items-center gap-3 px-4 py-2.5 text-sm">
                <Mono>{id}</Mono><Badge className="bg-slate-50 text-ink-2 ring-line">{String(rec.kind)}</Badge>
                <span className="min-w-0 flex-1 truncate text-ink-2">{String(rec.source)}</span>
                <span className="font-mono text-[11px] text-ink-3">{String(rec.hash).slice(0, 10)}</span>
              </summary>
              <pre className="max-h-80 overflow-auto border-t border-line bg-slate-50 px-4 py-3 font-mono text-[11.5px] leading-relaxed">{JSON.stringify(rec.data, null, 2)}</pre>
            </details>))}
        </div>
      </TabsContent>
    </Tabs>
  );
}
