import { useQuery } from "@tanstack/react-query";
import { Activity, Bot, FileCheck2, GitFork, LayoutDashboard, ListChecks, Radar, ScrollText, ShieldCheck, ShieldX } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { api } from "./lib/api";
import { cn } from "./lib/utils";
import { Button, Empty } from "./components/ui";
import Overview from "./pages/Overview";
import Findings from "./pages/Findings";
import RiskGraph from "./pages/RiskGraph";
import Remediation from "./pages/Remediation";
import Audit from "./pages/Audit";
import Scan from "./pages/Scan";

const PAGES = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "findings", label: "Findings", icon: ListChecks },
  { id: "graph", label: "Risk map", icon: GitFork },
  { id: "remediation", label: "Remediation", icon: FileCheck2 },
  { id: "audit", label: "Policy & audit", icon: ScrollText },
  { id: "scan", label: "New scan", icon: Radar },
] as const;
type PageId = (typeof PAGES)[number]["id"];
const HIDDEN = new Set<PageId>(["remediation", "audit"]);
const NAV = PAGES.filter((p) => !HIDDEN.has(p.id));

const readHash = (): PageId => {
  const h = location.hash.replace("#", "");
  return (PAGES.find((p) => p.id === h)?.id ?? "overview") as PageId;
};

export default function App() {
  const [page, setPage] = useState<PageId>(readHash);
  const [run, setRun] = useState<string | null>(() => { try { return localStorage.getItem("guardian.run"); } catch { return null; } });
  const [focus, setFocus] = useState<string | null>(null);   // finding to open in Findings

  useEffect(() => { const f = () => setPage(readHash()); addEventListener("hashchange", f); return () => removeEventListener("hashchange", f); }, []);
  const go = (p: PageId, findingId?: string) => { if (findingId) setFocus(findingId); location.hash = p; setPage(p); };

  const runs = useQuery({ queryKey: ["runs"], queryFn: api.runs });
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  useEffect(() => {
    const list = runs.data ?? [];
    if (list.length && (!run || !list.some((r) => r.run === run))) setRun(list.find((r) => r.run === "out")?.run ?? list[0].run);
  }, [runs.data, run]);
  useEffect(() => { try { if (run) localStorage.setItem("guardian.run", run); } catch { /* storage blocked */ } }, [run]);

  const state = useQuery({ queryKey: ["state", run], queryFn: () => api.state(run!), enabled: !!run });
  const s = state.data;

  let body: ReactNode;
  if (page === "scan") body = <Scan onScanned={(out) => { setRun(out); go("overview"); }} />;
  else if (!runs.isLoading && !runs.data?.length) body = (
    <Empty icon={<Radar className="size-6" />} title="No scans yet">
      Run your first scan from <button className="font-medium text-brand underline" onClick={() => go("scan")}>New scan</button>, or in a terminal: <code className="font-mono">./run_demo.sh</code>
    </Empty>);
  else if (!s || !run) body = <div className="p-10 text-ink-3">{state.error ? String(state.error) : "Loading…"}</div>;
  else if (page === "overview") body = <Overview s={s} run={run} go={go} />;
  else if (page === "findings") body = <Findings s={s} run={run} focus={focus} clearFocus={() => setFocus(null)} go={go} />;
  else if (page === "graph") body = <RiskGraph s={s} run={run} go={go} />;
  else if (page === "remediation") body = <Remediation s={s} run={run} go={go} />;
  else body = <Audit s={s} run={run} />;

  const title = PAGES.find((p) => p.id === page)!.label;
  return (
    <div className="flex h-full">
      <aside className="hidden w-60 shrink-0 flex-col border-r border-line bg-white md:flex">
        <div className="flex items-center gap-2.5 px-5 py-5">
          <div className="grid size-9 place-items-center rounded-lg bg-brand text-white shadow-sm"><ShieldCheck className="size-5" /></div>
          <div className="leading-tight">
            <div className="text-[15px] font-semibold tracking-tight">Guardian</div>
            <div className="text-xs text-ink-3">Supply chain console</div>
          </div>
        </div>
        <nav className="flex flex-col gap-0.5 px-3">
          {NAV.map((p) => (
            <button key={p.id} onClick={() => go(p.id)}
              className={cn("flex items-center gap-2.5 rounded-lg px-3 py-2 text-left text-sm font-medium transition-colors",
                page === p.id ? "bg-brand-soft text-brand" : "text-ink-2 hover:bg-slate-50 hover:text-ink")}>
              <p.icon className="size-4" />{p.label}
              {p.id === "remediation" && s && s.plans.some((x) => !x.approval) &&
                <span className="ml-auto rounded-full bg-human/15 px-1.5 text-[11px] font-semibold text-human">{s.plans.filter((x) => !x.approval).length}</span>}
            </button>
          ))}
        </nav>
        <div className="mt-auto space-y-3 border-t border-line p-4 text-xs">
          <div className="flex items-center gap-2 text-ink-2"><Bot className="size-4 text-ai" /><span className="truncate">{health.data?.brain ?? "…"}</span></div>
          <div className="flex items-center gap-2 text-ink-2"><Activity className="size-4 text-ok" />API on 127.0.0.1 only</div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex flex-wrap items-center gap-3 border-b border-line bg-white/85 px-6 py-3 backdrop-blur">
          <h1 className="text-lg font-semibold tracking-tight">{title}</h1>
          {s && page !== "scan" && (
            <span className={cn("inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset",
              s.policy.build_allowed ? "bg-emerald-50 text-emerald-700 ring-emerald-200" : "bg-rose-50 text-rose-700 ring-rose-200")}>
              {s.policy.build_allowed ? <ShieldCheck className="size-3.5" /> : <ShieldX className="size-3.5" />}
              Build {s.policy.build_allowed ? "allowed" : "blocked"}
            </span>
          )}
          <div className="ml-auto flex items-center gap-2">
            <label htmlFor="run" className="text-xs text-ink-3">Project</label>
            <select id="run" value={run ?? ""} onChange={(e) => setRun(e.target.value)}
              className="h-9 rounded-lg border border-line bg-white px-2.5 text-sm font-medium outline-none focus:border-brand">
              {(runs.data ?? []).map((r) => <option key={r.run} value={r.run}>{r.app} · {r.run}</option>)}
            </select>
            <Button size="md" variant="primary" onClick={() => go("scan")}><Radar className="size-4" />Scan</Button>
          </div>
          <nav className="flex w-full gap-1 overflow-x-auto md:hidden">
            {NAV.map((p) => <button key={p.id} onClick={() => go(p.id)} className={cn("rounded-md px-2.5 py-1 text-xs font-medium", page === p.id ? "bg-brand-soft text-brand" : "text-ink-2")}>{p.label}</button>)}
          </nav>
        </header>
        <main className="min-w-0 flex-1 overflow-y-auto p-6">{body}</main>
      </div>
    </div>
  );
}