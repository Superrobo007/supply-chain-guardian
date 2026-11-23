import { ArrowRight, Boxes, CheckCircle2, Container, Fingerprint, GitBranch, ShieldAlert, Target, UserCheck } from "lucide-react";
import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Finding, Priority, State } from "../lib/api";
import { PRIORITIES, REACH_LABEL, cn, prioColor, typeLabel } from "../lib/utils";
import { Badge, Card, CardHeader, PriorityBadge } from "../components/ui";

type Go = (p: "findings" | "remediation" | "graph" | "audit", id?: string) => void;

function Kpi({ label, value, sub, icon, tone }: { label: string; value: React.ReactNode; sub?: React.ReactNode; icon: React.ReactNode; tone?: string }) {
  return (
    <Card className="p-4">
      <div className="flex items-center justify-between text-[13px] font-medium text-ink-3">{label}<span className={cn("rounded-md p-1.5", tone ?? "bg-brand-soft text-brand")}>{icon}</span></div>
      <div className="mt-2 text-[28px] font-semibold leading-none tracking-tight tnum">{value}</div>
      {sub && <div className="mt-2 text-[12.5px] text-ink-3">{sub}</div>}
    </Card>
  );
}

const STAGES = [
  { k: "Discover", d: "SBOM + graph" }, { k: "Detect", d: "CVEs + anomalies" }, { k: "Analyze", d: "reachability, AI" },
  { k: "Remediate", d: "plans + approval" }, { k: "Validate", d: "sandbox rescan" },
];

export default function Overview({ s, go }: { s: State; run: string; go: Go }) {
  const f = s.findings;
  const byPrio = PRIORITIES.map((p) => ({ name: p, value: f.filter((x) => x.priority === p).length }));
  const typeCounts = Object.entries(f.reduce<Record<string, number>>((a, x) => ((a[x.type] = (a[x.type] ?? 0) + 1), a), {}))
    .map(([t, n]) => ({ t: typeLabel(t), n })).sort((a, b) => b.n - a.n);
  const pkgFindings = f.filter((x) => x.reachability.status !== "n/a");
  const reach = ["reachable_direct", "transitive_of_reachable", "unreferenced", "dev_or_test_only"].map((k) => ({
    k, label: REACH_LABEL[k], n: pkgFindings.filter((x) => x.reachability.status === k).length,
  }));
  const reachable = reach[0].n + reach[1].n;
  const top = f.slice(0, 7);
  const pending = s.plans.filter((p) => !p.approval);
  const verified = s.validations.filter((v) => v.status === "VERIFIED").length;
  const stageCount = [s.inventory.components, f.length, f.filter((x) => x.assessment).length, s.plans.length, s.validations.length];

  return (
    <div className="mx-auto max-w-[1400px] space-y-5">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h2 className="text-2xl font-semibold tracking-tight">{s.inventory.app}</h2>
        <span className="truncate font-mono text-xs text-ink-3">{s.target}</span>
        <Badge className="bg-violet-50 text-violet-700 ring-violet-200">brain: {s.ai_mode}</Badge>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <Kpi label="Components" value={s.inventory.components.toLocaleString()} icon={<Boxes className="size-4" />}
          sub={<>{s.inventory.direct} direct · {(s.inventory.components - s.inventory.direct).toLocaleString()} transitive</>} />
        <Kpi label="Findings" value={f.length} icon={<ShieldAlert className="size-4" />} tone="bg-rose-50 text-crit"
          sub={<><b className="text-crit">{byPrio[0].value}</b> critical · <b className="text-high">{byPrio[1].value}</b> high</>} />
        <Kpi label="Reachable by app code" value={reachable} icon={<Target className="size-4" />} tone="bg-orange-50 text-high"
          sub={<>of {pkgFindings.length} package findings</>} />
        <Kpi label="Containers & CI" value={s.inventory.images.length + s.inventory.actions} icon={<Container className="size-4" />}
          sub={<>{s.inventory.images.length} base images · {s.inventory.actions} actions</>} />
        <Kpi label="Evidence ledger" value={s.ledger_status.ok ? "Intact" : "Tampered"} icon={<Fingerprint className="size-4" />}
          tone={s.ledger_status.ok ? "bg-emerald-50 text-ok" : "bg-rose-50 text-crit"}
          sub={<span className="truncate">{s.ledger_status.message.split(",")[0]}</span>} />
      </div>

      <Card className="overflow-x-auto">
        <div className="grid min-w-[720px] grid-cols-5">
          {STAGES.map((st, i) => (
            <div key={st.k} className={cn("relative px-5 py-4", i && "border-l border-line")}>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-ink-3">{i + 1} · {st.k}</div>
              <div className="mt-1 text-xl font-semibold tnum">{stageCount[i].toLocaleString()}</div>
              <div className="text-xs text-ink-3">{["components mapped", "findings raised", "AI-assessed", "fix plans", "validated"][i]} · {st.d}</div>
              {i < 4 && <ArrowRight className="absolute -right-2.5 top-1/2 z-10 size-5 -translate-y-1/2 rounded-full bg-white p-0.5 text-ink-3 ring-1 ring-line" />}
            </div>
          ))}
        </div>
      </Card>

      <div className="grid gap-5 xl:grid-cols-3">
        <Card>
          <CardHeader title="Risk by priority" sub="Severity × reachability × exposure × environment" />
          <div className="flex items-center gap-4 p-5">
            <div className="relative size-44 shrink-0">
              <ResponsiveContainer>
                <PieChart>
                  <Pie data={byPrio} dataKey="value" innerRadius={56} outerRadius={82} paddingAngle={2} stroke="none" isAnimationActive={false}>
                    {byPrio.map((d) => <Cell key={d.name} fill={prioColor[d.name as Priority]} />)}
                  </Pie>
                  <Tooltip formatter={(v) => [v, "findings"]} />
                </PieChart>
              </ResponsiveContainer>
              <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">
                <div><div className="text-2xl font-semibold tnum">{f.length}</div><div className="text-[11px] text-ink-3">findings</div></div>
              </div>
            </div>
            <ul className="flex-1 space-y-2.5 text-sm">
              {byPrio.map((d) => (
                <li key={d.name} className="flex items-center gap-2">
                  <span className="size-2.5 rounded-sm" style={{ background: prioColor[d.name as Priority] }} />{d.name}
                  <span className="ml-auto font-semibold tnum">{d.value}</span>
                </li>
              ))}
            </ul>
          </div>
        </Card>

        <Card>
          <CardHeader title="What kind of risk" sub="CVEs plus attacks that have no CVE yet" />
          <div className="px-2 py-3" style={{ height: Math.max(180, typeCounts.length * 24 + 20) }}>
            <ResponsiveContainer>
              <BarChart data={typeCounts} layout="vertical" margin={{ left: 8, right: 24 }}>
                <XAxis type="number" hide />
                <YAxis type="category" dataKey="t" width={168} tick={{ fontSize: 11.5, fill: "#4b5563", width: 400 }} axisLine={false} tickLine={false} interval={0} />
                <Tooltip cursor={{ fill: "#f1f5f9" }} formatter={(v) => [v, "findings"]} />
                <Bar dataKey="n" fill="#4f46e5" radius={[0, 4, 4, 0]} barSize={11} isAnimationActive={false}
                  label={{ position: "right", fontSize: 11, fill: "#4b5563" }} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card>
          <CardHeader title="Does it reach the app?" sub="Static import scan of the app's own source" />
          <div className="space-y-3.5 p-5">
            {reach.map((r) => (
              <div key={r.k}>
                <div className="mb-1 flex justify-between text-sm"><span>{r.label}</span><span className="font-semibold tnum">{r.n}</span></div>
                <div className="h-2 rounded-full bg-slate-100">
                  <div className="h-2 rounded-full" style={{ width: `${pkgFindings.length ? (r.n / pkgFindings.length) * 100 : 0}%`,
                    background: ["#e11d48", "#f97316", "#94a3b8", "#cbd5e1"][reach.indexOf(r)] }} />
                </div>
              </div>
            ))}
            <p className="pt-1 text-xs text-ink-3">A bug in code the app never imports is real but less urgent. That's why the risk score multiplies in reachability.</p>
          </div>
        </Card>
      </div>

      <div className="grid gap-5 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader title="Top risks" sub="Highest score first. Click for evidence." right={
            <button className="text-sm font-medium text-brand hover:underline" onClick={() => go("findings")}>All findings →</button>} />
          <ul className="divide-y divide-line">
            {top.map((x: Finding) => (
              <li key={x.id}>
                <button onClick={() => go("findings", x.id)} className="flex w-full items-center gap-3 px-5 py-3 text-left hover:bg-slate-50">
                  <span className="w-12 font-mono text-xs text-ink-3">{x.id}</span>
                  <PriorityBadge p={x.priority} />
                  <span className="min-w-0 flex-1 truncate text-sm">{x.title}</span>
                  <span className="hidden text-xs text-ink-3 sm:inline">{REACH_LABEL[x.reachability.status] ?? x.reachability.status}</span>
                  <span className="w-10 text-right font-semibold tnum">{x.risk_score.toFixed(1)}</span>
                </button>
              </li>
            ))}
          </ul>
        </Card>

        <Card>
          <CardHeader title="Needs a human" sub="Nothing changes without your approval" />
          <div className="space-y-3 p-5 text-sm">
            <div className="flex items-center gap-3 rounded-lg bg-amber-50 p-3 ring-1 ring-amber-200">
              <UserCheck className="size-5 text-human" />
              <div><div className="font-semibold">{pending.length} plan{pending.length === 1 ? "" : "s"} awaiting approval</div>
                <div className="text-xs text-ink-2">Review the proposed fix, then approve or pick another option</div></div>
            </div>
            <div className="flex items-center gap-3 rounded-lg bg-emerald-50 p-3 ring-1 ring-emerald-200">
              <CheckCircle2 className="size-5 text-ok" />
              <div><div className="font-semibold">{verified} verified fix{verified === 1 ? "" : "es"}</div>
                <div className="text-xs text-ink-2">Rescanned in a sandbox; patch ready for review</div></div>
            </div>
            <div className="flex items-center gap-3 rounded-lg bg-rose-50 p-3 ring-1 ring-rose-200">
              <GitBranch className="size-5 text-crit" />
              <div><div className="font-semibold">{s.policy.deny.length} policy violation{s.policy.deny.length === 1 ? "" : "s"}</div>
                <div className="text-xs text-ink-2">These block the build until fixed or accepted</div></div>
            </div>
            <button onClick={() => go("remediation")} className="w-full rounded-lg bg-brand py-2 text-sm font-medium text-white hover:bg-indigo-700">Open remediation</button>
          </div>
        </Card>
      </div>
    </div>
  );
}
