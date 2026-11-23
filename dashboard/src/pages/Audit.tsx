import { useQuery } from "@tanstack/react-query";
import { Ban, Download, Fingerprint, Link2, ShieldAlert, TriangleAlert } from "lucide-react";
import { api, type State } from "../lib/api";
import { cn } from "../lib/utils";
import { Badge, Card, CardHeader, Mono } from "../components/ui";

const ACTOR = (a: string) => a.startsWith("human:") ? "bg-amber-50 text-amber-800 ring-amber-200"
  : a.startsWith("ai:") ? "bg-violet-50 text-violet-700 ring-violet-200" : "bg-slate-50 text-ink-2 ring-line";

export default function Audit({ s, run }: { s: State; run: string }) {
  const led = useQuery({ queryKey: ["ledger", run], queryFn: () => api.ledger(run) });
  const files = ["report.html", "report.json", "report.md", "sbom.cdx.json", "ledger.jsonl"];
  return (
    <div className="mx-auto grid max-w-[1400px] gap-5 xl:grid-cols-[1fr_1.3fr]">
      <div className="space-y-5">
        <Card>
          <CardHeader title="Build gate" sub={`Policy-as-code (${s.policy.engine === "opa" ? "Open Policy Agent" : "Rego rules, Python evaluator"}) · policy/guardian.rego`} />
          <div className="space-y-2 p-5">
            {s.policy.deny.length ? s.policy.deny.map((d) => (
              <div key={d} className="flex gap-2 rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-800 ring-1 ring-rose-200"><Ban className="mt-0.5 size-4 shrink-0" />{d}</div>))
              : <p className="text-sm text-ok">No blocking violations.</p>}
            <details className="pt-2">
              <summary className="cursor-pointer text-sm font-medium text-ink-2">{s.policy.warn.length} warnings (allowed, reported)</summary>
              <ul className="mt-2 space-y-1.5">{s.policy.warn.map((w) => (
                <li key={w} className="flex gap-2 text-sm text-ink-2"><TriangleAlert className="mt-0.5 size-4 shrink-0 text-med" />{w}</li>))}</ul>
            </details>
            <div className="mt-3 flex items-center gap-2 rounded-lg bg-slate-50 px-3 py-2 text-sm ring-1 ring-line">
              <ShieldAlert className="size-4 text-brand" /> Auto-merge allowed: <b>never</b> · fixes enter the sandbox only after a named human approves
            </div>
          </div>
        </Card>
        <Card>
          <CardHeader title="Downloads" sub="Machine- and human-readable deliverables" />
          <div className="grid grid-cols-2 gap-2 p-5">
            {files.map((f) => (
              <a key={f} href={`/api/runs/${run}/download/${f}`} className="flex items-center gap-2 rounded-lg border border-line px-3 py-2 text-sm hover:border-brand hover:text-brand">
                <Download className="size-4" />{f}</a>))}
          </div>
        </Card>
      </div>

      <Card className="min-w-0">
        <CardHeader title="Evidence ledger" sub="Every fact, AI claim and human approval, hash-chained"
          right={led.data && <Badge className={led.data.ok ? "bg-emerald-50 text-emerald-700 ring-emerald-200" : "bg-rose-50 text-rose-700 ring-rose-200"}>
            <Fingerprint className="size-3.5" />{led.data.ok ? "chain intact" : "TAMPERED"}</Badge>} />
        {led.data && (
          <>
            <div className="flex flex-wrap gap-1.5 border-b border-line px-5 py-3">
              {Object.entries(led.data.kinds).sort((a, b) => b[1] - a[1]).map(([k, n]) => (
                <Badge key={k} className="bg-white text-ink-2 ring-line">{k} <span className="tnum text-ink-3">{n}</span></Badge>))}
            </div>
            <div className="max-h-[640px] overflow-auto">
              <table className="w-full min-w-[640px] text-sm">
                <thead className="sticky top-0 bg-white"><tr className="border-b border-line text-left text-xs uppercase tracking-wide text-ink-3">
                  <th className="px-5 py-2">ID</th><th className="px-2 py-2">Kind</th><th className="px-2 py-2">Actor</th><th className="px-2 py-2">Source</th><th className="px-5 py-2">Hash</th></tr></thead>
                <tbody>{led.data.records.map((r, i) => (
                  <tr key={r.id} className="border-b border-line last:border-0">
                    <td className="px-5 py-1.5"><Mono>{r.id}</Mono></td>
                    <td className="px-2 py-1.5 text-ink-2">{r.kind}</td>
                    <td className="px-2 py-1.5"><Badge className={ACTOR(r.actor)}>{r.actor}</Badge></td>
                    <td className="max-w-[260px] truncate px-2 py-1.5 text-xs text-ink-3">{r.source}</td>
                    <td className="px-5 py-1.5 font-mono text-[11px] text-ink-3"><span className={cn("inline-flex items-center gap-1", i < led.data!.records.length - 1 && "")}><Link2 className="size-3" />{r.hash.slice(0, 12)}</span></td>
                  </tr>))}</tbody>
              </table>
            </div>
            <p className="border-t border-line px-5 py-2.5 text-xs text-ink-3">{led.data.message}. Showing the latest {led.data.records.length} of {led.data.total}.</p>
          </>)}
      </Card>
    </div>
  );
}
