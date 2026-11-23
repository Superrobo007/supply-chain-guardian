import { useMutation, useQuery } from "@tanstack/react-query";
import { FolderGit2, Radar } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { api } from "../lib/api";
import { timeAgo } from "../lib/utils";
import { Button, Card, CardHeader, Input } from "../components/ui";
import { JobLog } from "../components/JobLog";

const EXAMPLES = [
  { label: "Juice Shop (local)", target: "targets/juice-shop", out: "out" },
  { label: "PyGoat (Python)", target: "https://github.com/adeyosemanputra/pygoat", out: "out-pygoat" },
  { label: "Express (no lockfile)", target: "https://github.com/expressjs/express", out: "out-express", prepare: true },
];

export default function Scan({ onScanned }: { onScanned: (out: string) => void }) {
  const [target, setTarget] = useState("");
  const [out, setOut] = useState("out-myrepo");
  const [prepare, setPrepare] = useState(true);
  const [investigate, setInvestigate] = useState(8);
  const [job, setJob] = useState<string | null>(null);
  const runs = useQuery({ queryKey: ["runs"], queryFn: api.runs });
  const m = useMutation({ mutationFn: () => api.scan({ target: target.trim(), out: out.trim(), prepare, investigate }),
    onSuccess: (j) => setJob(j.id), onError: (e) => toast.error(String(e)) });

  return (
    <div className="mx-auto grid max-w-[1200px] gap-5 lg:grid-cols-[1.4fr_1fr]">
      <Card>
        <CardHeader title="Scan a repository" sub="A local folder or a Git URL. Read-only: install scripts never run, nothing is pushed." />
        <form className="space-y-4 p-5" onSubmit={(e) => { e.preventDefault(); if (target.trim()) m.mutate(); }}>
          <div>
            <label htmlFor="target" className="text-sm font-medium">Target</label>
            <Input id="target" className="mt-1.5" placeholder="https://github.com/owner/repo  or  /path/to/project" value={target} onChange={(e) => setTarget(e.target.value)} />
            <div className="mt-2 flex flex-wrap gap-1.5">
              {EXAMPLES.map((x) => (
                <button type="button" key={x.label} onClick={() => { setTarget(x.target); setOut(x.out); setPrepare(!!x.prepare); }}
                  className="rounded-md bg-slate-100 px-2 py-1 text-xs text-ink-2 hover:bg-brand-soft hover:text-brand">{x.label}</button>))}
            </div>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label htmlFor="out" className="text-sm font-medium">Save results as</label>
              <Input id="out" className="mt-1.5 font-mono" value={out} onChange={(e) => setOut(e.target.value)} />
              <p className="mt-1 text-xs text-ink-3">Must start with “out”, e.g. out-myrepo</p>
            </div>
            <div>
              <label htmlFor="inv" className="text-sm font-medium">AI investigations</label>
              <Input id="inv" type="number" min={0} max={30} className="mt-1.5" value={investigate} onChange={(e) => setInvestigate(Number(e.target.value))} />
              <p className="mt-1 text-xs text-ink-3">Top finding of each type first</p>
            </div>
          </div>
          <label htmlFor="prep" className="flex items-start gap-2.5 text-sm">
            <input id="prep" type="checkbox" checked={prepare} onChange={(e) => setPrepare(e.target.checked)} className="mt-0.5 accent-indigo-600" />
            <span><b className="font-medium">Generate missing lockfiles</b><br /><span className="text-ink-3">Runs npm with --package-lock-only --ignore-scripts, so no package code executes</span></span>
          </label>
          <Button type="submit" variant="primary" size="lg" disabled={!target.trim() || m.isPending || !!job}><Radar className="size-4" />Start scan</Button>
        </form>
        {job && <div className="px-5 pb-5"><JobLog jobId={job} onDone={() => { setJob(null); toast.success("Scan finished"); onScanned(out.trim()); }} /></div>}
      </Card>

      <Card>
        <CardHeader title="Previous scans" />
        <ul className="divide-y divide-line">
          {(runs.data ?? []).map((r) => (
            <li key={r.run}>
              <button onClick={() => onScanned(r.run)} className="flex w-full items-center gap-3 px-5 py-3 text-left hover:bg-slate-50">
                <FolderGit2 className="size-5 text-brand" />
                <div className="min-w-0 flex-1"><div className="truncate font-medium">{r.app}</div><div className="font-mono text-xs text-ink-3">{r.run} · {timeAgo(r.updated)}</div></div>
                <div className="text-right text-xs"><div className="font-semibold tnum">{r.findings} findings</div>
                  <div className={r.build_allowed ? "text-ok" : "text-crit"}>{r.build_allowed ? "build allowed" : "build blocked"}</div></div>
              </button>
            </li>))}
        </ul>
      </Card>
    </div>
  );
}
