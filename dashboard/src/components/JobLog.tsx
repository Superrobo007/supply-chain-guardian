import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Loader2, XCircle } from "lucide-react";
import { useEffect, useRef } from "react";
import { api } from "../lib/api";
import { cn } from "../lib/utils";

/** Live log for a background Guardian job; refreshes the run's data when the job finishes. */
export function JobLog({ jobId, onDone, className }: { jobId: string; onDone?: () => void; className?: string }) {
  const qc = useQueryClient();
  const { data } = useQuery({
    queryKey: ["job", jobId],
    queryFn: () => api.job(jobId),
    refetchInterval: (q) => (q.state.data?.status === "running" ? 800 : false),
  });
  const done = useRef(false);
  const box = useRef<HTMLPreElement>(null);
  useEffect(() => {
    if (data && data.status !== "running" && !done.current) {
      done.current = true;
      qc.invalidateQueries({ queryKey: ["state"] });
      qc.invalidateQueries({ queryKey: ["runs"] });
      qc.invalidateQueries({ queryKey: ["ledger"] });
      qc.invalidateQueries({ queryKey: ["riskmap"] });
      onDone?.();
    }
    box.current?.scrollTo({ top: box.current.scrollHeight });
  }, [data, qc, onDone]);

  const status = data?.status ?? "running";
  return (
    <div className={cn("overflow-hidden rounded-lg border border-line bg-white", className)}>
      <div className="flex items-center gap-2 border-b border-line px-3 py-2 text-sm">
        {status === "running" && <Loader2 className="size-4 animate-spin text-brand" />}
        {status === "done" && <CheckCircle2 className="size-4 text-ok" />}
        {status === "failed" && <XCircle className="size-4 text-crit" />}
        <span className="font-medium capitalize">{data?.kind ?? "job"}</span>
        <span className="text-ink-3">{status === "running" ? "running…" : status === "done" ? "finished" : `failed (exit ${data?.exit})`}</span>
      </div>
      <pre ref={box} className="max-h-72 overflow-auto bg-slate-50 px-3 py-2 font-mono text-[12px] leading-relaxed text-ink-2">
        {(data?.log ?? []).join("\n") || "starting…"}
      </pre>
    </div>
  );
}
