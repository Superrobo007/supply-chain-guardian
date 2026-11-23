import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type { Priority } from "./api";

export const cn = (...v: ClassValue[]) => twMerge(clsx(v));

export const PRIORITIES: Priority[] = ["Critical", "High", "Medium", "Low"];

export const prioColor: Record<Priority, string> = {
  Critical: "#e11d48", High: "#f97316", Medium: "#eab308", Low: "#94a3b8",
};

export const prioClass: Record<Priority, string> = {
  Critical: "bg-rose-50 text-rose-700 ring-rose-200",
  High: "bg-orange-50 text-orange-700 ring-orange-200",
  Medium: "bg-amber-50 text-amber-800 ring-amber-200",
  Low: "bg-slate-100 text-slate-600 ring-slate-200",
};

export const TYPE_LABEL: Record<string, string> = {
  vulnerability: "Known vulnerability",
  typosquat: "Typosquat suspect",
  suspicious_version: "Version anomaly",
  install_script: "Install script",
  lockfile_uncommitted: "No committed lockfile",
  lockfile_integrity: "Lockfile integrity",
  lockfile_drift: "Lockfile tampering",
  unpinned_image: "Unpinned image",
  unpinned_build_tool: "Floating build tool",
  container_root: "Container as root",
  unpinned_action: "Unpinned CI action",
  ci_risky_trigger: "Risky CI trigger",
  ci_curl_pipe: "curl | sh in CI",
};

export const REACH_LABEL: Record<string, string> = {
  reachable_direct: "Imported by app",
  transitive_of_reachable: "Via imported package",
  unreferenced: "Not referenced",
  dev_or_test_only: "Dev / test only",
  "n/a": "Build / CI",
};

export const typeLabel = (t: string) => TYPE_LABEL[t] ?? t.replace(/_/g, " ");

export function timeAgo(ts: number) {
  const s = Math.max(1, Math.round(Date.now() / 1000 - ts));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}
