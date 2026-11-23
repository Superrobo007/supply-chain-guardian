import dagre from "@dagrejs/dagre";
import { useQuery } from "@tanstack/react-query";
import { Background, Controls, Handle, MarkerType, MiniMap, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import { GitFork } from "lucide-react";
import { useMemo } from "react";
import { api, type RiskNode, type State } from "../lib/api";
import { PRIORITIES, cn, prioColor, typeLabel } from "../lib/utils";
import { Card, Empty } from "../components/ui";

type Go = (p: "findings", id?: string) => void;
type PkgData = { n: RiskNode };
const W = 210, H = 54;

function PkgNode({ data }: NodeProps<Node<PkgData>>) {
  const n = data.n;
  const isRoot = n.kind === "project";
  const color = n.flag ? prioColor[n.flag.priority] : undefined;
  return (
    <div className={cn("rounded-lg border bg-white px-3 py-2 text-left shadow-sm", isRoot && "border-brand bg-brand text-white", n.flag && "cursor-pointer")}
      style={{ width: W, borderColor: color, borderWidth: n.flag ? 2 : 1 }}>
      <Handle type="target" position={Position.Left} className="!size-1.5 !border-0 !bg-slate-300" />
      <div className="truncate text-[12.5px] font-semibold">{n.name}</div>
      <div className={cn("flex items-center gap-1.5 truncate font-mono text-[10.5px]", isRoot ? "text-indigo-100" : "text-ink-3")}>
        {isRoot ? "application" : n.version}
        {n.flag && <span className="ml-auto rounded px-1 font-sans text-[10px] font-semibold text-white" style={{ background: color }}>{n.flag.priority}</span>}
      </div>
      <Handle type="source" position={Position.Right} className="!size-1.5 !border-0 !bg-slate-300" />
    </div>
  );
}
const nodeTypes = { pkg: PkgNode };

export default function RiskGraph({ s, run, go }: { s: State; run: string; go: Go }) {
  const q = useQuery({ queryKey: ["riskmap", run], queryFn: () => api.riskmap(run) });
  const { nodes, edges } = useMemo(() => {
    if (!q.data) return { nodes: [] as Node<PkgData>[], edges: [] as Edge[] };
    const g = new dagre.graphlib.Graph();
    g.setGraph({ rankdir: "LR", nodesep: 14, ranksep: 70, marginx: 20, marginy: 20 });
    g.setDefaultEdgeLabel(() => ({}));
    q.data.nodes.forEach((n) => g.setNode(n.id, { width: W, height: H }));
    q.data.edges.forEach((e) => g.setEdge(e.source, e.target));
    dagre.layout(g);
    const byId = new Map(q.data.nodes.map((n) => [n.id, n]));
    return {
      nodes: q.data.nodes.map((n) => { const p = g.node(n.id); return { id: n.id, type: "pkg", position: { x: p.x - W / 2, y: p.y - H / 2 }, data: { n } }; }),
      edges: q.data.edges.map((e) => {
        const t = byId.get(e.target);
        const c = t?.flag ? prioColor[t.flag.priority] : "#c7cdd8";
        return { id: `${e.source}->${e.target}`, source: e.source, target: e.target, type: "smoothstep",
          style: { stroke: c, strokeWidth: t?.flag ? 1.8 : 1.2 }, markerEnd: { type: MarkerType.ArrowClosed, color: c, width: 14, height: 14 } };
      }),
    };
  }, [q.data]);

  if (q.isLoading) return <p className="text-ink-3">Laying out the dependency graph…</p>;
  if (!nodes.length) return <Empty icon={<GitFork className="size-6" />} title="No package-level findings to map" />;
  const flagged = q.data!.nodes.filter((n) => n.flag);

  return (
    <div className="mx-auto max-w-[1600px] space-y-4">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
        <p className="text-ink-2">Every risky package and the chain of dependencies that brings it into <b>{s.inventory.app}</b>. Showing {q.data!.nodes.length} of {q.data!.total_packages.toLocaleString()} packages. Click a coloured box to see its evidence.</p>
        <div className="ml-auto flex items-center gap-3">
          {PRIORITIES.map((p) => <span key={p} className="flex items-center gap-1.5 text-xs"><span className="size-2.5 rounded-sm" style={{ background: prioColor[p] }} />{p}</span>)}
        </div>
      </div>
      <Card className="h-[calc(100vh-210px)] min-h-[520px] overflow-hidden">
        <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView minZoom={0.1} maxZoom={1.6} nodesDraggable={false}
          onNodeClick={(_, n) => { const f = (n.data as PkgData).n.flag; if (f) go("findings", f.finding); }} proOptions={{ hideAttribution: true }}>
          <Background gap={20} color="#e5e7eb" />
          <MiniMap pannable zoomable nodeColor={(n) => { const f = (n.data as PkgData).n.flag; return f ? prioColor[f.priority] : "#e2e8f0"; }} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </Card>
      <div className="grid gap-2 text-sm sm:grid-cols-2 xl:grid-cols-4">
        {flagged.sort((a, b) => PRIORITIES.indexOf(a.flag!.priority) - PRIORITIES.indexOf(b.flag!.priority)).slice(0, 8).map((n) => (
          <button key={n.id} onClick={() => go("findings", n.flag!.finding)} className="flex items-center gap-2 rounded-lg border border-line bg-white px-3 py-2 text-left hover:border-brand">
            <span className="size-2.5 shrink-0 rounded-sm" style={{ background: prioColor[n.flag!.priority] }} />
            <span className="truncate font-medium">{n.name}@{n.version}</span>
            <span className="ml-auto shrink-0 text-xs text-ink-3">{typeLabel(n.flag!.type)}</span>
          </button>))}
      </div>
    </div>
  );
}
