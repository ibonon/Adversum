import React, { useCallback, useEffect, useMemo } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  addEdge,
  MarkerType,
  type Node,
  type Edge,
  type Connection,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface AttackNode {
  id: string;
  label: string;
  type: "attacker" | "flashloan" | "target" | "victim" | "bridge" | "oracle";
  protocol: string;
}

export interface AttackEdge {
  from: string;
  to: string;
  label: string;
  amount_usd: number;
  token: string;
  animated?: boolean;
}

export interface AttackFlowProps {
  nodes: AttackNode[];
  edges: AttackEdge[];
  activeStepIndex?: number;
  className?: string;
}

// ─── Node color scheme per type ──────────────────────────────────────────────

const NODE_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  attacker:  { bg: "#1a0a0a", border: "#ef4444", text: "#ef4444" },
  flashloan: { bg: "#0a0a1a", border: "#6366f1", text: "#6366f1" },
  target:    { bg: "#1a0a0a", border: "#f97316", text: "#f97316" },
  victim:    { bg: "#0f1a0a", border: "#22c55e", text: "#22c55e" },
  bridge:    { bg: "#0a1a1a", border: "#06b6d4", text: "#06b6d4" },
  oracle:    { bg: "#1a1a0a", border: "#eab308", text: "#eab308" },
};

const NODE_ICONS: Record<string, string> = {
  attacker:  "💀",
  flashloan: "⚡",
  target:    "🏦",
  victim:    "😱",
  bridge:    "🌉",
  oracle:    "🔮",
};

// ─── Default scenario (Euler Finance) when no props provided ─────────────────

const EULER_NODES: AttackNode[] = [
  { id: "attacker",  label: "Attacker EOA",       type: "attacker",  protocol: "Attacker"       },
  { id: "aave",      label: "Aave v2\nFlash Loan", type: "flashloan", protocol: "Aave v2"        },
  { id: "euler",     label: "Euler Finance\n(Target)", type: "target", protocol: "Euler Finance"  },
  { id: "reserve",   label: "Reserve Pool\n(Victim)",  type: "victim", protocol: "Euler Reserve" },
  { id: "oracle",    label: "Price Oracle\n(Spot)",    type: "oracle", protocol: "Chainlink"     },
];

const EULER_EDGES: AttackEdge[] = [
  { from: "attacker", to: "aave",    label: "Borrow",     amount_usd: 30_000_000, token: "DAI",  animated: true  },
  { from: "aave",     to: "euler",   label: "Deposit 10x",amount_usd: 300_000_000,token: "eDAI", animated: true  },
  { from: "attacker", to: "oracle",  label: "Read Price", amount_usd: 0,          token: "N/A",  animated: false },
  { from: "euler",    to: "reserve", label: "donate()",   amount_usd: 100_000_000,token: "eDAI", animated: true  },
  { from: "reserve",  to: "attacker",label: "Liquidation\n+$197M",amount_usd: 197_000_000, token: "DAI", animated: true },
  { from: "attacker", to: "aave",    label: "Repay",      amount_usd: 30_027_000, token: "DAI",  animated: false },
];

// ─── Layout positions ────────────────────────────────────────────────────────

const DEFAULT_POSITIONS: Record<string, { x: number; y: number }> = {
  attacker: { x: 50,  y: 250 },
  aave:     { x: 300, y: 50  },
  euler:    { x: 550, y: 250 },
  reserve:  { x: 800, y: 250 },
  oracle:   { x: 550, y: 450 },
  bridge:   { x: 700, y: 450 },
  victim:   { x: 800, y: 50  },
  target:   { x: 550, y: 250 },
};

function getPosition(id: string, index: number) {
  if (DEFAULT_POSITIONS[id]) return DEFAULT_POSITIONS[id];
  const cols = 3;
  const col = index % cols;
  const row = Math.floor(index / cols);
  return { x: 100 + col * 280, y: 100 + row * 200 };
}

function formatUSD(amount: number): string {
  if (amount === 0) return "";
  if (amount >= 1_000_000) return `$${(amount / 1_000_000).toFixed(1)}M`;
  if (amount >= 1_000) return `$${(amount / 1_000).toFixed(0)}K`;
  return `$${amount}`;
}

// ─── Component ───────────────────────────────────────────────────────────────

export default function AttackFlow({
  nodes: propNodes = EULER_NODES,
  edges: propEdges = EULER_EDGES,
  activeStepIndex,
  className = "",
}: AttackFlowProps) {
  const rfNodes: Node[] = useMemo(() =>
    propNodes.map((n, i) => {
      const colors = NODE_COLORS[n.type] || NODE_COLORS.target;
      return {
        id: n.id,
        position: getPosition(n.id, i),
        data: {
          label: (
            <div className="flex flex-col items-center gap-1 px-2 py-1">
              <span className="text-xl">{NODE_ICONS[n.type] || "🔵"}</span>
              <span className="text-xs font-bold whitespace-pre-wrap text-center" style={{ color: colors.text }}>
                {n.label}
              </span>
              <span className="text-[10px] opacity-60">{n.protocol}</span>
            </div>
          ),
        },
        style: {
          background: colors.bg,
          border: `1.5px solid ${colors.border}`,
          borderRadius: "12px",
          minWidth: "120px",
          boxShadow: `0 0 16px ${colors.border}44`,
        },
      } satisfies Node;
    }),
    [propNodes]
  );

  const rfEdges: Edge[] = useMemo(() =>
    propEdges.map((e, i) => ({
      id: `e-${i}-${e.from}-${e.to}`,
      source: e.from,
      target: e.to,
      label: `${e.label}${e.amount_usd > 0 ? `\n${formatUSD(e.amount_usd)} ${e.token}` : ""}`,
      animated: e.animated ?? true,
      markerEnd: { type: MarkerType.ArrowClosed, color: "#ef4444" },
      style: { stroke: e.animated ? "#ef4444" : "#555", strokeWidth: 2 },
      labelStyle: { fill: "#ccc", fontSize: 10, fontFamily: "monospace" },
      labelBgStyle: { fill: "#111", fillOpacity: 0.8 },
    })),
    [propEdges]
  );

  const [nodes, setNodes, onNodesChange] = useNodesState(rfNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(rfEdges);

  // Sync when props change
  useEffect(() => { setNodes(rfNodes); }, [rfNodes, setNodes]);
  useEffect(() => { setEdges(rfEdges); }, [rfEdges, setEdges]);

  const onConnect = useCallback(
    (params: Connection) => setEdges((eds) => addEdge(params, eds)),
    [setEdges]
  );

  return (
    <div className={`w-full h-full min-h-[420px] rounded-xl overflow-hidden border border-white/10 ${className}`}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        fitView
        attributionPosition="bottom-right"
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#1a1a2e" gap={24} />
        <Controls
          style={{ background: "#111", border: "1px solid #333" }}
          showInteractive={false}
        />
        <MiniMap
          style={{ background: "#0a0a0f", border: "1px solid #333" }}
          nodeColor="#ef4444"
          maskColor="#000a"
        />
      </ReactFlow>
    </div>
  );
}
