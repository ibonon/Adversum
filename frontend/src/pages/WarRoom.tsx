import React, { useState, useCallback } from "react";
import AttackFlow, { type AttackNode, type AttackEdge } from "@/components/AttackFlow";
import AttackTimeline, { type TimelineStep } from "@/components/AttackTimeline";
import RiskMatrix, { type RiskMatrixData } from "@/components/RiskMatrix";

// ─── Types ────────────────────────────────────────────────────────────────────

interface SimulationResult {
  simulation_id: string;
  scenario_id: string;
  scenario_name: string;
  attacker_profit_usd: number;
  protocol_loss_usd: number;
  total_gas_usd: number;
  block_span: number;
  success: boolean;
  cascade_triggered: boolean;
  cascade_protocols: string[];
  risk_index: number;
  mitre_techniques: string[];
  steps: Array<{
    step_index: number;
    primitive: string;
    protocol: string;
    description: string;
    capital_in: number;
    capital_out: number;
    gas_usd: number;
    token: string;
    block_delta: number;
    net_impact: number;
    cumulative_profit_usd: number;
  }>;
}

interface Scenario {
  scenario_id: string;
  name: string;
  description: string;
  loss_usd: number;
  tags: string[];
  steps: number;
  real_hack_ref: string;
}

// ─── Scenario → Graph Nodes/Edges conversion ──────────────────────────────────

function scenarioIdToNodes(steps: SimulationResult["steps"]): AttackNode[] {
  const protocolMap: Record<string, { type: AttackNode["type"]; id: string }> = {};
  const nodeTypeFor = (primitive: string): AttackNode["type"] => {
    if (primitive === "FLASH_LOAN" || primitive === "REPAY_FLASH") return "flashloan";
    if (primitive === "BRIDGE_DRAIN") return "bridge";
    if (primitive === "ORACLE_MANIP" || primitive === "PRICE_PUMP") return "oracle";
    if (primitive === "LIQUIDATION") return "victim";
    if (primitive === "GOVERNANCE_VOTE") return "victim";
    return "target";
  };

  const nodes: AttackNode[] = [
    { id: "attacker", label: "Attacker", type: "attacker", protocol: "EOA" },
  ];

  steps.forEach((step, i) => {
    const slug = step.protocol.replace(/[^a-zA-Z0-9]/g, "_").toLowerCase();
    if (!protocolMap[step.protocol]) {
      protocolMap[step.protocol] = { type: nodeTypeFor(step.primitive), id: slug };
      nodes.push({
        id: slug,
        label: step.protocol,
        type: nodeTypeFor(step.primitive),
        protocol: step.protocol,
      });
    }
  });

  return nodes;
}

function scenarioIdToEdges(steps: SimulationResult["steps"]): AttackEdge[] {
  const edges: AttackEdge[] = [];
  const slugOf = (protocol: string) => protocol.replace(/[^a-zA-Z0-9]/g, "_").toLowerCase();

  steps.forEach((step) => {
    const target = slugOf(step.protocol);
    const isRepay = step.primitive === "REPAY_FLASH";

    edges.push({
      from: isRepay ? target : "attacker",
      to: isRepay ? "attacker" : target,
      label: step.primitive.replace(/_/g, " "),
      amount_usd: isRepay ? step.capital_in : step.capital_out,
      token: step.token,
      animated: step.net_impact > 0,
    });
  });

  return edges;
}

// ─── Static risk matrix data (used before API loads) ─────────────────────────

const FALLBACK_MATRIX: RiskMatrixData = {
  protocols: ["Euler Finance", "Ronin Bridge", "Mango Markets", "Wormhole", "Compound", "Aave"],
  vectors: [
    "Oracle Manipulation", "Flash Loan Attack", "Cross-Chain Bridge",
    "Governance Takeover", "Liquidity Concentration", "Smart Contract Exploit",
  ],
  matrix: {
    "Euler Finance": { "Oracle Manipulation": 45, "Flash Loan Attack": 92, "Cross-Chain Bridge": 10, "Governance Takeover": 30, "Liquidity Concentration": 65, "Smart Contract Exploit": 78 },
    "Ronin Bridge":  { "Oracle Manipulation": 20, "Flash Loan Attack": 10, "Cross-Chain Bridge": 98, "Governance Takeover": 75, "Liquidity Concentration": 40, "Smart Contract Exploit": 55 },
    "Mango Markets": { "Oracle Manipulation": 95, "Flash Loan Attack": 60, "Cross-Chain Bridge": 5,  "Governance Takeover": 85, "Liquidity Concentration": 70, "Smart Contract Exploit": 40 },
    "Wormhole":      { "Oracle Manipulation": 10, "Flash Loan Attack": 5,  "Cross-Chain Bridge": 97, "Governance Takeover": 50, "Liquidity Concentration": 35, "Smart Contract Exploit": 88 },
    "Compound":      { "Oracle Manipulation": 35, "Flash Loan Attack": 55, "Cross-Chain Bridge": 5,  "Governance Takeover": 65, "Liquidity Concentration": 45, "Smart Contract Exploit": 30 },
    "Aave":          { "Oracle Manipulation": 20, "Flash Loan Attack": 40, "Cross-Chain Bridge": 25, "Governance Takeover": 35, "Liquidity Concentration": 30, "Smart Contract Exploit": 20 },
  },
};

// ─── Static scenarios (offline-ready) ────────────────────────────────────────

const OFFLINE_SCENARIOS: Scenario[] = [
  { scenario_id: "euler_finance", name: "Euler Finance", description: "donateToReserves flash loan exploit", loss_usd: 197_000_000, tags: ["flash_loan", "accounting_bug"], steps: 5, real_hack_ref: "March 2023" },
  { scenario_id: "ronin_bridge", name: "Ronin Bridge", description: "Validator key compromise, bridge drain", loss_usd: 625_000_000, tags: ["bridge", "key_compromise"], steps: 4, real_hack_ref: "March 2022" },
  { scenario_id: "mango_markets", name: "Mango Markets", description: "Oracle price pump + governance", loss_usd: 116_000_000, tags: ["oracle", "governance"], steps: 5, real_hack_ref: "October 2022" },
  { scenario_id: "wormhole", name: "Wormhole Bridge", description: "Fake VAA signature bypass", loss_usd: 320_000_000, tags: ["bridge", "signature"], steps: 5, real_hack_ref: "February 2022" },
  { scenario_id: "generic_flashloan_cascade", name: "Generic Flash Loan Cascade", description: "Configurable multi-protocol cascade", loss_usd: 55_000_000, tags: ["template", "flash_loan"], steps: 6, real_hack_ref: "bZx / Cream Finance patterns" },
];

function formatUSD(amount: number): string {
  if (amount >= 1_000_000_000) return `$${(amount / 1_000_000_000).toFixed(2)}B`;
  if (amount >= 1_000_000) return `$${(amount / 1_000_000).toFixed(0)}M`;
  if (amount >= 1_000) return `$${(amount / 1_000).toFixed(0)}K`;
  return `$${amount.toFixed(0)}`;
}

// ─── Main Component ───────────────────────────────────────────────────────────

type ActiveTab = "replay" | "matrix";

export default function WarRoom() {
  const [selectedScenario, setSelectedScenario] = useState<string>("euler_finance");
  const [simulation, setSimulation] = useState<SimulationResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeStepIndex, setActiveStepIndex] = useState<number>(0);
  const [replayRunning, setReplayRunning] = useState(false);
  const [activeTab, setActiveTab] = useState<ActiveTab>("replay");
  const [riskMatrix] = useState<RiskMatrixData>(FALLBACK_MATRIX);

  // ── Run simulation ──────────────────────────────────────────────────────────
  const runSimulation = useCallback(async () => {
    setLoading(true);
    setError(null);
    setSimulation(null);
    setActiveStepIndex(0);
    setReplayRunning(false);

    try {
      const res = await fetch("/api/v1/simulator/run-attack", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": "adv-dev-key-123",
        },
        body: JSON.stringify({ scenario_id: selectedScenario }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || `HTTP ${res.status}`);
      }

      const data: SimulationResult = await res.json();
      setSimulation(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Simulation failed");
    } finally {
      setLoading(false);
    }
  }, [selectedScenario]);

  // ── Auto-replay ─────────────────────────────────────────────────────────────
  const startReplay = useCallback(() => {
    if (!simulation) return;
    setReplayRunning(true);
    setActiveStepIndex(0);

    let i = 0;
    const advance = () => {
      if (i < simulation.steps.length - 1) {
        i++;
        setActiveStepIndex(i);
        setTimeout(advance, 1200);
      } else {
        setReplayRunning(false);
      }
    };
    setTimeout(advance, 1200);
  }, [simulation]);

  // ── Graph data ──────────────────────────────────────────────────────────────
  const flowNodes: AttackNode[] = simulation ? scenarioIdToNodes(simulation.steps) : [];
  const flowEdges: AttackEdge[] = simulation ? scenarioIdToEdges(simulation.steps) : [];

  const timelineSteps: TimelineStep[] = (simulation?.steps ?? []).map((s) => ({
    index: s.step_index,
    primitive: s.primitive,
    protocol: s.protocol,
    description: s.description,
    capital_out: s.capital_out,
    net_impact: s.net_impact,
    gas_usd: s.gas_usd,
    token: s.token,
    block_delta: s.block_delta,
  }));

  const selectedScenarioInfo = OFFLINE_SCENARIOS.find((s) => s.scenario_id === selectedScenario);

  return (
    <div className="min-h-screen bg-[#050508] text-white font-mono">
      {/* Header */}
      <div className="border-b border-white/10 bg-black/60 backdrop-blur-sm sticky top-0 z-30">
        <div className="max-w-screen-xl mx-auto px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-red-500 text-xl">⚔️</span>
            <span className="font-bold text-white tracking-wider">ADVERSUM WAR ROOM</span>
            <span className="text-xs text-gray-500 border border-gray-700 rounded px-2 py-0.5">PHASE 3</span>
          </div>
          <div className="text-xs text-gray-500">
            Cross-Protocol Economic Attack Simulator
          </div>
        </div>
      </div>

      <div className="max-w-screen-xl mx-auto px-6 py-6 space-y-6">
        {/* Scenario selector + controls */}
        <div className="flex flex-wrap gap-4 items-end">
          <div className="flex-1 min-w-[260px]">
            <label className="text-xs text-gray-500 mb-1.5 block uppercase tracking-wider">
              Select Attack Scenario
            </label>
            <select
              value={selectedScenario}
              onChange={(e) => setSelectedScenario(e.target.value)}
              className="w-full bg-gray-900 border border-gray-700 text-white rounded-lg px-3 py-2.5
                         text-sm focus:outline-none focus:border-red-500 cursor-pointer"
            >
              {OFFLINE_SCENARIOS.map((s) => (
                <option key={s.scenario_id} value={s.scenario_id}>
                  {s.name} — {formatUSD(s.loss_usd)} ({s.real_hack_ref})
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={runSimulation}
            disabled={loading}
            className="px-6 py-2.5 rounded-lg bg-red-600 hover:bg-red-500 disabled:bg-gray-700
                       text-white text-sm font-bold transition-colors flex items-center gap-2"
          >
            {loading ? (
              <><span className="animate-spin">⟳</span> Simulating...</>
            ) : (
              <><span>▶</span> Run Simulation</>
            )}
          </button>

          {simulation && !replayRunning && (
            <button
              onClick={startReplay}
              className="px-5 py-2.5 rounded-lg border border-orange-600 text-orange-400
                         hover:bg-orange-950/30 text-sm font-bold transition-colors"
            >
              ⟳ Replay
            </button>
          )}
        </div>

        {/* Scenario info */}
        {selectedScenarioInfo && (
          <div className="text-xs text-gray-500 bg-gray-900/40 border border-white/8 rounded-lg px-4 py-2">
            {selectedScenarioInfo.description} · {selectedScenarioInfo.steps} attack steps ·{" "}
            Ref: {selectedScenarioInfo.real_hack_ref}
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="bg-red-950/40 border border-red-800 rounded-lg p-4 text-red-400 text-sm">
            ❌ {error}
          </div>
        )}

        {/* Results */}
        {simulation && (
          <>
            {/* KPI strip */}
            <div className="grid grid-cols-2 sm:grid-cols-4 xl:grid-cols-6 gap-3">
              {[
                { label: "Protocol Loss", value: formatUSD(simulation.protocol_loss_usd), color: "text-red-400" },
                { label: "Attacker Profit", value: formatUSD(simulation.attacker_profit_usd), color: "text-green-400" },
                { label: "Gas Cost", value: formatUSD(simulation.total_gas_usd), color: "text-gray-400" },
                { label: "Blocks Elapsed", value: simulation.block_span.toString(), color: "text-blue-400" },
                { label: "Risk Index", value: `${simulation.risk_index.toFixed(0)}/100`, color: simulation.risk_index >= 75 ? "text-red-400" : "text-orange-400" },
                { label: "Cascade", value: simulation.cascade_triggered ? `+${simulation.cascade_protocols.length} protocols` : "None", color: simulation.cascade_triggered ? "text-orange-400" : "text-gray-500" },
              ].map(({ label, value, color }) => (
                <div key={label} className="bg-gray-900/50 border border-white/8 rounded-xl px-4 py-3">
                  <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">{label}</div>
                  <div className={`text-base font-bold ${color}`}>{value}</div>
                </div>
              ))}
            </div>

            {/* MITRE techniques */}
            {simulation.mitre_techniques.length > 0 && (
              <div className="bg-gray-900/30 border border-white/8 rounded-lg px-4 py-3">
                <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">
                  MITRE ATT&CK Techniques
                </div>
                <div className="flex flex-wrap gap-2">
                  {simulation.mitre_techniques.map((t) => (
                    <span key={t} className="text-[10px] bg-purple-950/50 border border-purple-800 text-purple-300 rounded px-2 py-0.5">
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Cascade alert */}
            {simulation.cascade_triggered && (
              <div className="bg-orange-950/40 border border-orange-800 rounded-lg p-3 text-sm">
                <span className="text-orange-400 font-bold">⚠ Cascade triggered</span>
                <span className="text-gray-400"> — Attack propagates to: </span>
                <span className="text-orange-300">{simulation.cascade_protocols.join(", ")}</span>
              </div>
            )}

            {/* Tabs */}
            <div className="flex gap-1 border-b border-white/10">
              {(["replay", "matrix"] as ActiveTab[]).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`px-4 py-2 text-xs font-semibold uppercase tracking-wider transition-colors
                    ${activeTab === tab
                      ? "border-b-2 border-red-500 text-white"
                      : "text-gray-500 hover:text-gray-300"
                    }`}
                >
                  {tab === "replay" ? "⚔️ Attack Replay" : "📊 Risk Matrix"}
                </button>
              ))}
            </div>

            {/* Tab content */}
            {activeTab === "replay" && (
              <div className="space-y-6">
                {/* Flow graph */}
                <div className="bg-gray-950/60 border border-white/8 rounded-xl p-1 h-[440px]">
                  <AttackFlow
                    nodes={flowNodes}
                    edges={flowEdges}
                    activeStepIndex={activeStepIndex}
                    className="h-full"
                  />
                </div>

                {/* Timeline */}
                <div className="bg-gray-900/40 border border-white/8 rounded-xl p-5">
                  <div className="text-xs text-gray-500 uppercase tracking-wider mb-4">
                    Attack Timeline — {timelineSteps.length} steps
                    {replayRunning && (
                      <span className="ml-2 text-red-400 animate-pulse">● REPLAYING</span>
                    )}
                  </div>
                  <AttackTimeline
                    steps={timelineSteps}
                    activeIndex={activeStepIndex}
                    onStepClick={setActiveStepIndex}
                  />
                </div>
              </div>
            )}

            {activeTab === "matrix" && (
              <div className="bg-gray-900/40 border border-white/8 rounded-xl p-5">
                <div className="text-xs text-gray-500 uppercase tracking-wider mb-4">
                  DeFi Protocol × Attack Vector Risk Matrix
                </div>
                <RiskMatrix data={riskMatrix} />
              </div>
            )}
          </>
        )}

        {/* Idle state */}
        {!simulation && !loading && (
          <div className="flex flex-col items-center justify-center py-24 text-gray-600 space-y-3">
            <span className="text-6xl">⚔️</span>
            <div className="text-lg font-bold text-gray-500">Select a scenario and run simulation</div>
            <div className="text-sm text-gray-600">
              Replay real DeFi hacks: Euler Finance ($197M), Ronin ($625M), Wormhole ($320M)...
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
