import React, { useState, useCallback } from "react";

export interface ClashResult {
  clash_id: string;
  protocol: string;
  scenario_type: string;
  total_exposure_usd: number;
  capital_saved_usd: number;
  capital_loss_usd: number;
  salvage_rate_pct: number;
  ttd_ms: number;
  ttm_ms: number;
  defense_action: string;
  defense_tripped: boolean;
  circuit_breaker_status: string;
  incident_rounds: Array<{
    round: number;
    block_offset: number;
    event: string;
    inflow_outflow_usd: number;
    state: string;
  }>;
}

interface BenchmarkResult {
  protocol: string;
  scenarios_evaluated: number;
  average_salvage_rate_pct: number;
  average_ttd_ms: number;
  average_ttm_ms: number;
  total_capital_saved_usd: number;
  scenario_details: ClashResult[];
}

function formatUSD(num: number): string {
  if (num >= 1_000_000_000) return `$${(num / 1_000_000_000).toFixed(2)}B`;
  if (num >= 1_000_000) return `$${(num / 1_000_000).toFixed(1)}M`;
  if (num >= 1_000) return `$${(num / 1_000).toFixed(0)}K`;
  return `$${num.toFixed(0)}`;
}

export default function ArenaClash() {
  const [protocol, setProtocol] = useState("Euler Finance");
  const [scenario, setScenario] = useState("flashloan_drain");
  const [loading, setLoading] = useState(false);
  const [clash, setClash] = useState<ClashResult | null>(null);
  const [benchmark, setBenchmark] = useState<BenchmarkResult | null>(null);
  const [synthesizing, setSynthesizing] = useState(false);
  const [solidityCode, setSolidityCode] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const runClash = useCallback(async () => {
    setLoading(true);
    setBenchmark(null);
    try {
      const res = await fetch("/api/v1/wargame/simulate-incident", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": "adv-dev-key-123",
        },
        body: JSON.stringify({
          protocol,
          scenario_key: scenario,
        }),
      });
      if (res.ok) {
        const data: ClashResult = await res.json();
        setClash(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, [protocol, scenario]);

  const runBenchmark = useCallback(async () => {
    setLoading(true);
    setClash(null);
    try {
      const res = await fetch(`/api/v1/wargame/resilience-benchmark?protocol=${encodeURIComponent(protocol)}`, {
        headers: { "x-api-key": "adv-dev-key-123" },
      });
      if (res.ok) {
        const data: BenchmarkResult = await res.json();
        setBenchmark(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, [protocol]);

  const synthesizeBreaker = useCallback(async () => {
    setSynthesizing(true);
    try {
      const res = await fetch("/api/v1/wargame/synthesize-circuit-breaker", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": "adv-dev-key-123",
        },
        body: JSON.stringify({
          protocol_name: protocol.replace(/\s+/g, ""),
          target_token: "USDC",
          max_tvl_outflow_pct_per_window: 4.5,
          window_blocks: 12,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setSolidityCode(data.solidity_code);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setSynthesizing(false);
    }
  }, [protocol]);

  const copyCode = () => {
    if (solidityCode) {
      navigator.clipboard.writeText(solidityCode);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="space-y-6 text-white font-mono">
      {/* Controls Bar */}
      <div className="bg-gray-900/60 border border-white/10 rounded-xl p-5 flex flex-wrap gap-4 items-end">
        <div className="flex-1 min-w-[200px]">
          <label className="text-xs text-gray-400 block mb-1.5 uppercase">Target Protocol</label>
          <input
            type="text"
            value={protocol}
            onChange={(e) => setProtocol(e.target.value)}
            className="w-full bg-gray-950 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex-1 min-w-[220px]">
          <label className="text-xs text-gray-400 block mb-1.5 uppercase">Threat Scenario</label>
          <select
            value={scenario}
            onChange={(e) => setScenario(e.target.value)}
            className="w-full bg-gray-950 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
          >
            <option value="flashloan_drain">Flash Loan Drain Cascade ($85M)</option>
            <option value="oracle_desync">Oracle Manipulation & Desync ($42M)</option>
            <option value="reentrancy_wave">Recursive Reentrancy Wave ($28M)</option>
            <option value="bridge_forgery">Cross-Chain Signature Forgery ($150M)</option>
          </select>
        </div>

        <button
          onClick={runClash}
          disabled={loading}
          className="px-5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-700 text-white font-bold text-sm transition-colors flex items-center gap-2"
        >
          {loading ? "Simulating..." : "⚔️ Run Clash"}
        </button>

        <button
          onClick={runBenchmark}
          disabled={loading}
          className="px-5 py-2 rounded-lg border border-purple-500 text-purple-300 hover:bg-purple-950/40 text-sm font-bold transition-colors"
        >
          📊 Full Benchmark
        </button>

        <button
          onClick={synthesizeBreaker}
          disabled={synthesizing}
          className="px-5 py-2 rounded-lg border border-green-500 text-green-300 hover:bg-green-950/40 text-sm font-bold transition-colors"
        >
          {synthesizing ? "Synthesizing..." : "🛡️ Synthesize Breaker"}
        </button>
      </div>

      {/* Clash Result View */}
      {clash && (
        <div className="space-y-6">
          {/* Key Metrics */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div className="bg-gray-900/50 border border-white/10 rounded-xl p-4">
              <div className="text-[10px] text-gray-500 uppercase">Total Exposure</div>
              <div className="text-lg font-bold text-red-400">{formatUSD(clash.total_exposure_usd)}</div>
            </div>
            <div className="bg-gray-900/50 border border-white/10 rounded-xl p-4">
              <div className="text-[10px] text-gray-500 uppercase">Capital Saved</div>
              <div className="text-lg font-bold text-green-400">
                {formatUSD(clash.capital_saved_usd)} ({clash.salvage_rate_pct.toFixed(1)}%)
              </div>
            </div>
            <div className="bg-gray-900/50 border border-white/10 rounded-xl p-4">
              <div className="text-[10px] text-gray-500 uppercase">Time to Detect (TTD)</div>
              <div className="text-lg font-bold text-yellow-400">{clash.ttd_ms.toFixed(1)} ms</div>
            </div>
            <div className="bg-gray-900/50 border border-white/10 rounded-xl p-4">
              <div className="text-[10px] text-gray-500 uppercase">Time to Mitigate (TTM)</div>
              <div className="text-lg font-bold text-cyan-400">{clash.ttm_ms.toFixed(1)} ms</div>
            </div>
            <div className="bg-gray-900/50 border border-white/10 rounded-xl p-4">
              <div className="text-[10px] text-gray-500 uppercase">Defense Status</div>
              <div className="text-sm font-bold text-emerald-400 truncate">{clash.circuit_breaker_status}</div>
            </div>
          </div>

          {/* Incident Timeline */}
          <div className="bg-gray-900/40 border border-white/10 rounded-xl p-5 space-y-3">
            <div className="text-xs text-gray-400 uppercase tracking-wider">
              Autonomous Defense Interception Sequence
            </div>
            <div className="space-y-2">
              {clash.incident_rounds.map((rnd) => (
                <div
                  key={rnd.round}
                  className="flex items-center justify-between p-3 rounded-lg bg-gray-950/70 border border-white/5"
                >
                  <div className="flex items-center gap-3">
                    <span className="w-6 h-6 rounded-full bg-cyan-950 border border-cyan-700 text-cyan-300 text-xs flex items-center justify-center font-bold">
                      {rnd.round}
                    </span>
                    <span className="text-sm text-gray-200">{rnd.event}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    {rnd.inflow_outflow_usd !== 0 && (
                      <span className="text-xs text-red-400">{formatUSD(rnd.inflow_outflow_usd)}</span>
                    )}
                    <span className="text-[10px] px-2 py-0.5 rounded bg-white/10 text-cyan-300 font-semibold">
                      {rnd.state}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Benchmark View */}
      {benchmark && (
        <div className="bg-gray-900/50 border border-white/10 rounded-xl p-5 space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-base font-bold text-white">
              Resilience Benchmark Report: {benchmark.protocol}
            </h3>
            <span className="text-xs bg-purple-950/60 text-purple-300 border border-purple-800 px-2.5 py-1 rounded-full">
              Avg Salvage: {benchmark.average_salvage_rate_pct.toFixed(1)}%
            </span>
          </div>

          <div className="grid grid-cols-3 gap-3 text-center">
            <div className="p-3 bg-black/40 rounded-lg border border-white/5">
              <div className="text-[10px] text-gray-400">Total Capital Preserved</div>
              <div className="text-lg font-bold text-green-400">{formatUSD(benchmark.total_capital_saved_usd)}</div>
            </div>
            <div className="p-3 bg-black/40 rounded-lg border border-white/5">
              <div className="text-[10px] text-gray-400">Average Detection Time</div>
              <div className="text-lg font-bold text-yellow-400">{benchmark.average_ttd_ms.toFixed(1)} ms</div>
            </div>
            <div className="p-3 bg-black/40 rounded-lg border border-white/5">
              <div className="text-[10px] text-gray-400">Average Mitigation Time</div>
              <div className="text-lg font-bold text-cyan-400">{benchmark.average_ttm_ms.toFixed(1)} ms</div>
            </div>
          </div>

          <div className="space-y-2 pt-2">
            {benchmark.scenario_details.map((sc) => (
              <div
                key={sc.clash_id}
                className="flex items-center justify-between p-3 rounded-lg bg-gray-950/50 border border-white/5"
              >
                <div>
                  <div className="text-sm font-semibold text-white">{sc.scenario_type}</div>
                  <div className="text-xs text-gray-500">
                    Exposure: {formatUSD(sc.total_exposure_usd)} · Saved: {formatUSD(sc.capital_saved_usd)}
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-sm font-bold text-green-400">{sc.salvage_rate_pct.toFixed(1)}% Saved</div>
                  <div className="text-xs text-gray-500">TTM: {sc.ttm_ms.toFixed(1)}ms</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Synthesized Solidity Modal / Panel */}
      {solidityCode && (
        <div className="bg-gray-950 border border-cyan-800 rounded-xl p-5 space-y-3">
          <div className="flex justify-between items-center">
            <div className="flex items-center gap-2">
              <span className="text-cyan-400 font-bold">🛡️ Generated CircuitBreakerGuard.sol</span>
              <span className="text-[10px] text-gray-400 border border-gray-700 px-2 py-0.5 rounded">Solidity 0.8.20</span>
            </div>
            <button
              onClick={copyCode}
              className="text-xs bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-700 px-3 py-1 rounded transition-colors"
            >
              {copied ? "Copied!" : "Copy Code"}
            </button>
          </div>
          <pre className="text-xs text-gray-300 overflow-x-auto max-h-96 bg-black/60 p-4 rounded-lg border border-white/5">
            {solidityCode}
          </pre>
        </div>
      )}
    </div>
  );
}
