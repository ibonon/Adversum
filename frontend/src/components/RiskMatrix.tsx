import React, { useState } from "react";

export interface RiskMatrixData {
  matrix: Record<string, Record<string, number>>;
  protocols: string[];
  vectors: string[];
}

interface RiskMatrixProps {
  data: RiskMatrixData;
  className?: string;
}

function scoreColor(score: number): string {
  if (score >= 80) return "bg-red-900/80 text-red-300 border-red-700";
  if (score >= 60) return "bg-orange-900/70 text-orange-300 border-orange-700";
  if (score >= 40) return "bg-yellow-900/60 text-yellow-300 border-yellow-700";
  if (score >= 20) return "bg-green-900/60 text-green-400 border-green-700";
  return "bg-gray-900/50 text-gray-400 border-gray-700";
}

function scoreLabel(score: number): string {
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 40) return "MEDIUM";
  if (score >= 20) return "LOW";
  return "SAFE";
}

const VECTOR_ICONS: Record<string, string> = {
  "Oracle Manipulation":       "🔮",
  "Flash Loan Attack":         "⚡",
  "Cross-Chain Bridge":        "🌉",
  "Governance Takeover":       "🗳️",
  "Liquidity Concentration":   "💧",
  "Smart Contract Exploit":    "🐛",
};

interface TooltipState {
  visible: boolean;
  protocol: string;
  vector: string;
  score: number;
  x: number;
  y: number;
}

export default function RiskMatrix({ data, className = "" }: RiskMatrixProps) {
  const [tooltip, setTooltip] = useState<TooltipState>({
    visible: false, protocol: "", vector: "", score: 0, x: 0, y: 0,
  });

  const handleMouseEnter = (e: React.MouseEvent, protocol: string, vector: string, score: number) => {
    const rect = (e.target as HTMLElement).getBoundingClientRect();
    setTooltip({
      visible: true,
      protocol,
      vector,
      score,
      x: rect.left + rect.width / 2,
      y: rect.top - 8,
    });
  };

  const handleMouseLeave = () => setTooltip((t) => ({ ...t, visible: false }));

  if (!data || !data.protocols?.length || !data.vectors?.length) {
    return (
      <div className={`p-8 text-center text-gray-500 ${className}`}>
        Loading risk matrix...
      </div>
    );
  }

  return (
    <div className={`relative w-full overflow-x-auto ${className}`}>
      <table className="w-full border-collapse text-xs">
        <thead>
          <tr>
            {/* Protocol column */}
            <th className="text-left py-2 px-3 text-gray-400 font-semibold min-w-[140px] border-b border-white/10">
              Protocol
            </th>
            {data.vectors.map((vector) => (
              <th
                key={vector}
                className="text-center py-2 px-2 text-gray-400 font-semibold border-b border-white/10 min-w-[90px]"
              >
                <div className="flex flex-col items-center gap-0.5">
                  <span>{VECTOR_ICONS[vector] || "⚡"}</span>
                  <span className="text-[10px] leading-tight text-center">{vector}</span>
                </div>
              </th>
            ))}
            <th className="text-center py-2 px-3 text-gray-400 font-semibold border-b border-white/10 min-w-[80px]">
              Avg Risk
            </th>
          </tr>
        </thead>
        <tbody>
          {data.protocols.map((protocol) => {
            const protocolScores = data.matrix[protocol] || {};
            const values = data.vectors.map((v) => protocolScores[v] ?? 0);
            const avg = values.length ? values.reduce((a, b) => a + b, 0) / values.length : 0;

            return (
              <tr key={protocol} className="border-b border-white/5 hover:bg-white/2 transition-colors">
                <td className="py-2 px-3 text-white font-medium text-xs">{protocol}</td>
                {data.vectors.map((vector) => {
                  const score = protocolScores[vector] ?? 0;
                  return (
                    <td key={vector} className="py-1.5 px-1 text-center">
                      <div
                        className={`inline-flex flex-col items-center justify-center rounded border
                          w-14 h-10 cursor-default transition-transform hover:scale-105 ${scoreColor(score)}`}
                        onMouseEnter={(e) => handleMouseEnter(e, protocol, vector, score)}
                        onMouseLeave={handleMouseLeave}
                      >
                        <span className="font-bold text-sm">{score.toFixed(0)}</span>
                      </div>
                    </td>
                  );
                })}
                {/* Average */}
                <td className="py-1.5 px-2 text-center">
                  <div className={`inline-flex flex-col items-center justify-center rounded border
                    w-16 h-10 ${scoreColor(avg)}`}>
                    <span className="font-bold text-sm">{avg.toFixed(0)}</span>
                    <span className="text-[9px] opacity-70">{scoreLabel(avg)}</span>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      {/* Legend */}
      <div className="flex gap-4 mt-4 text-[10px] text-gray-500 flex-wrap">
        {[
          { label: "CRITICAL (80–100)", cls: "bg-red-900/80 border-red-700" },
          { label: "HIGH (60–79)",      cls: "bg-orange-900/70 border-orange-700" },
          { label: "MEDIUM (40–59)",    cls: "bg-yellow-900/60 border-yellow-700" },
          { label: "LOW (20–39)",       cls: "bg-green-900/60 border-green-700" },
          { label: "SAFE (0–19)",       cls: "bg-gray-900/50 border-gray-700" },
        ].map(({ label, cls }) => (
          <div key={label} className="flex items-center gap-1.5">
            <div className={`w-4 h-4 rounded border ${cls}`} />
            <span>{label}</span>
          </div>
        ))}
      </div>

      {/* Tooltip */}
      {tooltip.visible && (
        <div
          className="fixed z-50 bg-gray-900 border border-white/20 rounded-lg px-3 py-2 text-xs shadow-xl pointer-events-none"
          style={{ left: tooltip.x, top: tooltip.y, transform: "translate(-50%, -100%)" }}
        >
          <div className="font-bold text-white">{tooltip.protocol}</div>
          <div className="text-gray-400">{tooltip.vector}</div>
          <div className={`font-bold mt-1 ${scoreColor(tooltip.score).split(" ")[1]}`}>
            {tooltip.score.toFixed(1)} — {scoreLabel(tooltip.score)}
          </div>
        </div>
      )}
    </div>
  );
}
