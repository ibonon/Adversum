import React from "react";

export interface TimelineStep {
  index: number;
  primitive: string;
  protocol: string;
  description: string;
  capital_out: number;
  net_impact: number;
  gas_usd: number;
  token: string;
  block_delta: number;
}

interface AttackTimelineProps {
  steps: TimelineStep[];
  activeIndex?: number;
  onStepClick?: (index: number) => void;
}

const PRIMITIVE_ICONS: Record<string, string> = {
  FLASH_LOAN:      "⚡",
  ORACLE_MANIP:    "🔮",
  LIQUIDATION:     "💀",
  BRIDGE_DRAIN:    "🌉",
  GOVERNANCE_VOTE: "🗳️",
  PRICE_PUMP:      "📈",
  UNBACKED_MINT:   "🖨️",
  DONATE_ATTACK:   "🎁",
  REPAY_FLASH:     "🔄",
  CUSTOM:          "⚙️",
};

const PRIMITIVE_COLORS: Record<string, string> = {
  FLASH_LOAN:      "border-indigo-500 bg-indigo-950/40",
  ORACLE_MANIP:    "border-yellow-500 bg-yellow-950/40",
  LIQUIDATION:     "border-red-500 bg-red-950/40",
  BRIDGE_DRAIN:    "border-cyan-500 bg-cyan-950/40",
  GOVERNANCE_VOTE: "border-purple-500 bg-purple-950/40",
  PRICE_PUMP:      "border-orange-500 bg-orange-950/40",
  UNBACKED_MINT:   "border-pink-500 bg-pink-950/40",
  DONATE_ATTACK:   "border-green-500 bg-green-950/40",
  REPAY_FLASH:     "border-gray-500 bg-gray-950/40",
  CUSTOM:          "border-slate-500 bg-slate-950/40",
};

function formatUSD(amount: number): string {
  if (Math.abs(amount) >= 1_000_000) return `$${(amount / 1_000_000).toFixed(1)}M`;
  if (Math.abs(amount) >= 1_000) return `$${(amount / 1_000).toFixed(0)}K`;
  return `$${amount.toFixed(0)}`;
}

export default function AttackTimeline({
  steps,
  activeIndex,
  onStepClick,
}: AttackTimelineProps) {
  return (
    <div className="w-full overflow-x-auto pb-3">
      {/* Legend */}
      <div className="flex gap-4 mb-4 text-xs text-gray-500 flex-wrap">
        {["FLASH_LOAN", "ORACLE_MANIP", "LIQUIDATION", "BRIDGE_DRAIN"].map((p) => (
          <span key={p} className="flex items-center gap-1">
            <span>{PRIMITIVE_ICONS[p]}</span>
            <span>{p.replace("_", " ")}</span>
          </span>
        ))}
      </div>

      {/* Timeline track */}
      <div className="relative flex gap-3 min-w-max">
        {/* Connector line */}
        <div className="absolute top-8 left-8 right-8 h-0.5 bg-gradient-to-r from-red-900 via-orange-700 to-red-900 z-0" />

        {(steps || []).map((step) => {
          const isActive = step.index === activeIndex;
          const colorClass = PRIMITIVE_COLORS[step.primitive] || PRIMITIVE_COLORS.CUSTOM;
          const icon = PRIMITIVE_ICONS[step.primitive] || "⚙️";

          return (
            <div
              key={step.index}
              className={`relative z-10 flex flex-col items-center cursor-pointer transition-all duration-200 ${
                isActive ? "scale-110" : "hover:scale-105"
              }`}
              onClick={() => onStepClick?.(step.index)}
            >
              {/* Step bubble */}
              <div
                className={`w-16 h-16 rounded-full border-2 flex flex-col items-center justify-center text-center
                  ${colorClass} ${isActive ? "ring-2 ring-white/50 shadow-lg" : ""}`}
              >
                <span className="text-xl">{icon}</span>
                <span className="text-[9px] font-mono text-gray-400">#{step.index + 1}</span>
              </div>

              {/* Card below */}
              <div
                className={`mt-3 w-44 rounded-lg border p-2.5 text-left transition-all
                  ${colorClass} ${isActive ? "ring-1 ring-white/20" : ""}`}
              >
                <div className="text-[10px] font-bold text-gray-300 mb-1 uppercase tracking-wider">
                  {step.primitive.replace(/_/g, " ")}
                </div>
                <div className="text-xs text-white font-semibold truncate" title={step.protocol}>
                  {step.protocol}
                </div>
                <div className="text-[10px] text-gray-400 mt-1 line-clamp-2">{step.description}</div>

                <div className="mt-2 flex justify-between text-[10px]">
                  <span className={step.net_impact >= 0 ? "text-green-400" : "text-red-400"}>
                    {step.net_impact >= 0 ? "+" : ""}{formatUSD(step.net_impact)}
                  </span>
                  <span className="text-gray-500">gas: {formatUSD(step.gas_usd)}</span>
                </div>

                {step.block_delta > 0 && (
                  <div className="text-[9px] text-gray-600 mt-1">
                    +{step.block_delta} block{step.block_delta > 1 ? "s" : ""}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
