"use client";

import { useState } from "react";

const mockLogs = [
    { timestamp: "2025-12-26 17:42:01", event: "RBAT Cycle Initiated", target: "Job #402", status: "PROCESSING" },
    { timestamp: "2025-12-26 17:42:05", event: "Invariant Check: NoFlow(External -> Database)", result: "PASSED", proof: "GASR-9921" },
    { timestamp: "2025-12-26 17:42:08", event: "Adversarial Probing: SystemInstructionOverride", result: "FAILED (Resilient)", proof: "PROBE-X2" },
    { timestamp: "2025-12-26 17:42:10", event: "Immune Response: Delta +0.42 Applied", status: "STABLE" }
];

export default function ImmuneConsole() {
    return (
        <div className="space-y-10 animate-in fade-in duration-700">
            <div className="flex justify-between items-end">
                <div>
                    <h1 className="text-4xl font-bold tracking-tight text-white mb-2">Immune Console</h1>
                    <p className="text-primaryMuted">
                        Autonomous verified remediation logs and formal safety invariant monitoring.
                    </p>
                </div>
            </div>

            <div className="grid grid-cols-12 gap-8">
                {/* Status Bento */}
                <div className="col-span-12 lg:col-span-4 space-y-6">
                    <div className="bento-card bg-accentMint/5 border-accentMint/20">
                        <div className="tech-label text-accentMint mb-4">Verification Status</div>
                        <div className="text-3xl font-black text-white mb-2">ACTIVE</div>
                        <p className="text-xs text-primaryMuted">
                            The Red-on-Blue Autonomous Training (RBAT) engine is monitoring all applied patches for drift or bypass.
                        </p>
                    </div>

                    <div className="bento-card">
                        <div className="tech-label mb-4">Active Invariants</div>
                        <div className="space-y-3">
                            {["NoFlow", "AuthBoundary", "LatentConstraint"].map((inv) => (
                                <div key={inv} className="flex justify-between items-center text-sm border-b border-surfaceBorder pb-2 last:border-0">
                                    <span className="text-white font-medium">{inv}</span>
                                    <span className="text-[10px] font-bold text-accentMint px-2 py-0.5 bg-accentMint/10 rounded">ENFORCED</span>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                {/* Log Console Bento */}
                <div className="col-span-12 lg:col-span-8 bento-card font-mono text-[11px] h-[500px] flex flex-col">
                    <div className="flex justify-between items-center mb-6">
                        <div className="tech-label">Live Verification Stream</div>
                        <div className="w-2 h-2 rounded-full bg-accentMint animate-pulse" />
                    </div>

                    <div className="flex-1 overflow-y-auto space-y-2 pr-4 custom-scrollbar">
                        {mockLogs.map((log, i) => (
                            <div key={i} className="flex gap-4 py-2 border-b border-surfaceBorder/50 hover:bg-white/5 px-2 rounded transition-colors group">
                                <span className="text-primaryMuted min-w-[120px]">{log.timestamp}</span>
                                <span className="text-white flex-1">{log.event}</span>
                                <span className={`font-bold ${log.result === 'PASSED' || log.result === 'FAILED (Resilient)' ? 'text-accentMint' :
                                        log.status === 'PROCESSING' ? 'text-accentBlue' : 'text-primary'
                                    }`}>
                                    {log.result || log.status}
                                </span>
                                {log.proof && (
                                    <span className="text-[9px] px-1.5 py-0.5 border border-surfaceBorder rounded text-primaryMuted group-hover:border-white/20">
                                        {log.proof}
                                    </span>
                                )}
                            </div>
                        ))}
                        <div className="text-primaryMuted animate-pulse pt-4">_ Awaiting next deterministic probe...</div>
                    </div>
                </div>
            </div>

            {/* Invariant Explanation Bento */}
            <div className="col-span-12 bento-card bg-surfaceHighlight/30">
                <h3 className="text-xl font-bold mb-6">About High-Tech Determinism</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-10">
                    <div>
                        <div className="text-accentBlue text-2xl mb-4 font-black">01</div>
                        <h4 className="font-bold text-white mb-2">No Randomness</h4>
                        <p className="text-xs text-primaryMuted leading-relaxed">
                            Unlike probabilistic scanners, Adversum uses G-ASR to prove vulnerabilities via AST traversal. If a path exists, it is found.
                        </p>
                    </div>
                    <div>
                        <div className="text-accentPurple text-2xl mb-4 font-black">02</div>
                        <h4 className="font-bold text-white mb-2">Formal Verification</h4>
                        <p className="text-xs text-primaryMuted leading-relaxed">
                            Patches are not just tested; they are verified against mathematical safety invariants to ensure 100% remediation.
                        </p>
                    </div>
                    <div>
                        <div className="text-accentMint text-2xl mb-4 font-black">03</div>
                        <h4 className="font-bold text-white mb-2">Adversarial Resistance</h4>
                        <p className="text-xs text-primaryMuted leading-relaxed">
                            Every fix is subjected to the RBAT loop, simulating state-of-the-art AML attacks to guarantee mission-critical durability.
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
}
