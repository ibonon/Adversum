"use client";

import { ValidatedFinding } from "../lib/api";
import { useState, useRef, useEffect } from "react";
import { useApplyFix } from "../lib/hooks";
import { useVirtualizer } from "@tanstack/react-virtual";
import FlowVisualizer from "./FlowVisualizer";
import DiffPreview from "./DiffPreview";

const severityStyles: Record<string, string> = {
    CRITICAL: "bg-error/10 text-error border-error/20",
    HIGH: "text-warning border-warning/20 bg-warning/5",
    MEDIUM: "text-accentPurple border-accentPurple/20 bg-accentPurple/5",
    LOW: "text-accentBlue border-accentBlue/20 bg-accentBlue/5",
};

export default function FindingsTable({ findings, robustnessScore = 0.85 }: { findings: ValidatedFinding[], robustnessScore?: number }) {
    const { mutate: fixFinding, isPending: isFixing } = useApplyFix();
    const [fixingId, setFixingId] = useState<number | null>(null);

    // Virtualization setup
    const parentRef = useRef<HTMLDivElement>(null);

    const virtualizer = useVirtualizer({
        count: findings.length,
        getScrollElement: () => parentRef.current,
        estimateSize: () => 300, // Estimated height of a finding card
        overscan: 5,
    });

    const handleRepair = (id: number) => {
        if (!id) return;
        setFixingId(id);
        fixFinding({ findingId: id }, {
            onSuccess: () => {
                alert("Remediation Applied & Verified.");
                setFixingId(null);
            },
            onError: (e) => {
                alert(`Failed: ${e.message}`);
                setFixingId(null);
            }
        });
    };

    if (!findings || findings.length === 0) return (
        <div className="text-center p-20 bento-card">
            <div className="text-accentMint text-6xl mb-6">✓</div>
            <h3 className="text-2xl font-bold text-white">System Integrity Verified</h3>
            <p className="text-primaryMuted mt-3 max-w-xs mx-auto">
                No deterministic flow path violations detected in the current audit scope.
            </p>
        </div>
    );

    return (
        <div
            ref={parentRef}
            className="h-[800px] overflow-auto pr-4 -mr-4 relative"
            style={{ contain: 'strict' }}
        >
            <div
                style={{
                    height: `${virtualizer.getTotalSize()}px`,
                    width: '100%',
                    position: 'relative',
                }}
            >
                {virtualizer.getVirtualItems().map((virtualItem) => {
                    const f = findings[virtualItem.index];
                    return (
                        <div
                            key={virtualItem.key}
                            data-index={virtualItem.index}
                            ref={virtualizer.measureElement}
                            className="absolute top-0 left-0 w-100% w-full pb-6"
                            style={{
                                transform: `translateY(${virtualItem.start}px)`,
                            }}
                        >
                            <div className="bento-card group hover:scale-[1.01] transition-transform duration-200">
                                <div className="flex justify-between items-start mb-6">
                                    <div className="flex gap-4 items-center">
                                        <span className={`px-2 py-0.5 rounded text-[10px] font-black tracking-widest uppercase border ${severityStyles[f.raw.severity] || "bg-surfaceHighlight text-primaryMuted"}`}>
                                            {f.raw.severity}
                                        </span>
                                        <h3 className="text-lg font-bold text-white tracking-tight">{f.raw.rule_id}</h3>

                                        {f.raw.immune_context?.invariant_holds && (
                                            <div className="flex items-center gap-2 px-2 py-0.5 bg-accentPurple/10 border border-accentPurple/20 rounded">
                                                <div className="w-1.5 h-1.5 rounded-full bg-accentPurple animate-pulse" />
                                                <span className="text-[9px] font-black text-accentPurple uppercase tracking-tighter">Immune</span>
                                            </div>
                                        )}
                                    </div>
                                    <div className="text-right">
                                        <div className="tech-label mb-1">Validation State</div>
                                        <div className="flex items-center gap-2 text-xs font-bold text-white justify-end">
                                            <span className={`w-1.5 h-1.5 rounded-full ${f.validation_status === 'CONFIRMED' ? 'bg-accentMint' : 'bg-primaryMuted'}`} />
                                            {f.validation_status}
                                        </div>
                                    </div>
                                </div>

                                <div className="grid grid-cols-12 gap-8">
                                    <div className="col-span-12 lg:col-span-8">
                                        <p className="text-primaryMuted text-sm leading-relaxed mb-6">
                                            {f.raw.description}
                                        </p>

                                        <div className="flex items-center gap-6">
                                            <div>
                                                <div className="tech-label mb-1">File Location</div>
                                                <div className="text-xs font-mono text-white">
                                                    {f.raw.file_path.split(/[\\/]/).pop()}:{f.raw.line_number}
                                                </div>
                                            </div>
                                            <div>
                                                <div className="tech-label mb-1">AI Confidence</div>
                                                <div className="text-xs font-bold text-accentBlue">
                                                    {(f.ai_confidence * 100).toFixed(0)}%
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                    <div className="col-span-12 lg:col-span-4 flex flex-col justify-end gap-3">
                                        {f.fix_code && !f.is_fixed && (
                                            <button
                                                onClick={() => f.id && handleRepair(f.id)}
                                                disabled={fixingId === f.id}
                                                className="w-full bg-white text-black text-[10px] font-black uppercase tracking-[0.1em] py-3 rounded hover:bg-white/90 transition-all disabled:opacity-50"
                                            >
                                                {fixingId === f.id ? "Verifying Invariants..." : "Apply AVR Fix"}
                                            </button>
                                        )}
                                        {f.is_fixed && (
                                            <div className="w-full text-center py-3 rounded border border-accentMint/20 bg-accentMint/5 text-accentMint text-[10px] font-black uppercase tracking-[0.1em]">
                                                Remediation Success
                                            </div>
                                        )}
                                    </div>
                                </div>

                                {/* Expandable G-ASR Trace */}
                                <details
                                    className="mt-6 border-t border-surfaceBorder pt-4 group/details"
                                    onToggle={() => {
                                        // Trigger re-measurement when details are toggled
                                        virtualizer.measure();
                                    }}
                                >
                                    <summary className="tech-label cursor-pointer hover:text-white transition-colors flex items-center gap-2 list-none">
                                        <span className="group-open/details:rotate-90 transition-transform">▸</span>
                                        Deterministic Path Trace (G-ASR)
                                    </summary>
                                    <div className="mt-4 p-4 bg-black rounded-lg border border-surfaceBorder font-mono text-[11px] leading-relaxed text-primaryMuted whitespace-pre-wrap">
                                        <div className="text-accentMint mb-3 flex items-center gap-2 font-bold">
                                            <span className="w-1 h-1 bg-accentMint rounded-full" />
                                            RUST CORE VERIFICATION ENGINE
                                        </div>
                                        {f.reasoning_notes}

                                        {f.raw.proof && (
                                            <FlowVisualizer
                                                evidence={f.raw.proof.evidence}
                                                source={f.raw.proof.taint_source}
                                                sink={f.raw.rule_id}
                                            />
                                        )}

                                        {f.fix_code && (
                                            <div className="mt-8">
                                                <div className="tech-label mb-4">Proposed Remediation Diff</div>
                                                <DiffPreview
                                                    oldCode={f.raw.snippet}
                                                    newCode={f.fix_code}
                                                />
                                            </div>
                                        )}
                                    </div>
                                </details>
                            </div>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}
