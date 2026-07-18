"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { compareAudits, AuditComparison } from "@/lib/api";
import Link from "next/link";
import { ArrowLeft, TrendingUp, TrendingDown, Plus, Minus, Equal } from "lucide-react";
import { ErrorBoundary } from "@/components/ErrorBoundary";

export default function AuditComparePage() {
    const searchParams = useSearchParams();
    const id1 = searchParams.get("id1");
    const id2 = searchParams.get("id2");

    const [comparison, setComparison] = useState<AuditComparison | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        if (!id1 || !id2) {
            setError("Missing audit IDs for comparison");
            setLoading(false);
            return;
        }

        const fetchComparison = async () => {
            try {
                const data = await compareAudits(id1, id2);
                setComparison(data);
            } catch (err) {
                setError("Failed to load audit comparison");
                console.error(err);
            } finally {
                setLoading(false);
            }
        };

        fetchComparison();
    }, [id1, id2]);

    if (loading) {
        return (
            <div className="p-20 text-center">
                <div className="w-16 h-16 rounded-full border-4 border-accentBlue/20 border-t-accentBlue animate-spin mb-6 mx-auto" />
                <p className="text-white/60">Comparing audits...</p>
            </div>
        );
    }

    if (error || !comparison) {
        return (
            <div className="p-20 text-center text-error">
                <p>{error || "Failed to load comparison"}</p>
                <Link href="/audits" className="text-accentBlue hover:text-white transition-colors mt-4 inline-block">
                    ← Back to Audits
                </Link>
            </div>
        );
    }

    const { audit1, audit2, added_findings, removed_findings, common_findings, robustness_delta } = comparison;

    return (
        <ErrorBoundary widgetName="Audit Comparison">
            <div className="space-y-8 animate-fade-in-up">
                {/* Header */}
                <div className="flex justify-between items-start border-b border-white/10 pb-6">
                    <div>
                        <Link href="/audits" className="text-primaryMuted hover:text-white transition-colors text-sm mb-2 inline-flex items-center gap-2">
                            <ArrowLeft className="w-4 h-4" />
                            Back to Audits
                        </Link>
                        <h1 className="text-3xl font-black italic tracking-tighter text-white mb-2">AUDIT COMPARISON</h1>
                        <p className="text-primaryMuted text-sm uppercase tracking-widest font-bold">
                            Differential Analysis: #{id1} vs #{id2}
                        </p>
                    </div>
                </div>

                {/* Summary Cards */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="bg-surface/30 border border-white/5 rounded-2xl p-6 backdrop-blur-sm">
                        <div className="flex items-center gap-2 mb-4">
                            <Plus className="w-5 h-5 text-yellow-500" />
                            <h3 className="text-sm font-bold text-white/60 uppercase tracking-wider">Added Findings</h3>
                        </div>
                        <div className="text-4xl font-black text-yellow-500">{added_findings.length}</div>
                        <p className="text-xs text-white/40 mt-2">New vulnerabilities in Audit #{id2}</p>
                    </div>

                    <div className="bg-surface/30 border border-white/5 rounded-2xl p-6 backdrop-blur-sm">
                        <div className="flex items-center gap-2 mb-4">
                            <Minus className="w-5 h-5 text-accentMint" />
                            <h3 className="text-sm font-bold text-white/60 uppercase tracking-wider">Removed Findings</h3>
                        </div>
                        <div className="text-4xl font-black text-accentMint">{removed_findings.length}</div>
                        <p className="text-xs text-white/40 mt-2">Fixed vulnerabilities from Audit #{id1}</p>
                    </div>

                    <div className="bg-surface/30 border border-white/5 rounded-2xl p-6 backdrop-blur-sm">
                        <div className="flex items-center gap-2 mb-4">
                            {robustness_delta >= 0 ? (
                                <TrendingUp className="w-5 h-5 text-accentMint" />
                            ) : (
                                <TrendingDown className="w-5 h-5 text-error" />
                            )}
                            <h3 className="text-sm font-bold text-white/60 uppercase tracking-wider">Robustness Delta</h3>
                        </div>
                        <div className={`text-4xl font-black ${robustness_delta >= 0 ? 'text-accentMint' : 'text-error'}`}>
                            {robustness_delta >= 0 ? '+' : ''}{(robustness_delta * 100).toFixed(1)}%
                        </div>
                        <p className="text-xs text-white/40 mt-2">
                            {audit1.robustness_score ? ((audit1.robustness_score || 0) * 100).toFixed(0) : 'N/A'}% → {audit2.robustness_score ? ((audit2.robustness_score || 0) * 100).toFixed(0) : 'N/A'}%
                        </p>
                    </div>
                </div>

                {/* Added Findings */}
                {added_findings.length > 0 && (
                    <div className="bg-surface/30 border border-yellow-500/20 rounded-2xl p-8 backdrop-blur-sm">
                        <div className="flex items-center gap-3 mb-6">
                            <Plus className="w-6 h-6 text-yellow-500" />
                            <h2 className="text-xl font-bold text-white">Added Findings ({added_findings.length})</h2>
                        </div>
                        <div className="space-y-4">
                            {added_findings.map((finding, idx) => (
                                <div key={idx} className="bg-black/30 border border-white/5 rounded-lg p-4">
                                    <div className="flex items-start justify-between mb-2">
                                        <div>
                                            <span className="text-xs font-bold text-yellow-500 uppercase">{finding.raw.severity}</span>
                                            <h4 className="text-sm font-bold text-white mt-1">{finding.raw.rule_id}</h4>
                                        </div>
                                        <span className="text-xs text-white/40 font-mono">{finding.raw.file_path}</span>
                                    </div>
                                    <p className="text-xs text-white/60">{finding.raw.description}</p>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {/* Removed Findings */}
                {removed_findings.length > 0 && (
                    <div className="bg-surface/30 border border-accentMint/20 rounded-2xl p-8 backdrop-blur-sm">
                        <div className="flex items-center gap-3 mb-6">
                            <Minus className="w-6 h-6 text-accentMint" />
                            <h2 className="text-xl font-bold text-white">Removed Findings ({removed_findings.length})</h2>
                        </div>
                        <div className="space-y-4">
                            {removed_findings.map((finding, idx) => (
                                <div key={idx} className="bg-black/30 border border-white/5 rounded-lg p-4">
                                    <div className="flex items-start justify-between mb-2">
                                        <div>
                                            <span className="text-xs font-bold text-accentMint uppercase">{finding.raw.severity}</span>
                                            <h4 className="text-sm font-bold text-white mt-1">{finding.raw.rule_id}</h4>
                                        </div>
                                        <span className="text-xs text-white/40 font-mono">{finding.raw.file_path}</span>
                                    </div>
                                    <p className="text-xs text-white/60">{finding.raw.description}</p>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {/* Common Findings */}
                <div className="bg-surface/30 border border-white/5 rounded-2xl p-8 backdrop-blur-sm">
                    <div className="flex items-center gap-3 mb-6">
                        <Equal className="w-6 h-6 text-white/40" />
                        <h2 className="text-xl font-bold text-white">Common Findings ({common_findings.length})</h2>
                    </div>
                    <p className="text-sm text-white/60">
                        {common_findings.length} vulnerabilities present in both audits (no change)
                    </p>
                </div>
            </div>
        </ErrorBoundary>
    );
}
