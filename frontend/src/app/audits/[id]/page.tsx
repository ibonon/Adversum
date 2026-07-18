"use client";

import { useParams } from "next/navigation";
import { useAudit } from "@/lib/hooks";
import { useFocusMode } from "@/contexts/FocusModeContext";
import FindingsTable from "@/components/FindingsTable";
import SummaryCard from "@/components/SummaryCard";
import Link from "next/link";
import { FileText, CheckCircle, XCircle, Clock, ArrowLeft } from "lucide-react";
import { ErrorBoundary } from "@/components/ErrorBoundary";

export default function AuditDetail() {
    const { id } = useParams();
    const { data: job, isLoading, isError } = useAudit(id as string);
    const { isFocusMode } = useFocusMode();

    if (isLoading && !job) {
        return (
            <div className="text-white animate-pulse p-20 text-center">
                <div className="w-16 h-16 rounded-full border-4 border-accentBlue/20 border-t-accentBlue animate-spin mb-6 mx-auto" />
                <p>Scanning G-ASR pathways...</p>
            </div>
        );
    }

    if (isError || !job) {
        return (
            <div className="text-error p-20 text-center">
                <p>Audit log #{id} not found in the deterministic storage.</p>
                <Link href="/audits" className="text-accentBlue hover:text-white transition-colors mt-4 inline-block">
                    ← Back to Audits
                </Link>
            </div>
        );
    }

    const isProcessing = job.status === "running" || job.status === "queued";

    return (
        <ErrorBoundary widgetName="Audit Detail">
            <div className={`space-y-10 ${isFocusMode ? 'animate-fade-in' : 'animate-in fade-in duration-700'}`}>
                {/* Context Header */}
                <div className="flex justify-between items-start">
                    <div>
                        <div className="flex items-center gap-3 mb-2">
                            <Link href="/audits" className="text-primaryMuted hover:text-white transition-colors flex items-center gap-2">
                                <ArrowLeft className="w-4 h-4" />
                                Audits
                            </Link>
                            <span className="text-surfaceBorder">/</span>
                            <span className="text-white font-mono">Job #{id}</span>
                        </div>
                        <h1 className="text-4xl font-bold tracking-tight text-white mb-4">
                            {isFocusMode ? 'Audit Report' : 'Audit Explorer'}
                        </h1>
                        <div className="flex items-center gap-4">
                            <div className={`px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${job.status === 'completed'
                                    ? 'bg-accentMint/10 text-accentMint border border-accentMint/20'
                                    : 'bg-accentBlue/10 text-accentBlue border border-accentBlue/20 animate-pulse'
                                }`}>
                                {job.status}
                                {isProcessing && " (Auto-refreshing...)"}
                            </div>
                            {job.robustness_score !== undefined && (
                                <div className="px-3 py-1 rounded-full bg-surface border border-surfaceBorder text-[10px] font-bold text-primaryMuted uppercase tracking-wider">
                                    ARS: {(job.robustness_score * 100).toFixed(0)}%
                                </div>
                            )}
                            {job.result && job.result.length > 0 && (
                                <div className="px-3 py-1 rounded-full bg-surface border border-surfaceBorder text-[10px] font-bold text-primaryMuted uppercase tracking-wider">
                                    {job.result.length} Finding{job.result.length !== 1 ? 's' : ''}
                                </div>
                            )}
                        </div>
                    </div>
                    {job.status === 'completed' && (
                        <div className="flex gap-4">
                            <button className="px-6 py-2.5 rounded-lg bg-white text-black font-bold text-sm hover:bg-white/90 transition-all">
                                Verify All Patch Sets
                            </button>
                        </div>
                    )}
                </div>

                {job.status === 'completed' ? (
                    <div className="grid grid-cols-12 gap-8">
                        {/* Main Content */}
                        <div className="col-span-12 lg:col-span-8 space-y-8">
                            <ErrorBoundary widgetName="Summary Card">
                                <SummaryCard summary={job.summary} />
                            </ErrorBoundary>

                            <div>
                                <div className="flex items-center justify-between mb-6">
                                    <h3 className="text-xl font-bold">Vulnerability Ledger</h3>
                                    <span className="tech-label">{job.result?.length || 0} Points of Path Compromise</span>
                                </div>
                                <ErrorBoundary widgetName="Findings Table">
                                    <FindingsTable findings={job.result || []} robustnessScore={job.robustness_score} />
                                </ErrorBoundary>
                            </div>
                        </div>

                        {/* Meta Sidebar */}
                        <div className="col-span-12 lg:col-span-4 space-y-8">
                            <div className="bento-card">
                                <h4 className="tech-label mb-4">Deterministic Context</h4>
                                <div className="space-y-4">
                                    <div>
                                        <div className="text-[10px] text-primaryMuted uppercase font-bold mb-1">Audit ID</div>
                                        <div className="text-sm font-medium font-mono">#{job.id}</div>
                                    </div>
                                    <div>
                                        <div className="text-[10px] text-primaryMuted uppercase font-bold mb-1">Created At</div>
                                        <div className="text-sm font-medium">{job.created_at ? new Date(job.created_at).toLocaleString() : 'N/A'}</div>
                                    </div>
                                    <div>
                                        <div className="text-[10px] text-primaryMuted uppercase font-bold mb-1">Verification Method</div>
                                        <div className="text-sm font-medium">RBAT Formal Probing</div>
                                    </div>
                                    <div>
                                        <div className="text-[10px] text-primaryMuted uppercase font-bold mb-1">Compliance Status</div>
                                        <div className={`text-sm font-bold ${job.robustness_score && job.robustness_score > 0.8 ? 'text-accentMint' : 'text-warning'}`}>
                                            {job.robustness_score && job.robustness_score > 0.8 ? 'PASSED' : 'PENDING REMEDIATION'}
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div className="bento-card border-accentPurple/20 bg-accentPurple/5">
                                <h4 className="tech-label text-accentPurple mb-4">G-ASR Traceability</h4>
                                <p className="text-xs text-primaryMuted leading-relaxed mb-6">
                                    All findings listed are backed by an Abstract Syntax Representation trace,
                                    eliminating false positives through deterministic flow verification.
                                </p>
                                <div className="flex items-center gap-2 text-primary text-xs font-bold bg-white/5 p-3 rounded-lg cursor-not-allowed">
                                    <span>⚡ GENERATE ATTACK GRAPH</span>
                                </div>
                            </div>
                        </div>
                    </div>
                ) : (
                    <div className="bento-card h-[400px] flex flex-col items-center justify-center text-center">
                        <div className="w-16 h-16 rounded-full border-4 border-accentBlue/20 border-t-accentBlue animate-spin mb-6" />
                        <h2 className="text-2xl font-bold mb-2">Analyzing Program Structure</h2>
                        <p className="text-primaryMuted max-w-sm">
                            Building the Graph-Augmented Security Reasoning model and traversing deterministic flow paths.
                        </p>
                    </div>
                )}
            </div>
        </ErrorBoundary>
    );
}
