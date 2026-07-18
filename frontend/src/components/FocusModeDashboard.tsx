"use client";

import { Shield, Zap, Activity, Lock, TrendingUp, Layers } from "lucide-react";
import { useAuditStats } from "@/lib/hooks";
import ActivityChart from "@/components/ActivityChart";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { StatSkeleton } from "@/components/LoadingSkeleton";

export default function FocusModeDashboard() {
    const { data: stats, isLoading } = useAuditStats();

    const globalResilience = stats?.average_robustness
        ? Math.round(stats.average_robustness * 100)
        : 92;

    return (
        <div className="space-y-8 animate-fade-in-up">
            {/* Header */}
            <div className="border-b border-white/10 pb-6">
                <h1 className="text-3xl font-black italic tracking-tighter text-white mb-2">SYSTEM OVERVIEW</h1>
                <p className="text-primaryMuted text-sm uppercase tracking-widest font-bold">
                    Deterministic Security Dashboard
                </p>
            </div>

            {/* Key Metrics Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <ErrorBoundary widgetName="Robustness Metric">
                    {isLoading ? (
                        <StatSkeleton />
                    ) : (
                        <div className="bg-surface/30 border border-white/5 rounded-2xl p-6 backdrop-blur-sm hover:bg-surface/40 transition-all">
                            <div className="flex items-center justify-between mb-4">
                                <h3 className="text-xs font-bold text-white/40 uppercase tracking-wider">Robustness Index</h3>
                                <Shield className="w-5 h-5 text-accentMint opacity-50" />
                            </div>
                            <div className="text-4xl font-black text-white mb-2">{globalResilience}%</div>
                            <div className="flex items-center gap-2 text-emerald-400 text-sm font-bold">
                                <TrendingUp className="w-4 h-4" />
                                <span>+2.4</span>
                            </div>
                        </div>
                    )}
                </ErrorBoundary>

                <ErrorBoundary widgetName="Total Audits">
                    {isLoading ? (
                        <StatSkeleton />
                    ) : (
                        <div className="bg-surface/30 border border-white/5 rounded-2xl p-6 backdrop-blur-sm hover:bg-surface/40 transition-all">
                            <div className="flex items-center justify-between mb-4">
                                <h3 className="text-xs font-bold text-white/40 uppercase tracking-wider">Total Audits</h3>
                                <Activity className="w-5 h-5 text-accentBlue opacity-50" />
                            </div>
                            <div className="text-4xl font-black text-white mb-2">{stats?.total_audits?.toLocaleString() || 0}</div>
                            <p className="text-xs text-white/40 uppercase tracking-widest font-bold">System Scans</p>
                        </div>
                    )}
                </ErrorBoundary>

                <ErrorBoundary widgetName="Threats Detected">
                    {isLoading ? (
                        <StatSkeleton />
                    ) : (
                        <div className="bg-surface/30 border border-white/5 rounded-2xl p-6 backdrop-blur-sm hover:bg-surface/40 transition-all">
                            <div className="flex items-center justify-between mb-4">
                                <h3 className="text-xs font-bold text-white/40 uppercase tracking-wider">Threats Detected</h3>
                                <Zap className="w-5 h-5 text-yellow-500 opacity-50" />
                            </div>
                            <div className="text-4xl font-black text-white mb-2">{stats?.total_threats?.toLocaleString() || 0}</div>
                            <p className="text-xs text-white/40 uppercase tracking-widest font-bold">Findings Identified</p>
                        </div>
                    )}
                </ErrorBoundary>

                <ErrorBoundary widgetName="G-ASR Status">
                    <div className="bg-surface/30 border border-white/5 rounded-2xl p-6 backdrop-blur-sm hover:bg-surface/40 transition-all">
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="text-xs font-bold text-white/40 uppercase tracking-wider">G-ASR Logic</h3>
                            <Layers className="w-5 h-5 text-accentPurple opacity-50" />
                        </div>
                        <div className="text-4xl font-black text-white mb-2">DEEP</div>
                        <p className="text-xs text-white/40 uppercase tracking-widest font-bold">Reasoning Active</p>
                    </div>
                </ErrorBoundary>
            </div>

            {/* Activity Chart */}
            <ActivityChart data={stats?.recent_activity || []} isLoading={isLoading} />

            {/* Quick Actions */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-surface/30 border border-white/5 rounded-2xl p-8 backdrop-blur-sm">
                    <Zap className="w-10 h-10 text-white mb-6 opacity-30" />
                    <h3 className="text-2xl font-black mb-3 italic tracking-tight uppercase">Initiate Audit</h3>
                    <p className="text-xs text-white/30 leading-relaxed uppercase tracking-widest font-bold mb-6">
                        Comprehensive neural path analysis across global mesh.
                    </p>
                    <button
                        onClick={() => window.location.href = '/audits'}
                        className="w-full py-4 rounded-xl bg-white text-black font-black text-lg tracking-tighter hover:bg-white/90 active:scale-[0.98] transition-all"
                    >
                        VIEW AUDIT LOGS
                    </button>
                </div>

                <div className="bg-surface/30 border border-white/5 rounded-2xl p-8 backdrop-blur-sm">
                    <Lock className="w-10 h-10 text-white mb-6 opacity-30" />
                    <h3 className="text-2xl font-black mb-3 italic tracking-tight uppercase">System Config</h3>
                    <p className="text-xs text-white/30 leading-relaxed uppercase tracking-widest font-bold mb-6">
                        Manage API keys, scanner rules, and interface preferences.
                    </p>
                    <button
                        onClick={() => window.location.href = '/settings'}
                        className="w-full py-4 rounded-xl border-2 border-white text-white font-black text-lg tracking-tighter hover:bg-white hover:text-black active:scale-[0.98] transition-all"
                    >
                        OPEN SETTINGS
                    </button>
                </div>
            </div>
        </div>
    );
}
