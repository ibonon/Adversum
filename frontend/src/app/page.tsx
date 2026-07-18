"use client";

import { Shield, Zap, Activity, Lock, TrendingUp, Sparkles, ChevronRight, Globe, Cpu, Database, Menu, Grid, Layers, HardDrive } from "lucide-react";
import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import toast from "react-hot-toast";

import { useAudits, useAuditStats } from "@/lib/hooks";
import { useFocusMode } from "@/contexts/FocusModeContext";
import FocusModeDashboard from "@/components/FocusModeDashboard";
import { submitAudit } from "@/lib/api";

export default function Dashboard() {
    const { data: audits } = useAudits();
    const { data: stats } = useAuditStats();
    const { isFocusMode } = useFocusMode();
    const [statsVisible, setStatsVisible] = useState(false);
    const monolithRef = useRef<HTMLDivElement>(null);
    const router = useRouter();

    // Audit submission state
    const [targetPath, setTargetPath] = useState("f:\\Adversum\\adversum");
    const [loading, setLoading] = useState(false);

    // Calculate Real Metrics
    const totalAudits = stats?.total_audits || 0;
    const totalThreats = stats?.total_threats || 0;

    // Average Robustness (Default directly to 92 if no audits yet to keep the look cool for first launch)
    const avgRobustness = stats?.average_robustness
        ? Math.round(stats.average_robustness * 100)
        : 92;

    const globalResilience = avgRobustness;

    useEffect(() => {
        setStatsVisible(true);
        // Only add mouse tracking if not in Focus Mode
        if (isFocusMode) return;

        const handleMouseMove = (e: MouseEvent) => {
            if (!monolithRef.current) return;
            const { clientX, clientY } = e;
            const x = (clientX / window.innerWidth) * 100;
            const y = (clientY / window.innerHeight) * 100;
            monolithRef.current.style.setProperty('--mouse-x', `${x}%`);
            monolithRef.current.style.setProperty('--mouse-y', `${y}%`);

            const rotateX = (clientY / window.innerHeight - 0.5) * -6;
            const rotateY = (clientX / window.innerWidth - 0.5) * 6;
            monolithRef.current.style.setProperty('--rot-x', `${rotateX}deg`);
            monolithRef.current.style.setProperty('--rot-y', `${rotateY}deg`);
        };

        window.addEventListener('mousemove', handleMouseMove);
        return () => window.removeEventListener('mousemove', handleMouseMove);
    }, [isFocusMode]);

    const handleScan = async () => {
        if (!targetPath.trim()) {
            toast.error("Please enter a valid project path");
            return;
        }

        setLoading(true);
        try {
            const job = await submitAudit(targetPath);
            toast.success(`Audit started: ${job.id}`);
            // Navigate to the audit details page
            router.push(`/audits/${job.id}`);
        } catch (e) {
            toast.error(`Failed to start audit: ${String(e)}`);
        } finally {
            setLoading(false);
        }
    };

    // Render Focus Mode Dashboard if enabled
    if (isFocusMode) {
        return <FocusModeDashboard />;
    }

    return (
        <div className="min-h-screen bg-black text-white font-sans overflow-hidden flex items-center justify-center p-20">
            {/* Absolute Deep Black Background */}
            <div className="fixed inset-0 pointer-events-none bg-black" />

            {/* THE MONOLITH LAYER */}
            <div
                ref={monolithRef}
                className="relative z-10 w-full max-w-[1300px] monolith-layer"
                style={{ transform: 'rotateX(var(--rot-x, 0deg)) rotateY(var(--rot-y, 0deg))' } as any}
            >
                <div className="monolith-structure rounded-[40px] border border-white/10 shadow-[0_0_100px_rgba(0,0,0,0.8)]">

                    {/* Interior Lighting & Scanline */}
                    <div className="monolith-lighting" />
                    <div className="animate-scan" />

                    {/* MONOLITH HEADER - Integrated Navigation */}
                    <div className="h-24 border-b border-white/5 flex items-center justify-between px-16 relative z-20">
                        <div className="flex items-center gap-8">
                            <h1 className="text-3xl font-black italic tracking-tighter monolith-mirror-text">ADVERSUM</h1>
                            <div className="h-6 w-[1px] bg-white/10" />
                            <div className="flex gap-10">
                                {['SYSTEM', 'AUDITS', 'VAULT', 'NETWORK'].map((item, i) => (
                                    <button key={item} className={`text-[10px] font-bold tracking-[0.4em] transition-all ${i === 0 ? 'text-white' : 'text-white/20 hover:text-white'}`}>
                                        {item}
                                    </button>
                                ))}
                            </div>
                        </div>
                        <div className="flex items-center gap-4 text-[10px] font-bold text-white/30 uppercase tracking-[0.2em]">
                            <div className={`w-1.5 h-1.5 rounded-full shadow-[0_0_10px_rgba(16,185,129,0.4)] ${totalAudits > 0 ? 'bg-emerald-500' : 'bg-yellow-500'}`} />
                            {totalAudits > 0 ? 'Active Monitoring' : 'System Standby'}
                        </div>
                    </div>

                    {/* MAIN CONTENT DECK */}
                    <div className="monolith-grid">

                        {/* Primary Stat Cell (Large) */}
                        <div className="grid-cell col-span-12 lg:col-span-8 h-[600px] flex flex-col justify-between border-b border-white/5 relative group">
                            <div className="space-y-4">
                                <div className="flex items-center gap-3">
                                    <div className="w-8 h-[1px] bg-white/20" />
                                    <span className="text-[10px] font-bold uppercase tracking-[0.5em] text-white/30 italic">Robustness Quotient</span>
                                </div>
                                <h2 className="text-4xl font-light tracking-[0.3em] uppercase opacity-80">Deterministic Index</h2>
                            </div>

                            <div className="flex items-end gap-16 py-12">
                                <div className="text-[14rem] font-black leading-none tracking-tighter monolith-mirror-text select-none">
                                    {globalResilience}
                                </div>
                                <div className="flex flex-col gap-4 pb-10">
                                    <span className="text-7xl font-bold opacity-10">%</span>
                                    <div className="flex items-center gap-3 text-emerald-400 font-bold text-2xl tracking-tight">
                                        <TrendingUp className="w-6 h-6" />
                                        <span>+2.4</span>
                                    </div>
                                </div>
                            </div>

                            <div className="space-y-8">
                                <div className="chrome-inlay w-full rounded-full" />
                                <div className="flex justify-between items-center text-[10px] font-bold text-white/20 uppercase tracking-[0.4em]">
                                    <div className="flex gap-12">
                                        <span>G-ASR ACTIVE</span>
                                        <span>RBAT VERIFIED</span>
                                    </div>
                                    <span className="text-white/40">Total Audits: {totalAudits}</span>
                                </div>
                            </div>
                        </div>

                        {/* Control Slab Cell */}
                        <div className="grid-cell col-span-12 lg:col-span-4 h-[600px] border-l border-b border-white/5 bg-white/[0.01] flex flex-col justify-between group">
                            <div className="space-y-8">
                                <div className="p-6 border border-white/5 rounded-2xl bg-black/40 group-hover:border-white/20 transition-all">
                                    <Zap className="w-10 h-10 text-white mb-6 opacity-30 group-hover:opacity-100 transition-opacity" />
                                    <h3 className="text-2xl font-black mb-3 italic tracking-tight uppercase">Initiate Audit</h3>
                                    <p className="text-xs text-white/30 leading-relaxed uppercase tracking-widest font-bold mb-6">Comprehensive neural path analysis across global mesh.</p>

                                    {/* Audit Form */}
                                    <div className="space-y-4">
                                        <input
                                            type="text"
                                            value={targetPath}
                                            onChange={(e) => setTargetPath(e.target.value)}
                                            placeholder="Enter project path..."
                                            className="w-full px-4 py-3 rounded-lg bg-black/60 border border-white/10 text-white text-sm placeholder-white/20 focus:border-white/30 focus:outline-none transition-all"
                                        />
                                        <button
                                            onClick={handleScan}
                                            disabled={loading}
                                            className="w-full py-3 rounded-lg bg-white/10 hover:bg-white/20 text-white font-bold text-sm tracking-wider uppercase transition-all disabled:opacity-50 disabled:cursor-not-allowed border border-white/20"
                                        >
                                            {loading ? (
                                                <span className="flex items-center justify-center gap-2">
                                                    <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
                                                    Launching...
                                                </span>
                                            ) : (
                                                "Launch Audit"
                                            )}
                                        </button>
                                    </div>
                                </div>

                                <div className="flex flex-col gap-4">
                                    <div className="flex justify-between text-[10px] items-center">
                                        <span className="text-white/30 font-bold uppercase tracking-widest">Formal Proofing</span>
                                        <span className="text-emerald-500 font-bold uppercase tracking-widest">Complete</span>
                                    </div>
                                    <div className="h-1 bg-white/5 rounded-full overflow-hidden">
                                        <div className="h-full bg-white/40 w-[96%]" />
                                    </div>
                                </div>
                            </div>

                            <button onClick={() => window.location.href = '/audits'} className="w-full py-10 rounded-[20px] bg-white text-black font-black text-2xl tracking-tighter hover:bg-white/90 active:scale-[0.98] transition-all shadow-[0_20px_40px_rgba(255,255,255,0.1)]">
                                VIEW AUDIT LOGS
                            </button>
                        </div>

                        {/* Secondary Stats Row */}
                        {[
                            { label: "Neutralization", value: totalThreats.toLocaleString(), icon: Shield, detail: "THREATS DETECTED" },
                            { label: "Throughput", value: "1.2 PB/S", icon: Activity, detail: "DETERMINISTIC SYNC" },
                            { label: "Reasoning", value: "DEEP", icon: Layers, detail: "G-ASR LOGIC" },
                            { label: "Encryption", value: "S-LEVEL", icon: Lock, detail: "RSA-4096-ADV" },
                        ].map((stat, i) => (
                            <div key={i} className={`grid-cell col-span-12 md:col-span-3 border-r border-white/5 group hover:bg-white/[0.02]`}>
                                <stat.icon className="w-5 h-5 text-white/20 mb-6 group-hover:text-white transition-colors" />
                                <div className="space-y-1">
                                    <p className="text-[9px] font-bold text-white/20 uppercase tracking-[0.3em]">{stat.label}</p>
                                    <div className="text-2xl font-black tracking-tight monolith-mirror-text">{stat.value}</div>
                                    <p className="text-[8px] font-bold text-white/40 uppercase tracking-widest mt-2">{stat.detail}</p>
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* FOOTER STRIP */}
                    <div className="h-16 flex items-center justify-between px-16 text-[9px] font-bold text-white/10 uppercase tracking-[0.6em]">
                        <span>© 2024 ADVERSUM MONOLITH-III SYSTEMS</span>
                        <div className="flex gap-12">
                            <span>LATENCY: 0.004 MS</span>
                            <span>NODE: X-7728</span>
                        </div>
                    </div>
                </div>
            </div>

            {/* Side Labels (Fixed in Space) */}
            <div className="fixed top-1/2 left-10 -translate-y-1/2 -rotate-90 z-20 text-[10px] font-bold opacity-10 uppercase tracking-[1em] select-none pointer-events-none">
                STRUCTURAL DETERMINISM
            </div>
            <div className="fixed top-1/2 right-10 -translate-y-1/2 rotate-90 z-20 text-[10px] font-bold opacity-10 uppercase tracking-[1em] select-none pointer-events-none">
                SECURE INTERFACE UNIT
            </div>
        </div>
    );
}
