"use client";

import { motion } from "framer-motion";
import { Shield, Zap, AlertTriangle, ArrowRight, Circle, Activity } from "lucide-react";

interface FlowVisualizerProps {
    evidence: string[];
    source?: string;
    sink?: string;
}

export default function FlowVisualizer({ evidence, source, sink }: FlowVisualizerProps) {
    return (
        <div className="relative mt-8 p-6 bg-black/40 rounded-2xl border border-white/5 overflow-hidden">
            {/* Background decorative elements */}
            <div className="absolute top-0 right-0 w-32 h-32 bg-accentBlue/5 blur-3xl rounded-full -translate-y-1/2 translate-x-1/2" />

            <div className="relative z-10">
                <div className="flex items-center gap-3 mb-8">
                    <Activity className="w-4 h-4 text-accentBlue" />
                    <h4 className="text-[10px] font-black uppercase tracking-[0.2em] text-white/50">
                        Deterministic Flow Path Visualization
                    </h4>
                </div>

                <div className="flex flex-col gap-6 relative">
                    {/* The connector line */}
                    <div className="absolute left-[13px] top-4 bottom-4 w-[1px] bg-gradient-to-b from-accentBlue/40 via-accentPurple/40 to-error/40" />

                    {/* Source Node */}
                    <motion.div
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        className="flex gap-6 items-start group"
                    >
                        <div className="relative z-20 mt-1">
                            <div className="w-7 h-7 rounded-full bg-accentBlue/20 border border-accentBlue/40 flex items-center justify-center shadow-[0_0_15px_rgba(59,130,246,0.3)]">
                                <Zap className="w-3.5 h-3.5 text-accentBlue" />
                            </div>
                        </div>
                        <div className="flex-1 pt-0.5">
                            <div className="text-[9px] font-bold text-accentBlue uppercase tracking-widest mb-1">Source Ingestion</div>
                            <div className="text-sm text-white font-mono bg-white/5 p-2 rounded border border-white/5 group-hover:border-white/10 transition-colors">
                                {source || "EXTERNAL_INPUT"}
                            </div>
                        </div>
                    </motion.div>

                    {/* Evidence Steps */}
                    {evidence.map((step, idx) => (
                        <motion.div
                            key={idx}
                            initial={{ opacity: 0, x: -10 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ delay: (idx + 1) * 0.1 }}
                            className="flex gap-6 items-start group"
                        >
                            <div className="relative z-20 mt-1">
                                <div className="w-7 h-7 rounded-full bg-white/5 border border-white/10 flex items-center justify-center group-hover:bg-white/10 transition-colors">
                                    <div className="w-1.5 h-1.5 rounded-full bg-white/40 group-hover:bg-white/80" />
                                </div>
                            </div>
                            <div className="flex-1 pt-0.5">
                                <div className="text-[9px] font-bold text-white/20 uppercase tracking-widest mb-1">Hop {idx + 1}</div>
                                <div className="text-xs text-white/70 leading-relaxed font-sans">{step}</div>
                            </div>
                        </motion.div>
                    ))}

                    {/* Sink Node */}
                    <motion.div
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: (evidence.length + 1) * 0.1 }}
                        className="flex gap-6 items-start group"
                    >
                        <div className="relative z-20 mt-1">
                            <div className="w-7 h-7 rounded-full bg-error/20 border border-error/40 flex items-center justify-center shadow-[0_0_15px_rgba(239,68,68,0.3)]">
                                <AlertTriangle className="w-3.5 h-3.5 text-error" />
                            </div>
                        </div>
                        <div className="flex-1 pt-0.5">
                            <div className="text-[9px] font-bold text-error uppercase tracking-widest mb-1">Critical Sink</div>
                            <div className="text-sm text-white font-bold bg-error/5 p-2 rounded border border-error/10 group-hover:border-error/20 transition-colors">
                                {sink || "SENSITIVE_OPERATION"}
                            </div>
                        </div>
                    </motion.div>
                </div>
            </div>

            {/* Glassmorphism scanline */}
            <div className="absolute inset-0 pointer-events-none overflow-hidden">
                <div className="w-full h-[1px] bg-white/5 animate-scan top-0 absolute" />
            </div>
        </div>
    );
}
