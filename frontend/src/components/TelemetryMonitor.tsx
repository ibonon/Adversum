"use client";

import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Terminal, Cpu, Database, Globe, Activity, ShieldCheck } from "lucide-react";

interface TelemetryEvent {
    id: string;
    event: string;
    method: string;
    path: string;
    status_code: number;
    duration_ms: number;
    client_ip: string;
    timestamp: string;
}

export default function TelemetryMonitor() {
    const [events, setEvents] = useState<TelemetryEvent[]>([]);

    useEffect(() => {
        // Simulate real-time events based on the GAFAM-style JSON logs in the API
        const interval = setInterval(() => {
            const newEvent: TelemetryEvent = {
                id: Math.random().toString(36).substr(2, 9),
                event: "api_request",
                method: ["GET", "POST", "DELETE"][Math.floor(Math.random() * 3)],
                path: ["/audit", "/fix", "/analyze", "/immune/start"][Math.floor(Math.random() * 4)],
                status_code: [200, 201, 404, 500][Math.floor(Math.random() * 4)],
                duration_ms: Math.floor(Math.random() * 500) + 10,
                client_ip: `192.168.1.${Math.floor(Math.random() * 255)}`,
                timestamp: new Date().toLocaleTimeString(),
            };

            setEvents(prev => [newEvent, ...prev].slice(0, 10));
        }, 2000);

        return () => clearInterval(interval);
    }, []);

    return (
        <div className="w-full h-full p-8 bg-black/80 rounded-3xl border border-white/5 backdrop-blur-xl overflow-hidden flex flex-col">
            <div className="flex items-center justify-between mb-8">
                <div className="flex items-center gap-4">
                    <div className="p-3 bg-accentBlue/10 rounded-xl border border-accentBlue/20">
                        <Activity className="w-6 h-6 text-accentBlue" />
                    </div>
                    <div>
                        <h2 className="text-xl font-black italic tracking-tighter uppercase">Operations Telemetry</h2>
                        <p className="text-[10px] font-bold text-white/30 uppercase tracking-[0.2em]">Real-time Deterministic Monitoring</p>
                    </div>
                </div>
                <div className="flex gap-4">
                    <div className="text-right">
                        <div className="text-[10px] font-bold text-white/20 uppercase tracking-widest mb-1">System Health</div>
                        <div className="flex items-center gap-2 text-accentMint font-black text-xs uppercase">
                            <ShieldCheck className="w-3 h-3" />
                            Optimal
                        </div>
                    </div>
                </div>
            </div>

            <div className="flex-1 space-y-3 overflow-hidden">
                <AnimatePresence initial={false}>
                    {events.map((event) => (
                        <motion.div
                            key={event.id}
                            initial={{ opacity: 0, y: -20, scale: 0.98 }}
                            animate={{ opacity: 1, y: 0, scale: 1 }}
                            exit={{ opacity: 0, scale: 0.95 }}
                            className="p-4 bg-white/[0.02] border border-white/5 rounded-xl flex items-center justify-between group hover:bg-white/[0.04] transition-all"
                        >
                            <div className="flex items-center gap-6">
                                <div className={`w-12 text-[10px] font-black py-1 rounded text-center uppercase tracking-tighter ${event.method === 'POST' ? 'bg-accentPurple/20 text-accentPurple' :
                                    event.method === 'GET' ? 'bg-accentBlue/20 text-accentBlue' : 'bg-white/10 text-white/60'
                                    }`}>
                                    {event.method}
                                </div>
                                <div>
                                    <div className="text-xs font-mono text-white/80">{event.path}</div>
                                    <div className="text-[9px] font-bold text-white/20 uppercase tracking-widest mt-1">
                                        {event.client_ip} • {event.timestamp}
                                    </div>
                                </div>
                            </div>

                            <div className="flex items-center gap-8">
                                <div className="text-right">
                                    <div className="text-[9px] font-bold text-white/20 uppercase tracking-[0.2em] mb-1">Lat.</div>
                                    <div className="text-xs font-mono text-white">{event.duration_ms}ms</div>
                                </div>
                                <div className={`w-10 h-10 rounded-lg flex items-center justify-center font-black text-xs border ${event.status_code < 300 ? 'bg-accentMint/10 border-accentMint/20 text-accentMint' :
                                    event.status_code === 404 ? 'bg-warning/10 border-warning/20 text-warning' :
                                        'bg-error/10 border-error/20 text-error'
                                    }`}>
                                    {event.status_code}
                                </div>
                            </div>
                        </motion.div>
                    ))}
                </AnimatePresence>
            </div>

            <div className="mt-8 pt-6 border-t border-white/5 flex gap-12">
                <div className="flex items-center gap-3">
                    <div className="w-2 h-2 rounded-full bg-accentBlue animate-pulse" />
                    <span className="text-[9px] font-black text-white/40 uppercase tracking-[0.2em]">Stream Connected: ADS-NODE-X77</span>
                </div>
                <div className="flex items-center gap-3">
                    <Activity className="w-3 h-3 text-white/20" />
                    <span className="text-[9px] font-black text-white/40 uppercase tracking-[0.2em]">Throughput: 1.2 GB/S</span>
                </div>
            </div>
        </div>
    );
}
