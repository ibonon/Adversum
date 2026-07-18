"use client";

import TelemetryMonitor from "../../components/TelemetryMonitor";
import { ChevronLeft } from "lucide-react";
import Link from "next/link";

export default function TelemetryPage() {
    return (
        <div className="min-h-screen bg-black text-white p-20 flex flex-col gap-12">
            <div className="flex items-center justify-between">
                <Link
                    href="/"
                    className="flex items-center gap-2 text-[10px] font-black uppercase tracking-[0.4em] text-white/40 hover:text-white transition-colors group"
                >
                    <ChevronLeft className="w-4 h-4 group-hover:-translate-x-1 transition-transform" />
                    Return to Hub
                </Link>
                <div className="text-[10px] font-black uppercase tracking-[0.6em] text-white/10">
                    Secure Operation Center • Node.01
                </div>
            </div>

            <div className="flex-1 max-w-6xl mx-auto w-full">
                <TelemetryMonitor />
            </div>
        </div>
    );
}
