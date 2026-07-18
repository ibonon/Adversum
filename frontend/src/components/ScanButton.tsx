"use client";

import { useState } from "react";
import { submitAudit } from "../lib/api";

export default function ScanButton({ onScanStart, onScanComplete }: { onScanStart: (id: string) => void, onScanComplete: (error: string | null) => void }) {
    const [loading, setLoading] = useState(false);
    const [targetPath, setTargetPath] = useState("f:\\Adversum\\adversum"); // Default for demo

    const handleScan = async () => {
        setLoading(true);
        try {
            const job = await submitAudit(targetPath);
            onScanStart(job.id);
        } catch (e) {
            onScanComplete(String(e));
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="flex gap-4 items-center mb-8 relative z-10">
            <div className="relative flex-grow max-w-2xl">
                <input
                    type="text"
                    value={targetPath}
                    onChange={(e) => setTargetPath(e.target.value)}
                    className="w-full px-4 py-3 rounded-lg bg-surface border border-slate-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent transition-all shadow-sm"
                    placeholder="Enter absolute path to project..."
                />
            </div>
            <button
                onClick={handleScan}
                disabled={loading}
                className="px-8 py-3 bg-primary hover:bg-primaryHover text-white font-semibold rounded-lg transition-all transform hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50 disabled:hover:scale-100 flex items-center gap-2 shadow-lg shadow-primary/20"
            >
                {loading ? (
                    <>
                        <span className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
                        <span className="tracking-wide">Scanning...</span>
                    </>
                ) : (
                    <span className="tracking-wide">Start Audit</span>
                )}
            </button>
        </div>
    );
}
