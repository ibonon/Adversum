"use client";

import { motion } from "framer-motion";

interface DiffPreviewProps {
    oldCode: string;
    newCode: string;
}

export default function DiffPreview({ oldCode, newCode }: DiffPreviewProps) {
    const oldLines = oldCode.split('\n');
    const newLines = newCode.split('\n');

    return (
        <div className="mt-6 rounded-xl border border-white/5 overflow-hidden bg-black/60 font-mono text-xs">
            <div className="grid grid-cols-2 border-b border-white/5 bg-white/5 text-[9px] font-bold uppercase tracking-[0.2em] text-white/40">
                <div className="p-3 border-r border-white/5">Original Code</div>
                <div className="p-3">Proposed Remediation</div>
            </div>

            <div className="grid grid-cols-2 min-h-[100px]">
                {/* Old Code Panel */}
                <div className="p-4 border-r border-white/5 bg-error/5 overflow-auto max-h-[400px]">
                    {oldLines.map((line, i) => (
                        <div key={i} className="flex gap-4">
                            <span className="w-8 text-right text-white/20 select-none">{i + 1}</span>
                            <span className="text-error/80">{line || ' '}</span>
                        </div>
                    ))}
                </div>

                {/* New Code Panel */}
                <div className="p-4 bg-accentMint/5 overflow-auto max-h-[400px]">
                    {newLines.map((line, i) => (
                        <div key={i} className="flex gap-4">
                            <span className="w-8 text-right text-white/20 select-none">{i + 1}</span>
                            <span className="text-accentMint">{line || ' '}</span>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
