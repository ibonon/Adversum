"use client";

import FindingsTable from "@/components/FindingsTable";
import { ValidatedFinding } from "@/lib/api";
import { useState, useMemo } from "react";

export default function TestVirtualization() {
    const [count, setCount] = useState(10000);

    const mockFindings = useMemo(() => {
        const findings: ValidatedFinding[] = [];
        for (let i = 0; i < count; i++) {
            findings.push({
                id: i,
                raw: {
                    rule_id: `RULE-${i % 100}`,
                    description: `Description for finding ${i}. This is a long description to test multi-line layout in the table. Deterministic flow paths are being verified for this specific injection point.`,
                    severity: i % 4 === 0 ? "CRITICAL" : i % 3 === 0 ? "HIGH" : i % 2 === 0 ? "MEDIUM" : "LOW",
                    file_path: `src/core/module_${i % 10}.rs`,
                    snippet: `fn handle_request(req: Request) {\n    let data = req.body();\n    unsafe { process(data) };\n}`,
                    line_number: (i % 500) + 1,
                    proof: {
                        verified: true,
                        evidence: [`Evidence line 1 for ${i}`, `Evidence line 2 for ${i}`],
                        taint_source: "UserRequest"
                    }
                },
                validation_status: "CONFIRMED",
                ai_confidence: 0.8 + (Math.random() * 0.2),
                reasoning_notes: `Reasoning notes for finding ${i}. Detailed trace of the taint propagation through the call graph. Verified by RUST CORE ENGINE.`,
                is_fixed: false
            });
        }
        return findings;
    }, [count]);

    return (
        <div className="p-10 space-y-10">
            <div className="flex justify-between items-center">
                <h1 className="text-3xl font-bold">Virtualization Stress Test</h1>
                <div className="flex items-center gap-4">
                    <input
                        type="number"
                        value={count}
                        onChange={(e) => setCount(parseInt(e.target.value) || 0)}
                        className="bg-surface border border-surfaceBorder rounded px-3 py-1 text-white w-32"
                    />
                    <span className="tech-label">{count} Findings Generated</span>
                </div>
            </div>

            <div className="bg-surface/50 border border-surfaceBorder rounded-xl p-6">
                <FindingsTable findings={mockFindings} />
            </div>
        </div>
    );
}
