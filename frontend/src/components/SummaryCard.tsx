"use client";

export default function SummaryCard({ summary }: { summary: string | undefined }) {
    if (!summary) return null;

    return (
        <div className="bento-card bg-accentPurple/5 border-accentPurple/20 animate-in fade-in duration-700">
            <div className="flex items-center gap-4 mb-8">
                <div className="w-10 h-10 rounded-lg bg-accentPurple/10 flex items-center justify-center border border-accentPurple/30">
                    <span className="text-xl">🧠</span>
                </div>
                <div>
                    <h3 className="text-xl font-bold text-white tracking-tight">Executive Intelligence</h3>
                    <div className="tech-label">AI Reasoning Core</div>
                </div>
            </div>

            <div className="space-y-4">
                {summary.split('\n').map((line, i) => (
                    <div key={i} className={
                        line.startsWith('#')
                            ? "text-lg font-black text-white mt-8 mb-4 tracking-tight uppercase"
                            : line.startsWith('-')
                                ? "flex gap-3 text-sm text-primaryMuted py-1"
                                : "text-sm text-primaryMuted leading-relaxed"
                    }>
                        {line.startsWith('-') && <span className="text-accentPurple font-black">→</span>}
                        {line.replace(/^#+\s/, '').replace(/^-\s/, '')}
                    </div>
                ))}
            </div>
        </div>
    );
}
