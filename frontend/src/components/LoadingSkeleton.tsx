"use client";

export function CardSkeleton() {
    return (
        <div className="bg-surface/30 border border-white/5 rounded-2xl p-8 backdrop-blur-sm animate-pulse">
            <div className="h-4 bg-white/5 rounded w-1/3 mb-4"></div>
            <div className="h-8 bg-white/10 rounded w-2/3 mb-2"></div>
            <div className="h-3 bg-white/5 rounded w-1/2"></div>
        </div>
    );
}

export function TableSkeleton({ rows = 5 }: { rows?: number }) {
    return (
        <div className="bg-surface/30 border border-white/5 rounded-2xl overflow-hidden backdrop-blur-sm">
            <div className="animate-pulse">
                {/* Header */}
                <div className="bg-white/5 p-6 flex gap-4">
                    <div className="h-3 bg-white/10 rounded w-20"></div>
                    <div className="h-3 bg-white/10 rounded w-24"></div>
                    <div className="h-3 bg-white/10 rounded w-32"></div>
                    <div className="h-3 bg-white/10 rounded flex-1"></div>
                </div>
                {/* Rows */}
                {Array.from({ length: rows }).map((_, i) => (
                    <div key={i} className="border-t border-white/5 p-6 flex gap-4">
                        <div className="h-4 bg-white/5 rounded w-20"></div>
                        <div className="h-4 bg-white/5 rounded w-24"></div>
                        <div className="h-4 bg-white/5 rounded w-32"></div>
                        <div className="h-4 bg-white/5 rounded flex-1"></div>
                    </div>
                ))}
            </div>
        </div>
    );
}

export function ChartSkeleton() {
    return (
        <div className="bg-surface/30 border border-white/5 rounded-2xl p-8 backdrop-blur-sm">
            <div className="animate-pulse">
                <div className="h-4 bg-white/5 rounded w-1/4 mb-6"></div>
                <div className="h-64 bg-white/5 rounded"></div>
            </div>
        </div>
    );
}

export function StatSkeleton() {
    return (
        <div className="bg-surface/30 border border-white/5 rounded-2xl p-6 backdrop-blur-sm animate-pulse">
            <div className="h-3 bg-white/5 rounded w-1/2 mb-3"></div>
            <div className="h-12 bg-white/10 rounded w-3/4"></div>
        </div>
    );
}
