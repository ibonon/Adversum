"use client";

import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Area, AreaChart } from "recharts";
import { ErrorBoundary } from "./ErrorBoundary";
import { ChartSkeleton } from "./LoadingSkeleton";

interface ActivityData {
    date: string;
    count: number;
    avg_robustness: number;
}

interface ActivityChartProps {
    data: ActivityData[];
    isLoading?: boolean;
}

export default function ActivityChart({ data, isLoading }: ActivityChartProps) {
    if (isLoading) {
        return <ChartSkeleton />;
    }

    if (!data || data.length === 0) {
        return (
            <div className="bg-surface/30 border border-white/5 rounded-2xl p-8 backdrop-blur-sm">
                <h3 className="text-lg font-bold text-white mb-4">Activity Trend</h3>
                <div className="h-64 flex items-center justify-center text-primaryMuted">
                    No activity data available for the last 7 days
                </div>
            </div>
        );
    }

    // Format data for display
    const chartData = data.map(item => ({
        date: new Date(item.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
        audits: item.count,
        robustness: Math.round(item.avg_robustness * 100),
    }));

    return (
        <ErrorBoundary widgetName="Activity Chart">
            <div className="bg-surface/30 border border-white/5 rounded-2xl p-8 backdrop-blur-sm">
                <div className="flex items-center justify-between mb-6">
                    <div>
                        <h3 className="text-lg font-bold text-white mb-1">Activity Trend</h3>
                        <p className="text-xs text-primaryMuted uppercase tracking-wider font-bold">
                            Last 7 Days Performance
                        </p>
                    </div>
                    <div className="flex gap-6 text-xs">
                        <div className="flex items-center gap-2">
                            <div className="w-3 h-3 rounded-full bg-accentBlue"></div>
                            <span className="text-primaryMuted">Audits</span>
                        </div>
                        <div className="flex items-center gap-2">
                            <div className="w-3 h-3 rounded-full bg-accentMint"></div>
                            <span className="text-primaryMuted">Robustness %</span>
                        </div>
                    </div>
                </div>

                <ResponsiveContainer width="100%" height={300}>
                    <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                        <defs>
                            <linearGradient id="colorAudits" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.3} />
                                <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
                            </linearGradient>
                            <linearGradient id="colorRobustness" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                                <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                            </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                        <XAxis
                            dataKey="date"
                            stroke="rgba(255,255,255,0.3)"
                            style={{ fontSize: '10px', fontWeight: 'bold' }}
                        />
                        <YAxis
                            stroke="rgba(255,255,255,0.3)"
                            style={{ fontSize: '10px', fontWeight: 'bold' }}
                        />
                        <Tooltip
                            contentStyle={{
                                backgroundColor: 'rgba(15, 23, 42, 0.95)',
                                border: '1px solid rgba(255, 255, 255, 0.1)',
                                borderRadius: '8px',
                                backdropFilter: 'blur(10px)',
                            }}
                            labelStyle={{ color: '#fff', fontWeight: 'bold', fontSize: '11px' }}
                            itemStyle={{ fontSize: '10px' }}
                        />
                        <Area
                            type="monotone"
                            dataKey="audits"
                            stroke="#3B82F6"
                            strokeWidth={2}
                            fillOpacity={1}
                            fill="url(#colorAudits)"
                        />
                        <Area
                            type="monotone"
                            dataKey="robustness"
                            stroke="#10b981"
                            strokeWidth={2}
                            fillOpacity={1}
                            fill="url(#colorRobustness)"
                        />
                    </AreaChart>
                </ResponsiveContainer>
            </div>
        </ErrorBoundary>
    );
}
