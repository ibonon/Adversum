"use client";

import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import { ValidatedFinding } from '../lib/api';

const COLORS = {
    CRITICAL: '#EF4444',
    HIGH: '#F59E0B',
    MEDIUM: '#8B5CF6',
    LOW: '#3B82F6',
};

interface SeverityData {
    name: string;
    value: number;
}

export default function SeverityChart({ findings }: { findings: ValidatedFinding[] }) {
    if (!findings || findings.length === 0) return null;

    const dataMap = findings.reduce((acc, curr) => {
        const sev = curr.raw.severity || 'LOW';
        acc[sev] = (acc[sev] || 0) + 1;
        return acc;
    }, {} as Record<string, number>);

    const data: SeverityData[] = Object.keys(dataMap).map(key => ({
        name: key,
        value: dataMap[key]
    }));

    return (
        <div className="h-64 w-full bento-card flex flex-col items-center justify-center">
            <h3 className="tech-label mb-4">Vulnerability Distribution</h3>
            <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                    <Pie
                        data={data}
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={70}
                        paddingAngle={4}
                        dataKey="value"
                        stroke="none"
                    >
                        {data.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[entry.name as keyof typeof COLORS] || '#8884d8'} />
                        ))}
                    </Pie>
                    <Tooltip
                        contentStyle={{ backgroundColor: '#111', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px', fontSize: '10px', color: '#fff' }}
                        itemStyle={{ color: '#fff' }}
                        formatter={(value: number) => [`${value} Findings`, 'Count']}
                    />
                    <Legend iconSize={8} wrapperStyle={{ fontSize: '10px', color: '#A1A1AA', textTransform: 'uppercase', letterSpacing: '0.05em' }} />
                </PieChart>
            </ResponsiveContainer>
        </div>
    );
}
