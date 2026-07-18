"use client";

import { useState } from "react";
import { useAudits } from "@/lib/hooks";
import Link from "next/link";
import { FileText, CheckCircle, XCircle, Clock, ArrowRight, Download, Filter, ArrowUpDown, GitCompare } from "lucide-react";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { TableSkeleton } from "@/components/LoadingSkeleton";
import SearchBar from "@/components/SearchBar";
import DateRangePicker from "@/components/DateRangePicker";
import { isWithinInterval } from "date-fns";
import toast from "react-hot-toast";

type SortField = "id" | "status" | "robustness_score" | "created_at";
type SortDirection = "asc" | "desc";
type StatusFilter = "all" | "completed" | "running" | "failed" | "queued";

export default function AuditsHistory() {
    const { data: audits, isLoading, isError } = useAudits();
    const [sortField, setSortField] = useState<SortField>("created_at");
    const [sortDirection, setSortDirection] = useState<SortDirection>("desc");
    const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
    const [minRobustness, setMinRobustness] = useState<number>(0);
    const [selectedAudits, setSelectedAudits] = useState<string[]>([]);
    const [searchQuery, setSearchQuery] = useState("");
    const [dateRange, setDateRange] = useState<{ from: Date | undefined; to: Date | undefined }>({ from: undefined, to: undefined });

    if (isLoading) return <TableSkeleton rows={8} />;
    if (isError) return <div className="p-20 text-center text-error">Failed to load audits.</div>;

    // Filter and sort audits
    let filteredAudits = audits || [];

    if (statusFilter !== "all") {
        filteredAudits = filteredAudits.filter(job => job.status === statusFilter);
    }

    if (minRobustness > 0) {
        filteredAudits = filteredAudits.filter(job =>
            (job.robustness_score || 0) * 100 >= minRobustness
        );
    }

    // Search filtering
    if (searchQuery) {
        filteredAudits = filteredAudits.filter(job => {
            const query = searchQuery.toLowerCase();
            return (
                job.id.toLowerCase().includes(query) ||
                job.status.toLowerCase().includes(query) ||
                (job.created_at && new Date(job.created_at).toLocaleString().toLowerCase().includes(query))
            );
        });
    }

    // Date range filtering
    if (dateRange.from && dateRange.to) {
        filteredAudits = filteredAudits.filter(job => {
            if (!job.created_at) return false;
            const jobDate = new Date(job.created_at);
            return isWithinInterval(jobDate, { start: dateRange.from!, end: dateRange.to! });
        });
    }

    const sortedAudits = [...filteredAudits].sort((a, b) => {
        let aVal: any = a[sortField];
        let bVal: any = b[sortField];

        if (sortField === "created_at") {
            aVal = new Date(aVal).getTime();
            bVal = new Date(bVal).getTime();
        }

        if (aVal === undefined) aVal = 0;
        if (bVal === undefined) bVal = 0;

        if (sortDirection === "asc") {
            return aVal > bVal ? 1 : -1;
        } else {
            return aVal < bVal ? 1 : -1;
        }
    });

    const handleSort = (field: SortField) => {
        if (sortField === field) {
            setSortDirection(sortDirection === "asc" ? "desc" : "asc");
        } else {
            setSortField(field);
            setSortDirection("desc");
        }
    };

    const toggleAuditSelection = (id: string) => {
        setSelectedAudits(prev => {
            if (prev.includes(id)) {
                return prev.filter(x => x !== id);
            } else if (prev.length < 2) {
                return [...prev, id];
            } else {
                toast.error("You can only select 2 audits for comparison");
                return prev;
            }
        });
    };

    const exportData = () => {
        const jsonString = `data:text/json;charset=utf-8,${encodeURIComponent(
            JSON.stringify(sortedAudits, null, 2)
        )}`;
        const link = document.createElement("a");
        link.href = jsonString;
        link.download = `adversum_audits_${new Date().toISOString()}.json`;
        link.click();
        toast.success("Audit data exported successfully");
    };

    return (
        <ErrorBoundary widgetName="Audits History">
            <div className="space-y-8 animate-fade-in-up">
                <div className="flex justify-between items-center border-b border-white/10 pb-6">
                    <div>
                        <h1 className="text-3xl font-black italic tracking-tighter text-white mb-2">AUDIT HISTORY</h1>
                        <p className="text-primaryMuted text-sm uppercase tracking-widest font-bold">
                            Archive Access // {sortedAudits.length} of {audits?.length || 0} Records
                        </p>
                    </div>
                    <div className="flex gap-3">
                        {selectedAudits.length === 2 && (
                            <Link
                                href={`/audits/compare?id1=${selectedAudits[0]}&id2=${selectedAudits[1]}`}
                                className="flex items-center gap-2 bg-accentPurple/20 hover:bg-accentPurple/30 text-accentPurple px-6 py-3 rounded-lg border border-accentPurple/30 transition-all font-bold text-xs uppercase tracking-wider"
                            >
                                <GitCompare className="w-4 h-4" />
                                Compare Selected
                            </Link>
                        )}
                        <button
                            onClick={exportData}
                            className="flex items-center gap-2 bg-surface hover:bg-surfaceHighlight text-white px-6 py-3 rounded-lg border border-white/10 transition-all font-bold text-xs uppercase tracking-wider"
                        >
                            <Download className="w-4 h-4" />
                            Export JSON
                        </button>
                    </div>
                </div>

                {/* Filters */}
                <div className="bg-surface/30 border border-white/5 rounded-2xl p-6 backdrop-blur-sm">
                    <div className="flex items-center gap-2 mb-4">
                        <Filter className="w-4 h-4 text-white/40" />
                        <h3 className="text-sm font-bold text-white/60 uppercase tracking-wider">Filters</h3>
                    </div>
                    <div className="flex gap-4 flex-wrap">
                        <div className="flex-1 min-w-[200px]">
                            <label className="block text-xs font-bold text-white/40 uppercase tracking-widest mb-2">
                                Status
                            </label>
                            <select
                                value={statusFilter}
                                onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}
                                className="w-full bg-black/50 border border-white/10 rounded-lg px-4 py-2 text-white text-sm focus:border-accentBlue focus:outline-none transition-colors"
                            >
                                <option value="all">All Statuses</option>
                                <option value="completed">Completed</option>
                                <option value="running">Running</option>
                                <option value="failed">Failed</option>
                                <option value="queued">Queued</option>
                            </select>
                        </div>
                        <div className="flex-1 min-w-[200px]">
                            <label className="block text-xs font-bold text-white/40 uppercase tracking-widest mb-2">
                                Min Robustness (%)
                            </label>
                            <input
                                type="number"
                                min="0"
                                max="100"
                                value={minRobustness}
                                onChange={(e) => setMinRobustness(Number(e.target.value))}
                                className="w-full bg-black/50 border border-white/10 rounded-lg px-4 py-2 text-white text-sm focus:border-accentBlue focus:outline-none transition-colors"
                                placeholder="0"
                            />
                        </div>
                        {(statusFilter !== "all" || minRobustness > 0) && (
                            <button
                                onClick={() => {
                                    setStatusFilter("all");
                                    setMinRobustness(0);
                                }}
                                className="self-end px-4 py-2 text-xs font-bold text-white/40 hover:text-white transition-colors"
                            >
                                Clear Filters
                            </button>
                        )}
                    </div>
                </div>

                <div className="bg-surface/30 border border-white/5 rounded-2xl overflow-hidden backdrop-blur-sm">
                    <table className="w-full text-left">
                        <thead>
                            <tr className="bg-white/5 text-[10px] font-bold text-white/40 uppercase tracking-[0.2em]">
                                <th className="p-6 w-12"></th>
                                <th className="p-6 cursor-pointer hover:text-white transition-colors" onClick={() => handleSort("id")}>
                                    <div className="flex items-center gap-2">
                                        ID
                                        <ArrowUpDown className="w-3 h-3" />
                                    </div>
                                </th>
                                <th className="p-6 cursor-pointer hover:text-white transition-colors" onClick={() => handleSort("status")}>
                                    <div className="flex items-center gap-2">
                                        Status
                                        <ArrowUpDown className="w-3 h-3" />
                                    </div>
                                </th>
                                <th className="p-6 cursor-pointer hover:text-white transition-colors" onClick={() => handleSort("robustness_score")}>
                                    <div className="flex items-center gap-2">
                                        Robustness
                                        <ArrowUpDown className="w-3 h-3" />
                                    </div>
                                </th>
                                <th className="p-6 cursor-pointer hover:text-white transition-colors" onClick={() => handleSort("created_at")}>
                                    <div className="flex items-center gap-2">
                                        Timestamp
                                        <ArrowUpDown className="w-3 h-3" />
                                    </div>
                                </th>
                                <th className="p-6 text-right">Action</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-white/5">
                            {sortedAudits.map((job) => (
                                <tr key={job.id} className="hover:bg-white/[0.02] transition-colors group">
                                    <td className="p-6">
                                        <input
                                            type="checkbox"
                                            checked={selectedAudits.includes(job.id)}
                                            onChange={() => toggleAuditSelection(job.id)}
                                            className="w-4 h-4 rounded border-white/20 bg-black/50 checked:bg-accentBlue"
                                        />
                                    </td>
                                    <td className="p-6 font-mono text-sm text-white/60">
                                        <span className="text-accentBlue">#</span>{job.id}
                                    </td>
                                    <td className="p-6">
                                        <StatusBadge status={job.status} />
                                    </td>
                                    <td className="p-6">
                                        <div className="flex items-center gap-2">
                                            <div className="w-24 h-1.5 bg-white/10 rounded-full overflow-hidden">
                                                <div
                                                    className="h-full bg-accentMint"
                                                    style={{ width: `${(job.robustness_score || 0) * 100}%` }}
                                                />
                                            </div>
                                            <span className="text-xs font-bold text-white">{((job.robustness_score || 0) * 100).toFixed(0)}%</span>
                                        </div>
                                    </td>
                                    <td className="p-6 text-sm text-primaryMuted font-mono">
                                        <div className="flex items-center gap-2">
                                            <Clock className="w-3 h-3" />
                                            {job.created_at ? new Date(job.created_at).toLocaleString() : "N/A"}
                                        </div>
                                    </td>
                                    <td className="p-6 text-right">
                                        <Link
                                            href={`/audits/${job.id}`}
                                            className="inline-flex items-center gap-2 text-xs font-bold text-accentBlue hover:text-white transition-colors uppercase tracking-wider pr-2"
                                        >
                                            View Report <ArrowRight className="w-3 h-3 group-hover:translate-x-1 transition-transform" />
                                        </Link>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>

                    {sortedAudits.length === 0 && (
                        <div className="p-20 text-center text-primaryMuted">
                            <FileText className="w-12 h-12 mx-auto mb-4 opacity-20" />
                            <p>No audit records match your filters.</p>
                        </div>
                    )}
                </div>
            </div>
        </ErrorBoundary>
    );
}

function StatusBadge({ status }: { status: string }) {
    const styles = {
        completed: "bg-accentMint/10 text-accentMint border-accentMint/20",
        running: "bg-accentBlue/10 text-accentBlue border-accentBlue/20 animate-pulse",
        failed: "bg-error/10 text-error border-error/20",
        queued: "bg-white/5 text-white/60 border-white/10"
    };

    const icons = {
        completed: <CheckCircle className="w-3 h-3" />,
        running: <Clock className="w-3 h-3" />,
        failed: <XCircle className="w-3 h-3" />,
        queued: <Clock className="w-3 h-3" />
    };

    const key = status.toLowerCase() as keyof typeof styles;

    return (
        <span className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-widest border ${styles[key] || styles.queued}`}>
            {icons[key]}
            {status}
        </span>
    );
}
