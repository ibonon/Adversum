import { useState, useEffect } from "react";
import { useMetrics } from "@/hooks/useMetrics";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Activity,
  BarChart3,
  Cpu,
  Database,
  RefreshCw,
  Shield,
  TrendingUp,
  Zap,
  AlertCircle,
  CheckCircle2,
} from "lucide-react";

// ── Sparkline mini-chart (pure CSS + SVG, no lib) ────────────────────────────

function Sparkline({ values, color = "#22d3ee", height = 32 }: { values: number[]; color?: string; height?: number }) {
  if (values.length < 2) return <div style={{ height }} className="flex items-center justify-center text-slate-600 text-xs">No data</div>;
  const max = Math.max(...values, 1);
  const w = 120;
  const pts = values.map((v, i) => {
    const x = (i / (values.length - 1)) * w;
    const y = height - (v / max) * (height - 4);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  return (
    <svg width={w} height={height} className="overflow-visible">
      <polyline
        points={pts.join(" ")}
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
      <circle
        cx={parseFloat(pts[pts.length - 1].split(",")[0])}
        cy={parseFloat(pts[pts.length - 1].split(",")[1])}
        r="2.5"
        fill={color}
      />
    </svg>
  );
}

// ── Metric Tile ───────────────────────────────────────────────────────────────

function MetricTile({
  label, value, unit = "", icon: Icon, color = "text-cyan-400", trend, status,
}: {
  label: string;
  value: number | string;
  unit?: string;
  icon: React.ComponentType<{ className?: string }>;
  color?: string;
  trend?: number[];
  status?: "ok" | "warn" | "error";
}) {
  const statusColor = status === "ok" ? "border-green-800" : status === "warn" ? "border-yellow-700" : status === "error" ? "border-red-800" : "border-slate-700";
  return (
    <Card className={`bg-slate-900 border ${statusColor} hover:border-slate-600 transition-colors`}>
      <CardContent className="p-4">
        <div className="flex items-start justify-between mb-2">
          <div className="flex items-center gap-2">
            <Icon className={`w-4 h-4 ${color}`} />
            <span className="text-xs text-slate-400 uppercase tracking-wide">{label}</span>
          </div>
          {status === "ok" && <CheckCircle2 className="w-3 h-3 text-green-500" />}
          {status === "warn" && <AlertCircle className="w-3 h-3 text-yellow-500" />}
          {status === "error" && <AlertCircle className="w-3 h-3 text-red-500" />}
        </div>
        <div className={`text-2xl font-bold font-mono ${color} mb-1`}>
          {typeof value === "number" ? value.toLocaleString() : value}
          {unit && <span className="text-sm text-slate-500 ml-1">{unit}</span>}
        </div>
        {trend && trend.length > 2 && (
          <Sparkline values={trend} color={color.includes("red") ? "#ef4444" : color.includes("yellow") ? "#eab308" : "#22d3ee"} />
        )}
      </CardContent>
    </Card>
  );
}

// ── Main Analytics Page ───────────────────────────────────────────────────────

export default function Analytics() {
  const { metrics, loading, error, refresh } = useMetrics(15_000);

  // Circular buffer: keep last 20 snapshots per metric
  const [history, setHistory] = useState<{
    requests: number[];
    errors: number[];
    avgMs: number[];
    scans: number[];
  }>({ requests: [], errors: [], avgMs: [], scans: [] });

  useEffect(() => {
    if (!metrics) return;
    setHistory(prev => ({
      requests: [...prev.requests, metrics.requestsTotal].slice(-20),
      errors:   [...prev.errors,   metrics.errorsTotal].slice(-20),
      avgMs:    [...prev.avgMs,    metrics.avgDurationMs].slice(-20),
      scans:    [...prev.scans,    metrics.scansTotal].slice(-20),
    }));
  }, [metrics]);

  const errorRate = metrics
    ? metrics.requestsTotal > 0
      ? ((metrics.errorsTotal / metrics.requestsTotal) * 100).toFixed(1)
      : "0.0"
    : "--";

  const cacheHitPct = metrics ? (metrics.cacheHitRate * 100).toFixed(0) : "--";

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <BarChart3 className="w-7 h-7 text-cyan-400" />
            Analytics & Observability
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Prometheus metrics · Cache performance · Job queue · Real-time
          </p>
        </div>
        <div className="flex items-center gap-3">
          {metrics?.lastUpdated && (
            <span className="text-xs text-slate-500">
              Updated {metrics.lastUpdated.toLocaleTimeString()}
            </span>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={refresh}
            disabled={loading}
            className="border-slate-700 text-slate-300 hover:text-white"
          >
            <RefreshCw className={`w-3.5 h-3.5 mr-2 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="bg-red-950 border border-red-700 rounded-lg p-3 mb-6 flex items-center gap-2 text-red-300 text-sm">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          {error} — Ensure the API is running with <code className="bg-red-900 px-1 rounded">NEBIUS_MOCK=1</code>
        </div>
      )}

      {/* KPI Tiles */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <MetricTile
          label="Total Requests"
          value={metrics?.requestsTotal ?? 0}
          icon={Activity}
          color="text-cyan-400"
          trend={history.requests}
          status="ok"
        />
        <MetricTile
          label="Error Rate"
          value={errorRate}
          unit="%"
          icon={AlertCircle}
          color={parseFloat(String(errorRate)) > 5 ? "text-red-400" : "text-green-400"}
          trend={history.errors}
          status={parseFloat(String(errorRate)) > 5 ? "error" : "ok"}
        />
        <MetricTile
          label="Avg Latency"
          value={metrics?.avgDurationMs ?? 0}
          unit="ms"
          icon={Zap}
          color={metrics && metrics.avgDurationMs > 500 ? "text-yellow-400" : "text-cyan-400"}
          trend={history.avgMs}
          status={metrics && metrics.avgDurationMs > 500 ? "warn" : "ok"}
        />
        <MetricTile
          label="Total Scans"
          value={metrics?.scansTotal ?? 0}
          icon={Shield}
          color="text-purple-400"
          trend={history.scans}
          status="ok"
        />
      </div>

      {/* Secondary Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        {/* Cache Performance */}
        <Card className="bg-slate-900 border-slate-700">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-slate-300 flex items-center gap-2">
              <Database className="w-4 h-4 text-blue-400" />
              Cache Performance
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between mb-3">
              <span className="text-3xl font-bold font-mono text-blue-400">{cacheHitPct}%</span>
              <Badge className={
                parseInt(cacheHitPct) >= 70 ? "bg-green-700" :
                parseInt(cacheHitPct) >= 40 ? "bg-yellow-700" : "bg-red-800"
              }>
                {parseInt(cacheHitPct) >= 70 ? "EXCELLENT" : parseInt(cacheHitPct) >= 40 ? "GOOD" : "COLD"}
              </Badge>
            </div>
            <div className="w-full bg-slate-800 rounded-full h-2">
              <div
                className="bg-blue-500 h-2 rounded-full transition-all duration-700"
                style={{ width: `${cacheHitPct}%` }}
              />
            </div>
            <p className="text-xs text-slate-500 mt-2">LRU cache · 30s TTL · 512 slots</p>
          </CardContent>
        </Card>

        {/* Job Queue */}
        <Card className="bg-slate-900 border-slate-700">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-slate-300 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-orange-400" />
              Job Queue
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <span className="text-xs text-slate-400">Queued</span>
                <span className="text-lg font-bold font-mono text-orange-400">{metrics?.queueSize ?? 0}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-xs text-slate-400">Active</span>
                <span className="text-lg font-bold font-mono text-green-400">{metrics?.activeJobs ?? 0}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-xs text-slate-400">Max Concurrent</span>
                <span className="text-sm font-mono text-slate-300">3</span>
              </div>
              <Badge className={metrics?.queueSize === 0 ? "bg-green-900 text-green-300" : "bg-orange-900 text-orange-300"}>
                {metrics?.queueSize === 0 ? "IDLE" : "PROCESSING"}
              </Badge>
            </div>
          </CardContent>
        </Card>

        {/* System Health */}
        <Card className="bg-slate-900 border-slate-700">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-slate-300 flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-green-400" />
              System Health
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {[
                { label: "API", status: error ? "error" : "ok" },
                { label: "Cache", status: "ok" },
                { label: "Job Queue", status: "ok" },
                { label: "Prometheus", status: metrics ? "ok" : "warn" },
              ].map(({ label, status }) => (
                <div key={label} className="flex items-center justify-between">
                  <span className="text-xs text-slate-400">{label}</span>
                  <div className="flex items-center gap-1.5">
                    <div className={`w-2 h-2 rounded-full ${
                      status === "ok" ? "bg-green-500 animate-pulse" :
                      status === "warn" ? "bg-yellow-500" : "bg-red-500"
                    }`} />
                    <span className={`text-xs font-semibold ${
                      status === "ok" ? "text-green-400" :
                      status === "warn" ? "text-yellow-400" : "text-red-400"
                    }`}>
                      {status.toUpperCase()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Footer */}
      <div className="text-center text-xs text-slate-600 mt-8">
        Adversum Analytics · Prometheus-compatible metrics · Auto-refresh every 15s
      </div>
    </div>
  );
}
