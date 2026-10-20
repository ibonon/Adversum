import { useState, useEffect, useCallback, useRef } from "react";

const API_KEY = import.meta.env.VITE_API_KEY || "adv-dev-key-123";
const BASE_URL = import.meta.env.VITE_API_URL || "";

interface MetricsSnapshot {
  requestsTotal: number;
  errorsTotal: number;
  scansTotal: number;
  avgDurationMs: number;
  cacheHitRate: number;
  queueSize: number;
  activeJobs: number;
  lastUpdated: Date;
}

interface UseMetricsReturn {
  metrics: MetricsSnapshot | null;
  loading: boolean;
  error: string | null;
  refresh: () => void;
}

function parsePrometheusText(text: string): Record<string, number> {
  const result: Record<string, number> = {};
  const lines = text.split("\n");
  for (const line of lines) {
    if (line.startsWith("#") || !line.trim()) continue;
    // Match: metric_name{labels} value OR metric_name value
    const match = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*?)(?:\{[^}]*\})?\s+([\d.e+]+)/);
    if (match) {
      const [, name, value] = match;
      const parsed = parseFloat(value);
      if (!isNaN(parsed)) {
        result[name] = (result[name] ?? 0) + parsed;
      }
    }
  }
  return result;
}

export function useMetrics(pollIntervalMs: number = 15_000): UseMetricsReturn {
  const [metrics, setMetrics] = useState<MetricsSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchMetrics = useCallback(async () => {
    try {
      // Fetch Prometheus metrics and cache stats in parallel
      const [metricsRes, cacheRes, queueRes] = await Promise.allSettled([
        fetch(`${BASE_URL}/metrics`),
        fetch(`${BASE_URL}/api/v1/cache/stats`, { headers: { "X-API-Key": API_KEY } }),
        fetch(`${BASE_URL}/api/v1/queue/stats`, { headers: { "X-API-Key": API_KEY } }),
      ]);

      let raw: Record<string, number> = {};
      let cacheHitRate = 0;
      let queueSize = 0;
      let activeJobs = 0;

      if (metricsRes.status === "fulfilled" && metricsRes.value.ok) {
        const text = await metricsRes.value.text();
        raw = parsePrometheusText(text);
      }

      if (cacheRes.status === "fulfilled" && cacheRes.value.ok) {
        const data = await cacheRes.value.json() as Record<string, number>;
        cacheHitRate = data.hit_rate ?? 0;
      }

      if (queueRes.status === "fulfilled" && queueRes.value.ok) {
        const data = await queueRes.value.json() as Record<string, number>;
        queueSize = data.queue_size ?? 0;
        activeJobs = data.active ?? 0;
      }

      const requestsTotal  = raw["adversum_http_requests_total"]   ?? 0;
      const errorsTotal    = raw["adversum_http_errors_total"]      ?? 0;
      const scansTotal     = raw["adversum_scans_total"]            ?? 0;
      const durationSum    = raw["adversum_http_duration_seconds_sum"] ?? 0;
      const durationCount  = raw["adversum_http_duration_seconds_count"] ?? 1;
      const avgDurationMs  = durationCount > 0 ? Math.round((durationSum / durationCount) * 1000) : 0;

      setMetrics({
        requestsTotal,
        errorsTotal,
        scansTotal,
        avgDurationMs,
        cacheHitRate,
        queueSize,
        activeJobs,
        lastUpdated: new Date(),
      });
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch metrics");
    } finally {
      setLoading(false);
    }
  }, []);

  // Expose manual refresh
  const refresh = useCallback(() => {
    setLoading(true);
    fetchMetrics();
  }, [fetchMetrics]);

  useEffect(() => {
    fetchMetrics();
    intervalRef.current = setInterval(fetchMetrics, pollIntervalMs);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [fetchMetrics, pollIntervalMs]);

  return { metrics, loading, error, refresh };
}
