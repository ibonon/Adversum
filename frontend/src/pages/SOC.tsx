import { useState, useEffect, useRef, useCallback } from "react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import {
  Shield,
  Activity,
  Zap,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Radio,
  TrendingUp,
  Globe,
  Lock,
  FileText,
  BarChart3,
} from "lucide-react";

// ── Types ────────────────────────────────────────────────────────────────────

interface ThreatEvent {
  event_id:    string;
  event_type:  string;
  severity:    "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  title:       string;
  description: string;
  source:      string;
  timestamp:   string;
  payload?:    Record<string, unknown>;
}

interface SOC2Control {
  control_id:       string;
  category:         string;
  status:           "PASS" | "FAIL" | "PARTIAL" | "NOT_EVALUATED";
  findings_count:   number;
  remediation?:     string;
}

interface ComplianceSummary {
  soc2_score:    number;
  iso_score:     number;
  soc2_status:   string;
  iso_status:    string;
  failing:       string[];
}

interface MEVPattern {
  attack_type:       string;
  risk_level:        string;
  value_at_risk_usd: number;
  chain:             string;
  signature:         string;
}

// ── Severity Styling ─────────────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "bg-red-950 border-red-500 text-red-300",
  HIGH:     "bg-orange-950 border-orange-500 text-orange-300",
  MEDIUM:   "bg-yellow-950 border-yellow-600 text-yellow-300",
  LOW:      "bg-blue-950 border-blue-500 text-blue-300",
  INFO:     "bg-slate-800 border-slate-500 text-slate-300",
};

const SEV_BADGE: Record<string, string> = {
  CRITICAL: "bg-red-600 text-white",
  HIGH:     "bg-orange-500 text-white",
  MEDIUM:   "bg-yellow-500 text-black",
  LOW:      "bg-blue-500 text-white",
  INFO:     "bg-slate-500 text-white",
};

const TYPE_ICON: Record<string, React.ReactNode> = {
  mev_attack_detected: <Zap className="w-3 h-3" />,
  exploit_confirmed:   <AlertTriangle className="w-3 h-3" />,
  finding_detected:    <Shield className="w-3 h-3" />,
  patch_generated:     <CheckCircle2 className="w-3 h-3" />,
  pr_opened:           <FileText className="w-3 h-3" />,
  compliance_report:   <BarChart3 className="w-3 h-3" />,
  threat_model_ready:  <Globe className="w-3 h-3" />,
  cve_correlation:     <AlertTriangle className="w-3 h-3" />,
};

// ── Compliance Score Gauge ────────────────────────────────────────────────────

function ScoreGauge({ score, label, status }: { score: number; label: string; status: string }) {
  const color =
    score >= 90 ? "text-green-400" :
    score >= 70 ? "text-yellow-400" : "text-red-400";

  const progressColor =
    score >= 90 ? "bg-green-500" :
    score >= 70 ? "bg-yellow-500" : "bg-red-500";

  return (
    <div className="flex flex-col gap-1">
      <div className="flex justify-between items-center">
        <span className="text-xs text-slate-400">{label}</span>
        <span className={`text-sm font-bold ${color}`}>{score.toFixed(0)}%</span>
      </div>
      <div className="w-full bg-slate-700 rounded-full h-2">
        <div
          className={`h-2 rounded-full transition-all duration-700 ${progressColor}`}
          style={{ width: `${score}%` }}
        />
      </div>
      <span className={`text-xs font-semibold ${color}`}>{status}</span>
    </div>
  );
}

// ── MEV Attack Card ───────────────────────────────────────────────────────────

function MEVCard({ pattern }: { pattern: MEVPattern }) {
  const riskColor =
    pattern.risk_level === "CRITICAL" ? "border-red-500 bg-red-950/40" :
    pattern.risk_level === "HIGH"     ? "border-orange-500 bg-orange-950/40" :
    "border-yellow-500 bg-yellow-950/40";

  return (
    <div className={`border rounded-lg p-3 text-xs ${riskColor}`}>
      <div className="flex items-center justify-between mb-1">
        <span className="font-bold text-white uppercase tracking-wide">
          {pattern.attack_type.replace(/_/g, " ")}
        </span>
        <Badge className={SEV_BADGE[pattern.risk_level] || "bg-slate-500"}>
          {pattern.risk_level}
        </Badge>
      </div>
      <div className="text-slate-300">
        Chain: <span className="text-cyan-400">{pattern.chain.toUpperCase()}</span>
        {" · "}
        Risk: <span className="text-red-300 font-semibold">
          ${pattern.value_at_risk_usd.toLocaleString(undefined, { maximumFractionDigits: 0 })}
        </span>
      </div>
      <div className="text-slate-500 mt-1 font-mono truncate">sig:{pattern.signature}</div>
    </div>
  );
}

// ── Main SOC Dashboard ────────────────────────────────────────────────────────

export default function SOCDashboard() {
  const [events, setEvents]           = useState<ThreatEvent[]>([]);
  const [mevPatterns, setMevPatterns] = useState<MEVPattern[]>([]);
  const [wsStatus, setWsStatus]       = useState<"connecting" | "connected" | "disconnected">("disconnected");
  const [subscriberCount, setSubscriberCount] = useState(0);
  const [eventCount, setEventCount]   = useState(0);
  const [compliance, setCompliance]   = useState<ComplianceSummary>({
    soc2_score: 100, iso_score: 100,
    soc2_status: "COMPLIANT", iso_status: "COMPLIANT",
    failing: [],
  });
  const [filterSev, setFilterSev]     = useState<string | null>(null);
  const wsRef                         = useRef<WebSocket | null>(null);
  const feedRef                       = useRef<HTMLDivElement>(null);

  // ── WebSocket connection ───────────────────────────────────────────────────

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    setWsStatus("connecting");
    const ws = new WebSocket(`ws://${window.location.host}/ws/threat-stream`);
    wsRef.current = ws;

    ws.onopen = () => {
      setWsStatus("connected");
    };

    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data) as Record<string, unknown>;

      if (msg.type === "welcome") {
        setSubscriberCount(msg.subscriber_count as number);
        const hist = (msg.recent_events as ThreatEvent[]) || [];
        if (hist.length > 0) setEvents(hist.slice(0, 50));
        return;
      }

      if (msg.type === "heartbeat") {
        setSubscriberCount(msg.subscriber_count as number);
        return;
      }

      // It's a real ThreatEvent
      const ev = msg as unknown as ThreatEvent;
      setEvents(prev => [ev, ...prev].slice(0, 100));
      setEventCount(n => n + 1);

      // Extract MEV patterns
      if (ev.event_type === "mev_attack_detected" && ev.payload) {
        setMevPatterns(prev => {
          const p: MEVPattern = {
            attack_type:       ev.payload!.attack_type as string || "unknown",
            risk_level:        ev.severity,
            value_at_risk_usd: (ev.payload!.value_at_risk_usd as number) || 0,
            chain:             ev.payload!.chain as string || "ethereum",
            signature:         String(ev.payload!.tx_hash || "").slice(0, 16),
          };
          return [p, ...prev].slice(0, 10);
        });
      }

      // Update compliance
      if (ev.event_type === "compliance_report" && ev.payload) {
        const score = (ev.payload.soc2_score as number) || 100;
        setCompliance(prev => ({
          ...prev,
          soc2_score:  score,
          soc2_status: score >= 90 ? "COMPLIANT" : score >= 60 ? "PARTIAL" : "NON_COMPLIANT",
        }));
      }
    };

    ws.onclose = () => {
      setWsStatus("disconnected");
      // Auto-reconnect after 5s
      setTimeout(connect, 5000);
    };

    ws.onerror = () => {
      setWsStatus("disconnected");
      ws.close();
    };
  }, []);

  useEffect(() => {
    connect();
    return () => {
      wsRef.current?.close();
    };
  }, [connect]);

  // Auto-scroll feed
  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = 0;
    }
  }, [events]);

  // ── Demo data simulation ───────────────────────────────────────────────────

  const runMEVDemo = async () => {
    try {
      const resp = await fetch("/api/v1/intelligence/mev-analyze", {
        method:  "POST",
        headers: { "Content-Type": "application/json", "X-API-Key": "adv-dev-key-123" },
        body: JSON.stringify({
          transactions: [
            { tx_hash: "0x" + "a".repeat(64), from_address: "0x" + "dead".repeat(10), to_address: "0x" + "1234".repeat(10), value_wei: 50000000000000000000, gas_price: 200000000000, input_data: "0xd0e30db0" },
            { tx_hash: "0x" + "b".repeat(64), from_address: "0x" + "cafe".repeat(10), to_address: "0x" + "1234".repeat(10), value_wei: 10000000000000000000, gas_price: 50000000000,  input_data: "0xd0e30db0" },
            { tx_hash: "0x" + "c".repeat(64), from_address: "0x" + "dead".repeat(10), to_address: "0x" + "1234".repeat(10), value_wei: 49000000000000000000, gas_price: 30000000000,  input_data: "0xd0e30db0" },
          ],
          chain: "ethereum", pool_liquidity_eth: 1000.0, eth_price_usd: 2650.0,
        }),
      });
      if (resp.ok) {
        const data = await resp.json();
        if (data.patterns_found?.length > 0) {
          const newPatterns: MEVPattern[] = data.patterns_found.map((p: Record<string, unknown>) => ({
            attack_type: p.attack_type as string,
            risk_level:  p.risk_level as string,
            value_at_risk_usd: p.value_at_risk_usd as number,
            chain: p.chain as string,
            signature: p.signature as string,
          }));
          setMevPatterns(prev => [...newPatterns, ...prev].slice(0, 10));
        }
      }
    } catch (_) {}
  };

  const runComplianceDemo = async () => {
    try {
      const resp = await fetch("/api/v1/compliance/report", {
        method:  "POST",
        headers: { "Content-Type": "application/json", "X-API-Key": "adv-dev-key-123" },
        body: JSON.stringify({ findings: [], target: "DemoProtocol", frameworks: ["soc2", "iso27001"] }),
      });
      if (resp.ok) {
        const data = await resp.json();
        const soc2 = data.frameworks?.soc2;
        const iso  = data.frameworks?.iso27001;
        if (soc2 || iso) {
          setCompliance({
            soc2_score:  soc2?.compliance_score ?? 100,
            iso_score:   iso?.compliance_score  ?? 100,
            soc2_status: soc2?.overall_status   ?? "COMPLIANT",
            iso_status:  iso?.overall_status    ?? "COMPLIANT",
            failing:     [...(soc2?.failing_controls ?? []), ...(iso?.failing_controls ?? [])],
          });
        }
      }
    } catch (_) {}
  };

  // ── Filtered events ────────────────────────────────────────────────────────

  const filtered = filterSev
    ? events.filter(e => e.severity === filterSev)
    : events;

  const wsColor =
    wsStatus === "connected"    ? "text-green-400" :
    wsStatus === "connecting"   ? "text-yellow-400" : "text-red-400";

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-4 font-mono">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="w-7 h-7 text-cyan-400" />
            Adversum AI-ASOC
            <Badge className="bg-cyan-600 text-white text-xs ml-2">Phase 2</Badge>
          </h1>
          <p className="text-slate-400 text-sm">Autonomous Security Operations Center — Real-Time Intelligence</p>
        </div>
        <div className="flex items-center gap-3 text-xs">
          <div className={`flex items-center gap-1 ${wsColor}`}>
            <Radio className="w-3 h-3 animate-pulse" />
            {wsStatus.toUpperCase()}
          </div>
          <span className="text-slate-500">|</span>
          <span className="text-slate-400">{subscriberCount} subscribers</span>
          <span className="text-slate-500">|</span>
          <span className="text-cyan-400">{eventCount} events received</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

        {/* Column 1: Live Threat Feed */}
        <div className="lg:col-span-2 flex flex-col gap-4">

          {/* Controls */}
          <Card className="bg-slate-900 border-slate-700">
            <CardHeader className="pb-2 pt-3 px-4">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm text-slate-300 flex items-center gap-2">
                  <Activity className="w-4 h-4 text-cyan-400" />
                  Live Threat Stream
                </CardTitle>
                <div className="flex gap-2">
                  {["CRITICAL", "HIGH", "MEDIUM", null].map(s => (
                    <button
                      key={s ?? "all"}
                      onClick={() => setFilterSev(s)}
                      className={`text-xs px-2 py-1 rounded border transition-colors ${
                        filterSev === s
                          ? "border-cyan-500 bg-cyan-900/40 text-cyan-300"
                          : "border-slate-600 text-slate-400 hover:border-slate-500"
                      }`}
                    >
                      {s ?? "ALL"}
                    </button>
                  ))}
                </div>
              </div>
            </CardHeader>
            <CardContent className="px-4 pb-3">
              <div
                ref={feedRef}
                className="max-h-[420px] overflow-y-auto flex flex-col gap-2 pr-1"
              >
                {filtered.length === 0 ? (
                  <div className="text-slate-500 text-xs text-center py-8">
                    {wsStatus === "connected"
                      ? "Waiting for events... Run MEV Demo or trigger a scan."
                      : "Connecting to threat stream..."}
                  </div>
                ) : (
                  filtered.map(ev => (
                    <div
                      key={ev.event_id}
                      className={`border rounded-lg p-3 text-xs transition-all ${SEV_COLORS[ev.severity] || SEV_COLORS.INFO}`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center gap-2">
                          {TYPE_ICON[ev.event_type] || <Shield className="w-3 h-3" />}
                          <span className="font-bold">{ev.title}</span>
                        </div>
                        <Badge className={`text-xs ${SEV_BADGE[ev.severity]}`}>
                          {ev.severity}
                        </Badge>
                      </div>
                      <p className="text-slate-400 truncate">{ev.description}</p>
                      <div className="flex justify-between mt-1 text-slate-600">
                        <span>{ev.source}</span>
                        <span>{new Date(ev.timestamp).toLocaleTimeString()}</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>

          {/* MEV Intelligence Panel */}
          <Card className="bg-slate-900 border-slate-700">
            <CardHeader className="pb-2 pt-3 px-4">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm text-slate-300 flex items-center gap-2">
                  <Zap className="w-4 h-4 text-yellow-400" />
                  MEV Attack Intelligence
                </CardTitle>
                <Button
                  size="sm"
                  variant="outline"
                  className="text-xs border-yellow-600 text-yellow-400 hover:bg-yellow-950"
                  onClick={runMEVDemo}
                >
                  Run MEV Demo
                </Button>
              </div>
            </CardHeader>
            <CardContent className="px-4 pb-3">
              {mevPatterns.length === 0 ? (
                <div className="text-slate-500 text-xs text-center py-4">
                  No MEV patterns detected. Click "Run MEV Demo" to simulate.
                </div>
              ) : (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {mevPatterns.slice(0, 6).map((p, i) => (
                    <MEVCard key={i} pattern={p} />
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Column 2: Compliance + Stats */}
        <div className="flex flex-col gap-4">

          {/* Compliance Scores */}
          <Card className="bg-slate-900 border-slate-700">
            <CardHeader className="pb-2 pt-3 px-4">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm text-slate-300 flex items-center gap-2">
                  <Lock className="w-4 h-4 text-green-400" />
                  Compliance Dashboard
                </CardTitle>
                <Button
                  size="sm"
                  variant="outline"
                  className="text-xs border-green-700 text-green-400 hover:bg-green-950"
                  onClick={runComplianceDemo}
                >
                  Refresh
                </Button>
              </div>
            </CardHeader>
            <CardContent className="px-4 pb-4 flex flex-col gap-4">
              <ScoreGauge
                score={compliance.soc2_score}
                label="SOC2 Type II"
                status={compliance.soc2_status}
              />
              <ScoreGauge
                score={compliance.iso_score}
                label="ISO 27001:2022"
                status={compliance.iso_status}
              />
              {compliance.failing.length > 0 && (
                <div>
                  <p className="text-xs text-red-400 mb-1 font-semibold">Failing Controls:</p>
                  <div className="flex flex-wrap gap-1">
                    {compliance.failing.slice(0, 8).map(c => (
                      <Badge key={c} className="bg-red-900 text-red-300 text-xs">{c}</Badge>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Severity Breakdown */}
          <Card className="bg-slate-900 border-slate-700">
            <CardHeader className="pb-2 pt-3 px-4">
              <CardTitle className="text-sm text-slate-300 flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-purple-400" />
                Event Breakdown
              </CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-4 flex flex-col gap-2">
              {(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const).map(sev => {
                const count = events.filter(e => e.severity === sev).length;
                const pct   = events.length > 0 ? (count / events.length) * 100 : 0;
                return (
                  <div key={sev} className="flex items-center gap-2 text-xs">
                    <span className="w-16 text-slate-400">{sev}</span>
                    <div className="flex-1 bg-slate-800 rounded-full h-1.5">
                      <div
                        className={`h-1.5 rounded-full ${
                          sev === "CRITICAL" ? "bg-red-500" :
                          sev === "HIGH"     ? "bg-orange-500" :
                          sev === "MEDIUM"   ? "bg-yellow-500" :
                          sev === "LOW"      ? "bg-blue-500" : "bg-slate-500"
                        }`}
                        style={{ width: `${pct}%`, transition: "width 0.5s" }}
                      />
                    </div>
                    <span className="w-6 text-right text-slate-500">{count}</span>
                  </div>
                );
              })}
              {events.length === 0 && (
                <p className="text-slate-500 text-xs text-center py-2">No events yet</p>
              )}
            </CardContent>
          </Card>

          {/* Quick Actions */}
          <Card className="bg-slate-900 border-slate-700">
            <CardHeader className="pb-2 pt-3 px-4">
              <CardTitle className="text-sm text-slate-300 flex items-center gap-2">
                <Globe className="w-4 h-4 text-cyan-400" />
                Quick Actions
              </CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-4 flex flex-col gap-2">
              {[
                { label: "Live Fork Exploit Demo",     path: "/api/v1/exploit/live-fork",           color: "text-red-400 border-red-700" },
                { label: "Self-Healing PR",            path: "/api/v1/remediation/self-healing-pr", color: "text-green-400 border-green-700" },
                { label: "Threat Model",               path: "/api/v1/intelligence/threat-model",   color: "text-purple-400 border-purple-700" },
                { label: "SARIF Export",               path: "/api/v1/compliance/report",           color: "text-cyan-400 border-cyan-700" },
              ].map(action => (
                <a
                  key={action.path}
                  href={action.path}
                  target="_blank"
                  rel="noopener noreferrer"
                  className={`text-xs px-3 py-2 border rounded transition-colors hover:bg-slate-800 ${action.color}`}
                >
                  {action.label} →
                </a>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
