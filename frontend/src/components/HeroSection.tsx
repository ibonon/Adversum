import { useState, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { ArrowRight, Loader2, AlertCircle, CheckCircle2, RotateCcw, ShieldAlert, Cpu } from 'lucide-react';
import HolographicShield, { OrbState } from './HolographicShield';
import { apiFetch, ApiError } from '@/lib/api';

/**
 * LIMITATION TECHNIQUE VÉRIFIÉE (cf. KNOWN_LIMITATIONS.md §11) :
 * Le WebSocket /ws/threat-stream existe mais ne couvre pas encore les transitions
 * de statut de job d'audit : le polling GET /audit/{id} est la source de vérité
 * pour l'état affiché par l'orbe.
 */

interface FindingItem {
  id?: number;
  rule_id?: string;
  severity?: string;
  message?: string;
  file_path?: string;
  line?: number;
  z3_verdict?: string;
  validation_status?: string;
  raw?: {
    id?: string;
    rule_id?: string;
    message?: string;
    severity?: string;
    file_path?: string;
    line?: number;
    snippet?: string;
    proof_anchor?: string;
  };
}

const getFindingSeverity = (f: FindingItem): string => {
  return (f.severity || f.raw?.severity || '').toUpperCase();
};

const getFindingZ3 = (f: FindingItem): string => {
  return (f.z3_verdict || '').toUpperCase();
};

interface AuditJobDetail {
  id: number;
  status: string;
  summary?: string;
  error?: string;
  error_message?: string;
  robustness_score?: number;
  total_findings?: number;
  findings_count?: number;
  result?: FindingItem[];
  created_at?: string;
}

const HeroSection = () => {
  const [targetPath, setTargetPath] = useState('');
  const [orbState, setOrbState] = useState<OrbState>('idle');
  const [jobId, setJobId] = useState<number | null>(null);
  const [jobDetail, setJobDetail] = useState<AuditJobDetail | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [hasCriticalFindings, setHasCriticalFindings] = useState(false);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);

  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopTimers = () => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
  };

  const startPolling = (currentJobId: number) => {
    if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);

    pollIntervalRef.current = setInterval(async () => {
      try {
        const pollRes = await apiFetch(`/audit/${currentJobId}`);
        const data: AuditJobDetail = await pollRes.json();
        const normalizedStatus = (data.status || '').toUpperCase();

        if (normalizedStatus === 'COMPLETED') {
          stopTimers();
          sessionStorage.removeItem('adversum_active_job_id');
          sessionStorage.removeItem('adversum_active_target');
          sessionStorage.removeItem('adversum_scan_start_time');
          setJobDetail(data);

          const findings = data.result || [];
          const hasCrit = findings.some((f) => {
            const sev = getFindingSeverity(f);
            const z3 = getFindingZ3(f);
            return sev === 'CRITICAL' || sev === 'HIGH' || z3 === 'SAT';
          });
          setHasCriticalFindings(hasCrit);
          setOrbState('completed');
        } else if (normalizedStatus === 'FAILED') {
          stopTimers();
          sessionStorage.removeItem('adversum_active_job_id');
          sessionStorage.removeItem('adversum_active_target');
          sessionStorage.removeItem('adversum_scan_start_time');
          setJobDetail(data);
          setErrorMessage(data.error_message || data.error || data.summary || 'Audit job execution failed on server.');
          setOrbState('failed');
        }
      } catch (pollErr) {
        console.warn('[Adversum] Polling status attempt failed:', pollErr);
      }
    }, 2500);
  };

  // Restore in-flight audit from sessionStorage if user refreshed the page
  useEffect(() => {
    const savedJobId = sessionStorage.getItem('adversum_active_job_id');
    const savedTarget = sessionStorage.getItem('adversum_active_target');
    const savedStartTime = sessionStorage.getItem('adversum_scan_start_time');

    if (savedJobId) {
      const id = parseInt(savedJobId, 10);
      if (!isNaN(id)) {
        setJobId(id);
        if (savedTarget) setTargetPath(savedTarget);
        setOrbState('scanning');

        if (savedStartTime) {
          const start = parseInt(savedStartTime, 10);
          if (!isNaN(start)) {
            const elapsed = Math.max(0, Math.floor((Date.now() - start) / 1000));
            setElapsedSeconds(elapsed);
          }
        }

        timerRef.current = setInterval(() => {
          setElapsedSeconds((prev) => prev + 1);
        }, 1000);

        startPolling(id);
      }
    }

    return () => {
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, []);

  const handleLaunchAudit = async () => {
    const target = targetPath.trim();
    if (!target || orbState === 'scanning') return;

    stopTimers();
    setErrorMessage(null);
    setJobDetail(null);
    setJobId(null);
    setHasCriticalFindings(false);
    setElapsedSeconds(0);
    setOrbState('scanning');

    // Live elapsed timer for honest user feedback
    timerRef.current = setInterval(() => {
      setElapsedSeconds((prev) => prev + 1);
    }, 1000);

    try {
      // 1. Submit audit job to backend
      const res = await apiFetch('/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_path: target,
          project_name: 'adversum_core_audit',
        }),
      });

      const initialJob: { id: number; status: string; created_at: string } = await res.json();
      const currentJobId = initialJob.id;
      setJobId(currentJobId);

      // Persist in sessionStorage so page refreshes survive
      sessionStorage.setItem('adversum_active_job_id', String(currentJobId));
      sessionStorage.setItem('adversum_active_target', target);
      sessionStorage.setItem('adversum_scan_start_time', String(Date.now()));

      // 2. Poll GET /audit/{id} every 2.5s until COMPLETED or FAILED
      startPolling(currentJobId);
    } catch (err) {
      stopTimers();
      setOrbState('failed');
      if (err instanceof ApiError) {
        setErrorMessage(err.detail || err.message);
      } else if (err instanceof Error) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage('Failed to submit audit job to the backend.');
      }
    }
  };

  const handleReset = () => {
    stopTimers();
    sessionStorage.removeItem('adversum_active_job_id');
    sessionStorage.removeItem('adversum_active_target');
    sessionStorage.removeItem('adversum_scan_start_time');
    setOrbState('idle');
    setJobId(null);
    setJobDetail(null);
    setErrorMessage(null);
    setHasCriticalFindings(false);
    setElapsedSeconds(0);
  };

  const findingsList = jobDetail?.result || [];
  const totalFindings = jobDetail?.total_findings ?? findingsList.length;
  const criticalCount = findingsList.filter((f) => getFindingSeverity(f) === 'CRITICAL').length;
  const highCount = findingsList.filter((f) => getFindingSeverity(f) === 'HIGH').length;
  const satCount = findingsList.filter((f) => getFindingZ3(f) === 'SAT').length;
  const robustnessScore =
    typeof jobDetail?.robustness_score === 'number'
      ? Math.round(jobDetail.robustness_score * 100)
      : null;

  return (
    <section className="relative min-h-[90vh] w-full flex flex-col items-center justify-start sm:justify-center px-4 pt-12 pb-24 overflow-x-hidden">
      {/* Subtle radial ambient glow behind the central orb */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-primary/10 rounded-full blur-[120px] pointer-events-none" />

      <div className="container max-w-4xl mx-auto flex flex-col items-center text-center relative z-10">
        
        {/* ── Central 3D Orb ────────────────────────────────────────── */}
        <div className="relative aspect-square w-72 h-72 sm:w-80 sm:h-80 md:w-96 md:h-96 mx-auto mb-4">
          <HolographicShield state={orbState} hasCriticalFindings={hasCriticalFindings} />
        </div>

        {/* ── Adversum Core Labels & Live Backend State ──────────────── */}
        <div className="mb-8">
          <div className="text-xs font-mono uppercase tracking-[0.3em] text-primary/90 mb-1.5 flex items-center justify-center gap-2">
            <span>Adversum Core</span>
            <span className="text-[10px] text-muted-foreground/60">•</span>
            <span className="text-[10px] text-muted-foreground font-mono">v5.0</span>
          </div>

          <div className="text-[11px] font-mono text-muted-foreground">
            Rust AST · NVIDIA Nemotron · Z3 SMT Formal Verification
          </div>

          {/* Real Status Badge */}
          <div className="mt-3 inline-flex items-center gap-2 px-3.5 py-1 rounded-full text-xs font-mono border backdrop-blur-sm transition-all duration-300">
            {orbState === 'idle' && (
              <>
                <span className="w-2 h-2 rounded-full bg-primary/80" />
                <span className="text-muted-foreground">Standby : Ready for audit</span>
              </>
            )}
            {orbState === 'scanning' && (
              <>
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                <span className="text-cyan-400 font-medium">
                  Scanning job #{jobId || '...'} ({elapsedSeconds}s) : Polling /audit/{jobId || '...'}
                </span>
              </>
            )}
            {orbState === 'completed' && (
              <>
                <span className={`w-2 h-2 rounded-full ${hasCriticalFindings ? 'bg-amber-400' : 'bg-emerald-400'}`} />
                <span className={hasCriticalFindings ? 'text-amber-400' : 'text-emerald-400'}>
                  Audit complete : {totalFindings} findings ({satCount} Z3 SAT proofs)
                </span>
              </>
            )}
            {orbState === 'failed' && (
              <>
                <span className="w-2 h-2 rounded-full bg-destructive animate-pulse" />
                <span className="text-destructive font-medium">Audit failed</span>
              </>
            )}
          </div>
        </div>

        {/* ── Single Unified Input Bar ──────────────────────────────── */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleLaunchAudit();
          }}
          className="w-full max-w-xl mx-auto mb-8"
        >
          <div className="flex flex-col sm:flex-row items-stretch gap-2 p-1.5 rounded-2xl bg-card/70 border border-border/60 shadow-2xl backdrop-blur-md focus-within:border-primary/80 transition-all">
            <label htmlFor="target-path-input" className="sr-only">
              Target repository or local path
            </label>
            <input
              id="target-path-input"
              type="text"
              value={targetPath}
              onChange={(e) => setTargetPath(e.target.value)}
              placeholder="github.com/user/repo ou chemin local"
              disabled={orbState === 'scanning'}
              className="flex-1 bg-transparent px-4 py-3 text-sm md:text-base font-mono text-foreground placeholder:text-muted-foreground/60 focus:outline-none disabled:opacity-50"
            />
            <Button
              type="submit"
              disabled={!targetPath.trim() || orbState === 'scanning'}
              className="rounded-xl px-7 py-3 font-medium bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer transition-all shrink-0 flex items-center justify-center gap-2 h-auto"
            >
              {orbState === 'scanning' ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <span>Launch Audit</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </Button>
          </div>
        </form>

        {/* ── Real Feedback & Results Card ──────────────────────────── */}
        {orbState === 'completed' && jobDetail && (
          <div className="w-full max-w-xl mx-auto p-5 rounded-2xl bg-card/80 border border-border/60 shadow-xl backdrop-blur-md text-left transition-all animate-in fade-in duration-300">
            <div className="flex items-center justify-between pb-3 mb-4 border-b border-border/40">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                <span className="font-semibold text-sm">Audit Report · Job #{jobDetail.id}</span>
              </div>
              {robustnessScore !== null && (
                <div className="text-xs font-mono text-muted-foreground">
                  Robustness: <span className="font-bold text-foreground">{robustnessScore}%</span>
                </div>
              )}
            </div>

            <div className="grid grid-cols-4 gap-2 mb-4 text-center">
              <div className="p-2.5 rounded-lg bg-background/50 border border-border/30">
                <div className="text-xl font-bold font-mono text-foreground">{totalFindings}</div>
                <div className="text-[10px] uppercase text-muted-foreground">Total</div>
              </div>
              <div className="p-2.5 rounded-lg bg-background/50 border border-border/30">
                <div className={`text-xl font-bold font-mono ${criticalCount > 0 ? 'text-destructive' : 'text-muted-foreground'}`}>
                  {criticalCount}
                </div>
                <div className="text-[10px] uppercase text-muted-foreground">Critical</div>
              </div>
              <div className="p-2.5 rounded-lg bg-background/50 border border-border/30">
                <div className={`text-xl font-bold font-mono ${highCount > 0 ? 'text-amber-400' : 'text-muted-foreground'}`}>
                  {highCount}
                </div>
                <div className="text-[10px] uppercase text-muted-foreground">High</div>
              </div>
              <div className="p-2.5 rounded-lg bg-background/50 border border-border/30">
                <div className={`text-xl font-bold font-mono ${satCount > 0 ? 'text-cyan-400' : 'text-muted-foreground'}`}>
                  {satCount}
                </div>
                <div className="text-[10px] uppercase text-muted-foreground">Z3 SAT</div>
              </div>
            </div>

            {jobDetail.summary && (
              <p className="text-xs text-muted-foreground font-mono leading-relaxed mb-4 bg-background/40 p-3 rounded-lg border border-border/30">
                {jobDetail.summary}
              </p>
            )}

            <div className="flex items-center justify-end pt-1">
              <Button
                variant="outline"
                size="sm"
                onClick={handleReset}
                className="rounded-lg text-xs gap-1.5 cursor-pointer"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>New Audit</span>
              </Button>
            </div>
          </div>
        )}

        {/* ── Error Message Card ────────────────────────────────────── */}
        {orbState === 'failed' && errorMessage && (
          <div className="w-full max-w-xl mx-auto p-4 rounded-xl bg-destructive/10 border border-destructive/30 text-left transition-all animate-in fade-in duration-300">
            <div className="flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-destructive shrink-0 mt-0.5" />
              <div className="flex-1">
                <div className="text-sm font-semibold text-destructive mb-1">Audit Failed</div>
                <div className="text-xs font-mono text-destructive/90 break-words">{errorMessage}</div>
              </div>
            </div>
            <div className="mt-3 flex justify-end">
              <Button
                variant="outline"
                size="sm"
                onClick={handleReset}
                className="text-xs border-destructive/30 hover:bg-destructive/20 text-destructive cursor-pointer"
              >
                Reset
              </Button>
            </div>
          </div>
        )}

      </div>
    </section>
  );
};

export default HeroSection;
