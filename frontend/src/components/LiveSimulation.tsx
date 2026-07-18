import { useEffect, useRef, useState } from 'react';
import { AlertTriangle, ShieldCheck, Zap, Cpu } from 'lucide-react';
import HolographicShield from './HolographicShield';

type Line = { code: string; state: 'idle' | 'scanning' | 'vuln' | 'fixed'; type?: 'add' | 'remove' };

const scenarios = [
  {
    name: 'SQL Injection',
    vuln: [
      { code: 'app.get("/user/:id", (req, res) => {', state: 'idle' as const },
      { code: '  const id = req.params.id;', state: 'idle' as const },
      { code: '  const query =', state: 'idle' as const },
      { code: '    `SELECT * FROM users WHERE id = ${id}`;', state: 'vuln' as const },
      { code: '  db.execute(query, (err, result) => {', state: 'idle' as const },
      { code: '    res.json(result);', state: 'idle' as const },
      { code: '  });', state: 'idle' as const },
      { code: '});', state: 'idle' as const },
    ],
    fixed: [
      { code: 'app.get("/user/:id", (req, res) => {', state: 'idle' as const },
      { code: '  const id = req.params.id;', state: 'idle' as const },
      { code: '  const query =', state: 'idle' as const },
      { code: '    "SELECT * FROM users WHERE id = ?";', state: 'fixed' as const },
      { code: '  db.execute(query, [id], (err, result) => {', state: 'fixed' as const },
      { code: '    res.json(result);', state: 'idle' as const },
      { code: '  });', state: 'idle' as const },
      { code: '});', state: 'idle' as const },
    ],
    severity: 'Critique',
    cwe: 'CWE-89',
  },
  {
    name: 'XSS Vulnerability',
    vuln: [
      { code: 'function renderComment(comment) {', state: 'idle' as const },
      { code: '  const container =', state: 'idle' as const },
      { code: '    document.getElementById("comments");', state: 'idle' as const },
      { code: '  container.innerHTML =', state: 'idle' as const },
      { code: '    `<div>${comment.text}</div>`;', state: 'vuln' as const },
      { code: '}', state: 'idle' as const },
    ],
    fixed: [
      { code: 'function renderComment(comment) {', state: 'idle' as const },
      { code: '  const container =', state: 'idle' as const },
      { code: '    document.getElementById("comments");', state: 'idle' as const },
      { code: '  const div = document.createElement("div");', state: 'fixed' as const },
      { code: '  div.textContent = comment.text;', state: 'fixed' as const },
      { code: '  container.appendChild(div);', state: 'fixed' as const },
      { code: '}', state: 'idle' as const },
    ],
    severity: 'Élevée',
    cwe: 'CWE-79',
  },
  {
    name: 'Insecure Deserialization',
    vuln: [
      { code: 'function loadSession(token) {', state: 'idle' as const },
      { code: '  const decoded =', state: 'idle' as const },
      { code: '    Buffer.from(token, "base64").toString();', state: 'idle' as const },
      { code: '  return eval("(" + decoded + ")");', state: 'vuln' as const },
      { code: '}', state: 'idle' as const },
    ],
    fixed: [
      { code: 'function loadSession(token) {', state: 'idle' as const },
      { code: '  const decoded =', state: 'idle' as const },
      { code: '    Buffer.from(token, "base64").toString();', state: 'idle' as const },
      { code: '  return JSON.parse(decoded);', state: 'fixed' as const },
      { code: '}', state: 'idle' as const },
    ],
    severity: 'Critique',
    cwe: 'CWE-502',
  },
];

type Phase = 'typing' | 'scanning' | 'detected' | 'fixing' | 'fixed' | 'pause';

const LiveSimulation = () => {
  const [scenarioIdx, setScenarioIdx] = useState(0);
  const [displayedLines, setDisplayedLines] = useState<Line[]>([]);
  const [phase, setPhase] = useState<Phase>('typing');
  const [scanProgress, setScanProgress] = useState(0);
  const [pulse, setPulse] = useState(0);
  const [stats, setStats] = useState({ scanned: 12847, blocked: 3421, fixed: 3208 });
  const sectionRef = useRef<HTMLDivElement>(null);
  const [isInView, setIsInView] = useState(false);

  const scenario = scenarios[scenarioIdx];

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => setIsInView(entry.isIntersecting),
      { threshold: 0.2 }
    );
    if (sectionRef.current) observer.observe(sectionRef.current);
    return () => observer.disconnect();
  }, []);

  // Stats counter
  useEffect(() => {
    if (!isInView) return;
    const interval = setInterval(() => {
      setStats((s) => ({
        scanned: s.scanned + Math.floor(Math.random() * 5) + 1,
        blocked: s.blocked + (Math.random() > 0.6 ? 1 : 0),
        fixed: s.fixed + (Math.random() > 0.7 ? 1 : 0),
      }));
    }, 800);
    return () => clearInterval(interval);
  }, [isInView]);

  // Main animation loop
  useEffect(() => {
    if (!isInView) return;
    let timeoutId: ReturnType<typeof setTimeout>;

    if (phase === 'typing') {
      setDisplayedLines([]);
      let i = 0;
      const typeNext = () => {
        if (i < scenario.vuln.length) {
          setDisplayedLines((prev) => [...prev, scenario.vuln[i]]);
          i++;
          timeoutId = setTimeout(typeNext, 180);
        } else {
          timeoutId = setTimeout(() => setPhase('scanning'), 500);
        }
      };
      typeNext();
    } else if (phase === 'scanning') {
      setScanProgress(0);
      let p = 0;
      const scan = () => {
        p += 4;
        setScanProgress(p);
        if (p < 100) {
          timeoutId = setTimeout(scan, 30);
        } else {
          timeoutId = setTimeout(() => setPhase('detected'), 300);
        }
      };
      scan();
    } else if (phase === 'detected') {
      setPulse(1);
      timeoutId = setTimeout(() => {
        setPulse(0);
        setPhase('fixing');
      }, 1200);
    } else if (phase === 'fixing') {
      // Replace/extend lines one by one, using the fixed array as the source of truth
      let i = 0;
      const applyFix = () => {
        setDisplayedLines((prev) => {
          const next = [...scenario.fixed];
          // Keep only the first i+1 lines revealed; hide the rest until reached
          // But we want a progressive reveal: show fixed[0..i] and keep vuln[i+1..] beneath
          const merged: Line[] = [];
          const maxLen = Math.max(prev.length, scenario.fixed.length);
          for (let k = 0; k < maxLen; k++) {
            if (k <= i && scenario.fixed[k]) merged.push(scenario.fixed[k]);
            else if (prev[k]) merged.push(prev[k]);
            else if (scenario.fixed[k]) merged.push(scenario.fixed[k]);
          }
          return merged;
        });
        i++;
        if (i < scenario.fixed.length) {
          timeoutId = setTimeout(applyFix, 120);
        } else {
          setDisplayedLines(scenario.fixed);
          setStats((s) => ({ ...s, fixed: s.fixed + 1, blocked: s.blocked + 1 }));
          timeoutId = setTimeout(() => setPhase('fixed'), 400);
        }
      };
      applyFix();

    } else if (phase === 'fixed') {
      setPulse(0.5);
      timeoutId = setTimeout(() => {
        setPulse(0);
        setPhase('pause');
      }, 1500);
    } else if (phase === 'pause') {
      timeoutId = setTimeout(() => {
        setScenarioIdx((idx) => (idx + 1) % scenarios.length);
        setPhase('typing');
      }, 1200);
    }

    return () => clearTimeout(timeoutId);
  }, [phase, scenarioIdx, isInView, scenario]);

  const getPhaseLabel = () => {
    switch (phase) {
      case 'typing':
        return { text: 'Réception du code…', color: 'text-muted-foreground', icon: Cpu };
      case 'scanning':
        return { text: `Analyse en cours ${scanProgress}%`, color: 'text-primary', icon: Cpu };
      case 'detected':
        return { text: `${scenario.severity} · ${scenario.cwe} · ${scenario.name}`, color: 'text-destructive', icon: AlertTriangle };
      case 'fixing':
        return { text: 'Génération du patch AVR…', color: 'text-accent', icon: Zap };
      case 'fixed':
        return { text: 'Vulnérabilité neutralisée', color: 'text-success', icon: ShieldCheck };
      default:
        return { text: 'Prochain scénario…', color: 'text-muted-foreground', icon: Cpu };
    }
  };

  const phaseInfo = getPhaseLabel();
  const PhaseIcon = phaseInfo.icon;

  return (
    <section ref={sectionRef} className="relative py-32 overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-to-b from-background via-card/20 to-background" />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[600px] bg-primary/5 rounded-full blur-3xl pointer-events-none" />

      <div className="container mx-auto px-6 relative z-10">
        {/* Header */}
        <div className="text-center max-w-3xl mx-auto mb-16">
          <span className="text-xs uppercase tracking-[0.3em] text-muted-foreground mb-4 block">
            Live · En temps réel
          </span>
          <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6 tracking-tight">
            Regardez Adversum{' '}
            <span className="bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
              travailler
            </span>
          </h2>
          <p className="text-lg text-muted-foreground leading-relaxed">
            Détection, validation IA et correction automatique — en moins d'une seconde.
          </p>
        </div>

        <div className="grid lg:grid-cols-2 gap-8 max-w-6xl mx-auto items-center">
          {/* Code editor */}
          <div className="relative">
            <div className="rounded-2xl bg-card/80 backdrop-blur-xl border border-border/50 overflow-hidden shadow-2xl shadow-primary/5">
              {/* Editor header */}
              <div className="flex items-center gap-3 px-5 py-3 border-b border-border/50 bg-card/60">
                <div className="flex gap-1.5">
                  <div className="w-2.5 h-2.5 rounded-full bg-destructive/50" />
                  <div className="w-2.5 h-2.5 rounded-full bg-warning/50" />
                  <div className="w-2.5 h-2.5 rounded-full bg-success/50" />
                </div>
                <span className="text-xs font-mono text-muted-foreground ml-2">
                  {scenario.name.toLowerCase().replace(/ /g, '-')}.js
                </span>
                <div className="ml-auto flex items-center gap-2">
                  <span className={`w-1.5 h-1.5 rounded-full ${phase === 'scanning' ? 'bg-primary animate-pulse' : phase === 'detected' ? 'bg-destructive animate-pulse' : phase === 'fixed' ? 'bg-success' : 'bg-muted-foreground/50'}`} />
                  <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider">
                    {phase}
                  </span>
                </div>
              </div>

              {/* Code area */}
              <div className="relative font-mono text-sm p-5 min-h-[320px] bg-background/40">
                {/* Scan line overlay */}
                {phase === 'scanning' && (
                  <div
                    className="absolute left-0 right-0 h-16 bg-gradient-to-b from-transparent via-primary/20 to-transparent pointer-events-none"
                    style={{
                      top: `${(scanProgress / 100) * 260}px`,
                      transition: 'top 0.03s linear',
                    }}
                  />
                )}

                {displayedLines.filter(Boolean).map((line, idx) => (
                  <div
                    key={idx}
                    className={`flex items-start gap-3 py-0.5 rounded transition-all duration-300 ${
                      line.state === 'vuln'
                        ? 'bg-destructive/10 -mx-2 px-2 border-l-2 border-destructive'
                        : line.state === 'fixed'
                        ? 'bg-success/10 -mx-2 px-2 border-l-2 border-success'
                        : ''
                    }`}
                  >
                    <span className="text-muted-foreground/40 text-xs pt-0.5 w-6 shrink-0 text-right select-none">
                      {idx + 1}
                    </span>
                    <span
                      className={`whitespace-pre ${
                        line.state === 'vuln'
                          ? 'text-destructive'
                          : line.state === 'fixed'
                          ? 'text-success'
                          : 'text-foreground/80'
                      }`}
                    >
                      {line.code}
                    </span>
                  </div>
                ))}

                {phase === 'typing' && (
                  <span className="inline-block w-2 h-4 bg-primary ml-1 animate-pulse" />
                )}
              </div>

              {/* Status bar */}
              <div className="flex items-center gap-2 px-5 py-3 border-t border-border/50 bg-card/60">
                <PhaseIcon className={`w-3.5 h-3.5 ${phaseInfo.color}`} />
                <span className={`text-xs font-mono ${phaseInfo.color}`}>
                  {phaseInfo.text}
                </span>
              </div>
            </div>
          </div>

          {/* Shield + Stats */}
          <div className="relative">
            <div className="relative aspect-square max-w-md mx-auto">
              <HolographicShield pulse={pulse} />
              {/* Overlay label */}
              <div className="absolute bottom-4 left-1/2 -translate-x-1/2 text-center pointer-events-none">
                <div className="text-xs font-mono uppercase tracking-[0.3em] text-primary/80 mb-1">
                  Adversum Core
                </div>
                <div className="text-[10px] font-mono text-muted-foreground">
                  v2.0 · Rust + IA
                </div>
              </div>
            </div>

            {/* Live stats */}
            <div className="grid grid-cols-3 gap-3 mt-8">
              {[
                { label: 'Scannés', value: stats.scanned, color: 'text-foreground' },
                { label: 'Bloqués', value: stats.blocked, color: 'text-destructive' },
                { label: 'Corrigés', value: stats.fixed, color: 'text-success' },
              ].map((stat) => (
                <div
                  key={stat.label}
                  className="p-4 rounded-xl bg-card/50 border border-border/40 backdrop-blur-sm text-center"
                >
                  <div className={`text-2xl font-bold tabular-nums ${stat.color}`}>
                    {stat.value.toLocaleString('fr-FR')}
                  </div>
                  <div className="text-[10px] uppercase tracking-widest text-muted-foreground mt-1">
                    {stat.label}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default LiveSimulation;
