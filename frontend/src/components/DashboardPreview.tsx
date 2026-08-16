import { useRef, useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle, Clock, TrendingUp, Download, FileCode, Wrench, Loader2 } from 'lucide-react';

const DashboardPreview = () => {
  const sectionRef = useRef<HTMLDivElement>(null);
  const [isVisible, setIsVisible] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsVisible(true);
        }
      },
      { threshold: 0.2 }
    );

    if (sectionRef.current) {
      observer.observe(sectionRef.current);
    }

    return () => observer.disconnect();
  }, []);

  const handleScan = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const repoUrl = (e.currentTarget.elements.namedItem('repoUrl') as HTMLInputElement)?.value;
    if (!repoUrl) return;

    setIsScanning(true);
    setScanResult(null);

    try {
      const res = await fetch('/api/v1/scan/clone-and-scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': 'adv-dev-key-123'
        },
        body: JSON.stringify({
          repo_url: repoUrl,
          all_modules: true
        })
      });

      // Read raw text first — avoids crash on empty or non-JSON body
      const rawText = await res.text();

      if (!rawText || rawText.trim() === '') {
        alert(`L'API a répondu avec un corps vide (HTTP ${res.status}). Vérifie les logs du serveur uvicorn.`);
        return;
      }

      let data: any;
      try {
        data = JSON.parse(rawText);
      } catch {
        alert(`L'API a répondu mais pas en JSON (HTTP ${res.status}):\n\n${rawText.slice(0, 400)}`);
        return;
      }

      if (!res.ok) {
        alert(`Erreur API (${res.status}) : ${data.detail || JSON.stringify(data)}`);
      } else {
        setScanResult(data);
        if (data.findings?.length === 0) {
          alert(`✅ Scan terminé sur ${repoUrl}\nAucune vulnérabilité détectée avec les modules actifs.`);
        }
      }
    } catch (err: any) {
      console.error(err);
      // Network-level failure (CORS, no server, etc.)
      alert(
        `❌ Impossible de joindre l'API (http://localhost:8080).\n\n` +
        `Vérifie que :\n1. Le serveur uvicorn tourne bien\n2. Le port 8080 n'est pas bloqué\n\n` +
        `Détail : ${err?.message || err}`
      );
    } finally {
      setIsScanning(false);
    }
  };

  // Helper to trigger file download in browser
  const downloadFile = (content: string, filename: string, type: string) => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleExportSarif = () => {
    if (!scanResult) {
      alert("Aucun résultat de scan disponible à exporter. Lancez d'abord une analyse.");
      return;
    }
    const sarif = {
      $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [{
        tool: { driver: { name: "Adversum Unified SAST", version: "1.0.0" } },
        results: (scanResult.findings || []).map((f: any) => ({
          ruleId: f.rule_id || "UNKNOWN",
          level: f.severity === "CRITICAL" || f.severity === "HIGH" ? "error" : "warning",
          message: { text: f.description || f.title || f.rule_id },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: f.file_path || f.file || "unknown" },
              region: { startLine: f.line || 1 }
            }
          }]
        }))
      }]
    };
    downloadFile(JSON.stringify(sarif, null, 2), "adversum_audit.sarif", "application/json");
  };

  const handleExportMarkdown = () => {
    if (!scanResult) {
      alert("Aucun résultat de scan disponible à exporter. Lancez d'abord une analyse.");
      return;
    }
    const findings = scanResult.findings || [];
    let md = `# 🛡️ Adversum Security Audit Report\n\n`;
    md += `**Repository:** ${scanResult.repo_url || scanResult.target || 'Local Target'}\n`;
    md += `**Date:** ${new Date().toLocaleString()}\n`;
    md += `**Total Findings:** ${findings.length}\n\n`;
    md += `## Summary by Severity\n\n`;
    md += `| Severity | Count |\n| --- | --- |\n`;
    md += `| CRITICAL | ${findings.filter((f: any) => f.severity === 'CRITICAL' || f.severity === 'critical').length} |\n`;
    md += `| HIGH | ${findings.filter((f: any) => f.severity === 'HIGH' || f.severity === 'high').length} |\n`;
    md += `| MEDIUM | ${findings.filter((f: any) => f.severity === 'MEDIUM' || f.severity === 'medium').length} |\n`;
    md += `| LOW | ${findings.filter((f: any) => f.severity === 'LOW' || f.severity === 'low').length} |\n\n`;
    md += `## Detailed Findings\n\n`;
    findings.forEach((f: any, idx: number) => {
      md += `### ${idx + 1}. [${f.severity}] ${f.rule_id || f.title || 'Finding'}\n`;
      md += `- **File:** \`${f.file_path || f.file}\` (Line ${f.line || 1})\n`;
      md += `- **Module:** \`${f.module || 'SAST'}\` | **CWE:** \`${f.cwe || 'N/A'}\`\n\n`;
      if (f.snippet) md += `\`\`\`\n${f.snippet}\n\`\`\`\n\n`;
      if (f.recommendation) md += `**Recommendation:** ${f.recommendation}\n\n`;
      md += `---\n\n`;
    });
    downloadFile(md, "adversum_report.md", "text/markdown");
  };

  const defaultVulnerabilities = [
    { severity: 'critical', name: 'Reentrancy', file: 'contracts/Vault.sol', module: 'Solidity', status: 'analyzing', snippet: 'msg.sender.call{value: amount}("")' },
    { severity: 'high', name: 'Hardcoded JWT Key', file: 'api/auth.py', module: 'Crypto', status: 'pending', snippet: 'JWT_SECRET = "supersecret123"' },
    { severity: 'high', name: 'Root User in Docker', file: 'infra/Dockerfile', module: 'IaC', status: 'fixed', snippet: 'USER root' },
    { severity: 'medium', name: 'Tainted Data Flow', file: 'core/parser.js', module: 'Taint Core', status: 'analyzing', snippet: 'eval(req.query.cmd)' },
  ];

  // Use dynamic vulnerabilities if scan succeeded
  const vulnerabilities = scanResult && scanResult.findings ? scanResult.findings.map((f: any) => ({
    severity: (f.severity || 'medium').toLowerCase(),
    name: f.rule_id || f.title || 'Vuln',
    file: f.file_path || f.file,
    module: f.module || 'Scanner',
    status: 'pending',
    snippet: f.snippet || '',
    recommendation: f.recommendation || ''
  })) : defaultVulnerabilities;

  const totalCount = scanResult?.summary?.total_findings ?? vulnerabilities.length;
  const criticalCount = scanResult?.findings ? scanResult.findings.filter((f: any) => (f.severity || '').toUpperCase() === 'CRITICAL').length : 1;
  const highCount = scanResult?.findings ? scanResult.findings.filter((f: any) => (f.severity || '').toUpperCase() === 'HIGH').length : 2;

  return (
    <section ref={sectionRef} className="relative py-32 overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-to-b from-background to-card/20" />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[600px] bg-primary/5 rounded-full blur-3xl" />
      
      <div className="container mx-auto px-6 relative z-10">
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16">
          <span className="text-xs uppercase tracking-[0.3em] text-muted-foreground mb-4 block">
            Interface
          </span>
          <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6 tracking-tight">
            Design{' '}
            <span className="bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
              intuitif
            </span>
          </h2>
          <p className="text-lg text-muted-foreground leading-relaxed">
            Une interface épurée pour une productivité maximale
          </p>
        </div>

        {/* Dashboard Mockup */}
        <div 
          className={`relative max-w-5xl mx-auto transition-all duration-1000 ${
            isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-12'
          }`}
        >
          {/* Browser Frame */}
          <div className="rounded-3xl bg-card/80 backdrop-blur-xl border border-border/50 overflow-hidden shadow-2xl shadow-background/50">
            {/* Browser Header */}
            <div className="flex items-center gap-3 px-6 py-4 border-b border-border/50">
              <div className="flex gap-2">
                <div className="w-3 h-3 rounded-full bg-destructive/60" />
                <div className="w-3 h-3 rounded-full bg-warning/60" />
                <div className="w-3 h-3 rounded-full bg-success/60" />
              </div>
              <div className="flex-1 flex justify-center">
                <div className="px-4 py-1.5 rounded-full bg-background/50 text-xs text-muted-foreground font-mono">
                  app.adversum.io/dashboard
                </div>
              </div>
            </div>

            {/* Dashboard Content */}
            <div className="p-8 bg-background/30">
              {/* Git Repo Scan Bar */}
              <div className="mb-8 p-4 rounded-2xl bg-card/60 border border-border/40 backdrop-blur-md">
                <form onSubmit={handleScan} className="flex items-center gap-3">
                  <div className="relative flex-1">
                    <input 
                      type="url"
                      name="repoUrl"
                      placeholder="https://github.com/votre-user/votre-repo..."
                      className="w-full px-4 py-2.5 rounded-xl bg-background/80 border border-border/50 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 font-mono text-foreground placeholder:text-muted-foreground/60"
                      required
                      disabled={isScanning}
                    />
                  </div>
                  <button 
                    type="submit"
                    disabled={isScanning}
                    className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-primary to-accent text-primary-foreground text-sm font-semibold hover:opacity-90 transition-all flex items-center gap-2 shadow-lg shadow-primary/25 shrink-0 disabled:opacity-50"
                  >
                    {isScanning ? (
                      <><Loader2 className="w-4 h-4 animate-spin" /> Analyse en cours...</>
                    ) : (
                      <>🚀 Analyser ce Dépôt</>
                    )}
                  </button>
                </form>
              </div>

              {/* Stats Row */}
              <div className="grid grid-cols-4 gap-4 mb-8">
                {[
                  { label: 'Vulnérabilités', value: String(totalCount), icon: AlertTriangle, color: 'text-destructive' },
                  { label: 'Critiques', value: String(criticalCount), icon: AlertTriangle, color: 'text-destructive' },
                  { label: 'Élevées (High)', value: String(highCount), icon: Clock, color: 'text-warning' },
                  { label: 'Score Sécurité', value: totalCount === 0 ? '100%' : `${Math.max(10, 100 - totalCount * 12)}%`, icon: TrendingUp, color: 'text-primary' },
                ].map((stat, i) => (
                  <div 
                    key={i} 
                    className={`p-5 rounded-2xl bg-card/50 border border-border/30 transition-all duration-500 ${
                      isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'
                    }`}
                    style={{ transitionDelay: `${300 + i * 100}ms` }}
                  >
                    <stat.icon className={`w-5 h-5 ${stat.color} mb-3`} />
                    <div className="text-2xl font-bold mb-1">{stat.value}</div>
                    <div className="text-sm text-muted-foreground">{stat.label}</div>
                  </div>
                ))}
              </div>

              {/* Vulnerabilities List */}
              <div className="rounded-2xl bg-card/30 border border-border/30 p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wide">
                    {scanResult ? `Résultats du Scan (${vulnerabilities.length} trouvées)` : 'Vulnérabilités démo (Multi-Modules)'}
                  </h3>
                  <div className="flex gap-2">
                    <button 
                      onClick={handleExportSarif}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-background/50 border border-border/50 rounded-lg hover:bg-muted transition-colors"
                    >
                      <FileCode className="w-3.5 h-3.5" /> Export SARIF 2.1
                    </button>
                    <button 
                      onClick={handleExportMarkdown}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-background/50 border border-border/50 rounded-lg hover:bg-muted transition-colors"
                    >
                      <Download className="w-3.5 h-3.5" /> Export Markdown
                    </button>
                  </div>
                </div>
                <div className="space-y-3">
                  {vulnerabilities.map((vuln: any, i: number) => (
                    <div
                      key={i}
                      className={`flex items-center justify-between p-4 rounded-xl bg-background/50 border border-border/20 transition-all duration-500 ${
                        isVisible ? 'opacity-100 translate-x-0' : 'opacity-0 -translate-x-4'
                      }`}
                      style={{ transitionDelay: `${600 + i * 100}ms` }}
                    >
                      <div className="flex items-center gap-4">
                        <div
                          className={`w-2.5 h-2.5 rounded-full ${
                            vuln.severity === 'critical'
                              ? 'bg-destructive'
                              : vuln.severity === 'high'
                              ? 'bg-warning'
                              : 'bg-primary'
                          }`}
                        />
                        <div>
                          <div className="flex items-center gap-2">
                            <div className="text-sm font-semibold text-foreground">{vuln.name}</div>
                            <span className="text-[10px] uppercase tracking-wider px-2 py-0.5 rounded-md bg-muted/50 border border-border/50 text-muted-foreground font-mono">
                              {vuln.module}
                            </span>
                          </div>
                          <div className="text-xs text-muted-foreground font-mono">{vuln.file}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        <span
                          className={`px-3 py-1 rounded-full text-xs font-medium uppercase tracking-wider ${
                            vuln.severity === 'critical'
                              ? 'bg-destructive/15 text-destructive border border-destructive/30'
                              : vuln.severity === 'high'
                              ? 'bg-warning/15 text-warning border border-warning/30'
                              : 'bg-primary/15 text-primary border border-primary/30'
                          }`}
                        >
                          {vuln.severity}
                        </span>
                        
                        <button 
                          onClick={() => alert(`Patch de correction pour ${vuln.name} (${vuln.file}):\n\nCode impacté : ${vuln.snippet || 'N/A'}\n\nRecommandation : ${vuln.recommendation || 'Appliquer la mise à jour de sécurité'}`)}
                          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors shadow-sm"
                        >
                          <Wrench className="w-3.5 h-3.5" /> Voir Patch / Fix
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Decorative glows */}
          <div className="absolute -top-10 -right-10 w-40 h-40 bg-primary/10 rounded-full blur-3xl" />
          <div className="absolute -bottom-10 -left-10 w-40 h-40 bg-accent/10 rounded-full blur-3xl" />
        </div>
      </div>
    </section>
  );
};

export default DashboardPreview;
