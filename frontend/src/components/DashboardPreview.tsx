import { useRef, useEffect, useState } from 'react';
import {
  AlertTriangle, Clock, TrendingUp, Download, FileCode, Copy, Check,
  Wrench, Loader2, Zap, Shield, Building2, FileText, ChevronDown, ChevronUp, CheckCircle2, Terminal
} from 'lucide-react';

const SCAN_PROFILES = [
  {
    id: 'quick',
    icon: Zap,
    label: 'Rapide',
    desc: 'Secrets · Crypto · IaC',
    detail: ['Mauvais usages cryptographiques', 'Clés / tokens hardcodés', 'Dockerfiles & Terraform'],
    badge: '~30s',
    badgeClass: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10',
    borderActive: 'border-emerald-500/60 shadow-emerald-500/10',
    all_modules: false,
    modules: ['crypto', 'iac'],
    cex_audit: false,
    format: 'json',
    poc: false,
  },
  {
    id: 'smart_contract',
    icon: FileCode,
    label: 'Smart Contract',
    desc: 'Solidity · Vyper · SMT',
    detail: ['Reentrancy & Flash Loan', 'Oracle Manipulation', 'Preuve formelle SMT', 'Foundry Exploit PoC'],
    badge: 'Foundry PoC',
    badgeClass: 'text-blue-400 border-blue-500/30 bg-blue-500/10',
    borderActive: 'border-blue-500/60 shadow-blue-500/10',
    all_modules: false,
    modules: ['solidity'],
    cex_audit: false,
    format: 'json',
    poc: true,
  },
  {
    id: 'cex',
    icon: Building2,
    label: 'CEX / Custody',
    desc: 'CCSS v3.0 · API · STRIDE',
    detail: ['Conformité CCSS 10 aspects', 'Race Conditions / Double Spend', 'STRIDE Threat Modeling', 'Sécurité API Trading'],
    badge: 'Institutionnel',
    badgeClass: 'text-amber-400 border-amber-500/30 bg-amber-500/10',
    borderActive: 'border-amber-500/60 shadow-amber-500/10',
    all_modules: false,
    modules: ['solidity', 'crypto', 'iac', 'cex_api'],
    cex_audit: true,
    format: 'json',
    poc: false,
  },
  {
    id: 'full',
    icon: Shield,
    label: 'Complet',
    desc: 'Tous les modules · PoC · Rapport',
    detail: ['Tous les modules combinés', 'CCSS + STRIDE + SMT', 'Foundry PoC auto-généré', 'Rapport Exécutif Markdown'],
    badge: '~2-3 min',
    badgeClass: 'text-violet-400 border-violet-500/30 bg-violet-500/10',
    borderActive: 'border-violet-500/60 shadow-violet-500/10',
    all_modules: true,
    modules: ['solidity', 'crypto', 'iac', 'cex_api'],
    cex_audit: true,
    format: 'json',
    poc: true,
  },
];

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

const SEV_COLOR: Record<string, string> = {
  critical: 'bg-destructive/15 text-destructive border-destructive/30',
  high: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  medium: 'bg-primary/15 text-primary border-primary/30',
  low: 'bg-muted/40 text-muted-foreground border-border/50',
};

const SEV_DOT: Record<string, string> = {
  critical: 'bg-destructive',
  high: 'bg-amber-400',
  medium: 'bg-primary',
  low: 'bg-muted-foreground',
};

const CCSS_STATUS_COLOR: Record<string, string> = {
  PASS_L3: 'text-emerald-400',
  PASS_L2: 'text-blue-400',
  PASS_L1: 'text-amber-400',
  NON_COMPLIANT: 'text-destructive',
};

const DEMO_REENTRANCY_POC = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IVault {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
    function balances(address) external view returns (uint256);
}

contract ReentrancyAttacker {
    IVault public immutable target;
    address public immutable owner;

    constructor(address _target) {
        target = IVault(_target);
        owner = msg.sender;
    }

    function attack() external payable {
        require(msg.value >= 1 ether, "1 ETH required");
        target.deposit{value: 1 ether}();
        target.withdraw(1 ether);
    }

    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.withdraw(1 ether);
        }
    }
}

contract ReentrancyExploitPoCTest is Test {
    IVault public target;
    ReentrancyAttacker public attackerContract;

    function test_ExploitReentrancyDrain() public {
        // Run: forge test --match-contract ReentrancyExploitPoCTest -vvvv
        emit log("Proving reentrancy balance drain invariant failure...");
    }
}`;

const DashboardPreview = () => {
  const sectionRef = useRef<HTMLElement>(null);
  const [isVisible, setIsVisible] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);
  const [repoUrl, setRepoUrl] = useState('https://github.com/ibonon/Sigui');
  const [scanStatusMsg, setScanStatusMsg] = useState<string | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [selectedProfile, setSelectedProfile] = useState('quick');
  const [expandedFinding, setExpandedFinding] = useState<number | null>(null);
  const [showCCSS, setShowCCSS] = useState(false);
  const [copiedPocIdx, setCopiedPocIdx] = useState<number | null>(null);

  const profile = SCAN_PROFILES.find(p => p.id === selectedProfile) || SCAN_PROFILES[0];

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([e]) => { if (e.isIntersecting) setIsVisible(true); },
      { threshold: 0.2 }
    );
    if (sectionRef.current) observer.observe(sectionRef.current);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    let interval: any;
    if (isScanning) {
      setElapsedSeconds(0);
      interval = setInterval(() => setElapsedSeconds(s => s + 1), 1000);
    }
    return () => clearInterval(interval);
  }, [isScanning]);

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const url = repoUrl.trim();
    if (!url) return;
    const isLocal = !url.startsWith('http') && (url.startsWith('.') || url.startsWith('/') || /^[a-zA-Z]:[/\\]/.test(url));
    setIsScanning(true);
    setScanResult(null);
    setExpandedFinding(null);
    setShowCCSS(false);
    setScanStatusMsg(isLocal ? '⚡ Analyse instantanée du dossier local...' : '⏳ [1/2] Téléchargement depuis GitHub...');

    const body = {
      repo_url: url,
      all_modules: profile.all_modules,
      modules: profile.modules,
      cex_audit: profile.cex_audit,
      format: profile.format,
      poc: profile.poc,
      project_name: 'Digital Asset Platform Audit'
    };

    try {
      let res;
      try {
        res = await fetch('/api/v1/scan/clone-and-scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-API-Key': 'adv-dev-key-123' },
          body: JSON.stringify(body)
        });
      } catch {
        res = await fetch('http://127.0.0.1:8080/api/v1/scan/clone-and-scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-API-Key': 'adv-dev-key-123' },
          body: JSON.stringify(body)
        });
      }
      const rawText = await res.text();
      if (!rawText?.trim()) {
        setScanStatusMsg('❌ Réponse vide du serveur');
        return;
      }
      let data;
      try {
        data = JSON.parse(rawText);
      } catch {
        setScanStatusMsg('❌ Réponse non-JSON reçue');
        return;
      }
      if (!res.ok) {
        setScanStatusMsg(`❌ Erreur ${res.status} : ${data.detail || ''}`);
      } else {
        setScanResult(data);
        const count = data.findings?.length ?? 0;
        setScanStatusMsg(`✅ Analyse terminée — ${count} vulnérabilité${count !== 1 ? 's' : ''} détectée${count !== 1 ? 's' : ''}`);
      }
    } catch {
      setScanStatusMsg("❌ Impossible de joindre le serveur — vérifiez que l'API tourne sur :8080");
    } finally {
      setIsScanning(false);
    }
  };

  const handleExportSarif = () => {
    if (!scanResult?.findings) return;
    const sarif = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'Adversum', version: '5.0', informationUri: 'https://adversum.io' } },
          results: scanResult.findings.map((f: any) => ({
            ruleId: f.rule_id,
            level: f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'error' : 'warning',
            message: { text: f.description || f.title },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: f.file || 'unknown' },
                  region: { startLine: f.line || 1 }
                }
              }
            ],
            properties: {
              cvssScore: f.cvss_score,
              cwe: f.cwe,
              module: f.module
            }
          }))
        }
      ]
    };
    downloadFile(JSON.stringify(sarif, null, 2), 'adversum_audit.sarif', 'application/json');
  };

  const handleExportMarkdown = () => {
    if (!scanResult) return;
    if (scanResult.markdown_report) {
      downloadFile(scanResult.markdown_report, 'adversum_institutional_report.md', 'text/markdown');
      return;
    }
    const findings = scanResult.findings || [];
    let md = `# Adversum Security Assessment Report\n\n**Date:** ${new Date().toLocaleString()}\n\n## Summary\n\n`;
    for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
      md += `- **${sev}**: ${findings.filter((f: any) => (f.severity || '').toUpperCase() === sev).length}\n`;
    }
    md += '\n## Findings\n\n';
    findings.forEach((f: any, i: number) => {
      md += `### ${i + 1}. [${f.severity}] ${f.rule_id}: ${f.title || ''}\n- **File:** \`${f.file}\` (Line ${f.line || 1})\n- **CWE:** ${f.cwe || 'N/A'}\n- **CVSS:** ${f.cvss_score || 'N/A'}\n\n`;
      if (f.description) md += `${f.description}\n\n`;
      if (f.snippet) md += `\`\`\`\n${f.snippet}\n\`\`\`\n\n`;
      if (f.recommendation) md += `**Remediation:** ${f.recommendation}\n\n`;
      if (f.poc_code) md += `<details><summary>Foundry Exploit PoC</summary>\n\n\`\`\`solidity\n${f.poc_code}\n\`\`\`\n</details>\n\n`;
      md += '---\n\n';
    });
    downloadFile(md, 'adversum_report.md', 'text/markdown');
  };

  const handleCopyPoc = (code: string, idx: number) => {
    navigator.clipboard.writeText(code);
    setCopiedPocIdx(idx);
    setTimeout(() => setCopiedPocIdx(null), 2500);
  };

  const findings = scanResult?.findings ?? [];
  const ccss = scanResult?.ccss_compliance ?? null;
  const threat = scanResult?.threat_model ?? null;
  const criticalCount = findings.filter((f: any) => (f.severity || '').toUpperCase() === 'CRITICAL').length;
  const highCount = findings.filter((f: any) => (f.severity || '').toUpperCase() === 'HIGH').length;
  const totalCount = findings.length;
  const secScore = totalCount === 0 ? 100 : Math.max(10, 100 - criticalCount * 25 - highCount * 10);

  const defaultVulns = [
    {
      severity: 'critical',
      name: 'SOL-001: Reentrancy Attack',
      file: 'contracts/Vault.sol',
      module: 'Solidity',
      description: 'Appel externe .call{value:...} effectue avant la mise a jour de la balance interne, permettant un vidage recursif du vault.',
      recommendation: 'Appliquer le pattern Checks-Effects-Interactions (CEI) et integrer ReentrancyGuard.',
      snippet: 'msg.sender.call{value: amount}("");\nbalances[msg.sender] -= amount;',
      cwe: 'CWE-841',
      cvss: 9.8,
      poc_code: DEMO_REENTRANCY_POC
    },
    {
      severity: 'high',
      name: 'CRYPTO-005: Hardcoded API Secret',
      file: 'api/auth.py',
      module: 'Crypto',
      description: 'Secret cryptographique et cle API de signature en clair dans le code source.',
      recommendation: 'Utiliser un gestionnaire de secrets type HashiCorp Vault ou AWS KMS.',
      snippet: 'API_KEY = "sk-prod-xxxxxxxxxxxx"',
      cwe: 'CWE-798',
      cvss: 9.0,
      poc_code: null
    },
    {
      severity: 'high',
      name: 'CEX-002: Missing recvWindow Replay Guard',
      file: 'trading/order_api.py',
      module: 'CEX API',
      description: 'Absence de validation du parametre recvWindow dans la validation des ordres signes.',
      recommendation: 'Valider timestamp +- 5000ms pour neutraliser les attaques par rejeu de requetes de trading.',
      snippet: 'def create_order(self, symbol, qty, timestamp):\n    # Replay window unverified',
      cwe: 'CWE-294',
      cvss: 8.5,
      poc_code: null
    },
    {
      severity: 'medium',
      name: 'IAC-004: Root User Execution in Container',
      file: 'infra/Dockerfile',
      module: 'IaC',
      description: 'Conteneur execute en tant qu utilisateur root, violant le principe du moindre privilege.',
      recommendation: 'Ajouter une directive USER nonroot avant le point d entree ENTRYPOINT.',
      snippet: 'FROM node:18\nRUN npm install\nCMD ["npm", "start"]',
      cwe: 'CWE-732',
      cvss: 5.5,
      poc_code: null
    },
  ];

  const displayFindings = findings.length > 0
    ? findings.map((f: any) => ({
        severity: (f.severity || 'medium').toLowerCase(),
        name: `${f.rule_id || 'SEC-VULN'}: ${f.title || ''}`,
        file: f.file || '',
        module: f.module || 'SAST',
        description: f.description || '',
        recommendation: f.recommendation || '',
        snippet: f.snippet || '',
        cwe: f.cwe || '',
        cvss: f.cvss_score ?? null,
        poc_code: f.poc_code || f.poc || null,
      }))
    : defaultVulns;

  return (
    <section ref={sectionRef} className="relative py-32 overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-b from-background to-card/20" />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[600px] bg-primary/5 rounded-full blur-3xl" />
      <div className="container mx-auto px-6 relative z-10">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <span className="text-xs uppercase tracking-[0.3em] text-muted-foreground mb-4 block">Plateforme d'Audit Institutionnelle</span>
          <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6 tracking-tight">
            Audit de Sécurité{' '}
            <span className="bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">Multi-Niveaux</span>
          </h2>
          <p className="text-lg text-muted-foreground leading-relaxed">
            Sélectionnez votre profil d'analyse selon la nature du code — Smart Contracts, Custody CEX, Secrets ou Audit Complet avec PoC Foundry.
          </p>
        </div>

        <div className={`relative max-w-5xl mx-auto transition-all duration-1000 ${isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-12'}`}>
          <div className="rounded-3xl bg-card/80 backdrop-blur-xl border border-border/50 overflow-hidden shadow-2xl shadow-background/50">
            <div className="flex items-center gap-3 px-6 py-4 border-b border-border/50">
              <div className="flex gap-2">
                <div className="w-3 h-3 rounded-full bg-destructive/60" />
                <div className="w-3 h-3 rounded-full bg-amber-400/60" />
                <div className="w-3 h-3 rounded-full bg-emerald-400/60" />
              </div>
              <div className="flex-1 flex justify-center">
                <div className="px-4 py-1.5 rounded-full bg-background/50 text-xs text-muted-foreground font-mono">app.adversum.io/audit-suite</div>
              </div>
            </div>

            <div className="p-8 bg-background/30 space-y-6">
              {/* SCAN PROFILE SELECTOR */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {SCAN_PROFILES.map((p) => {
                  const Icon = p.icon;
                  const active = selectedProfile === p.id;
                  return (
                    <button
                      key={p.id}
                      onClick={() => { setSelectedProfile(p.id); setScanResult(null); setScanStatusMsg(null); }}
                      disabled={isScanning}
                      className={`relative p-4 rounded-2xl border text-left transition-all duration-200 group ${active ? `bg-card/80 ${p.borderActive} shadow-lg` : 'bg-card/30 border-border/30 hover:border-border/60 hover:bg-card/50'}`}
                    >
                      <div className="flex items-start justify-between mb-3">
                        <Icon className={`w-5 h-5 ${active ? 'text-foreground' : 'text-muted-foreground'} transition-colors`} />
                        <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${p.badgeClass}`}>{p.badge}</span>
                      </div>
                      <div className={`text-sm font-semibold mb-0.5 ${active ? 'text-foreground' : 'text-muted-foreground'}`}>{p.label}</div>
                      <div className="text-[11px] text-muted-foreground leading-tight">{p.desc}</div>
                      <div className={`mt-3 space-y-1 overflow-hidden transition-all duration-200 ${active ? 'max-h-40 opacity-100' : 'max-h-0 opacity-0 group-hover:max-h-40 group-hover:opacity-100'}`}>
                        {p.detail.map(d => (
                          <div key={d} className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
                            <CheckCircle2 className="w-3 h-3 text-primary/60 shrink-0" />{d}
                          </div>
                        ))}
                      </div>
                    </button>
                  );
                })}
              </div>

              {/* URL INPUT */}
              <div className="p-4 rounded-2xl bg-card/60 border border-border/40 backdrop-blur-md">
                <form onSubmit={handleScan} noValidate className="flex flex-col gap-3">
                  <div className="flex items-center gap-3">
                    <input
                      type="text"
                      value={repoUrl}
                      onChange={e => setRepoUrl(e.target.value)}
                      placeholder="https://github.com/owner/repo  ou  ./chemin/local"
                      className="flex-1 px-4 py-2.5 rounded-xl bg-background/80 border border-border/50 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 font-mono text-foreground placeholder:text-muted-foreground/50"
                      disabled={isScanning}
                    />
                    <button
                      type="submit"
                      disabled={isScanning}
                      className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-primary to-accent text-primary-foreground text-sm font-semibold hover:opacity-90 transition-all flex items-center gap-2 shadow-lg shadow-primary/25 shrink-0 disabled:opacity-50"
                    >
                      {isScanning ? <><Loader2 className="w-4 h-4 animate-spin" /> Analyse…</> : <><Shield className="w-4 h-4" /> Lancer l'Audit</>}
                    </button>
                  </div>
                  {scanStatusMsg && (
                    <div className={`text-xs px-3.5 py-2 rounded-lg border font-mono flex items-center justify-between ${scanStatusMsg.includes('✅') ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : scanStatusMsg.includes('❌') ? 'bg-destructive/10 border-destructive/30 text-destructive' : 'bg-primary/10 border-primary/30 text-primary animate-pulse'}`}>
                      <span>{scanStatusMsg}</span>
                      {isScanning && <span className="font-bold text-xs bg-primary/20 px-2 py-0.5 rounded border border-primary/30">⏱ {elapsedSeconds}s</span>}
                    </div>
                  )}
                </form>
              </div>

              {/* STATS */}
              <div className="grid grid-cols-4 gap-4">
                {[
                  { label: 'Total', value: String(totalCount), icon: AlertTriangle, color: 'text-destructive' },
                  { label: 'Critiques', value: String(criticalCount), icon: AlertTriangle, color: 'text-destructive' },
                  { label: 'Élevées', value: String(highCount), icon: Clock, color: 'text-amber-400' },
                  { label: 'Score Sécurité', value: `${secScore}%`, icon: TrendingUp, color: secScore > 70 ? 'text-emerald-400' : secScore > 40 ? 'text-amber-400' : 'text-destructive' },
                ].map((stat, i) => (
                  <div key={i} className={`p-5 rounded-2xl bg-card/50 border border-border/30 transition-all duration-500 ${isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}`} style={{ transitionDelay: `${300 + i * 100}ms` }}>
                    <stat.icon className={`w-5 h-5 ${stat.color} mb-3`} />
                    <div className="text-2xl font-bold mb-1">{stat.value}</div>
                    <div className="text-sm text-muted-foreground">{stat.label}</div>
                  </div>
                ))}
              </div>

              {/* CCSS SCORECARD */}
              {ccss && (
                <div className="rounded-2xl bg-card/40 border border-amber-500/20 overflow-hidden">
                  <button onClick={() => setShowCCSS(s => !s)} className="w-full flex items-center justify-between px-5 py-3 text-sm font-medium text-amber-400 hover:bg-amber-500/5 transition-colors">
                    <span className="flex items-center gap-2"><Building2 className="w-4 h-4" />Conformité CCSS v3.0 — {ccss.achieved_level} ({ccss.overall_score}%)</span>
                    {showCCSS ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </button>
                  {showCCSS && (
                    <div className="px-5 pb-4 space-y-1.5">
                      {(ccss.aspect_results || []).map((a: any) => (
                        <div key={a.aspect_id} className="flex items-center justify-between py-1.5 border-b border-border/20 last:border-0">
                          <div className="flex items-center gap-3">
                            <span className="text-[10px] font-mono text-muted-foreground w-16">{a.aspect_id}</span>
                            <span className="text-xs text-foreground/80">{a.name}</span>
                          </div>
                          <div className="flex items-center gap-3">
                            <div className="w-24 h-1.5 rounded-full bg-border/40 overflow-hidden">
                              <div className="h-full rounded-full bg-gradient-to-r from-primary to-accent" style={{ width: `${a.score}%` }} />
                            </div>
                            <span className={`text-[10px] font-semibold font-mono ${CCSS_STATUS_COLOR[a.status] || 'text-muted-foreground'}`}>{a.status}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* THREAT MODEL MINI */}
              {threat && (
                <div className="rounded-2xl bg-card/40 border border-border/30 px-5 py-4">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2"><Shield className="w-3.5 h-3.5" />Modèle de Menaces Financières STRIDE</span>
                    <div className="flex gap-2 text-[10px] font-mono">
                      {Object.entries(threat.risk_summary || {}).map(([sev, count]) => (count as number) > 0 && (
                        <span key={sev} className={`px-2 py-0.5 rounded border ${sev === 'CRITICAL' ? 'text-destructive border-destructive/30 bg-destructive/10' : sev === 'HIGH' ? 'text-amber-400 border-amber-500/30 bg-amber-500/10' : 'text-muted-foreground border-border/30'}`}>{count as number} {sev}</span>
                      ))}
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    {(threat.scenarios || []).slice(0, 4).map((t: any) => (
                      <div key={t.id} className="flex items-start gap-2 p-2 rounded-lg bg-background/30 border border-border/20">
                        <div className={`mt-1 w-1.5 h-1.5 rounded-full shrink-0 ${t.risk_level === 'CRITICAL' ? 'bg-destructive' : t.risk_level === 'HIGH' ? 'bg-amber-400' : 'bg-primary'}`} />
                        <div>
                          <div className="text-[11px] font-medium text-foreground/80 leading-tight">{t.title}</div>
                          <div className="text-[10px] text-muted-foreground font-mono">DREAD {t.dread_score}/10 · {t.target_asset}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* FINDINGS */}
              <div className="rounded-2xl bg-card/30 border border-border/30 p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wide">
                    {findings.length > 0 ? `Résultats · ${displayFindings.length} vulnérabilités` : 'Aperçu démo — Vulnérabilités & PoC Foundry'}
                  </h3>
                  <div className="flex gap-2">
                    <button onClick={handleExportSarif} className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-background/50 border border-border/50 rounded-lg hover:bg-muted transition-colors">
                      <FileCode className="w-3.5 h-3.5" />SARIF 2.1
                    </button>
                    <button onClick={handleExportMarkdown} className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-background/50 border border-border/50 rounded-lg hover:bg-muted transition-colors">
                      <Download className="w-3.5 h-3.5" />{scanResult?.markdown_report ? 'Rapport Institutionnel' : 'Markdown'}
                    </button>
                  </div>
                </div>
                <div className="space-y-2">
                  {displayFindings.map((vuln, i) => (
                    <div key={i} className={`rounded-xl border border-border/20 bg-background/40 overflow-hidden transition-all duration-500 ${isVisible ? 'opacity-100 translate-x-0' : 'opacity-0 -translate-x-4'}`} style={{ transitionDelay: `${600 + i * 80}ms` }}>
                      <button className="w-full flex items-center justify-between p-4 text-left hover:bg-muted/10 transition-colors" onClick={() => setExpandedFinding(expandedFinding === i ? null : i)}>
                        <div className="flex items-center gap-4">
                          <div className={`w-2.5 h-2.5 rounded-full shrink-0 ${SEV_DOT[vuln.severity] || 'bg-muted'}`} />
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-semibold">{vuln.name}</span>
                              <span className="text-[10px] uppercase tracking-wider px-2 py-0.5 rounded-md bg-muted/50 border border-border/50 text-muted-foreground font-mono">{vuln.module}</span>
                              {vuln.cwe && <span className="text-[10px] text-muted-foreground/60 font-mono">{vuln.cwe}</span>}
                              {vuln.poc_code && (
                                <span className="text-[9px] font-semibold px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/30">
                                  ⚡ PoC Foundry
                                </span>
                              )}
                            </div>
                            <div className="text-xs text-muted-foreground font-mono">{vuln.file}</div>
                          </div>
                        </div>
                        <div className="flex items-center gap-3">
                          {vuln.cvss != null && <span className="text-xs font-mono text-muted-foreground">CVSS {vuln.cvss}</span>}
                          <span className={`px-3 py-1 rounded-full text-xs font-semibold uppercase border ${SEV_COLOR[vuln.severity] || SEV_COLOR.medium}`}>{vuln.severity}</span>
                          {expandedFinding === i ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                        </div>
                      </button>
                      {expandedFinding === i && (
                        <div className="px-4 pb-4 pt-1 border-t border-border/20 space-y-3">
                          {vuln.description && (
                            <p className="text-xs text-muted-foreground leading-relaxed">{vuln.description}</p>
                          )}
                          {vuln.snippet && (
                            <div>
                              <div className="text-[11px] font-medium text-muted-foreground mb-1">Code vulnérable :</div>
                              <div className="rounded-lg bg-background/60 border border-border/30 p-3 font-mono text-xs text-foreground/80 overflow-x-auto">
                                {vuln.snippet}
                              </div>
                            </div>
                          )}
                          {vuln.recommendation && (
                            <div className="flex items-start gap-2 text-xs text-muted-foreground bg-primary/5 p-3 rounded-lg border border-primary/20">
                              <Wrench className="w-3.5 h-3.5 mt-0.5 text-primary shrink-0" />
                              <span><strong className="text-foreground">Recommandation :</strong> {vuln.recommendation}</span>
                            </div>
                          )}
                          {vuln.poc_code && (
                            <div className="rounded-xl border border-blue-500/30 bg-blue-950/20 p-3.5 space-y-2">
                              <div className="flex items-center justify-between">
                                <div className="flex items-center gap-2 text-xs font-semibold text-blue-400">
                                  <Terminal className="w-4 h-4" />
                                  <span>PoC d'Exploit Foundry (<code>ExploitPoC.t.sol</code>)</span>
                                </div>
                                <div className="flex items-center gap-2">
                                  <button
                                    onClick={(e) => { e.stopPropagation(); handleCopyPoc(vuln.poc_code, i); }}
                                    className="flex items-center gap-1 px-2.5 py-1 rounded bg-blue-500/20 hover:bg-blue-500/30 text-blue-300 text-[11px] font-mono transition-colors border border-blue-500/30"
                                  >
                                    {copiedPocIdx === i ? <><Check className="w-3 h-3 text-emerald-400" /> Copié !</> : <><Copy className="w-3 h-3" /> Copier</>}
                                  </button>
                                  <button
                                    onClick={(e) => { e.stopPropagation(); downloadFile(vuln.poc_code, `Exploit_${vuln.name.split(':')[0].trim()}.t.sol`, 'text/plain'); }}
                                    className="flex items-center gap-1 px-2.5 py-1 rounded bg-background/50 hover:bg-muted text-muted-foreground hover:text-foreground text-[11px] font-mono transition-colors border border-border/40"
                                  >
                                    <Download className="w-3 h-3" /> .t.sol
                                  </button>
                                </div>
                              </div>
                              <div className="text-[10px] text-blue-300/70 font-mono">
                                Commande de reproduction : <span className="text-blue-200">forge test --match-contract {vuln.name.split(':')[0].replace(/[^a-zA-Z0-9]/g, '')}PoCTest -vvvv</span>
                              </div>
                              <pre className="rounded-lg bg-black/60 border border-blue-500/20 p-3 font-mono text-[11px] text-blue-100/90 overflow-x-auto max-h-60 leading-relaxed">
                                <code>{vuln.poc_code}</code>
                              </pre>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
          <div className="absolute -top-10 -right-10 w-40 h-40 bg-primary/10 rounded-full blur-3xl" />
          <div className="absolute -bottom-10 -left-10 w-40 h-40 bg-accent/10 rounded-full blur-3xl" />
        </div>
      </div>
    </section>
  );
};

export default DashboardPreview;
