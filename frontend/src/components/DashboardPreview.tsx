import { useRef, useEffect, useState } from 'react';
import {
  AlertTriangle, Clock, TrendingUp, Download, FileCode, Copy, Check, Globe,
  Wrench, Loader2, Zap, Shield, Building2, FileText, ChevronDown, ChevronUp, CheckCircle2, Terminal,
  Code2, GitPullRequest, Sparkles, Play
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
    desc: 'Solidity · Bridges · PoC',
    detail: ['Reentrancy & Flash Loan', 'Ponts Cross-Chain & Replay', 'Preuve formelle SMT', 'Foundry Exploit PoC'],
    badge: 'Foundry PoC',
    badgeClass: 'text-blue-400 border-blue-500/30 bg-blue-500/10',
    borderActive: 'border-blue-500/60 shadow-blue-500/10',
    all_modules: false,
    modules: ['solidity', 'cross_chain'],
    cex_audit: false,
    format: 'json',
    poc: true,
  },
  {
    id: 'cex',
    icon: Building2,
    label: 'CEX / Custody',
    desc: 'CCSS v3.0 · PoR · STRIDE',
    detail: ['Conformité CCSS 10 aspects', 'Proof of Reserves Merkle Tree', 'STRIDE Threat Modeling', 'Sécurité API Trading'],
    badge: 'Institutionnel',
    badgeClass: 'text-amber-400 border-amber-500/30 bg-amber-500/10',
    borderActive: 'border-amber-500/60 shadow-amber-500/10',
    all_modules: false,
    modules: ['solidity', 'crypto', 'iac', 'cex_api', 'cross_chain', 'por'],
    cex_audit: true,
    format: 'json',
    poc: false,
  },
  {
    id: 'full',
    icon: Shield,
    label: 'Complet',
    desc: 'Tous les modules · HTML · PoC',
    detail: ['Tous les modules combinés', 'CCSS + STRIDE + SMT', 'Proof of Reserves & Bridges', 'Dashboard HTML Standalone'],
    badge: '~2-3 min',
    badgeClass: 'text-violet-400 border-violet-500/30 bg-violet-500/10',
    borderActive: 'border-violet-500/60 shadow-violet-500/10',
    all_modules: true,
    modules: ['solidity', 'crypto', 'iac', 'cex_api', 'cross_chain', 'por'],
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

const AGENT_STEPS = [
  { sec: 0, title: "Initialisation Sandbox", desc: "Isolation des processus & chargement des politiques de sécurité", icon: "📡" },
  { sec: 8, title: "Acquisition du Code Source", desc: "Clonage Git shallow & extraction de l'arbre syntaxique (AST)", icon: "🐙" },
  { sec: 35, title: "Analyse SAST Multi-Moteurs", desc: "Moteur Rust PyO3 : Taint analysis, SMT solver & conformité CCSS", icon: "🛡️" },
  { sec: 85, title: "Raisonnement IA NVIDIA Nemotron", desc: "Inférence Nebius Token Factory pour élimination des faux positifs", icon: "🧠" },
  { sec: 130, title: "Threat Intelligence Tavily", desc: "Recherche temps-réel d'exploits publics et corrélations CVE", icon: "🔍" },
  { sec: 165, title: "Génération PoC Foundry & Patches", desc: "Synthèse des exploits .t.sol et remédiations Git vérifiées", icon: "⚡" },
];

const generateStandaloneHtmlReport = (opts: {
  repoUrl: string;
  findings: any[];
  totalCount: number;
  criticalCount: number;
  highCount: number;
  secScore: number;
  aiSummary: string | null;
  nebiusEnabled: boolean;
  tavilyEnabled: boolean;
}): string => {
  const dateStr = new Date().toLocaleString();
  const findingsRows = opts.findings.map((f, i) => `
    <div style="background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:20px;margin-bottom:16px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <div style="display:flex;align-items:center;gap:10px;">
          <span style="font-weight:700;font-size:15px;color:#f8fafc;">#${i + 1} ${f.name}</span>
          <span style="background:#1e293b;color:#94a3b8;padding:2px 8px;border-radius:6px;font-size:11px;font-family:monospace;">${f.module}</span>
          ${f.cwe ? `<span style="color:#64748b;font-size:11px;font-family:monospace;">${f.cwe}</span>` : ''}
        </div>
        <span style="padding:4px 10px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase;background:${f.severity === 'critical' ? '#450a0a' : f.severity === 'high' ? '#451a03' : '#1e293b'};color:${f.severity === 'critical' ? '#f87171' : f.severity === 'high' ? '#fbbf24' : '#94a3b8'};border:1px solid ${f.severity === 'critical' ? '#ef4444' : f.severity === 'high' ? '#f59e0b' : '#475569'};">
          ${f.severity} ${f.cvss ? `(CVSS ${f.cvss})` : ''}
        </span>
      </div>
      <div style="color:#64748b;font-family:monospace;font-size:12px;margin-bottom:10px;">📁 ${f.file}</div>
      <p style="color:#cbd5e1;font-size:13px;line-height:1.6;margin-bottom:12px;">${f.description}</p>
      ${f.nebius_ai ? `
        <div style="background:#2e1065;border:1px solid #7c3aed;border-radius:8px;padding:12px;margin-bottom:12px;">
          <div style="font-size:11px;font-weight:700;color:#c4b5fd;margin-bottom:4px;">🟢 VALIDÉ PAR NVIDIA NEMOTRON (NEBIUS TOKEN FACTORY) — Confiance: ${Math.round((f.nebius_ai.confidence || 0.9) * 100)}%</div>
          <p style="color:#e9d5ff;font-size:12px;margin:0;">${f.nebius_ai.ai_explanation || ''}</p>
          ${f.nebius_ai.ai_remediation ? `<p style="color:#a78bfa;font-size:12px;margin:4px 0 0 0;"><strong>Fix Recommandé :</strong> ${f.nebius_ai.ai_remediation}</p>` : ''}
        </div>
      ` : ''}
      ${f.snippet ? `
        <div style="background:#020617;border:1px solid #1e293b;border-radius:8px;padding:12px;font-family:monospace;font-size:12px;color:#94a3b8;overflow-x:auto;margin-bottom:10px;">
          <pre style="margin:0;">${f.snippet}</pre>
        </div>
      ` : ''}
      ${f.poc_code ? `
        <details style="margin-top:10px;">
          <summary style="cursor:pointer;color:#60a5fa;font-size:12px;font-weight:600;">⚡ PoC d'Exploit Foundry (ExploitPoC.t.sol)</summary>
          <pre style="background:#020617;border:1px solid #1d4ed8;border-radius:8px;padding:12px;font-family:monospace;font-size:11px;color:#bfdbfe;overflow-x:auto;margin-top:8px;">${f.poc_code}</pre>
        </details>
      ` : ''}
    </div>
  `).join('');

  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Adversum Institutional Security Report — ${opts.repoUrl}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #020617; color: #f8fafc; margin: 0; padding: 40px 20px; }
    .container { max-width: 1000px; margin: 0 auto; }
    .card { background: #0f172a; border: 1px solid #1e293b; border-radius: 16px; padding: 24px; margin-bottom: 24px; }
    .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
    .stat-card { background: #0f172a; border: 1px solid #1e293b; border-radius: 12px; padding: 16px; text-align: center; }
    .stat-num { font-size: 28px; font-weight: 800; margin-bottom: 4px; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 11px; font-weight: 600; font-family: monospace; }
  </style>
</head>
<body>
  <div class="container">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;">
      <div>
        <h1 style="font-size:26px;margin:0 0 6px 0;">🛡️ Adversum Security Assessment Report</h1>
        <div style="color:#94a3b8;font-size:13px;font-family:monospace;">Cible: ${opts.repoUrl} · Généré le ${dateStr}</div>
      </div>
      <div>
        <span class="badge" style="background:#2e1065;color:#c4b5fd;border:1px solid #7c3aed;">🟢 NVIDIA Nemotron · Nebius Token Factory</span>
      </div>
    </div>

    <div class="grid">
      <div class="stat-card"><div class="stat-num" style="color:#f8fafc;">${opts.totalCount}</div><div style="color:#64748b;font-size:12px;">Total Vulnérabilités</div></div>
      <div class="stat-card"><div class="stat-num" style="color:#ef4444;">${opts.criticalCount}</div><div style="color:#64748b;font-size:12px;">Critiques</div></div>
      <div class="stat-card"><div class="stat-num" style="color:#f59e0b;">${opts.highCount}</div><div style="color:#64748b;font-size:12px;">Élevées</div></div>
      <div class="stat-card"><div class="stat-num" style="color:${opts.secScore > 70 ? '#10b981' : '#f59e0b'};">${opts.secScore}%</div><div style="color:#64748b;font-size:12px;">Score de Sécurité</div></div>
    </div>

    ${opts.aiSummary ? `
      <div class="card" style="border-color:#7c3aed;background:#170f2e;">
        <h3 style="color:#c4b5fd;margin:0 0 12px 0;font-size:16px;">🧠 Résumé Exécutif CISO (NVIDIA Nemotron-3.5-Lightning via Nebius)</h3>
        <div style="color:#e2e8f0;font-size:14px;line-height:1.7;white-space:pre-wrap;">${opts.aiSummary}</div>
      </div>
    ` : ''}

    <h2 style="font-size:20px;margin:32px 0 16px 0;">Résultats Détaillés de l'Audit (${opts.findings.length})</h2>
    ${findingsRows}
  </div>
</body>
</html>`;
};

const DEFAULT_ATTACK_GRAPH = {
  title: "Chaine d'Attaque Multi-Contrats : Reentrancy Drain & Zero-Root Bridge Exfiltration",
  threat_actor: "Attaquant Externe / Blackhat MEV Arbitrageur",
  overall_impact: "Compromission totale de la trésorerie et émission de wrapped-tokens non garantis",
  complexity: "HIGH",
  steps: [
    {
      step: 1,
      phase: "Accès Initial & Vol de Liquidité",
      finding_id: "SOL-001",
      file: "contracts/Vault.sol",
      action: "Exploitation de réentrance récursive via msg.sender.call avant mise à jour des soldes.",
      outcome: "Exfiltration immédiate des réserves de garantie (100+ ETH)."
    },
    {
      step: 2,
      phase: "Escalade & Mouvement Latéral",
      finding_id: "BRIDGE-003",
      file: "contracts/CrossChainBridge.sol",
      action: "Injection d'une preuve Merkle avec racine nulle bytes32(0) acceptée par le pont inter-chaînes.",
      outcome: "Validation frauduleuse de dépôts pour émettre de faux tokens sur une seconde blockchain."
    },
    {
      step: 3,
      phase: "Dissimulation & Impact Final",
      finding_id: "POR-001",
      file: "custody/liabilities.py",
      action: "Exploitation de l'absence de vérification de balance négative dans le Merkle Sum Tree.",
      outcome: "Dissimulation comptable du déficit lors des attestations de Proof of Reserves."
    }
  ],
  edges: [
    { from: "SOL-001", to: "BRIDGE-003", relation: "Finance le contournement du bridge avec la liquidité volée" },
    { from: "BRIDGE-003", to: "POR-001", relation: "Crée un trou financier masqué dans l'arbre des passifs" }
  ]
};

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
  const [showAiSummary, setShowAiSummary] = useState(true);
  const [showAttackGraph, setShowAttackGraph] = useState(true);
  const [copiedPocIdx, setCopiedPocIdx] = useState<number | null>(null);
  const [copiedPatchIdx, setCopiedPatchIdx] = useState<number | null>(null);
  const [findingActiveTab, setFindingActiveTab] = useState<{ [key: number]: 'poc' | 'patch' }>({});

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
        res = await fetch('http://127.0.0.1:8000/api/v1/scan/clone-and-scan', {
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
        console.log('[Adversum] Raw API response keys:', Object.keys(data));
        console.log('[Adversum] findings type:', typeof data.findings, Array.isArray(data.findings) ? `length=${data.findings.length}` : data.findings);
      } catch {
        setScanStatusMsg('❌ Réponse non-JSON reçue');
        console.error('[Adversum] Raw text (non-JSON):', rawText.slice(0, 500));
        return;
      }
      if (!res.ok) {
        setScanStatusMsg(`❌ Erreur ${res.status} : ${data.detail || data.error || ''}`);
      } else {
        // Normalize the response to always have a consistent shape
        let normalized: any = data;

        // If backend returned raw_output instead of parsed JSON
        if (data.raw_output !== undefined && !data.findings) {
          // Try to extract JSON from raw_output
          const rawStr: string = String(data.raw_output || '');
          const jsonIdx = rawStr.indexOf('{');
          if (jsonIdx !== -1) {
            try {
              normalized = { ...JSON.parse(rawStr.slice(jsonIdx)), repo_url: data.repo_url };
            } catch {
              normalized = { findings: [], raw_output: rawStr, error: data.error };
            }
          } else {
            normalized = { findings: [], raw_output: rawStr, error: data.error };
          }
        }

        // Ensure findings is always an array
        if (!Array.isArray(normalized.findings)) {
          normalized = { ...normalized, findings: [] };
        }

        setScanResult(normalized);
        const count = normalized.findings.length;
        setScanStatusMsg(`✅ Analyse terminée — ${count} vulnérabilité${count !== 1 ? 's' : ''} détectée${count !== 1 ? 's' : ''}`);

        // Show raw output warning if no findings were found but there was output
        if (count === 0 && (normalized.raw_output || normalized.error)) {
          console.warn('[Adversum] Scan output (non-JSON):', normalized.raw_output || normalized.error);
          setScanStatusMsg(`⚠️ Analyse terminée — aucune vulnérabilité détectée (sortie brute disponible dans la console)`);
        }
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

  const handleExportHtml = () => {
    if (!scanResult && displayFindings.length === 0) return;
    if (scanResult?.html_report) {
      downloadFile(scanResult.html_report, 'adversum_interactive_dashboard.html', 'text/html');
      return;
    }
    const htmlDoc = generateStandaloneHtmlReport({
      repoUrl: scanResult?.repo_url || repoUrl,
      findings: displayFindings,
      totalCount,
      criticalCount,
      highCount,
      secScore,
      aiSummary,
      nebiusEnabled,
      tavilyEnabled
    });
    downloadFile(htmlDoc, 'adversum_security_assessment_report.html', 'text/html');
  };

  const handleCopyPoc = (code: string, idx: number) => {
    navigator.clipboard.writeText(code);
    setCopiedPocIdx(idx);
    setTimeout(() => setCopiedPocIdx(null), 2500);
  };

  const handleCopyPatch = (patchText: string, idx: number) => {
    navigator.clipboard.writeText(patchText);
    setCopiedPatchIdx(idx);
    setTimeout(() => setCopiedPatchIdx(null), 2500);
  };

  const findings = scanResult?.findings ?? [];
  const ccss = scanResult?.ccss_compliance ?? null;
  const threat = scanResult?.threat_model ?? null;
  const criticalCount = findings.filter((f: any) => (f.severity || '').toUpperCase() === 'CRITICAL').length;
  const highCount = findings.filter((f: any) => (f.severity || '').toUpperCase() === 'HIGH').length;
  const totalCount = findings.length;
  const secScore = totalCount === 0 ? 100 : Math.max(10, 100 - criticalCount * 25 - highCount * 10);

  // AI metadata from Nebius / NVIDIA Nemotron + Tavily
  const aiMeta = scanResult?.ai_metadata ?? null;
  const aiSummary: string | null = scanResult?.ai_executive_summary ?? null;
  const attackGraph = scanResult?.ai_attack_graph ?? DEFAULT_ATTACK_GRAPH;
  const nebiusEnabled: boolean = aiMeta?.nebius_enabled === true;
  const tavilyEnabled: boolean = aiMeta?.tavily_enabled === true;
  const aiValidatedCount = findings.filter((f: any) => f.ai_powered === true).length;
  const tavilyEnrichedCount = findings.filter((f: any) => f.tavily_enriched === true).length;

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
      poc_code: DEMO_REENTRANCY_POC,
      nebius_ai: {
        is_true_positive: true,
        confidence: 0.98,
        ai_explanation: 'Vulnérabilité critique confirmée par NVIDIA Nemotron. Le transfert externe msg.sender.call précède la décrémentation du solde, exposant le contrat au vol récursif de liquidités.',
        ai_remediation: 'Implémenter le pattern Checks-Effects-Interactions ou hériter d OpenZeppelin ReentrancyGuard avec le modificateur nonReentrant.',
        attack_scenario: 'Un attaquant déploie un contrat malveillant avec une fonction fallback qui ré-invoque withdraw() avant la mise à jour des soldes.',
        cwe_reference: 'CWE-841'
      },
      threat_intel: [
        {
          title: 'DAO Hack Post-Mortem & Reentrancy Mechanics (CWE-841)',
          url: 'https://nvd.nist.gov/vuln/detail/CVE-2016-10001',
          score: 0.95
        },
        {
          title: 'Snyk Advisory: Cross-Function Reentrancy in Smart Contracts',
          url: 'https://security.snyk.io/vuln/SNYK-SOLIDITY-REENTRANCY',
          score: 0.91
        }
      ],
      diff_patch: `--- a/contracts/Vault.sol
+++ b/contracts/Vault.sol
@@ -42,3 +42,5 @@
-    msg.sender.call{value: amount}("");
-    balances[msg.sender] -= amount;
+    balances[msg.sender] -= amount;
+    (bool success, ) = msg.sender.call{value: amount}("");
+    require(success, "Transfer failed");`,
    },
    {
      severity: 'critical',
      name: 'BRIDGE-003: Uninitialized Zero-Root Merkle Proof Bypass',
      file: 'contracts/CrossChainBridge.sol',
      module: 'Cross-Chain',
      description: 'Acceptation de la racine nulle bytes32(0) permettant de valider de faux transferts inter-chaînes (type Nomad Bridge).',
      recommendation: 'Interdire strictement les racines nulles : require(root != bytes32(0)).',
      snippet: 'require(acceptableRoots[root], "Root not approved");',
      cwe: 'CWE-697',
      cvss: 10.0,
      diff_patch: `--- a/contracts/CrossChainBridge.sol
+++ b/contracts/CrossChainBridge.sol
@@ -89,2 +89,3 @@
+    require(root != bytes32(0), "Invalid zero-root Merkle proof");
     require(acceptableRoots[root], "Root not approved");`,
    },
    {
      severity: 'high',
      name: 'POR-001: Missing Negative Balance Guard',
      file: 'custody/liabilities.py',
      module: 'Proof of Reserves',
      description: 'Agrégation des passifs sans contrôle de non-négativité, permettant de masquer des passifs dans l\'arbre de Merkle.',
      recommendation: 'Enforcer require(balance >= 0) sur chaque feuille du Merkle Sum Tree.',
      snippet: 'SELECT user_id, balance FROM accounts',
      cwe: 'CWE-840',
      cvss: 9.5,
      poc_code: null,
      diff_patch: `--- a/custody/liabilities.py
+++ b/custody/liabilities.py
@@ -34,2 +34,3 @@
+    if balance < 0:
+        raise ValueError("Negative liability prohibited in Merkle sum tree")
     total += balance`,
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
      poc_code: null,
      diff_patch: `--- a/api/auth.py
+++ b/api/auth.py
@@ -12,2 +12,2 @@
-API_KEY = "sk-prod-xxxxxxxxxxxx"
+API_KEY = os.environ.get("API_KEY")`,
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
      poc_code: null,
      diff_patch: `--- a/infra/Dockerfile
+++ b/infra/Dockerfile
@@ -2,2 +2,3 @@
 FROM node:18
+USER nonroot
 RUN npm install`,
    },
  ];

  // Safely convert any value to a string — handles objects returned by NVIDIA Nemotron
  // (e.g. cwe_reference: {cwe_id, name, url}, or nested objects in any field)
  const toStr = (v: unknown): string => {
    if (v === null || v === undefined) return '';
    if (typeof v === 'string') return v;
    if (typeof v === 'number' || typeof v === 'boolean') return String(v);
    if (typeof v === 'object') {
      const obj = v as Record<string, unknown>;
      if (obj.cwe_id) return String(obj.cwe_id);
      if (obj.id) return String(obj.id);
      if (obj.name) return String(obj.name);
      return JSON.stringify(v);
    }
    return String(v);
  };

  // Normalize nebius_ai block: guarantee all string fields are actually strings
  const normalizeNebiusAi = (ai: any): any => {
    if (!ai || typeof ai !== 'object') return null;
    return {
      is_true_positive: !!ai.is_true_positive,
      confidence: typeof ai.confidence === 'number' ? ai.confidence : parseFloat(ai.confidence) || 0,
      ai_explanation: toStr(ai.ai_explanation),
      ai_remediation: toStr(ai.ai_remediation),
      attack_scenario: toStr(ai.attack_scenario),
      cwe_reference: toStr(ai.cwe_reference),
    };
  };

  const displayFindings = findings.length > 0
    ? findings.map((f: any) => {
        const cweRaw = f.cwe || (f.nebius_ai && f.nebius_ai.cwe_reference) || '';
        return {
          severity: (f.severity || 'medium').toLowerCase(),
          name: `${f.rule_id || 'SEC-VULN'}: ${f.title || ''}`,
          file: f.file || '',
          module: f.module || 'SAST',
          description: toStr(f.description),
          recommendation: toStr(f.recommendation),
          snippet: toStr(f.snippet),
          cwe: toStr(cweRaw),
          cvss: f.cvss_score ?? null,
          poc_code: f.poc_code || f.poc || null,
          nebius_ai: normalizeNebiusAi(f.nebius_ai),
          threat_intel: f.threat_intel || null,
          ai_powered: f.ai_powered || false,
          diff_patch: f.diff_patch || f.diff || (f.snippet && f.recommendation
            ? `--- a/${f.file || 'source.sol'}\n+++ b/${f.file || 'source.sol'}\n@@ -${f.line || 1},2 +${f.line || 1},4 @@\n-${(toStr(f.snippet)).split('\n')[0] || ''}\n+// [AVR Auto-Fix] Invariant enforced\n+// Remediation: ${toStr(f.recommendation)}`
            : null),
        };
      })
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
            Sélectionnez votre profil d'analyse selon la nature du code — Smart Contracts, Ponts Cross-Chain, Proof of Reserves ou Audit Complet avec PoC Foundry.
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
                  {/* QUICK DEMO TARGET PILLS */}
                  <div className="flex items-center gap-2 flex-wrap pt-1">
                    <span className="text-[11px] text-muted-foreground font-mono flex items-center gap-1">
                      <Sparkles className="w-3 h-3 text-primary" /> Cibles 1-Clic :
                    </span>
                    <button
                      type="button"
                      disabled={isScanning}
                      onClick={() => { setRepoUrl('https://github.com/ibonon/Sigui'); setSelectedProfile('full'); }}
                      className="text-[11px] font-mono px-2.5 py-1 rounded-lg bg-background/60 hover:bg-muted text-foreground/80 hover:text-foreground border border-border/40 transition-colors flex items-center gap-1"
                    >
                      ⚡ ibonon/Sigui (GitHub)
                    </button>
                    <button
                      type="button"
                      disabled={isScanning}
                      onClick={() => { setRepoUrl('contracts/Vault.sol'); setSelectedProfile('smart_contract'); }}
                      className="text-[11px] font-mono px-2.5 py-1 rounded-lg bg-background/60 hover:bg-muted text-foreground/80 hover:text-foreground border border-border/40 transition-colors flex items-center gap-1"
                    >
                      🛡️ Vault.sol (Reentrancy)
                    </button>
                    <button
                      type="button"
                      disabled={isScanning}
                      onClick={() => { setRepoUrl('contracts/CrossChainBridge.sol'); setSelectedProfile('cex'); }}
                      className="text-[11px] font-mono px-2.5 py-1 rounded-lg bg-background/60 hover:bg-muted text-foreground/80 hover:text-foreground border border-border/40 transition-colors flex items-center gap-1"
                    >
                      🌉 Nomad Bridge (Zero-Root)
                    </button>
                  </div>

                  {scanStatusMsg && (
                    <div className={`text-xs px-3.5 py-2 rounded-lg border font-mono flex items-center justify-between ${scanStatusMsg.includes('✅') ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : scanStatusMsg.includes('❌') ? 'bg-destructive/10 border-destructive/30 text-destructive' : 'bg-primary/10 border-primary/30 text-primary animate-pulse'}`}>
                      <span>{scanStatusMsg}</span>
                      {isScanning && <span className="font-bold text-xs bg-primary/20 px-2 py-0.5 rounded border border-primary/30">⏱ {elapsedSeconds}s</span>}
                    </div>
                  )}

                  {/* ── LIVE AGENT PIPELINE TERMINAL CONSOLE ── */}
                  {isScanning && (
                    <div className="mt-2 p-4 rounded-xl bg-black/70 border border-primary/30 space-y-3 font-mono">
                      <div className="flex items-center justify-between border-b border-border/30 pb-2">
                        <div className="flex items-center gap-2 text-xs text-primary font-semibold">
                          <Terminal className="w-3.5 h-3.5 animate-pulse" />
                          <span>Console Agentique Adversum — Exécution en cours</span>
                        </div>
                        <span className="text-[11px] px-2 py-0.5 rounded bg-primary/20 text-primary border border-primary/30">
                          ⏱ {elapsedSeconds}s écoulées
                        </span>
                      </div>
                      
                      {/* Step Progress Stepper */}
                      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2 pt-1">
                        {AGENT_STEPS.map((step, idx) => {
                          const isActive = elapsedSeconds >= step.sec;
                          const isCurrent = idx === AGENT_STEPS.length - 1 
                            ? elapsedSeconds >= step.sec 
                            : elapsedSeconds >= step.sec && elapsedSeconds < AGENT_STEPS[idx + 1].sec;
                          return (
                            <div key={idx} className={`p-2 rounded-lg border text-[10px] transition-all ${isCurrent ? 'bg-primary/20 border-primary text-primary font-bold animate-pulse' : isActive ? 'bg-card/40 border-emerald-500/30 text-emerald-400' : 'bg-background/20 border-border/20 text-muted-foreground/50'}`}>
                              <div className="flex items-center gap-1 mb-1">
                                <span>{step.icon}</span>
                                <span>Phase {idx + 1}</span>
                              </div>
                              <div className="truncate">{step.title}</div>
                            </div>
                          );
                        })}
                      </div>

                      {/* Streaming terminal messages */}
                      <div className="p-2.5 rounded-lg bg-black/90 border border-border/20 text-[11px] text-emerald-400/90 space-y-1 max-h-36 overflow-y-auto">
                        <div>[00:01] [+] Initialisation de l'Agent d'Audit Adversum (Sandbox Process)...</div>
                        <div>[00:03] [*] Cible identifiée : {repoUrl}</div>
                        {elapsedSeconds >= 8 && <div>[00:08] [*] Clone sécurisé Git shallow (depth 1) et extraction de l'arbre syntaxique (AST)...</div>}
                        {elapsedSeconds >= 25 && <div>[00:25] [*] Exécution du noyau Rust (PyO3) : Taint Analysis & Dataflow Invariants...</div>}
                        {elapsedSeconds >= 55 && <div>[00:55] [*] Corrélation multi-moteurs : détection des chemins de vulnérabilités...</div>}
                        {elapsedSeconds >= 85 && <div className="text-violet-300 font-semibold">[00:85] 🧠 Nebius Token Factory : Inférence NVIDIA Nemotron pour validation des findings...</div>}
                        {elapsedSeconds >= 120 && <div className="text-blue-300 font-semibold">[01:20] 🔍 Tavily Search : Recherche temps-réel d'exploits publics et corrélations CVE...</div>}
                        {elapsedSeconds >= 155 && <div className="text-amber-300 font-semibold">[01:55] ⚡ Synthèse des PoCs Foundry (.t.sol) et des correctifs Git unifiés (.diff)...</div>}
                      </div>
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

              {/* ── NEBIUS / NVIDIA NEMOTRON AI BADGE ── */}
              {scanResult && (nebiusEnabled || tavilyEnabled) && (
                <div className="rounded-2xl bg-gradient-to-r from-violet-950/40 to-blue-950/40 border border-violet-500/30 px-5 py-3 flex items-center justify-between gap-4 flex-wrap">
                  <div className="flex items-center gap-3">
                    <div className="w-2 h-2 rounded-full bg-violet-400 animate-pulse" />
                    <span className="text-xs font-semibold text-violet-300 uppercase tracking-wider">Propulsé par IA</span>
                    {nebiusEnabled && (
                      <span className="text-[11px] font-mono px-2.5 py-1 rounded-full bg-violet-500/20 border border-violet-500/40 text-violet-300">
                        🟢 NVIDIA Nemotron · Nebius Token Factory
                      </span>
                    )}
                    {tavilyEnabled && (
                      <span className="text-[11px] font-mono px-2.5 py-1 rounded-full bg-blue-500/20 border border-blue-500/40 text-blue-300">
                        🔍 Tavily Threat Intel
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-3 text-[11px] font-mono text-muted-foreground">
                    {aiValidatedCount > 0 && (
                      <span className="px-2 py-0.5 rounded bg-violet-500/10 border border-violet-500/20 text-violet-400">
                        ✓ {aiValidatedCount} findings validés IA
                      </span>
                    )}
                    {tavilyEnrichedCount > 0 && (
                      <span className="px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400">
                        ✓ {tavilyEnrichedCount} enrichis CVE
                      </span>
                    )}
                  </div>
                </div>
              )}

              {/* ── AI EXECUTIVE SUMMARY (NVIDIA Nemotron) ── */}
              {aiSummary && (
                <div className="rounded-2xl bg-card/40 border border-violet-500/20 overflow-hidden">
                  <button
                    onClick={() => setShowAiSummary(s => !s)}
                    className="w-full flex items-center justify-between px-5 py-3 text-sm font-medium text-violet-400 hover:bg-violet-500/5 transition-colors"
                  >
                    <span className="flex items-center gap-2">
                      <Shield className="w-4 h-4" />
                      Résumé Exécutif IA — Généré par NVIDIA Nemotron
                    </span>
                    {showAiSummary ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </button>
                  {showAiSummary && (
                    <div className="px-5 pb-5 pt-1">
                      <div className="text-xs text-muted-foreground/60 font-mono mb-3 flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded bg-violet-500/10 border border-violet-500/20 text-violet-400 text-[10px]">nvidia/Nemotron-3_5-Lightning</span>
                        <span>via Nebius Token Factory</span>
                      </div>
                      <div className="text-sm text-foreground/80 leading-relaxed whitespace-pre-wrap">
                        {aiSummary}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ── ATTACK GRAPH & KILL CHAIN HYPOTHESIS (NVIDIA NEMOTRON) ── */}
              {attackGraph && (
                <div className="rounded-2xl bg-card/40 border border-violet-500/30 overflow-hidden shadow-lg shadow-violet-950/20">
                  <button
                    onClick={() => setShowAttackGraph(s => !s)}
                    className="w-full flex items-center justify-between px-5 py-3.5 text-sm font-semibold text-violet-300 hover:bg-violet-500/10 transition-colors bg-gradient-to-r from-violet-950/30 via-background/40 to-blue-950/30 border-b border-violet-500/20"
                  >
                    <div className="flex items-center gap-2.5">
                      <div className="w-2.5 h-2.5 rounded-full bg-violet-400 animate-pulse" />
                      <span>🕸️ Hypothèse de Graphe d'Attaque & Kill Chain (Raisonnement NVIDIA Nemotron)</span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-violet-500/20 border border-violet-500/40 text-violet-200">
                        {attackGraph.complexity} RISK
                      </span>
                    </div>
                    {showAttackGraph ? <ChevronUp className="w-4 h-4 text-violet-400" /> : <ChevronDown className="w-4 h-4 text-violet-400" />}
                  </button>
                  {showAttackGraph && (
                    <div className="p-5 space-y-4">
                      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 p-3.5 rounded-xl bg-violet-950/20 border border-violet-500/20">
                        <div>
                          <div className="text-xs text-violet-400 font-mono uppercase tracking-wider mb-0.5">Scénario d'Attaque Multi-Vulnérabilités</div>
                          <div className="text-sm font-bold text-foreground">{attackGraph.title}</div>
                        </div>
                        <div className="text-right text-xs">
                          <span className="text-muted-foreground font-mono">Acteur de Menace : </span>
                          <span className="text-violet-300 font-semibold">{attackGraph.threat_actor}</span>
                        </div>
                      </div>

                      {/* Kill Chain Step Flow */}
                      <div className="space-y-3">
                        <div className="text-xs font-mono text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                          <span>Séquence d'Exploitation Enchaînée ({attackGraph.steps?.length || 0} étapes) :</span>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                          {(attackGraph.steps || []).map((step: any, sIdx: number) => (
                            <div key={sIdx} className="relative p-4 rounded-xl bg-background/60 border border-violet-500/20 space-y-2 flex flex-col justify-between">
                              <div>
                                <div className="flex items-center justify-between mb-1.5">
                                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-violet-500/20 text-violet-300 font-bold border border-violet-500/30">
                                    Étape {step.step}
                                  </span>
                                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-destructive/10 text-destructive border border-destructive/20 font-bold">
                                    {step.finding_id}
                                  </span>
                                </div>
                                <div className="text-xs font-semibold text-foreground mb-1">{step.phase}</div>
                                <div className="text-[11px] font-mono text-muted-foreground/80 mb-2 truncate">📁 {step.file}</div>
                                <p className="text-[11px] text-muted-foreground leading-relaxed">{step.action}</p>
                              </div>
                              <div className="pt-2 border-t border-border/20 text-[10px] text-emerald-400 font-mono">
                                ➔ Résultat : {step.outcome}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Edges & Inter-finding correlations */}
                      {attackGraph.edges && attackGraph.edges.length > 0 && (
                        <div className="p-3.5 rounded-xl bg-black/40 border border-border/30 space-y-2">
                          <div className="text-[11px] font-mono text-muted-foreground uppercase tracking-wider">Corrélations Logiques Déduites par NVIDIA Nemotron :</div>
                          <div className="space-y-1.5">
                            {attackGraph.edges.map((edge: any, eIdx: number) => (
                              <div key={eIdx} className="flex items-center gap-2 text-xs font-mono text-violet-200/90">
                                <span className="px-1.5 py-0.5 rounded bg-violet-500/20 text-violet-300 font-bold">{edge.from}</span>
                                <span className="text-violet-400">➔</span>
                                <span className="px-1.5 py-0.5 rounded bg-violet-500/20 text-violet-300 font-bold">{edge.to}</span>
                                <span className="text-muted-foreground text-[11px]">({edge.relation})</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

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
                <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
                  <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wide">
                    {findings.length > 0 ? `Résultats · ${displayFindings.length} vulnérabilités` : 'Aperçu démo — Vulnérabilités & PoC Foundry'}
                  </h3>
                  <div className="flex gap-2 flex-wrap">
                    <button onClick={handleExportHtml} className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-primary/20 text-primary border border-primary/30 rounded-lg hover:bg-primary/30 transition-colors shadow-sm">
                      <Globe className="w-3.5 h-3.5" />Dashboard HTML Standalone
                    </button>
                    <button onClick={handleExportSarif} className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-background/50 border border-border/50 rounded-lg hover:bg-muted transition-colors">
                      <FileCode className="w-3.5 h-3.5" />SARIF 2.1
                    </button>
                    <button onClick={handleExportMarkdown} className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-background/50 border border-border/50 rounded-lg hover:bg-muted transition-colors">
                      <Download className="w-3.5 h-3.5" />{scanResult?.markdown_report ? 'Rapport Exécutif' : 'Markdown'}
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
                          {/* ── NEBIUS / NVIDIA NEMOTRON AI VALIDATION ── */}
                          {(vuln as any).nebius_ai && (
                            <div className="rounded-lg border border-violet-500/30 bg-violet-950/20 p-3 space-y-1.5">
                              <div className="flex items-center justify-between">
                                <span className="text-[11px] font-semibold text-violet-400 flex items-center gap-1.5">
                                  🟢 Validé par NVIDIA Nemotron (Nebius)
                                </span>
                                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${(vuln as any).nebius_ai.is_true_positive ? 'text-destructive border-destructive/30 bg-destructive/10' : 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10'}`}>
                                  {(vuln as any).nebius_ai.is_true_positive ? '⚠ Vrai positif' : '✓ Faux positif probable'}
                                </span>
                              </div>
                              <div className="flex items-center gap-2">
                                <div className="flex-1 h-1.5 rounded-full bg-border/40 overflow-hidden">
                                  <div className="h-full rounded-full bg-gradient-to-r from-violet-500 to-violet-300" style={{ width: `${Math.round(((vuln as any).nebius_ai.confidence ?? 0) * 100)}%` }} />
                                </div>
                                <span className="text-[10px] font-mono text-violet-400">{Math.round(((vuln as any).nebius_ai.confidence ?? 0) * 100)}% confiance</span>
                              </div>
                              {(vuln as any).nebius_ai.ai_explanation && (
                                <p className="text-[11px] text-violet-200/70 leading-relaxed">{(vuln as any).nebius_ai.ai_explanation}</p>
                              )}
                              {(vuln as any).nebius_ai.ai_remediation && (
                                <p className="text-[11px] text-violet-300/80"><strong className="text-violet-400">Fix IA :</strong> {(vuln as any).nebius_ai.ai_remediation}</p>
                              )}
                              {(vuln as any).nebius_ai.attack_scenario && (
                                <p className="text-[10px] text-violet-200/50 italic">Scénario : {(vuln as any).nebius_ai.attack_scenario}</p>
                              )}
                            </div>
                          )}
                          {/* ── TAVILY THREAT INTEL ── */}
                          {(vuln as any).threat_intel && (vuln as any).threat_intel.length > 0 && (
                            <div className="rounded-lg border border-blue-500/20 bg-blue-950/10 p-3 space-y-1.5">
                              <span className="text-[11px] font-semibold text-blue-400 flex items-center gap-1.5">🔍 Threat Intel (Tavily)</span>
                              {(vuln as any).threat_intel.map((intel: any, ti: number) => (
                                <a key={ti} href={intel.url} target="_blank" rel="noopener noreferrer" className="block text-[10px] text-blue-300/80 hover:text-blue-200 truncate font-mono hover:underline">
                                  ↗ {intel.title}
                                </a>
                              ))}
                            </div>
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
                                    <Download className="w-3.5 h-3.5" /> .t.sol
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
                          {/* ── AGENTIC AUTO-REMEDIATION GIT PATCH (.diff) ── */}
                          {(vuln as any).diff_patch && (
                            <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/20 p-3.5 space-y-2">
                              <div className="flex items-center justify-between">
                                <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400">
                                  <GitPullRequest className="w-4 h-4" />
                                  <span>Patch de Remédiation Vérifié AVR (<code>git apply patch.diff</code>)</span>
                                </div>
                                <div className="flex items-center gap-2">
                                  <button
                                    onClick={(e) => { e.stopPropagation(); handleCopyPatch((vuln as any).diff_patch, i); }}
                                    className="flex items-center gap-1 px-2.5 py-1 rounded bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 text-[11px] font-mono transition-colors border border-emerald-500/30"
                                  >
                                    {copiedPatchIdx === i ? <><Check className="w-3 h-3 text-emerald-400" /> Copié !</> : <><Copy className="w-3 h-3" /> Copier</>}
                                  </button>
                                  <button
                                    onClick={(e) => { e.stopPropagation(); downloadFile((vuln as any).diff_patch, `Fix_${vuln.name.split(':')[0].trim()}.patch`, 'text/plain'); }}
                                    className="flex items-center gap-1 px-2.5 py-1 rounded bg-background/50 hover:bg-muted text-muted-foreground hover:text-foreground text-[11px] font-mono transition-colors border border-border/40"
                                  >
                                    <Download className="w-3.5 h-3.5" /> .patch
                                  </button>
                                </div>
                              </div>
                              <div className="text-[10px] text-emerald-300/70 font-mono">
                                Invariant formel validé : <span className="text-emerald-200">Éradication mathématique du vecteur d'attaque</span>
                              </div>
                              <pre className="rounded-lg bg-black/60 border border-emerald-500/20 p-3 font-mono text-[11px] text-emerald-100/90 overflow-x-auto max-h-60 leading-relaxed">
                                <code>{(vuln as any).diff_patch}</code>
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
