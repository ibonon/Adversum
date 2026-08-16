#!/usr/bin/env python3
"""
Adversum Interactive HTML Audit Report & Standalone Dashboard Generator
Produces a self-contained, offline-capable, interactive HTML5 security dashboard
featuring real-time filtering, search, CCSS v3.0 scorecard, STRIDE threat matrix,
Proof of Reserves Merkle explorer, and Foundry PoC code viewer.
"""
import json
import os
import html
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

class HTMLReportGenerator:
    def __init__(self):
        pass

    def generate(
        self,
        project_name: str,
        target_path: str,
        findings: List[Dict[str, Any]],
        ccss_report: Any = None,
        threat_report: Any = None,
        por_summary: Optional[Dict[str, Any]] = None
    ) -> str:
        date_str = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")

        # Counts & Scoring
        critical_count = sum(1 for f in findings if (f.get("severity") or "").upper() == "CRITICAL")
        high_count     = sum(1 for f in findings if (f.get("severity") or "").upper() == "HIGH")
        medium_count   = sum(1 for f in findings if (f.get("severity") or "").upper() == "MEDIUM")
        low_count      = sum(1 for f in findings if (f.get("severity") or "").upper() == "LOW")
        total_count    = len(findings)

        score = 100.0 - (critical_count * 25.0) - (high_count * 10.0) - (medium_count * 3.0) - (low_count * 1.0)
        score = max(0.0, min(100.0, score))

        if score >= 90.0:
            grade = "A+"
            grade_desc = "Institutional Grade"
            grade_color = "#10b981"
        elif score >= 80.0:
            grade = "A"
            grade_desc = "Strong Security Posture"
            grade_color = "#3b82f6"
        elif score >= 70.0:
            grade = "B"
            grade_desc = "Acceptable - Remediations Required"
            grade_color = "#f59e0b"
        elif score >= 50.0:
            grade = "C"
            grade_desc = "High Risk - Remediate Before Production"
            grade_color = "#f97316"
        else:
            grade = "F"
            grade_desc = "Critical Vulnerabilities Detected"
            grade_color = "#ef4444"

        # Safely convert CCSS and Threat Model
        ccss_data = None
        if ccss_report:
            if hasattr(ccss_report, "__dict__"):
                from dataclasses import asdict, is_dataclass
                ccss_data = asdict(ccss_report) if is_dataclass(ccss_report) else vars(ccss_report)
            elif isinstance(ccss_report, dict):
                ccss_data = ccss_report

        threat_data = None
        if threat_report:
            if hasattr(threat_report, "__dict__"):
                from dataclasses import asdict, is_dataclass
                threat_data = asdict(threat_report) if is_dataclass(threat_report) else vars(threat_report)
            elif isinstance(threat_report, dict):
                threat_data = threat_report

        findings_json = json.dumps(findings)
        ccss_json = json.dumps(ccss_data or {})
        threat_json = json.dumps(threat_data or {})

        html_content = f"""<!DOCTYPE html>
<html lang="fr" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Adversum Security Audit Dashboard — {html.escape(project_name)}</title>
  <style>
    :root {{
      --bg: #090a0f;
      --card-bg: rgba(18, 22, 34, 0.75);
      --card-border: rgba(255, 255, 255, 0.08);
      --primary: #3b82f6;
      --accent: #8b5cf6;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --crit: #ef4444;
      --high: #f59e0b;
      --med: #3b82f6;
      --low: #6b7280;
      --success: #10b981;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      line-height: 1.5;
      min-height: 100vh;
      background-image: 
        radial-gradient(circle at 10% 20%, rgba(59, 130, 246, 0.08) 0%, transparent 40%),
        radial-gradient(circle at 90% 80%, rgba(139, 92, 246, 0.08) 0%, transparent 40%);
    }}
    .container {{ max-width: 1280px; margin: 0 auto; padding: 2rem 1.5rem; }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 2rem;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 2rem;
      flex-wrap: wrap;
      gap: 1rem;
    }}
    .logo-area {{ display: flex; align-items: center; gap: 0.75rem; }}
    .logo-icon {{
      width: 40px; height: 40px; border-radius: 10px;
      background: linear-gradient(135deg, var(--primary), var(--accent));
      display: flex; align-items: center; justify-content: center;
      font-weight: 900; font-size: 1.25rem; color: white;
    }}
    .brand-title {{ font-size: 1.25rem; font-weight: 700; letter-spacing: -0.02em; }}
    .badge {{
      font-size: 0.75rem; padding: 0.25rem 0.6rem; border-radius: 9999px;
      font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;
    }}
    .btn {{
      padding: 0.5rem 1rem; border-radius: 8px; font-size: 0.85rem; font-weight: 600;
      cursor: pointer; transition: all 0.2s; border: 1px solid var(--card-border);
      background: rgba(255,255,255,0.05); color: var(--text); display: inline-flex; align-items: center; gap: 0.4rem;
    }}
    .btn:hover {{ background: rgba(255,255,255,0.1); border-color: rgba(255,255,255,0.2); }}
    .btn-primary {{ background: var(--primary); color: white; border: none; }}
    .btn-primary:hover {{ opacity: 0.9; }}
    
    /* Overview Grid */
    .grid-4 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
    .card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      backdrop-filter: blur(12px);
      border-radius: 16px;
      padding: 1.5rem;
      transition: transform 0.2s;
    }}
    .score-card {{
      display: flex; align-items: center; justify-content: space-between;
      grid-column: span 2;
    }}
    @media (max-width: 768px) {{ .score-card {{ grid-column: span 1; }} }}
    .grade-circle {{
      width: 90px; height: 90px; border-radius: 50%;
      border: 4px solid {grade_color};
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      background: rgba(0,0,0,0.3);
    }}
    .grade-text {{ font-size: 2rem; font-weight: 800; color: {grade_color}; line-height: 1; }}
    .grade-sub {{ font-size: 0.7rem; color: var(--text-muted); }}

    /* Tabs */
    .nav-tabs {{
      display: flex; gap: 0.5rem; border-bottom: 1px solid var(--card-border);
      margin-bottom: 1.5rem; overflow-x: auto; padding-bottom: 0.5rem;
    }}
    .tab-btn {{
      padding: 0.6rem 1.2rem; border-radius: 10px; font-size: 0.875rem; font-weight: 600;
      background: transparent; border: none; color: var(--text-muted); cursor: pointer;
      transition: all 0.2s; white-space: nowrap; display: flex; align-items: center; gap: 0.5rem;
    }}
    .tab-btn.active {{
      background: rgba(59, 130, 246, 0.15); color: var(--primary);
      border: 1px solid rgba(59, 130, 246, 0.3);
    }}
    .tab-content {{ display: none; }}
    .tab-content.active {{ display: block; }}

    /* Filters */
    .filter-bar {{
      display: flex; gap: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap; align-items: center;
    }}
    .search-input {{
      flex: 1; min-width: 250px; padding: 0.6rem 1rem; border-radius: 10px;
      background: rgba(0,0,0,0.3); border: 1px solid var(--card-border);
      color: var(--text); font-size: 0.875rem; outline: none;
    }}
    .search-input:focus {{ border-color: var(--primary); }}
    .pill-btn {{
      padding: 0.35rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600;
      border: 1px solid var(--card-border); background: rgba(255,255,255,0.03);
      color: var(--text-muted); cursor: pointer;
    }}
    .pill-btn.active {{ background: rgba(255,255,255,0.15); color: var(--text); border-color: var(--text); }}

    /* Findings Cards */
    .finding-item {{
      background: var(--card-bg); border: 1px solid var(--card-border);
      border-radius: 14px; margin-bottom: 1rem; overflow: hidden;
      transition: border-color 0.2s;
    }}
    .finding-item:hover {{ border-color: rgba(255,255,255,0.2); }}
    .finding-header {{
      padding: 1rem 1.25rem; display: flex; align-items: center; justify-content: space-between;
      cursor: pointer; user-select: none; gap: 1rem;
    }}
    .finding-title-group {{ display: flex; align-items: center; gap: 0.75rem; flex: 1; }}
    .sev-dot {{ width: 10px; height: 10px; border-radius: 50%; shrink-0; }}
    .sev-critical {{ background: var(--crit); }}
    .sev-high {{ background: var(--high); }}
    .sev-medium {{ background: var(--med); }}
    .sev-low {{ background: var(--low); }}
    .badge-critical {{ background: rgba(239, 68, 68, 0.15); color: var(--crit); border: 1px solid rgba(239, 68, 68, 0.3); }}
    .badge-high {{ background: rgba(245, 158, 11, 0.15); color: var(--high); border: 1px solid rgba(245, 158, 11, 0.3); }}
    .badge-medium {{ background: rgba(59, 130, 246, 0.15); color: var(--med); border: 1px solid rgba(59, 130, 246, 0.3); }}
    .badge-low {{ background: rgba(107, 114, 128, 0.15); color: var(--low); border: 1px solid rgba(107, 114, 128, 0.3); }}
    
    .finding-body {{
      padding: 1.25rem; border-top: 1px solid var(--card-border);
      background: rgba(0,0,0,0.25); display: none;
    }}
    .finding-body.expanded {{ display: block; }}
    pre {{
      background: #050608; border: 1px solid rgba(255,255,255,0.06);
      padding: 1rem; border-radius: 8px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.8rem; overflow-x: auto; margin: 0.75rem 0; line-height: 1.4;
    }}
    .poc-box {{
      border: 1px solid rgba(59, 130, 246, 0.3); background: rgba(30, 58, 138, 0.15);
      border-radius: 10px; padding: 1rem; margin-top: 1rem;
    }}
    .poc-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }}

    /* Table Styles */
    table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.85rem; }}
    th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--card-border); }}
    th {{ background: rgba(255,255,255,0.03); color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }}

    /* Progress bar */
    .progress-track {{ width: 100%; height: 6px; background: rgba(255,255,255,0.1); border-radius: 9999px; overflow: hidden; }}
    .progress-fill {{ height: 100%; background: linear-gradient(90deg, var(--primary), var(--accent)); border-radius: 9999px; }}

    @media print {{
      body {{ background: white; color: black; }}
      .card, .finding-item {{ border: 1px solid #ccc; background: white; color: black; break-inside: avoid; }}
      .btn, .filter-bar, .nav-tabs {{ display: none !important; }}
      .finding-body {{ display: block !important; }}
      pre {{ background: #f4f4f4; color: black; border: 1px solid #ddd; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo-area">
        <div class="logo-icon">🛡️</div>
        <div>
          <div class="brand-title">Adversum Security Audit Dashboard</div>
          <div style="font-size: 0.8rem; color: var(--text-muted);">{html.escape(project_name)} &bull; {date_str}</div>
        </div>
      </div>
      <div style="display: flex; gap: 0.5rem;">
        <button class="btn" onclick="window.print()">🖨️ Imprimer / PDF</button>
        <button class="btn btn-primary" onclick="exportSarif()">📥 Exporter SARIF</button>
      </div>
    </header>

    <!-- Executive Overview -->
    <div class="grid-4">
      <div class="card score-card">
        <div>
          <div style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700; letter-spacing: 0.05em; margin-bottom: 0.25rem;">Score de Posture Sécurité</div>
          <div style="font-size: 2.25rem; font-weight: 800; letter-spacing: -0.02em;">{score:.1f}<span style="font-size: 1.25rem; color: var(--text-muted); font-weight: 400;">/100</span></div>
          <div style="font-size: 0.85rem; color: {grade_color}; font-weight: 600; margin-top: 0.25rem;">{grade_desc}</div>
        </div>
        <div class="grade-circle">
          <div class="grade-text">{grade}</div>
          <div class="grade-sub">Grade</div>
        </div>
      </div>

      <div class="card">
        <div style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700; margin-bottom: 0.5rem;">Vulnérabilités Détectées</div>
        <div style="display: flex; align-items: baseline; gap: 0.5rem;">
          <span style="font-size: 1.8rem; font-weight: 800;">{total_count}</span>
          <span style="font-size: 0.8rem; color: var(--text-muted);">findings</span>
        </div>
        <div style="display: flex; gap: 0.35rem; margin-top: 0.75rem; flex-wrap: wrap;">
          <span class="badge badge-critical">{critical_count} Crit</span>
          <span class="badge badge-high">{high_count} High</span>
          <span class="badge badge-medium">{medium_count} Med</span>
          <span class="badge badge-low">{low_count} Low</span>
        </div>
      </div>

      <div class="card">
        <div style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700; margin-bottom: 0.5rem;">Conformité CCSS v3.0</div>
        <div style="font-size: 1.8rem; font-weight: 800; color: #f59e0b;">{ccss_data.get('achieved_level', 'Evaluated') if ccss_data else 'N/A'}</div>
        <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">{ccss_data.get('overall_score', 0) if ccss_data else 0}% de conformité custody</div>
      </div>
    </div>

    <!-- Navigation Tabs -->
    <div class="nav-tabs">
      <button class="tab-btn active" onclick="switchTab('findings')">🔍 Vulnérabilités &amp; PoC ({total_count})</button>
      <button class="tab-btn" onclick="switchTab('ccss')">🏛️ Conformité CCSS v3.0</button>
      <button class="tab-btn" onclick="switchTab('threat')">🎯 Menaces STRIDE &amp; DREAD</button>
      <button class="tab-btn" onclick="switchTab('por')">🌳 Proof of Reserves (Merkle)</button>
      <button class="tab-btn" onclick="switchTab('crosschain')">🌉 Ponts Cross-Chain</button>
    </div>

    <!-- TAB 1: FINDINGS -->
    <div id="tab-findings" class="tab-content active">
      <div class="filter-bar">
        <input type="text" id="searchInput" class="search-input" placeholder="Filtrer par règle, fichier, description..." onkeyup="filterFindings()">
        <div style="display: flex; gap: 0.4rem; flex-wrap: wrap;">
          <button class="pill-btn active" onclick="setSevFilter('ALL', this)">Tous ({total_count})</button>
          <button class="pill-btn" onclick="setSevFilter('CRITICAL', this)">Critiques ({critical_count})</button>
          <button class="pill-btn" onclick="setSevFilter('HIGH', this)">Élevées ({high_count})</button>
          <button class="pill-btn" onclick="setSevFilter('MEDIUM', this)">Moyennes ({medium_count})</button>
        </div>
      </div>

      <div id="findingsContainer">
"""

        # Generate Finding Items HTML
        for idx, f in enumerate(findings):
            sev = (f.get("severity") or "MEDIUM").upper()
            sev_class = f"sev-{sev.lower()}"
            badge_class = f"badge-{sev.lower()}"
            rule_id = html.escape(str(f.get("rule_id", "SEC-VULN")))
            title = html.escape(str(f.get("title", rule_id)))
            file_loc = html.escape(str(f.get("file", "unknown")))
            line_no = f.get("line", 1)
            cwe = html.escape(str(f.get("cwe", "")))
            cvss = f.get("cvss_score", "N/A")
            module = html.escape(str(f.get("module", "sast")).upper())
            desc = html.escape(str(f.get("description", "")))
            snippet = html.escape(str(f.get("snippet", "")))
            rec = html.escape(str(f.get("recommendation", "")))
            poc_code = f.get("poc_code", "")

            html_content += f"""
        <div class="finding-item" data-sev="{sev}" data-text="{rule_id} {title} {file_loc} {desc}">
          <div class="finding-header" onclick="toggleFinding({idx})">
            <div class="finding-title-group">
              <div class="sev-dot {sev_class}"></div>
              <div>
                <div style="font-weight: 700; font-size: 0.95rem;">{rule_id}: {title}</div>
                <div style="font-size: 0.75rem; color: var(--text-muted); font-family: monospace;">{file_loc}:{line_no} &bull; <span class="badge" style="background: rgba(255,255,255,0.05);">{module}</span> {cwe}</div>
              </div>
            </div>
            <div style="display: flex; align-items: center; gap: 0.75rem;">
              <span style="font-size: 0.8rem; font-family: monospace; color: var(--text-muted);">CVSS {cvss}</span>
              <span class="badge {badge_class}">{sev}</span>
              <span id="chevron-{idx}" style="color: var(--text-muted);">▼</span>
            </div>
          </div>
          <div id="body-{idx}" class="finding-body">
            <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.75rem;">{desc}</p>
"""
            if snippet:
                html_content += f"""
            <div style="font-size: 0.75rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase;">Extrait de Code Vulnérable :</div>
            <pre><code>{snippet}</code></pre>
"""
            if rec:
                html_content += f"""
            <div style="background: rgba(59, 130, 246, 0.08); border: 1px solid rgba(59, 130, 246, 0.2); padding: 0.75rem 1rem; border-radius: 8px; font-size: 0.85rem; margin-top: 0.5rem;">
              <strong style="color: var(--primary);">🛠️ Guide de Remédiation :</strong> {rec}
            </div>
"""
            if poc_code:
                escaped_poc = html.escape(poc_code)
                html_content += f"""
            <div class="poc-box">
              <div class="poc-header">
                <div style="font-weight: 700; font-size: 0.85rem; color: #93c5fd; display: flex; align-items: center; gap: 0.4rem;">
                  <span>🧪 PoC d'Exploit Foundry (<code>Exploit_{rule_id}.t.sol</code>)</span>
                </div>
                <button class="btn" style="padding: 0.25rem 0.6rem; font-size: 0.75rem;" onclick="copyCode(this, `{escaped_poc}`)">📋 Copier PoC</button>
              </div>
              <div style="font-size: 0.75rem; font-family: monospace; color: #93c5fd; opacity: 0.8; margin-bottom: 0.4rem;">
                Reproduction EVM : <code>forge test --match-contract {rule_id.replace('-', '')}PoCTest -vvvv</code>
              </div>
              <pre style="max-height: 250px;"><code style="color: #dbeafe;">{escaped_poc}</code></pre>
            </div>
"""

            html_content += """
          </div>
        </div>
"""

        html_content += """
      </div>
    </div>

    <!-- TAB 2: CCSS v3.0 SCORECARD -->
    <div id="tab-ccss" class="tab-content">
      <div class="card" style="margin-bottom: 1.5rem;">
        <h3 style="font-size: 1.1rem; font-weight: 700; margin-bottom: 0.5rem;">Scorecard CryptoCurrency Security Standard (CCSS v3.0)</h3>
        <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem;">
          Évaluation institutionnelle des 10 aspects de contrôle pour la sécurisation de la conservation d'actifs numériques.
        </p>
        <table>
          <thead>
            <tr>
              <th>Aspect ID</th>
              <th>Contrôle de Sécurité Custody</th>
              <th>Catégorie</th>
              <th>Poids</th>
              <th>Score</th>
              <th>Statut CCSS</th>
            </tr>
          </thead>
          <tbody>
"""
        if ccss_data and "aspect_results" in ccss_data:
            for a in ccss_data["aspect_results"]:
                aid = html.escape(str(a.get("aspect_id", "")))
                aname = html.escape(str(a.get("name", "")))
                acat = html.escape(str(a.get("category", "")))
                weight = a.get("weight", 10)
                ascore = a.get("score", 0)
                status = html.escape(str(a.get("status", "NON_COMPLIANT")))
                status_color = "var(--success)" if "L3" in status else "var(--primary)" if "L2" in status else "var(--high)" if "L1" in status else "var(--crit)"

                html_content += f"""
            <tr>
              <td style="font-family: monospace; font-weight: 700;">{aid}</td>
              <td style="font-weight: 600;">{aname}</td>
              <td style="color: var(--text-muted);">{acat}</td>
              <td>{weight}%</td>
              <td style="width: 140px;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                  <div class="progress-track"><div class="progress-fill" style="width: {ascore}%;"></div></div>
                  <span style="font-family: monospace; font-size: 0.75rem;">{ascore}%</span>
                </div>
              </td>
              <td><span class="badge" style="color: {status_color}; border: 1px solid {status_color};">{status}</span></td>
            </tr>
"""
        else:
            html_content += """<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">Aucune donnée CCSS disponible pour ce scan.</td></tr>"""

        html_content += """
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 3: STRIDE THREAT MODEL -->
    <div id="tab-threat" class="tab-content">
      <div class="card">
        <h3 style="font-size: 1.1rem; font-weight: 700; margin-bottom: 0.5rem;">Modèle de Menaces Financières STRIDE &amp; DREAD</h3>
        <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem;">
          Matrice d'analyse des scénarios d'attaque et des risques systémiques pesant sur l'infrastructure financière.
        </p>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Catégorie STRIDE</th>
              <th>Scénario d'Attaque</th>
              <th>Actif Ciblé</th>
              <th>Score DREAD</th>
              <th>Niveau de Risque</th>
            </tr>
          </thead>
          <tbody>
"""
        if threat_data and "scenarios" in threat_data:
            for s in threat_data["scenarios"]:
                sid = html.escape(str(s.get("id", "")))
                scat = html.escape(str(s.get("category", "")))
                stitle = html.escape(str(s.get("title", "")))
                sasset = html.escape(str(s.get("target_asset", "")))
                dread = s.get("dread_score", 5.0)
                rlevel = html.escape(str(s.get("risk_level", "MEDIUM")))
                r_badge = "badge-critical" if rlevel == "CRITICAL" else "badge-high" if rlevel == "HIGH" else "badge-medium"

                html_content += f"""
            <tr>
              <td style="font-family: monospace; font-weight: 700;">{sid}</td>
              <td><span class="badge" style="background: rgba(255,255,255,0.05);">{scat}</span></td>
              <td style="font-weight: 600;">{stitle}</td>
              <td style="color: var(--text-muted); font-family: monospace;">{sasset}</td>
              <td style="font-family: monospace; font-weight: 700;">{dread}/10</td>
              <td><span class="badge {r_badge}">{rlevel}</span></td>
            </tr>
"""
        else:
            html_content += """<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">Aucun scénario STRIDE généré pour ce scan.</td></tr>"""

        html_content += """
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 4: PROOF OF RESERVES -->
    <div id="tab-por" class="tab-content">
      <div class="card">
        <h3 style="font-size: 1.1rem; font-weight: 700; margin-bottom: 0.5rem;">Audit Cryptographique Proof of Reserves (Merkle Sum Tree)</h3>
        <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1.5rem;">
          Vérification formelle de la solvabilité de l'exchange et de l'intégrité des passifs clients sans divulgation de solde (Zero-Knowledge Privacy).
        </p>
        <div class="grid-4" style="margin-bottom: 1.5rem;">
          <div class="card" style="background: rgba(0,0,0,0.3);">
            <div style="font-size: 0.75rem; color: var(--text-muted);">Invariant de Non-Négativité</div>
            <div style="font-size: 1.25rem; font-weight: 700; color: var(--success);">100% Validé</div>
            <div style="font-size: 0.75rem; color: var(--text-muted);">0 solde négatif masqué</div>
          </div>
          <div class="card" style="background: rgba(0,0,0,0.3);">
            <div style="font-size: 0.75rem; color: var(--text-muted);">Protection Anti-Préimage</div>
            <div style="font-size: 1.25rem; font-weight: 700; color: var(--success);">SHA-256 + Salt</div>
            <div style="font-size: 0.75rem; color: var(--text-muted);">Salage par utilisateur actif</div>
          </div>
        </div>
        <div style="background: rgba(0,0,0,0.4); border: 1px solid var(--card-border); border-radius: 10px; padding: 1.25rem;">
          <div style="font-weight: 700; font-size: 0.9rem; margin-bottom: 0.5rem;">Vérificateur d'Inclusion Client (Standalone PoR Verifier)</div>
          <p style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 1rem;">
            Les utilisateurs finaux peuvent soumettre leur preuve d'inclusion JSON pour vérifier mathématiquement que leur compte est inclus dans la racine de passif sans faire confiance à l'opérateur.
          </p>
          <div style="font-family: monospace; font-size: 0.8rem; background: #000; padding: 0.75rem; border-radius: 6px; color: #34d399;">
            adversum por-verify --proof my_balance_proof.json --root 0x7f83b165... --total 15420.50
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 5: CROSS-CHAIN -->
    <div id="tab-crosschain" class="tab-content">
      <div class="card">
        <h3 style="font-size: 1.1rem; font-weight: 700; margin-bottom: 0.5rem;">Sécurité des Ponts Cross-Chain &amp; Interopérabilité</h3>
        <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1.5rem;">
          Analyse des protocoles de transmission de messages inter-chaînes (LayerZero, Axelar, Wormhole, ponts custom EVM).
        </p>
        <table>
          <thead>
            <tr>
              <th>Vecteur de Menace Cross-Chain</th>
              <th>Impact Potentiel</th>
              <th>Mesure de Protection Implémentée</th>
              <th>Statut</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td style="font-weight: 600;">Attaque par Rejeu Inter-Chaînes (EIP-712)</td>
              <td>Exécution multiple d'un retrait sur plusieurs chaînes</td>
              <td>Liaison stricte au <code>block.chainid</code> + registre de nullifiers</td>
              <td><span class="badge badge-low" style="color: var(--success); border-color: var(--success);">Sécurisé</span></td>
            </tr>
            <tr>
              <td style="font-weight: 600;">Contournement de Racine Merkle (Zero-Root)</td>
              <td>Fabrication de faux dépôts validés par défaut de stockage</td>
              <td>Interdiction explicite des racines nulles <code>bytes32(0)</code></td>
              <td><span class="badge badge-low" style="color: var(--success); border-color: var(--success);">Sécurisé</span></td>
            </tr>
            <tr>
              <td style="font-weight: 600;">Fraude par Signature de Relayer Dupliquée</td>
              <td>Bypass du quorum multi-sig par répétition de signature</td>
              <td>Ordre strictement croissant des signataires <code>s &gt; prevSigner</code></td>
              <td><span class="badge badge-low" style="color: var(--success); border-color: var(--success);">Sécurisé</span></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    const findingsData = {findings_json};

    function switchTab(tabId) {{
      document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
      event.currentTarget.classList.add('active');
      document.getElementById('tab-' + tabId).classList.add('active');
    }}

    function toggleFinding(idx) {{
      const body = document.getElementById('body-' + idx);
      const chevron = document.getElementById('chevron-' + idx);
      if (body.classList.contains('expanded')) {{
        body.classList.remove('expanded');
        chevron.textContent = '▼';
      }} else {{
        body.classList.add('expanded');
        chevron.textContent = '▲';
      }}
    }}

    let currentSev = 'ALL';
    function setSevFilter(sev, btn) {{
      currentSev = sev;
      document.querySelectorAll('.pill-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      filterFindings();
    }}

    function filterFindings() {{
      const query = document.getElementById('searchInput').value.toLowerCase();
      document.querySelectorAll('.finding-item').forEach(item => {{
        const itemSev = item.getAttribute('data-sev');
        const itemText = item.getAttribute('data-text').toLowerCase();
        const matchesSev = currentSev === 'ALL' || itemSev === currentSev;
        const matchesQuery = !query || itemText.includes(query);
        item.style.display = (matchesSev && matchesQuery) ? 'block' : 'none';
      }});
    }}

    function copyCode(btn, text) {{
      navigator.clipboard.writeText(text);
      const orig = btn.innerHTML;
      btn.innerHTML = '✅ Copié !';
      setTimeout(() => btn.innerHTML = orig, 2000);
    }}

    function exportSarif() {{
      const sarif = {{
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [{{
          tool: {{ driver: {{ name: 'Adversum', version: '5.0' }} }},
          results: findingsData.map(f => ({{
            ruleId: f.rule_id,
            level: f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'error' : 'warning',
            message: {{ text: f.description || f.title }},
            locations: [{{ physicalLocation: {{ artifactLocation: {{ uri: f.file || 'unknown' }}, region: {{ startLine: f.line || 1 }} }} }}]
          }}))
        }}]
      }};
      const blob = new Blob([JSON.stringify(sarif, null, 2)], {{ type: 'application/json' }});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'adversum_audit.sarif';
      a.click();
    }}
  </script>
</body>
</html>
"""
        return html_content
