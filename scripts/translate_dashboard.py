from pathlib import Path

path = Path(r"c:\Users\SMC-DXB\Projects\Adversum\frontend\src\components\DashboardPreview.tsx")
text = path.read_text(encoding="utf-8")

replacements = [
    # Report HTML
    ("Cible: ${opts.repoUrl} · Généré le ${dateStr}", "Target: ${opts.repoUrl} · Generated on ${dateStr}"),
    ("Total Vulnérabilités", "Total Vulnerabilities"),
    ("Critiques", "Critical"),
    ("Élevées", "High"),
    ("Score de Sécurité", "Security Score"),
    ("🧠 Résumé Exécutif CISO (NVIDIA Nemotron-3.5-Lightning via Nebius)",
     "🧠 CISO Executive Summary (NVIDIA Nemotron-3.5-Lightning via Nebius)"),
    ("Résultats Détaillés de l'Audit", "Detailed Audit Findings"),
    ("VALIDÉ PAR NVIDIA NEMOTRON", "VALIDATED BY NVIDIA NEMOTRON"),
    ("Recommandation Corrective :", "Remediation Recommendation:"),

    # Attack Graph
    ('title: "Chaine d\'Attaque Multi-Contrats : Reentrancy Drain & Zero-Root Bridge Exfiltration"',
     'title: "Multi-Contract Attack Chain: Reentrancy Drain & Zero-Root Bridge Exfiltration"'),
    ('threat_actor: "Attaquant Externe / Blackhat MEV Arbitrageur"',
     'threat_actor: "External Adversary / Blackhat MEV Arbitrageur"'),
    ('overall_impact: "Compromission totale de la trésorerie et émission de wrapped-tokens non garantis"',
     'overall_impact: "Total treasury drain and unbacked wrapped-token minting"'),
    ('phase: "Accès Initial & Vol de Liquidité"', 'phase: "Initial Access & Liquidity Drain"'),
    ('action: "Exploitation de réentrance récursive via msg.sender.call avant mise à jour des soldes."',
     'action: "Recursive reentrancy exploit via msg.sender.call prior to balance state update."'),
    ('outcome: "Exfiltration immédiate des réserves de garantie (100+ ETH)."',
     'outcome: "Immediate exfiltration of collateral reserves (100+ ETH)."'),
    ('phase: "Escalade & Mouvement Latéral"', 'phase: "Privilege Escalation & Lateral Movement"'),
    ('action: "Injection d\'une preuve Merkle avec racine nulle bytes32(0) acceptée par le pont inter-chaînes."',
     'action: "Injection of zero-root bytes32(0) Merkle proof accepted by cross-chain bridge."'),
    ('outcome: "Validation frauduleuse de dépôts pour émettre de faux tokens sur une seconde blockchain."',
     'outcome: "Fraudulent deposit validation minting synthetic tokens on destination chain."'),
    ('phase: "Dissimulation & Impact Final"', 'phase: "Evasion & Balance Concealment"'),
    ('action: "Exploitation de l\'absence de vérification de balance négative dans le Merkle Sum Tree."',
     'action: "Exploitation of missing negative balance checks in Merkle Sum Tree."'),
    ('outcome: "Dissimulation comptable du déficit lors des attestations de Proof of Reserves."',
     'outcome: "Accounting concealment of solvency deficit during Proof of Reserves attestations."'),
    ('relation: "Finance le contournement du bridge avec la liquidité volée"',
     'relation: "Funds bridge exploit using drained liquidity"'),
    ('relation: "Crée un trou financier masqué dans l\'arbre des passifs"',
     'relation: "Creates masked liability deficit in Proof of Reserves tree"'),

    # UI buttons and labels
    ("Scanner le code", "Scan Target"),
    ("Analyse en cours...", "Analysis in progress..."),
    ("Télécharger le rapport", "Download Full Report"),
    ("Vulnérabilités Détectées", "Vulnerabilities Detected"),
    ("Graphe d'Attaque Multi-Contrats", "Multi-Contract Attack Graph"),
    ("Preuve Formelle SMT", "SMT Formal Proof"),
    ("Vérification Formelle Z3", "Z3 Formal Verification"),
    ("Score Global", "Global Security Score"),
    ("Aucune vulnérabilité trouvée", "No vulnerabilities detected"),
    ("Rapport HTML interactif généré avec succès", "Interactive HTML report generated successfully"),
]

for src, dst in replacements:
    text = text.replace(src, dst)

path.write_text(text, encoding="utf-8")
print("DashboardPreview.tsx updated successfully!")
