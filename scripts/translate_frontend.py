import re
from pathlib import Path

ROOT = Path(r"c:\Users\SMC-DXB\Projects\Adversum\frontend\src")

def replace_in_file(path: Path, replacements: list[tuple[str, str]]):
    text = path.read_text(encoding="utf-8")
    original = text
    for src, dst in replacements:
        text = text.replace(src, dst)
    if text != original:
        path.write_text(text, encoding="utf-8")
        print(f"Updated: {path.name}")
    else:
        print(f"No changes matched in: {path.name}")

# 1. Navbar.tsx
replace_in_file(ROOT / "components" / "Navbar.tsx", [
    ("{ name: 'Produit', href: '/#features' }", "{ name: 'Product', href: '/#features' }"),
    ("{ name: 'Fonctionnement', href: '/#how-it-works' }", "{ name: 'How It Works', href: '/#how-it-works' }"),
    ("{ name: 'SOC Live', href: '/soc', badge: 'AI-ASOC' }", "{ name: 'Live SOC', href: '/soc', badge: 'AI-ASOC' }"),
    ("{ name: 'War Room', href: '/war-room', badge: 'Simulateur' }", "{ name: 'War Room', href: '/war-room', badge: 'Simulator' }"),
    ("{ name: 'Tarifs', href: '/#pricing' }", "{ name: 'Pricing', href: '/#pricing' }"),
    ("{ name: 'Entreprise', href: '/#enterprise' }", "{ name: 'Enterprise', href: '/#enterprise' }"),
    ("Connexion", "Log In"),
    ("Démarrer", "Get Started"),
])

# 2. HeroSection.tsx
replace_in_file(ROOT / "components" / "HeroSection.tsx", [
    ("Nouvelle version 2.0 disponible", "Version 5.0 Enterprise Available"),
    ("Sécurité du code", "Code Security"),
    ("réinventée", "Reinvented"),
    ("Adversum combine la puissance de Rust avec l'intelligence artificielle \n            pour détecter et corriger automatiquement les vulnérabilités.",
     "Adversum combines high-performance Rust, NVIDIA Nemotron AI, and Z3 Formal Verification to detect, prove, and heal vulnerabilities autonomously."),
    ("Adversum combine la puissance de Rust avec l'intelligence artificielle \r\n            pour détecter et corriger automatiquement les vulnérabilités.",
     "Adversum combines high-performance Rust, NVIDIA Nemotron AI, and Z3 Formal Verification to detect, prove, and heal vulnerabilities autonomously."),
    ("Essai gratuit", "Launch Audit"),
    ("Voir la démo", "Watch Demo"),
    ("{ value: '10x', label: 'Plus rapide' }", "{ value: '10x', label: 'Faster Throughput' }"),
    ("{ value: '95%', label: 'Précision' }", "{ value: '100%', label: 'Mathematical Proof' }"),
    ("{ value: '24/7', label: 'Monitoring' }", "{ value: '24/7', label: 'Continuous SOC' }"),
])

# 3. FeaturesSection.tsx
replace_in_file(ROOT / "components" / "FeaturesSection.tsx", [
    ("title: 'Analyse Hybride',", "title: 'Hybrid Analysis Engine',"),
    ("description: 'Moteur Rust ultra-rapide combiné à des modèles IA pour une détection précise des vulnérabilités.',",
     "description: 'Ultra-fast Rust PyO3 core combined with NVIDIA Nemotron LLM for surgical vulnerability detection.',"),
    ("title: 'Correction Automatique',", "title: 'Autonomous Patching',"),
    ("description: 'Génération et vérification automatique de patches sécurisés sans intervention humaine.',",
     "description: 'Automatic synthesis and BitVec formal verification of secured patches with zero human latency.',"),
    ("title: 'Dashboard Intuitif',", "title: 'Real-Time Telemetry',"),
    ("description: 'Interface épurée pour visualiser et gérer vos audits de sécurité en temps réel.',",
     "description: 'Institutional glassmorphism UI to monitor, trace, and inspect multi-tier security audits live.',"),
    ("title: 'Système Immunitaire',", "title: 'Autonomous Cyber Defense',"),
    ("description: 'Technologie RBAT qui simule des attaques pour renforcer proactivement vos défenses.',",
     "description: 'Cross-Protocol War Room simulating real adversarial payloads to preempt zero-day exploits.',"),
    ("Fonctionnalités", "Capabilities"),
    ("Une protection{' '}", "Comprehensive{' '}"),
    ("complète", "Protection"),
    ("Quatre technologies qui redéfinissent la sécurité applicative",
     "Four core pillars redefining modern smart contract and cloud security"),
])

# 4. HowItWorksSection.tsx
replace_in_file(ROOT / "components" / "HowItWorksSection.tsx", [
    ("title: 'Intégration',", "title: 'Ingestion',"),
    ("description: 'Connectez votre repository en quelques secondes. GitHub, GitLab, Bitbucket supportés.',",
     "description: 'Instant repository connection or smart contract upload. Full CI/CD support.',"),
    ("title: 'Analyse',", "title: 'Rust SAST Core',"),
    ("description: 'Notre moteur Rust analyse votre code avec une précision chirurgicale.',",
     "description: 'Blazing fast Rust AST analysis, taint dataflow, and control flow graph generation.',"),
    ("title: 'Validation IA',", "title: 'Nemotron AI + Z3',"),
    ("description: 'L\\'intelligence artificielle confirme les vulnérabilités et élimine les faux positifs.',",
     "description: 'Semantic hypothesis generation backed by Z3 SMT BitVec formal proofs (SAT/UNSAT).',"),
    ("title: 'Correction',", "title: 'Self-Healing',"),
    ("description: 'Des patches sont générés et vérifiés automatiquement.',",
     "description: 'Auto-generation of Foundry .t.sol PoC exploits and AST-verified remediation patches.',"),
    ("title: 'Déploiement',", "title: 'Enforcement',"),
    ("description: 'Déployez en un clic avec rollback automatique si nécessaire.',",
     "description: 'One-click pull request generation with automated verification and safe fallback.',"),
    ("Comment ça marche", "Workflow"),
    ("Un processus en{' '}", "A surgical{' '}"),
    ("cinq étapes", "five-step pipeline"),
    ("De la détection au déploiement du correctif en toute transparence",
     "From raw code analysis to formal proof and self-healing deployment"),
])

# 5. LiveSimulation.tsx
replace_in_file(ROOT / "components" / "LiveSimulation.tsx", [
    ("severity: 'Critique',", "severity: 'Critical',"),
    ("severity: 'Élevée',", "severity: 'High',"),
    ("text: 'Génération du patch AVR…',", "text: 'Generating AVR patch…',"),
    ("text: 'Vulnérabilité neutralisée',", "text: 'Vulnerability Neutralized',"),
    ("text: 'Prochain scénario…',", "text: 'Next scenario…',"),
    ("Live · En temps réel", "Live · Real-time"),
    ("Regardez Adversum{' '}", "Watch Adversum{' '}"),
    ("travailler", "in action"),
    ("Détection, validation IA et correction automatique — en moins d'une seconde.",
     "Instant detection, SMT formal verification, and automated patching — in milliseconds."),
    ("{ label: 'Scannés',", "{ label: 'Scanned',"),
    ("{ label: 'Bloqués',", "{ label: 'Blocked',"),
    ("{ label: 'Corrigés',", "{ label: 'Remediated',"),
    ("v2.0 · Rust + IA", "v5.0 · Rust + Nemotron + Z3"),
])

# 6. PricingSection.tsx
replace_in_file(ROOT / "components" / "PricingSection.tsx", [
    ("Pour les équipes qui démarrent avec la sécurité applicative.", "For teams beginning their application security journey."),
    ("Pour les équipes de développement sérieuses sur la sécurité.", "For protocols and engineering teams requiring formal security assurance."),
    ("Pour les organisations avec des besoins de sécurité avancés.", "For institutions, custodians, and enterprise crypto infrastructures."),
    ("'5 projets'", "'5 Repositories'"),
    ("'1 000 scans / mois'", "'1,000 Scans / mo'"),
    ("'Détection OWASP Top 10'", "'OWASP Top 10 Detection'"),
    ("'Rapports PDF'", "'PDF / JSON Reports'"),
    ("'Support email'", "'Email Support'"),
    ("'Commencer'", "'Get Started'"),
    ("'25 projets'", "'25 Repositories'"),
    ("'10 000 scans / mois'", "'10,000 Scans / mo'"),
    ("'Analyse hybride Rust + IA'", "'Hybrid Rust + Nemotron AI Engine'"),
    ("'Correction automatique AVR'", "'Autonomous Patch Synthesis'"),
    ("'Dashboard temps réel'", "'Real-Time SOC Dashboard'"),
    ("'Intégrations CI/CD'", "'CI/CD GitHub Actions / GitLab'"),
    ("'Support prioritaire'", "'Priority SLA Support'"),
    ("'Essai gratuit 14 jours'", "'Start 14-Day Free Trial'"),
    ("'Projets illimités'", "'Unlimited Repositories'"),
    ("'Scans illimités'", "'Unlimited Formal Scans'"),
    ("'Système immunitaire RBAT'", "'Cross-Chain RBAT Attack Simulator'"),
    ("'Graphes d\\'attaque avancés'", "'Advanced Multi-Hop Attack Graphs'"),
    ("'SSO & SAML'", "'SSO / SAML / SCIM'"),
    ("'API dédiée'", "'Dedicated Low-Latency API'"),
    ("'SLA garanti 99.99%'", "'99.99% Guaranteed SLA'"),
    ("'Account manager dédié'", "'Dedicated Security Architect'"),
    ("'Contacter l\\'équipe'", "'Contact Security Team'"),
    ("Tarifs", "Pricing"),
    ("Des tarifs{' '}", "Transparent{' '}"),
    ("transparents", "Pricing Plans"),
    ("Choisissez le plan adapté à vos besoins de sécurité", "Choose the plan that fits your security and compliance needs"),
    ("Facturation annuelle", "Annual Billing"),
    ("Facturation mensuelle", "Monthly Billing"),
    ("Économisez 20%", "Save 20%"),
    ("Populaire", "Most Popular"),
    ("/mois", "/month"),
    ("Sur devis", "Custom Quote"),
    ("Comparer toutes les fonctionnalités", "Compare All Capabilities"),
    ("Fonctionnalité", "Capability"),
    ("category: 'Analyse'", "category: 'Detection & Proof'"),
    ("{ name: 'Analyse statique (AST)'", "{ name: 'Fast Rust AST Analysis'"),
    ("{ name: 'Flux de données & CFG'", "{ name: 'Taint & Control Flow Graph'"),
    ("{ name: 'Validation IA (LLM)'", "{ name: 'Nemotron AI Reasoning'"),
    ("{ name: 'Analyse inter-fichiers'", "{ name: 'Inter-File SMT Formal Prover (Z3)'"),
    ("category: 'Correction'", "category: 'Remediation'"),
    ("{ name: 'Suggestions de correctifs'", "{ name: 'Remediation Suggestions'"),
    ("{ name: 'Correction automatique AVR'", "{ name: 'Autonomous AST Patch Generation'"),
    ("{ name: 'Vérification des patches'", "{ name: 'SMT-Verified Patch Validation'"),
    ("{ name: 'Rollback automatique'", "{ name: 'Automated Safe Rollback'"),
    ("category: 'Dashboard'", "category: 'Observability'"),
    ("{ name: 'Rapports de base'", "{ name: 'Standard Reports'"),
    ("{ name: 'Graphes d\\'attaque'", "{ name: 'Multi-Hop Attack Graphs'"),
    ("{ name: 'Historique complet'", "{ name: 'Immutable Audit Trail'"),
    ("{ name: 'Tableaux de bord personnalisés'", "{ name: 'Customizable SOC Views'"),
    ("category: 'Sécurité avancée'", "category: 'Advanced Web3 & CEX'"),
    ("{ name: 'Système immunitaire RBAT'", "{ name: 'RBAT Autonomous Red Team'"),
    ("{ name: 'Pentest autonome simulé'", "{ name: 'Cross-Protocol War Room Sim'"),
    ("category: 'Support & Intégrations'", "category: 'Enterprise Support'"),
    ("{ name: 'Support email'", "{ name: 'Email Support'"),
    ("{ name: 'Support prioritaire'", "{ name: '24/7 Priority Support'"),
    ("{ name: 'CI/CD (GitHub, GitLab…)'", "{ name: 'CI/CD Integrations'"),
    ("{ name: 'SSO / SAML / SCIM'", "{ name: 'SSO / SAML / SCIM'"),
    ("{ name: 'SLA garanti'", "{ name: 'Guaranteed 99.99% SLA'"),
    ("{ name: 'Account manager dédié'", "{ name: 'Dedicated Solutions Architect'"),
])

# 7. CTASection.tsx
replace_in_file(ROOT / "components" / "CTASection.tsx", [
    ("Prêt à sécuriser", "Ready to Secure"),
    ("votre code ?", "Your Code?"),
    ("Rejoignez les équipes qui font confiance à Adversum. \n              Commencez gratuitement, sans carte bancaire.",
     "Join security teams and Web3 protocols that rely on Adversum. Start for free, zero credit card required."),
    ("Rejoignez les équipes qui font confiance à Adversum. \r\n              Commencez gratuitement, sans carte bancaire.",
     "Join security teams and Web3 protocols that rely on Adversum. Start for free, zero credit card required."),
    ("Commencer maintenant", "Start Free Scan"),
    ("Parler à un expert", "Speak with an Expert"),
])

# 8. Footer.tsx
replace_in_file(ROOT / "components" / "Footer.tsx", [
    ("produit: [", "product: ["),
    ("{ name: 'Fonctionnalités', href: '#features' }", "{ name: 'Capabilities', href: '#features' }"),
    ("{ name: 'Tarifs', href: '#pricing' }", "{ name: 'Pricing', href: '#pricing' }"),
    ("{ name: 'Documentation', href: '#docs' }", "{ name: 'Documentation', href: '#docs' }"),
    ("ressources: [", "resources: ["),
    ("entreprise: [", "company: ["),
    ("{ name: 'À propos', href: '#about' }", "{ name: 'About', href: '#about' }"),
    ("{ name: 'Carrières', href: '#careers' }", "{ name: 'Careers', href: '#careers' }"),
    ("{ name: 'Contact', href: '#contact' }", "{ name: 'Contact', href: '#contact' }"),
    ("Sécurité applicative de nouvelle génération propulsée par Rust et l'intelligence artificielle.",
     "Next-generation application and smart contract security powered by Rust, NVIDIA Nemotron, and Z3 Formal Verification."),
    ("Tous droits réservés.", "All rights reserved."),
    ("Conditions d'utilisation", "Terms of Service"),
    ("Politique de confidentialité", "Privacy Policy"),
    ("Sécurité", "Security Policy"),
])

# 9. DashboardPreview.tsx
replace_in_file(ROOT / "components" / "DashboardPreview.tsx", [
    ("label: 'Rapide'", "label: 'Fast SAST'"),
    ("desc: 'Secrets · Crypto · IaC'", "desc: 'Secrets · Crypto · IaC'"),
    ("['Mauvais usages cryptographiques', 'Clés / tokens hardcodés', 'Dockerfiles & Terraform']",
     "['Cryptographic misuse', 'Hardcoded API keys / secrets', 'Dockerfiles & Terraform IaC']"),
    ("label: 'Smart Contract'", "label: 'Smart Contract'"),
    ("desc: 'Solidity · Bridges · PoC'", "desc: 'Solidity · Bridges · PoC'"),
    ("['Reentrancy & Flash Loan', 'Ponts Cross-Chain & Replay', 'Preuve formelle SMT', 'Foundry Exploit PoC']",
     "['Reentrancy & Flash Loans', 'Cross-Chain Bridges & Replay', 'SMT Z3 Formal Proofs', 'Foundry Exploit PoC .t.sol']"),
    ("label: 'CEX / Custody'", "label: 'CEX & Custody'"),
    ("desc: 'CCSS v3.0 · PoR · STRIDE'", "desc: 'CCSS v3.0 · PoR · STRIDE'"),
    ("['Conformité CCSS 10 aspects', 'Proof of Reserves Merkle Tree', 'STRIDE Threat Modeling', 'Sécurité API Trading']",
     "['CCSS 10-Aspect Compliance', 'Proof of Reserves Merkle Tree', 'STRIDE Threat Modeling', 'Trading API Security']"),
    ("label: 'Complet'", "label: 'Full Spectrum'"),
    ("desc: 'Tous les modules · HTML · PoC'", "desc: 'All Modules · HTML · PoC'"),
    ("['Tous les modules combinés', 'CCSS + STRIDE + SMT', 'Proof of Reserves & Bridges', 'Dashboard HTML Standalone']",
     "['All engines combined', 'CCSS + STRIDE + Z3 SMT', 'Proof of Reserves & Bridges', 'Standalone Executive HTML Report']"),
    ("title: \"Initialisation Sandbox\", desc: \"Isolation des processus & chargement des politiques de sécurité\"",
     "title: \"Sandbox Initialization\", desc: \"Process isolation & security policy loading\""),
    ("title: \"Analyse SAST Multi-Moteurs\", desc: \"Moteur Rust PyO3 : Taint analysis & conformité CCSS\"",
     "title: \"Multi-Engine SAST Analysis\", desc: \"Native Rust PyO3 Core: Taint analysis & security rules\""),
    ("title: \"Raisonnement IA NVIDIA Nemotron\", desc: \"Inférence Nebius Token Factory pour élimination des faux positifs\"",
     "title: \"NVIDIA Nemotron AI Reasoning\", desc: \"Hypothesis synthesis & false-positive elimination\""),
    ("title: \"Threat Intelligence Tavily\", desc: \"Recherche temps-réel d'exploits publics et corrélation CVE\"",
     "title: \"Threat Intelligence Tavily\", desc: \"Real-time public exploit search & CVE correlation\""),
    ("title: \"Génération PoC Foundry & Patches\", desc: \"Synthèse des exploits .t.sol et remédiation automatique\"",
     "title: \"Foundry PoC & Patch Synthesis\", desc: \"Exploit reproduction in .t.sol & AST remediation\""),
    ("Lancer l'audit de sécurité", "Launch Security Audit"),
    ("Auditer le code", "Execute Security Scan"),
    ("Recherche de vulnérabilités en cours...", "Scanning for vulnerabilities in progress..."),
])
