# 🏆 Adversum — Guide de Soumission au Hackathon Nebius x NVIDIA

> **Événement :** [Nebius x NVIDIA Global AI Hackathon: Build the next frontier of AI on open infrastructure](https://nebiusglobalaihackathon.devpost.com/)  
> **Catégorie (Track) :** Coding and Agentic Engineering  
> **Prix additionnel ciblé :** Best Use of Tavily ($3,000)  
> **Date limite :** 30 octobre 2026

---

## 1. Résumé de l'alignement technique

| Critère du Hackathon | Implémentation dans Adversum | Fichiers clés |
| :--- | :--- | :--- |
| **Open Infrastructure** | Déployé & interfacé avec **Nebius Token Factory** (`https://api.tokenfactory.nebius.com/v1/`) | [`orchestrator/services/nebius_llm.py`](file:///C:/Users/SMC-DXB/Projects/Adversum/orchestrator/services/nebius_llm.py) |
| **NVIDIA Open Model** | **NVIDIA Nemotron-3.5-Lightning** (`nvidia/Nemotron-3_5-Lightning`) pour la validation de vulnérabilités et la synthèse exécutive CISO | [`orchestrator/services/nebius_llm.py`](file:///C:/Users/SMC-DXB/Projects/Adversum/orchestrator/services/nebius_llm.py) |
| **Track : Coding & Agents** | Agent autonome d'audit SAST, clonage de dépôt, raisonnement de sécurité multi-couches et remédiation automatique | [`api/main.py`](file:///C:/Users/SMC-DXB/Projects/Adversum/api/main.py) |
| **Bonus Tavily** | Recherche temps-réel d'exploits, avis de sécurité et CVE récents corrélés à chaque vulnérabilité | [`orchestrator/services/threat_intel.py`](file:///C:/Users/SMC-DXB/Projects/Adversum/orchestrator/services/threat_intel.py) |
| **Code Source Ouvert** | Dépôt Git complet avec SAST hybride Rust + Python + React | Racine du projet |

---

## 2. Variables d'Environnement à Configurer

Pour activer l'accélération IA Nebius et la threat intelligence Tavily :

```powershell
# 1. Clé API Nebius Token Factory (Obligatoire pour le hackathon)
# Obtenez-la sur : https://tokenfactory.nebius.com
$env:NEBIUS_API_KEY = "votre_cle_nebius"
$env:NEBIUS_MODEL = "nvidia/Nemotron-3_5-Lightning"

# 2. Clé Tavily (Optionnel - Pour concourir au prix de 3 000 $)
# Obtenez-la sur : https://tavily.com
$env:TAVILY_API_KEY = "votre_cle_tavily"

# 3. Lancer le backend
cd C:\Users\SMC-DXB\Projects\Adversum
$env:PYTHONPATH = "C:\Users\SMC-DXB\Projects\Adversum"
$env:API_KEY = "adv-dev-key-123"
cd api
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

> **Note de robustesse :** Si aucune clé n'est fournie, Adversum fonctionne en mode déterministe hors-ligne sans planter. Dès que les clés sont définies, les modules IA et Tavily s'activent instantanément.

---

## 3. Test de Validation Rapide

Un script dédié permet de tester la chaîne d'intégration en une commande :

```powershell
python scripts/verify_nebius_integration.py
```

---

## 4. Script pour la Vidéo de Démo (3 Minutes)

*La soumission Devpost exige une vidéo de présentation de 3 minutes maximum.*

* **0:00 - 0:35 : Le Problème**
  * Les audits de smart contracts et d'infrastructure Web3 coûtent entre 30 000 $ et 100 000 $ et prennent des semaines.
  * Les outils SAST classiques produisent des centaines de faux positifs que les développeurs ignorent.
* **0:35 - 1:15 : La Solution Adversum**
  * Un moteur d'audit hybride combinant un noyau Rust déterministe ultra-rapide et l'intelligence de **NVIDIA Nemotron** hébergé sur **Nebius Token Factory**.
  * Démo du lancement d'un scan directement depuis l'interface Web sur un dépôt GitHub public.
* **1:15 - 2:05 : L'Intelligence NVIDIA Nemotron & Tavily en Action**
  * Montrer la validation contextuelle de chaque finding (ex: détection de Reentrancy ou Nomad Bridge Bypass).
  * Montrer le score de confiance Nemotron et le scénario d'attaque synthétisé.
  * Montrer les CVEs réelles trouvées en direct par **Tavily**.
  * Montrer le **Résumé Exécutif CISO** généré par Nemotron.
* **2:05 - 2:40 : PoC Foundry & Remédiation**
  * Montrer la génération de code PoC (`.t.sol`) pour tester l'exploit dans Foundry.
  * Montrer le téléchargement des rapports institutionnels (SARIF 2.1, HTML interactif).
* **2:40 - 3:00 : Conclusion & Architecture Ouverte**
  * Résumé des technologies : Nebius Token Factory, NVIDIA Nemotron-3.5-Lightning, Tavily, Rust & FastAPI.

---

## 5. Textes Prêts pour la Soumission Devpost

### Project Tagline
> Autonomous AI Security Reasoning Engine powered by NVIDIA Nemotron on Nebius Token Factory with real-time Tavily threat intelligence.

### Description Courte
> Adversum bridges the gap between static code analysis and real-world exploit validation. By pairing a high-speed Rust SAST core with NVIDIA Nemotron-3.5-Lightning on Nebius open infrastructure, Adversum analyzes smart contracts and infrastructure code, eliminates false positives with AI reasoning, correlates live CVE data via Tavily, and generates executive CISO reports and Foundry test exploit PoCs in seconds.
