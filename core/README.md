# Core Module: Adversarial Analysis Engine

Le `core` d'Adversum est un moteur unifié dédié à l'analyse de sécurité statique et à l'exécution d'attaques adversariales haute performance. Il est conçu pour être un composant critique, passif et déterministe.

## Principes de Conception

- **Déterminisme** : À entrées identiques, sorties identiques. Aucune variabilité statistique.
- **Passivité** : Le moteur produit des faits techniques bruts. Il ne prend aucune décision de sécurité (bloquer/autoriser).
- **Zéro IA** : Aucun modèle de langage ou raisonnement heuristique n'est présent dans le Core.
- **Sécurité Mémoire** : Intégralement développé en Rust avec une utilisation minimale et justifiée de blocs `unsafe`.

## Périmètre Fonctionnel

### 1. Analyse Statique de Sécurité (SAST)
Le Core assure l'extraction de faits structurels et sémantiques depuis le code source :
- **AST (Abstract Syntax Tree)** : Parsing multi-langage via Tree-sitter.
- **CFG (Control Flow Graph)** : Modélisation des chemins d'exécution.
- **DFG (Data Flow Graph)** : Analyse de propagation des données (Taint Analysis).
- **Pattern Matching** : Détection de signatures de vulnérabilités connues au niveau IR (Intermediate Representation).

### 2. Fast Adversarial Kit
Exécution d'algorithmes de génération d'exemples adversariaux pour les modèles de Machine Learning :
- **PGD (Projected Gradient Descent)**
- **FGSM (Fast Gradient Sign Method)**
- **C&W (Carlini & Wagner)**
- Optimisation vectorisée via Rust pour une latence minimale.

## Interfaces Publiques (I/O)

| Composant | Entrées | Sorties |
| :--- | :--- | :--- |
| **SAST** | Code source (FS/Git) | Faits techniques bruts (JSON/Protobuf) |
| **Adversarial** | Poids du modèle, Gradients, Tensors | Perturbations, Exemples adversariaux |

## Frontières Architecturales

- **Core** : Générateur de faits. Déterministe. Bas niveau (Rust).
- **Orchestrator** : Gestionnaire de pipeline. Ingestion de données et flux (Python).
- **Reasoning Layer** : Interprétation et décision. Intelligence artificielle et heuristiques (LLM).

## Garanties Techniques

- **Performance** : Temps de parsing < 100ms pour les fichiers standards.
- **Isolation** : Aucune dépendance à un état global ou à des services externes.
- **Reproductibilité** : Les résultats sont auditables et re-jouables à l'identique.
