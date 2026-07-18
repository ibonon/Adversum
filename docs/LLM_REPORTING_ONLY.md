# LLM Uniquement pour la Rédaction des Rapports

## 🎯 Principe

**Les LLMs sont utilisés UNIQUEMENT pour rédiger et formater les rapports d'audit.**

Les décisions de sécurité (validation des findings) sont prises par le **moteur déterministe** (`DeterministicValidator`).

---

## 📊 Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Pipeline d'Audit                       │
└─────────────────────────────────────────────────────────┘
                          │
        ┌─────────────────┴─────────────────┐
        │                                   │
        ▼                                   ▼
┌──────────────────┐              ┌──────────────────┐
│  Core Rust       │              │  Deterministic   │
│  (SAST)          │              │  Validator       │
│                  │              │                  │
│  Détection       │              │  Validation      │
│  Déterministe    │              │  100% Déterministe│
└──────────────────┘              └──────────────────┘
        │                                   │
        └─────────────────┬─────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  ReportGenerator      │
              │                       │
              │  LLM (GPT-4o-mini)    │
              │  UNIQUEMENT pour      │
              │  la rédaction         │
              └───────────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Rapport Markdown     │
              │  Professionnel        │
              └───────────────────────┘
```

---

## ✅ Séparation des Responsabilités

### Moteur Déterministe (Validation)
- ✅ Détection des vulnérabilités (Core Rust)
- ✅ Validation des findings (DeterministicValidator)
- ✅ Détection de faux positifs
- ✅ Génération de correctifs
- ✅ **100% reproductible**

### LLM (Rédaction)
- ✅ Rédaction du résumé exécutif
- ✅ Formatage du rapport
- ✅ Recommandations basées sur les findings validés
- ❌ **NE VALIDE PAS** les findings
- ❌ **NE PREND PAS** de décisions de sécurité

---

## 📝 Fonctionnement du ReportGenerator

### 1. Calcul des Statistiques (Déterministe)

Le `ReportGenerator` calcule d'abord les statistiques de manière déterministe :

```python
stats = {
    "total": nombre_total_findings,
    "confirmed": findings_confirmés,
    "rejected": faux_positifs,
    "low_risk": faible_risque,
    "confirmed_critical": critiques_confirmés,
    "confirmed_high": hautes_confirmées,
    # ...
}
```

### 2. Préparation des Données (Déterministe)

Les données sont structurées de manière déterministe avant d'être envoyées au LLM :

```python
report_data = """
# Données d'Audit de Sécurité

## Statistiques Globales
- Total de findings: 10
- Findings confirmés: 7
- Findings rejetés: 2
- ...

## Top Findings Confirmés
1. RUST_CORE_001_DANGEROUS_EVAL - CRITICAL
   - Fichier: test.py:42
   - Description: ...
   ...
"""
```

### 3. Rédaction par LLM (Optionnel)

Le LLM reçoit les données validées et les rédige en Markdown professionnel :

```markdown
# Rapport d'Audit de Sécurité

## Résumé Exécutif

L'audit a identifié 10 findings de sécurité, dont 7 confirmés comme 
vulnérabilités réelles. Les 3 findings critiques nécessitent une 
attention immédiate...

## Recommandations Prioritaires

1. Traiter immédiatement les 3 vulnérabilités critiques
2. ...
```

---

## ⚙️ Configuration

### Utiliser le LLM pour les Rapports (Par Défaut)

```bash
# Le LLM est utilisé par défaut pour rédiger les rapports
cd adversum/api
uvicorn main:app --reload
```

### Désactiver le LLM (Templates Seulement)

```bash
export USE_LLM_FOR_REPORTS=false
cd adversum/api
uvicorn main:app --reload
```

Quand le LLM est désactivé, le système utilise des templates Markdown déterministes.

---

## 📊 Exemple de Rapport Généré

### Avec LLM (Rédaction)

```markdown
# Rapport d'Audit de Sécurité

## Résumé Exécutif

L'analyse de sécurité a révélé plusieurs vulnérabilités critiques 
dans le code source. Trois findings de sévérité critique nécessitent 
une attention immédiate, notamment une utilisation non sécurisée de 
la fonction `eval()` qui pourrait permettre une exécution de code à 
distance (RCE).

## Analyse des Risques

Les vulnérabilités identifiées présentent un risque élevé pour la 
sécurité de l'application. Les correctifs automatiques sont disponibles 
pour la majorité des findings, permettant une résolution rapide.

## Recommandations Prioritaires

1. **Action Immédiate**: Appliquer les correctifs pour les 3 findings 
   critiques identifiés dans les fichiers suivants:
   - `api/main.py:42` - RCE via eval()
   - `utils/command.py:15` - Command Injection
   - `db/query.py:28` - SQL Injection potentielle

2. **Court Terme**: Examiner les 4 findings de haute sévérité et 
   appliquer les correctifs disponibles.

3. **Moyen Terme**: Mettre en place des revues de code régulières pour 
   prévenir l'introduction de nouvelles vulnérabilités.
```

### Sans LLM (Template)

```markdown
# Rapport d'Audit de Sécurité

## Résumé Exécutif

L'audit a identifié 10 findings de sécurité, dont 7 confirmés comme 
vulnérabilités réelles.

### Répartition par Sévérité
- **CRITIQUE**: 3 findings confirmés
- **HAUTE**: 4 findings confirmés
- **MOYENNE**: 0 findings confirmés
- **FAIBLE**: 0 findings confirmés

### Validation
- 2 findings rejetés (faux positifs détectés)
- 1 finding à faible risque (sanitizers présents)

## Recommandations Prioritaires

1. Traiter immédiatement les 3 vulnérabilités critiques
2. Examiner les 4 vulnérabilités de haute sévérité
3. Appliquer les correctifs automatiques disponibles via l'interface
```

---

## 🔒 Sécurité et Confidentialité

### Données Envoyées au LLM

Le LLM reçoit **uniquement** :
- ✅ Statistiques agrégées
- ✅ Descriptions des findings (sans code complet)
- ✅ Snippets de code (lignes spécifiques)
- ✅ Statuts de validation (déjà déterminés)

Le LLM **ne reçoit jamais** :
- ❌ Le code source complet
- ❌ Les chemins d'exécution complets
- ❌ Les données sensibles
- ❌ Les informations de configuration

### Option: Désactiver Complètement le LLM

Pour une sécurité maximale, vous pouvez désactiver complètement le LLM :

```bash
export USE_LLM_FOR_REPORTS=false
```

Le système utilisera alors des templates Markdown déterministes.

---

## 📈 Avantages de cette Approche

1. **Sécurité** : Les décisions critiques sont déterministes
2. **Reproductibilité** : Même validation = même résultats
3. **Performance** : Validation instantanée (pas d'attente LLM)
4. **Coût** : LLM utilisé uniquement pour rédaction (optionnel)
5. **Qualité** : Rapports professionnels grâce au LLM
6. **Flexibilité** : Peut fonctionner sans LLM (templates)

---

## 🧪 Test

### Test avec LLM

```bash
# Démarrer l'API
cd adversum/api
uvicorn main:app --reload

# Soumettre un audit
curl -X POST http://localhost:8000/audit \
  -H "X-API-Key: adv-dev-key-123" \
  -H "Content-Type: application/json" \
  -d '{"target_path": "F:\\Adversum\\adversum"}'

# Le rapport sera généré avec LLM (si API keys configurées)
```

### Test sans LLM

```bash
export USE_LLM_FOR_REPORTS=false
cd adversum/api
uvicorn main:app --reload

# Même requête, mais rapport généré avec template
```

---

## 📝 Résumé

- ✅ **Validation** : 100% déterministe (DeterministicValidator)
- ✅ **Rédaction** : LLM optionnel (GPT-4o-mini)
- ✅ **Sécurité** : Décisions critiques sans LLM
- ✅ **Flexibilité** : Peut fonctionner sans LLM
- ✅ **Performance** : Validation instantanée

---

*Dernière mise à jour : 2025-01-27*
