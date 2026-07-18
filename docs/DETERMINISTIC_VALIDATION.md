# Validation Déterministe - Moteur Basé sur des Règles

## 🎯 Principe Fondamental

**Adversum utilise maintenant un moteur de validation 100% déterministe** pour réduire les faux positifs, remplaçant les LLMs probabilistes.

### Pourquoi Déterministe ?

1. **Reproductibilité** : Même entrée = même sortie, toujours
2. **Fiabilité** : Pas de variabilité probabiliste
3. **Performance** : Pas d'appels API externes (LLM)
4. **Sécurité** : Pas de dépendance à des services tiers
5. **Auditabilité** : Résultats traçables et explicables

---

## 🔍 Comment Ça Fonctionne

### Algorithme de Validation

```
Pour chaque finding:
  1. Analyser le flow_path (CFG) pour détecter les sanitizers
  2. Vérifier les patterns de faux positifs dans le code
  3. Appliquer les règles de validation spécifiques
  4. Décision déterministe: CONFIRMED / REJECTED / LOW_RISK
  5. Générer un correctif basé sur des templates
```

### Détection de Sanitizers

Le validateur reconnaît automatiquement les sanitizers Python courants :

- **Escaping**: `shlex.quote`, `html.escape`, `urllib.parse.quote`
- **Validation**: `re.match`, `str.isalnum`, `str.isdigit`
- **Encoding**: `base64.b64encode`, `urllib.parse.urlencode`
- **Parameterization**: `sqlite3.execute` (avec ?), `psycopg2.execute`

### Patterns de Faux Positifs

Le validateur détecte automatiquement les patterns qui indiquent un faux positif :

- Utilisation de `ast.literal_eval` au lieu de `eval`
- Utilisation de `subprocess.run` avec `shell=False`
- String literals (pas de variable)
- Commentaires de test dans le code

---

## 📋 Règles de Validation

### RUST_CORE_001_DANGEROUS_EVAL

**Sanitizers requis**: `ESCAPE` ou `VALIDATE`

**Faux positifs détectés**:
- `ast.literal_eval` présent
- `json.loads` présent
- String literals (pas de variable)

**Correctif généré**:
```python
import ast
result = ast.literal_eval(user_input)
```

### RUST_CORE_002_OS_SYSTEM

**Sanitizers requis**: `ESCAPE`

**Faux positifs détectés**:
- `shlex.quote` présent
- `subprocess.run` utilisé
- Code de test

**Correctif généré**:
```python
import subprocess
import shlex
subprocess.run([command] + shlex.split(args), shell=False)
```

### RUST_CORE_003_SUBPROCESS_POPEN

**Sanitizers requis**: `ESCAPE`

**Faux positifs détectés**:
- `shell=False` présent
- `subprocess.run` utilisé

**Correctif généré**:
```python
import subprocess
subprocess.run([command, arg1, arg2], shell=False)
```

---

## ⚙️ Configuration

### Utiliser le Validateur Déterministe (Par Défaut)

Le validateur déterministe est utilisé par défaut. Aucune configuration nécessaire.

```bash
# Le pipeline utilise automatiquement DeterministicValidator
cd adversum/api
uvicorn main:app --reload
```

### Utiliser l'Ancien Validateur LLM (Optionnel)

Si vous voulez utiliser l'ancien validateur basé sur LLM (non recommandé pour la production) :

```bash
export USE_LLM_VALIDATOR=true
cd adversum/api
uvicorn main:app --reload
```

---

## 🔧 Extension du Validateur

### Ajouter un Nouveau Sanitizer

Éditer `adversum/orchestrator/reasoning/deterministic_validator.py` :

```python
SANITIZERS: Dict[str, SanitizerType] = {
    # ... sanitizers existants ...
    "nouveau.sanitizer": SanitizerType.ESCAPE,
}
```

### Ajouter une Nouvelle Règle de Validation

```python
VALIDATION_RULES: Dict[str, ValidationRule] = {
    # ... règles existantes ...
    "NOUVELLE_REGLE": ValidationRule(
        rule_id="NOUVELLE_REGLE",
        required_sanitizers=[SanitizerType.ESCAPE],
        false_positive_patterns=[
            r"pattern1",
            r"pattern2",
        ],
        confidence=0.95,
    ),
}
```

### Ajouter un Pattern de Faux Positif

```python
FALSE_POSITIVE_PATTERNS: Dict[str, List[str]] = {
    "RUST_CORE_001_DANGEROUS_EVAL": [
        # ... patterns existants ...
        r"nouveau_pattern",
    ],
}
```

### Ajouter un Template de Correctif

```python
fix_templates: Dict[str, tuple[str, str]] = {
    # ... templates existants ...
    "NOUVELLE_REGLE": (
        "Description du correctif",
        "code_du_correctif"
    ),
}
```

---

## 📊 Résultats de Validation

### Statuts Possibles

- **CONFIRMED** : Vulnérabilité confirmée, aucun sanitizer détecté
- **REJECTED** : Faux positif détecté (pattern reconnu)
- **LOW_RISK** : Sanitizers présents dans le flow path

### Confiance (Confidence)

- **0.95** : Vulnérabilité critique confirmée
- **0.90** : Vulnérabilité confirmée
- **0.30** : Sanitizers présents (risque réduit)
- **0.10** : Faux positif probable

---

## 🧪 Tests

### Test Manuel

```python
from orchestrator.reasoning.deterministic_validator import DeterministicValidator
from orchestrator.models.findings import RawFinding, Severity

validator = DeterministicValidator()

finding = RawFinding(
    file_path="test.py",
    line_number=10,
    snippet="eval(user_input)",
    rule_id="RUST_CORE_001_DANGEROUS_EVAL",
    severity=Severity.CRITICAL,
    description="Dangerous eval detected",
    flow_path=[],
)

result = await validator.validate([finding])
print(result[0].validation_status)  # CONFIRMED
```

---

## 🆚 Comparaison: Déterministe vs LLM

| Critère | Déterministe | LLM (Ancien) |
|---------|--------------|--------------|
| **Reproductibilité** | ✅ 100% | ❌ Variable |
| **Performance** | ✅ Instantané | ❌ 1-5s par finding |
| **Coût** | ✅ Gratuit | ❌ Coûteux (API) |
| **Fiabilité** | ✅ Toujours identique | ❌ Peut varier |
| **Auditabilité** | ✅ Traçable | ❌ Boîte noire |
| **Dépendances** | ✅ Aucune | ❌ API externes |

---

## 📝 Notes Techniques

### Analyse du Flow Path

Le validateur analyse le `flow_path` fourni par le Core Rust, qui contient le chemin d'exécution dans le CFG (Control Flow Graph). Si des sanitizers sont présents dans ce chemin, le risque est réduit.

### Analyse Contextuelle

Le validateur lit le fichier source complet pour détecter les sanitizers dans le contexte (pas seulement dans le flow_path direct).

### Patterns Regex

Les patterns utilisent des expressions régulières Python pour la détection. Les patterns sont case-insensitive.

---

## 🚀 Avantages pour la Production

1. **Pas de dépendance externe** : Fonctionne sans API keys
2. **Performance** : Validation instantanée
3. **Reproductibilité** : Même code = mêmes résultats
4. **Sécurité** : Pas d'envoi de code à des services tiers
5. **Coût** : Zéro coût opérationnel

---

*Dernière mise à jour : 2025-01-27*
