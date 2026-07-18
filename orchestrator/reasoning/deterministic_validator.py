"""
Deterministic Validator - Remplace l'AIValidator probabiliste par un moteur basé sur des règles.

Principe: Validation 100% déterministe basée sur:
- Analyse du CFG/DFG (flow_path)
- Détection de sanitizers/validators dans le chemin
- Patterns de code et règles de validation
- Base de connaissances structurée

Aucun LLM probabiliste n'est utilisé.
"""

import logging
import re
import os
from typing import List, Optional, Dict, Set
from dataclasses import dataclass
from enum import Enum

from ..models.findings import RawFinding, ValidatedFinding, ValidationStatus, Severity

logger = logging.getLogger(__name__)


class SanitizerType(Enum):
    """Types de sanitizers/validators reconnus."""
    ESCAPE = "escape"  # shlex.quote, html.escape, etc.
    VALIDATE = "validate"  # Validation de format, whitelist
    ENCODE = "encode"  # Base64, URL encoding
    PARAMETERIZE = "parameterize"  # Prepared statements, paramétrage
    NONE = "none"  # Aucun sanitizer détecté


@dataclass
class ValidationRule:
    """Règle de validation déterministe."""
    rule_id: str
    required_sanitizers: List[SanitizerType]
    false_positive_patterns: List[str]  # Patterns qui indiquent un faux positif
    severity_override: Optional[Severity] = None
    confidence: float = 1.0


class DeterministicValidator:
    """
    Validateur déterministe basé sur des règles et l'analyse statique.
    
    Principe: Même entrée = même sortie, toujours.
    Aucune variabilité probabiliste.
    """
    
    # Base de connaissances: Sanitizers Python reconnus
    SANITIZERS: Dict[str, SanitizerType] = {
        # Escaping
        "shlex.quote": SanitizerType.ESCAPE,
        "shlex.quote_plus": SanitizerType.ESCAPE,
        "html.escape": SanitizerType.ESCAPE,
        "cgi.escape": SanitizerType.ESCAPE,
        "urllib.parse.quote": SanitizerType.ESCAPE,
        "urllib.parse.quote_plus": SanitizerType.ESCAPE,
        
        # Validation
        "re.match": SanitizerType.VALIDATE,
        "re.search": SanitizerType.VALIDATE,
        "re.fullmatch": SanitizerType.VALIDATE,
        "str.isalnum": SanitizerType.VALIDATE,
        "str.isalpha": SanitizerType.VALIDATE,
        "str.isdigit": SanitizerType.VALIDATE,
        
        # Encoding
        "base64.b64encode": SanitizerType.ENCODE,
        "urllib.parse.urlencode": SanitizerType.ENCODE,
        
        # Parameterization
        "sqlite3.execute": SanitizerType.PARAMETERIZE,  # Si utilisé avec ?
        "psycopg2.execute": SanitizerType.PARAMETERIZE,
        "pymysql.execute": SanitizerType.PARAMETERIZE,
    }
    
    # Patterns qui indiquent des faux positifs
    FALSE_POSITIVE_PATTERNS: Dict[str, List[str]] = {
        "RUST_CORE_001_DANGEROUS_EVAL": [
            r"ast\.literal_eval",  # Utilisation sécurisée d'ast.literal_eval
            r"json\.loads",  # JSON parsing sécurisé
            r"#.*test.*eval",  # Commentaires de test
            r"['\"].*['\"]",  # String literals (pas de variable)
        ],
        "RUST_CORE_002_OS_SYSTEM": [
            r"shlex\.quote",  # Escaping présent
            r"subprocess\.run",  # Utilisation sécurisée de subprocess
            r"#.*test",  # Code de test
        ],
        "RUST_CORE_003_SUBPROCESS_POPEN": [
            r"shell=False",  # Shell désactivé
            r"subprocess\.run",  # Alternative sécurisée
        ],
        "RUST_CORE_004_PATH_TRAVERSAL": [
            r"os\.path\.abspath",  # Abstraction de chemin sécurisée
            r"os\.path\.join",  # Construction de chemin structurée (si base fixe)
            r"Path\(.*\)\.resolve\(\)",  # Résolution de chemin moderne
        ],
        "RUST_CORE_006_SMB_VULN": [
            r"use_ntlm_v2=True",  # Utilisation de NTLM v2 (plus sûr)
            r"sign_messages=True",  # Signature SMB activée
        ],
    }
    
    # Règles de validation par rule_id
    VALIDATION_RULES: Dict[str, ValidationRule] = {
        "RUST_CORE_001_DANGEROUS_EVAL": ValidationRule(
            rule_id="RUST_CORE_001_DANGEROUS_EVAL",
            required_sanitizers=[SanitizerType.ESCAPE, SanitizerType.VALIDATE],
            false_positive_patterns=FALSE_POSITIVE_PATTERNS.get("RUST_CORE_001_DANGEROUS_EVAL", []),
            confidence=0.95,
        ),
        "RUST_CORE_002_OS_SYSTEM": ValidationRule(
            rule_id="RUST_CORE_002_OS_SYSTEM",
            required_sanitizers=[SanitizerType.ESCAPE],
            false_positive_patterns=FALSE_POSITIVE_PATTERNS.get("RUST_CORE_002_OS_SYSTEM", []),
            confidence=0.95,
        ),
        "RUST_CORE_003_SUBPROCESS_POPEN": ValidationRule(
            rule_id="RUST_CORE_003_SUBPROCESS_POPEN",
            required_sanitizers=[SanitizerType.ESCAPE],
            false_positive_patterns=FALSE_POSITIVE_PATTERNS.get("RUST_CORE_003_SUBPROCESS_POPEN", []),
            confidence=0.90,
        ),
        "RUST_CORE_004_PATH_TRAVERSAL": ValidationRule(
            rule_id="RUST_CORE_004_PATH_TRAVERSAL",
            required_sanitizers=[SanitizerType.VALIDATE, SanitizerType.ESCAPE],
            false_positive_patterns=FALSE_POSITIVE_PATTERNS.get("RUST_CORE_004_PATH_TRAVERSAL", []),
            confidence=0.85,
        ),
        "RUST_CORE_006_SMB_VULN": ValidationRule(
            rule_id="RUST_CORE_006_SMB_VULN",
            required_sanitizers=[SanitizerType.PARAMETERIZE],
            false_positive_patterns=FALSE_POSITIVE_PATTERNS.get("RUST_CORE_006_SMB_VULN", []),
            confidence=0.95,
        ),
    }
    
    def __init__(self):
        logger.info("DeterministicValidator initialized (100% deterministic, no LLM)")
    
    async def validate(self, findings: List[RawFinding]) -> List[ValidatedFinding]:
        """
        Valide les findings de manière déterministe.
        
        Algorithme:
        1. Pour chaque finding, analyser le flow_path
        2. Détecter les sanitizers dans le chemin
        3. Vérifier les patterns de faux positifs
        4. Appliquer les règles de validation
        5. Générer un correctif basé sur des templates
        """
        logger.info(f"Validating {len(findings)} findings deterministically (no LLM)")
        
        # Pré-charger les fichiers pour analyse contextuelle
        unique_paths = list(set(f.file_path for f in findings))
        file_cache = {}
        for path in unique_paths:
            try:
                if os.path.exists(path):
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        file_cache[path] = f.read()
                else:
                    file_cache[path] = ""
            except Exception as e:
                logger.warning(f"Failed to load {path}: {e}")
                file_cache[path] = ""
        
        validated_results = []
        for raw in findings:
            file_content = file_cache.get(raw.file_path, "")
            validated = self._validate_single(raw, file_content)
            validated_results.append(validated)
        
        return validated_results
    
    def _validate_single(self, raw: RawFinding, file_content: str) -> ValidatedFinding:
        """Valide un seul finding de manière déterministe."""
        
        # 1. Récupérer la règle de validation
        rule = self.VALIDATION_RULES.get(raw.id)
        if not rule:
            # Règle inconnue: validation conservatrice (CONFIRMED)
            return ValidatedFinding(
                raw=raw,
                validation_status=ValidationStatus.CONFIRMED,
                ai_confidence=0.8,
                reasoning_notes="[Deterministic] Unknown rule, conservative validation.",
                remediation_suggestion=self._generate_fix(raw.id, raw.snippet),
            )
        
        # 2. Analyser le flow_path pour détecter les sanitizers
        sanitizers_found = self._detect_sanitizers(raw.flow_path, file_content)
        
        # 3. Vérifier les patterns de faux positifs
        is_false_positive = self._check_false_positive_patterns(
            raw.id, 
            raw.snippet, 
            file_content
        )
        
        # 4. Vérifier si les sanitizers requis sont présents
        has_required_sanitizers = self._check_required_sanitizers(
            rule.required_sanitizers,
            sanitizers_found
        )
        
        # 5. Décision déterministe
        if is_false_positive:
            status = ValidationStatus.REJECTED
            confidence = 0.1
            notes = f"[Deterministic] False positive pattern detected: {raw.id}"
        elif has_required_sanitizers:
            status = ValidationStatus.LOW_RISK
            confidence = 0.3
            notes = f"[Deterministic] Sanitizers detected in flow path: {[s.value for s in sanitizers_found]}"
        else:
            status = ValidationStatus.CONFIRMED
            confidence = rule.confidence
            notes = f"[Deterministic] No sanitizers detected. Flow path: {' -> '.join(raw.flow_path) if raw.flow_path else 'Direct'}"
        
        # 6. Générer le correctif de manière déterministe
        fix_description, fix_code = self._generate_deterministic_fix(
            raw.id,
            raw.snippet,
            file_content
        )
        
        return ValidatedFinding(
            raw=raw,
            validation_status=status,
            ai_confidence=confidence,
            reasoning_notes=notes,
            remediation_suggestion=f"Deterministic fix: {fix_description}",
            fix_description=fix_description,
            fix_code=fix_code,
        )
    
    def _detect_sanitizers(self, flow_path: List[str], file_content: str) -> List[SanitizerType]:
        """Détecte les sanitizers dans le flow_path et le code."""
        found = set()
        
        # Analyser le flow_path (noms de fonctions dans le CFG)
        for step in flow_path:
            for sanitizer_name, sanitizer_type in self.SANITIZERS.items():
                if sanitizer_name in step:
                    found.add(sanitizer_type)
        
        # Analyser le code autour de la vulnérabilité
        for sanitizer_name, sanitizer_type in self.SANITIZERS.items():
            # Recherche simple mais efficace
            pattern = re.escape(sanitizer_name.replace(".", r"\."))
            if re.search(pattern, file_content, re.IGNORECASE):
                found.add(sanitizer_type)
        
        return list(found)
    
    def _check_false_positive_patterns(
        self, 
        rule_id: str, 
        snippet: str, 
        file_content: str
    ) -> bool:
        """Vérifie si le code correspond à un pattern de faux positif."""
        patterns = self.FALSE_POSITIVE_PATTERNS.get(rule_id, [])
        
        # Vérifier dans le snippet
        for pattern in patterns:
            if re.search(pattern, snippet, re.IGNORECASE):
                return True
        
        # Vérifier dans le contexte (50 lignes autour)
        context_start = max(0, file_content.find(snippet) - 2000)
        context_end = min(len(file_content), file_content.find(snippet) + len(snippet) + 2000)
        context = file_content[context_start:context_end]
        
        for pattern in patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        
        return False
    
    def _check_required_sanitizers(
        self,
        required: List[SanitizerType],
        found: List[SanitizerType]
    ) -> bool:
        """Vérifie si les sanitizers requis sont présents."""
        if not required:
            return False  # Aucun sanitizer requis = toujours vulnérable
        
        found_set = set(found)
        return any(req in found_set for req in required)
    
    def _generate_deterministic_fix(
        self,
        rule_id: str,
        snippet: str,
        file_content: str
    ) -> tuple[Optional[str], Optional[str]]:
        """Génère un correctif de manière déterministe basé sur des templates."""
        
        # Templates de correctifs par rule_id
        fix_templates: Dict[str, tuple[str, str]] = {
            "RUST_CORE_001_DANGEROUS_EVAL": (
                "Replace eval() with ast.literal_eval() for safe evaluation of literals only",
                "import ast\nresult = ast.literal_eval(user_input)"
            ),
            "RUST_CORE_002_OS_SYSTEM": (
                "Use subprocess.run() with shell=False and shlex.quote() for arguments",
                "import subprocess\nimport shlex\nsubprocess.run([command] + shlex.split(args), shell=False)"
            ),
            "RUST_CORE_003_SUBPROCESS_POPEN": (
                "Use subprocess.run() with shell=False instead of Popen with shell=True",
                "import subprocess\nsubprocess.run([command, arg1, arg2], shell=False)"
            ),
            "RUST_CORE_004_PATH_TRAVERSAL": (
                "Validate input against an allow-list or use os.path.abspath() and verify the base directory",
                "import os\nbase_dir = '/safe/path/'\nfinal_path = os.path.abspath(os.path.join(base_dir, user_input))\nif not final_path.startswith(base_dir):\n    raise ValueError('Unsafe path detected')"
            ),
            "RUST_CORE_006_SMB_VULN": (
                "Apply security update MS17-010 and disable SMBv1. Ensure secure flags in SMB libraries.",
                "# Disable SMBv1 on the system and use SMBv2/3 with message signing.\n# Example for library configuration:\n# conn = SMBConnection(..., use_ntlm_v2=True, sign_messages=True)"
            ),
        }
        
        template = fix_templates.get(rule_id)
        if template:
            return template
        
        # Fallback générique
        return (
            "Apply input validation and sanitization before using user input",
            "# TODO: Add sanitization based on rule requirements"
        )
    
    def _generate_fix(self, rule_id: str, snippet: str) -> str:
        """Génère une suggestion de correctif (méthode de compatibilité)."""
        description, code = self._generate_deterministic_fix(rule_id, snippet, "")
        if description and code:
            return f"{description}\n\nCode:\n```python\n{code}\n```"
        return "Refer to security best practices for this vulnerability type."
