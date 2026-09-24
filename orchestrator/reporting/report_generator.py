import os
import logging
from typing import List, Dict, Optional
from collections import Counter
from ..models.findings import ValidatedFinding, Severity, ValidationStatus
from ..ai_reasoning.llm_client import ProductionMultiModelClient, LLMModel
from ..ai_reasoning.prompts import REPORT_SYSTEM_PROMPT

logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Génère les rapports d'audit en utilisant les LLMs UNIQUEMENT pour la rédaction.
    
    Principe:
    - Validation: 100% déterministe (DeterministicValidator)
    - Rédaction: LLM pour résumer et formater (GPT-4o-mini)
    
    Les décisions de sécurité sont prises par le validateur déterministe.
    Le LLM ne fait que rédiger le rapport à partir des données validées.
    """

    def __init__(self):
        self.client = ProductionMultiModelClient()
        # Option pour désactiver LLM et utiliser un rapport template
        import os
        self.use_llm = os.getenv("USE_LLM_FOR_REPORTS", "true").lower() == "true"
        if not self.use_llm:
            logger.info("LLM désactivé pour les rapports. Utilisation de templates.")

    async def generate_summary(self, findings: List[ValidatedFinding]) -> str:
        """
        Génère un résumé exécutif de l'audit.
        Utilise les LLMs uniquement pour la rédaction, pas pour la validation.
        """
        if not findings:
            return self._generate_empty_summary()

        # Calculer les statistiques de manière déterministe
        stats = self._compute_statistics(findings)
        
        # Si LLM désactivé, utiliser template
        if not self.use_llm:
            return self._generate_template_summary(stats, findings)

        logger.info(f"Génération du rapport d'audit pour {len(findings)} findings (LLM pour rédaction uniquement)...")
        
        # Préparer les données structurées pour le LLM
        report_data = self._prepare_report_data(stats, findings)
        
        # Utiliser Ollama (open source) par défaut, fallback vers GPT-4o-mini si configuré
        # Le modèle GPT_4O_MINI sera automatiquement routé vers Ollama si disponible
        summary = await self.client.generate_async(
            LLMModel.GPT_4O_MINI,  # Routé automatiquement vers Ollama si disponible
            REPORT_SYSTEM_PROMPT,
            report_data
        )
        
        return summary

    def _compute_statistics(self, findings: List[ValidatedFinding]) -> Dict:
        """Calcule les statistiques de manière déterministe."""
        total = len(findings)
        
        by_status = Counter(f.validation_status for f in findings)
        by_severity = Counter(f.raw.severity for f in findings)
        
        # Findings confirmés par sévérité
        confirmed_critical = sum(1 for f in findings 
                                if str(f.validation_status) == "CONFIRMED" 
                                and str(f.raw.severity) == "CRITICAL")
        confirmed_high = sum(1 for f in findings 
                            if str(f.validation_status) == "CONFIRMED" 
                            and str(f.raw.severity) == "HIGH")
        confirmed_medium = sum(1 for f in findings 
                              if str(f.validation_status) == "CONFIRMED" 
                              and str(f.raw.severity) == "MEDIUM")
        confirmed_low = sum(1 for f in findings 
                           if str(f.validation_status) == "CONFIRMED" 
                           and str(f.raw.severity) == "LOW")
        
        rejected = by_status.get(ValidationStatus.REJECTED, 0)
        low_risk = by_status.get(ValidationStatus.LOW_RISK, 0)
        
        return {
            "total": total,
            "confirmed": by_status.get(ValidationStatus.CONFIRMED, 0),
            "rejected": rejected,
            "low_risk": low_risk,
            "confirmed_critical": confirmed_critical,
            "confirmed_high": confirmed_high,
            "confirmed_medium": confirmed_medium,
            "confirmed_low": confirmed_low,
            "by_severity": dict(by_severity),
            "by_status": dict(by_status),
        }

    def _prepare_report_data(self, stats: Dict, findings: List[ValidatedFinding]) -> str:
        """Prépare les données structurées pour le LLM (rédaction uniquement)."""
        data = f"""# Données d'Audit de Sécurité

## Statistiques Globales
## System Health (Adversum Diagnostics)
- **Engine**: {'Native Rust (High Performance)' if self.client.is_mock == False and os.path.exists('adversum_core.pyd') else 'Python Fallback (Degraded Performance)'}
- **Reasoning**: {'Real AI (Hybrid G-ASR)' if not self.client.is_mock else 'Simulation / Mock Mode (No API Keys)'}
- **Ollama**: {'Active' if self.client.ollama_enabled else 'Inactive/Missing'}

## Findings Confirmés par Sévérité
- CRITIQUE: {stats['confirmed_critical']}
- HAUTE: {stats['confirmed_high']}
- MOYENNE: {stats['confirmed_medium']}
- FAIBLE: {stats['confirmed_low']}

## Top Findings Confirmés (Critiques et Hautes)
"""
        
        # Ajouter les findings confirmés les plus critiques
        critical_findings = [
            f for f in findings 
            if f.validation_status == ValidationStatus.CONFIRMED 
            and f.raw.severity in [Severity.CRITICAL, Severity.HIGH]
        ]
        
        for i, finding in enumerate(critical_findings[:10], 1):
            severity_str = str(finding.raw.severity.value if hasattr(finding.raw.severity, 'value') else finding.raw.severity)
            conf = float(finding.ai_confidence) if isinstance(getattr(finding, 'ai_confidence', 0), (int, float)) else 0.0
            data += f"""
### {i}. {finding.raw.id} - {severity_str}
- **Fichier**: {finding.raw.file_path}:{finding.raw.line}
- **Description**: {finding.raw.message}
- **Snippet**: `{finding.raw.snippet[:100] if finding.raw.snippet else ""}...`
- **Confiance**: {conf:.0%}
- **Correctif disponible**: {'Oui' if getattr(finding, 'fix_code', None) else 'Non'}
"""
        
        data += """
## Instructions pour la Rédaction
Rédigez un rapport d'audit professionnel en Markdown incluant:
1. Un résumé exécutif (2-3 paragraphes)
2. Une analyse des risques principaux
3. Des recommandations prioritaires
4. Un aperçu des correctifs disponibles

Le rapport doit être clair, professionnel et orienté action.
"""
        
        return data

    def _generate_template_summary(self, stats: Dict, findings: List[ValidatedFinding]) -> str:
        """Génère un résumé template sans LLM (fallback)."""
        summary = f"""# Rapport d'Audit de Sécurité

## Résumé Exécutif

L'audit a identifié {stats['total']} findings de sécurité, dont {stats['confirmed']} confirmés comme vulnérabilités réelles.

### Répartition par Sévérité
- **CRITIQUE**: {stats['confirmed_critical']} findings confirmés
- **HAUTE**: {stats['confirmed_high']} findings confirmés
- **MOYENNE**: {stats['confirmed_medium']} findings confirmés
- **FAIBLE**: {stats['confirmed_low']} findings confirmés

### Validation
- {stats['rejected']} findings rejetés (faux positifs détectés)
- {stats['low_risk']} findings à faible risque (sanitizers présents)

## Recommandations Prioritaires

1. Traiter immédiatement les {stats['confirmed_critical']} vulnérabilités critiques
2. Examiner les {stats['confirmed_high']} vulnérabilités de haute sévérité
3. Appliquer les correctifs automatiques disponibles via l'interface

## Correctifs Disponibles

{sum(1 for f in findings if f.fix_code)} findings ont des correctifs automatiques disponibles.
"""
        return summary

    def _generate_empty_summary(self) -> str:
        """Génère un résumé pour un audit sans findings."""
        return """# Rapport d'Audit de Sécurité

## Résumé Exécutif

Aucune vulnérabilité détectée lors de cet audit. Le code analysé ne présente pas de problèmes de sécurité identifiés par les règles de détection actuelles.

**Note**: Il est recommandé de maintenir une surveillance continue et de mettre à jour régulièrement les règles de détection.
"""

    async def generate_detailed_report(self, findings: List[ValidatedFinding]) -> str:
        """
        Génère un rapport détaillé complet (optionnel, pour export PDF, etc.).
        Utilise les LLMs uniquement pour la rédaction.
        """
        if not findings:
            return self._generate_empty_summary()

        stats = self._compute_statistics(findings)
        
        if not self.use_llm:
            return self._generate_template_summary(stats, findings)

        logger.info("Génération du rapport détaillé (LLM pour rédaction)...")
        
        # Préparer toutes les données pour un rapport complet
        detailed_data = self._prepare_detailed_report_data(stats, findings)
        
        detailed_report = await self.client.generate_async(
            LLMModel.GPT_4O_MINI,
            REPORT_SYSTEM_PROMPT,
            detailed_data
        )
        
        return detailed_report

    def _prepare_detailed_report_data(self, stats: Dict, findings: List[ValidatedFinding]) -> str:
        """Prépare toutes les données pour un rapport détaillé."""
        data = self._prepare_report_data(stats, findings)
        
        # Ajouter tous les findings (pas seulement les top 10)
        data += "\n\n## Liste Complète des Findings\n\n"
        
        for i, finding in enumerate(findings, 1):
            severity_str = str(finding.raw.severity.value if hasattr(finding.raw.severity, 'value') else finding.raw.severity)
            data += f"""
### Finding #{i}: {finding.raw.id}
- **Statut**: {finding.validation_status}
- **Sévérité**: {severity_str}
- **Fichier**: {finding.raw.file_path}:{finding.raw.line}
- **Description**: {finding.raw.message}
- **Snippet**: `{finding.raw.snippet}`
- **Confiance**: {finding.ai_confidence:.0%}
- **Notes**: {finding.reasoning_notes[:200]}...
- **Correctif**: {'Disponible' if finding.fix_code else 'Non disponible'}
"""
        
        data += "\n\nRédigez un rapport détaillé professionnel incluant une analyse approfondie de chaque finding."
        
        return data
