#!/usr/bin/env python3
"""
Adversum CCSS Compliance Engine (CryptoCurrency Security Standard v3.0)
Evaluates CEX architecture, custody models, multi-sig quorums, velocity limits,
and disaster recovery against the 10 CCSS control aspects (Levels 1, 2, 3).
"""
import os
import re
import json
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class CCSSAspectResult:
    aspect_id: str
    name: str
    category: str
    weight: int
    score: float                # 0.0 to 100.0%
    status: str                 # 'PASS_L3', 'PASS_L2', 'PASS_L1', 'NON_COMPLIANT'
    matched_indicators: List[str]
    identified_gaps: List[str]
    recommendations: List[str]

@dataclass
class CCSSAuditReport:
    overall_score: float        # 0.0 to 100.0%
    achieved_level: str         # 'Level 3 (Banking Grade)', 'Level 2 (Enterprise)', 'Level 1 (Standard Baseline)', 'Non-Compliant'
    aspect_results: List[CCSSAspectResult]
    total_findings: int
    critical_gaps: List[str]
    compliance_summary: Dict[str, Any]

class CCSSChecker:
    def __init__(self, kb_path: Optional[str] = None):
        if not kb_path:
            kb_path = os.path.join(os.path.dirname(__file__), 'kb', 'ccss_matrix.json')
        with open(kb_path, 'r', encoding='utf-8') as f:
            self.matrix = json.load(f)
        self.aspects = self.matrix.get('aspects', [])

    def audit_target(self, target_dir: str) -> CCSSAuditReport:
        """
        Audits a codebase/architecture directory against the 10 CCSS aspects.
        """
        files_content = []
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', '.venv', 'venv', 'dist', 'build')]
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in ('.py', '.ts', '.js', '.sol', '.vy', '.tf', '.yaml', '.yml', '.md', '.json', '.env'):
                    full_path = os.path.join(root, f)
                    try:
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as fp:
                            files_content.append((full_path, fp.read()))
                    except Exception:
                        pass

        combined_text = '\n'.join([content for _, content in files_content]).lower()

        aspect_results = []
        weighted_score_sum = 0.0
        total_weight = sum(a.get('weight', 10) for a in self.aspects)

        for aspect in self.aspects:
            aspect_id = aspect['id']
            name = aspect['name']
            category = aspect['category']
            weight = aspect['weight']
            indicators = aspect.get('indicators', [])
            criteria = aspect.get('criteria', {})
            risks = aspect.get('risks', [])

            matched = []
            for ind in indicators:
                pattern = re.compile(r'\b' + re.escape(ind.lower()) + r'\b')
                if pattern.search(combined_text):
                    matched.append(ind)

            match_ratio = len(matched) / max(1, len(indicators))
            
            # Contextual scoring
            if aspect_id == 'CCSS-01': # Key Generation
                if 'hsm' in matched or 'airgap' in matched:
                    score = min(100.0, 70.0 + match_ratio * 30.0)
                elif 'secrets.token_bytes' in matched or 'os.urandom' in matched:
                    score = min(75.0, 45.0 + match_ratio * 30.0)
                else:
                    score = max(20.0, match_ratio * 40.0)
            elif aspect_id == 'CCSS-03': # Multi-sig
                if 'multisig' in matched or 'gnosis' in matched or 'safe' in matched or 'mpc_sign' in matched:
                    score = min(100.0, 65.0 + match_ratio * 35.0)
                else:
                    score = match_ratio * 30.0
            elif aspect_id == 'CCSS-05': # Hot/Cold
                if 'hot_wallet' in matched and 'cold_wallet' in matched:
                    score = min(100.0, 75.0 + match_ratio * 25.0)
                elif 'cold_wallet' in matched or 'custody' in matched:
                    score = 50.0 + match_ratio * 20.0
                else:
                    score = match_ratio * 30.0
            elif aspect_id == 'CCSS-06': # Velocity & Limits
                if 'timelock' in matched and ('daily_limit' in matched or 'velocity_limit' in matched):
                    score = min(100.0, 80.0 + match_ratio * 20.0)
                elif '2fa' in matched or 'totp' in matched:
                    score = 50.0 + match_ratio * 25.0
                else:
                    score = match_ratio * 30.0
            else:
                score = match_ratio * 100.0

            if score >= 85.0:
                status = 'PASS_L3'
            elif score >= 65.0:
                status = 'PASS_L2'
            elif score >= 45.0:
                status = 'PASS_L1'
            else:
                status = 'NON_COMPLIANT'

            gaps = []
            recs = []
            if status in ('NON_COMPLIANT', 'PASS_L1'):
                gaps.append(f"Missing Level 2/3 controls for {name}: {criteria.get('level_2', '')}")
                recs.append(f"Implement {criteria.get('level_2', '')}")
                recs.append(f"Upgrade to {criteria.get('level_3', '')} for banking-grade institutional custody.")
            elif status == 'PASS_L2':
                gaps.append(f"Sub-optimal for Level 3: {criteria.get('level_3', '')}")
                recs.append(f"Target Level 3 compliance: {criteria.get('level_3', '')}")

            weighted_score_sum += score * (weight / total_weight)

            aspect_results.append(CCSSAspectResult(
                aspect_id=aspect_id,
                name=name,
                category=category,
                weight=weight,
                score=round(score, 1),
                status=status,
                matched_indicators=matched,
                identified_gaps=gaps,
                recommendations=recs
            ))

        overall_score = round(weighted_score_sum, 1)
        min_aspect_score = min(r.score for r in aspect_results)

        if overall_score >= 85.0 and min_aspect_score >= 60.0:
            achieved_level = 'Level 3 (Banking Grade)'
        elif overall_score >= 65.0 and min_aspect_score >= 40.0:
            achieved_level = 'Level 2 (Enterprise Standard)'
        elif overall_score >= 45.0:
            achieved_level = 'Level 1 (Baseline Security)'
        else:
            achieved_level = 'Non-Compliant'

        critical_gaps = []
        for r in aspect_results:
            if r.status == 'NON_COMPLIANT':
                critical_gaps.append(f"[{r.aspect_id}] {r.name}: Score {r.score}% is below CCSS Level 1 requirement.")

        compliance_summary = {
            'level_3_passed': sum(1 for r in aspect_results if r.status == 'PASS_L3'),
            'level_2_passed': sum(1 for r in aspect_results if r.status in ('PASS_L3', 'PASS_L2')),
            'level_1_passed': sum(1 for r in aspect_results if r.status in ('PASS_L3', 'PASS_L2', 'PASS_L1')),
            'non_compliant': sum(1 for r in aspect_results if r.status == 'NON_COMPLIANT'),
            'total_aspects': len(aspect_results)
        }

        return CCSSAuditReport(
            overall_score=overall_score,
            achieved_level=achieved_level,
            aspect_results=aspect_results,
            total_findings=len(critical_gaps),
            critical_gaps=critical_gaps,
            compliance_summary=compliance_summary
        )
