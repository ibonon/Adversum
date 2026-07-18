from dataclasses import dataclass, field
from typing import Dict, Any, List

@dataclass
class VulnerabilityContext:
    file_path: str
    code_snippet: str
    vulnerability_type: str
    severity: str
    surrounding_code: str
    flow_path: List[str] = field(default_factory=list)

class ContextBuilder:
    def __init__(self):
        pass
    
    def build_context(self, finding: Any, file_content: str) -> VulnerabilityContext:
        """Extracts code and context for a finding."""
        # 'finding' is now a RawFinding object
        return VulnerabilityContext(
            file_path=finding.file_path,
            code_snippet=finding.snippet or "",
            vulnerability_type=finding.id,
            severity=str(finding.severity),
            surrounding_code=file_content[:500],
            flow_path=finding.flow_path
        )
