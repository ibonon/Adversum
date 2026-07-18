from typing import List
from .schemas import Finding

class ReasoningEngine:
    def __init__(self, model_name: str = "gemini-pro"):
        self.model_name = model_name

    def verify_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Simulates AI review of findings. 
        In production, this would call Vertex AI / OpenAI.
        """
        verified = []
        for f in findings:
            # Mock Logic: AI confirms "High" severity, downgrades "Medium"
            if f.severity == "High":
                f.description += " [Verified by AI]"
                verified.append(f)
            else:
                # AI thinks it's a false positive
                pass 
                # Or keep it but annotated
                f.description += " [AI: Low Confidence]"
                verified.append(f)
        
        return verified
