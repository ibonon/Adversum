from .scanner import Scanner
from .wrapper import CoreWrapper
from .reasoning import ReasoningEngine
from .schemas import AnalysisResult, Finding

class AnalysisPipeline:
    def __init__(self, project_id: str, root_path: str):
        self.project_id = project_id
        self.root_path = root_path
        self.scanner = Scanner(root_path)
        self.wrapper = CoreWrapper()
        self.reasoning = ReasoningEngine()

    def run(self) -> AnalysisResult:
        files = self.scanner.scan()
        raw_findings = []
        
        for file_path in files:
            findings = self.wrapper.analyze_file(file_path)
            raw_findings.extend(findings)
            
        # AI Verification Step
        final_findings = self.reasoning.verify_findings(raw_findings)
            
        return AnalysisResult(
            project_id=self.project_id,
            files_analyzed=len(files),
            findings=final_findings,
            status="success"
        )
