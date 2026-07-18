import asyncio
import os
import logging
from orchestrator.pipeline.analysis_pipeline import AnalysisPipeline
from orchestrator.services.db import create_db_and_tables

# Configure logging for visibility
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("Adversum-Audit")

async def run_minyx_audit():
    target = r"F:\Minyx"
    
    # 1. Ensure DB is ready
    create_db_and_tables()
    
    # 2. Configure Research Mode (for Shadow Discovery)
    os.environ["RESEARCH_MODE"] = "true"
    os.environ["USE_LLM_VALIDATOR"] = "false" # Use deterministic Rust/Python validation
    
    print("\n" + "="*50)
    print(f"RAPID AUDIT: {target}")
    print("="*50)

    # 3. Initialize Pipeline
    pipeline = AnalysisPipeline()
    
    if pipeline.core.use_ffi:
        print("RUST CORE: ACTIVE (Ultra-Fast AST Analysis)")
    else:
        print("RUST CORE: NOT LINKED (Using Python Fallback)")

    # 4. Run Analysis
    print("\nScanning and analyzing files...")
    results = await pipeline.run(target)
    
    findings = results.get("findings", [])
    summary = results.get("summary", "No summary generated.")
    
    print("\n" + "="*50)
    print(f"AUDIT RESULTS: {len(findings)} Findings")
    print("="*50)
    
    if not findings:
        print("No vulnerabilities detected. F:\Minyx seems clean.")
    else:
        # Sort by severity
        severity_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(findings, key=lambda x: severity_map.get(
            x.raw.severity.value if hasattr(x.raw.severity, 'value') else x.raw.severity, 4))
        
        for i, f in enumerate(sorted_findings, 1):
            raw = f.raw
            sev = raw.severity.value if hasattr(raw.severity, 'value') else raw.severity
            print(f"\n[{i}] {sev}: {raw.id}")
            print(f"    Status: {f.validation_status}")
            print(f"    Confidence: {f.ai_confidence:.2f}")
            print(f"    File: {raw.file_path}:{raw.line}")
            print(f"    Message: {raw.message}")
            if f.reasoning_notes:
                print(f"    Reasoning: {f.reasoning_notes[:200]}...")
            if raw.snippet:
                print(f"    Snippet: {raw.snippet.strip()}")

    print("\n" + "="*50)
    print("RAPID REPORT SUMMARY")
    print("="*50)
    print(summary)
    print("\nAudit duration logged in telemetry.")

if __name__ == "__main__":
    asyncio.run(run_minyx_audit())
