import sys
import os
import time
import asyncio
import logging

# Ensure orchestrator is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from orchestrator.pipeline.analysis_pipeline import AnalysisPipeline

async def run_self_audit():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("Adversum.SelfAudit")
    
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    logger.info(f"Starting Self-Audit Performance Test for: {project_root}")
    
    pipeline = AnalysisPipeline()
    
    start_time = time.time()
    result = await pipeline.run(project_root)
    duration = time.time() - start_time
    
    findings = result.get("findings", [])
    summary = result.get("summary", "No summary generated.")
    
    print("\n" + "="*50)
    print(" SELF-AUDIT PERFORMANCE RESULTS ")
    print("="*50)
    print(f"Total Time:     {duration:.4f}s")
    print(f"Total Findings: {len(findings)}")
    print(f"Robustness Score: {result.get('robustness_score', 1.0)*100:.1f}%")
    print(f"FFI Engine:     {'Active' if pipeline.core.use_ffi else 'MOCK (FFI Not Linked)'}")
    print("-"*50)
    
    if findings:
        print("\nFindings Overview:")
        for i, f in enumerate(findings[:5]):
            immune_status = "🛡️ IMMUNE" if f.raw.immune_context and f.raw.immune_context.get('invariant_holds') else "⚠️ VULNERABLE"
            print(f"{i+1}. [{f.raw.severity}] {f.raw.rule_id} ({immune_status}) in {os.path.basename(f.raw.file_path)}:{f.raw.line_number}")
        if len(findings) > 5:
            print(f"... and {len(findings)-5} more.")
            
    print("\nAI Summary:")
    print(summary)
    print("="*50)

if __name__ == "__main__":
    asyncio.run(run_self_audit())
