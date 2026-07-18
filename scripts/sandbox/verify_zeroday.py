import asyncio
import os
import sys

# Ensure we can import orchestrator
sys.path.append(os.getcwd())

# Enable Research Mode
os.environ["RESEARCH_MODE"] = "true"
os.environ["AI_MOCK_MODE"] = "true" # Use mock for tests
os.environ["USE_LLM_VALIDATOR"] = "true"

from orchestrator.pipeline.analysis_pipeline import AnalysisPipeline

async def test_zeroday_discovery():
    print("--- Starting ZeroDayMiner Verification ---")
    pipeline = AnalysisPipeline()
    
    # Target our hidden danger file
    test_file = os.path.join("temp_test_project", "hidden_danger.py")
    
    # Run the pipeline
    result = await pipeline.run("temp_test_project")
    
    findings = result.get("findings", [])
    print(f"\nTotal Findings: {len(findings)}")
    
    zeroday_candidates = [f for f in findings if f.raw.id == "ZERODAY_CANDIDATE_SINK"]
    print(f"Zero-Day Candidates found: {len(zeroday_candidates)}")
    
    for zd in zeroday_candidates:
        print(f"\n[DISCOVERED SINK: {zd.raw.flow_path[0]}]")
        print(f"File: {zd.raw.file_path}:{zd.raw.line}")
        print(f"Snippet: {zd.raw.snippet}")
        print(f"AI Verdict: {zd.validation_status}")
        print(f"Reasoning: {zd.reasoning_notes}")

if __name__ == "__main__":
    asyncio.run(test_zeroday_discovery())
