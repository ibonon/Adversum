import sys
import os
import logging

# Add the root directory to sys.path so we can import 'adversum'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from adversum.orchestrator.pipeline.analysis_pipeline import AnalysisPipeline

logging.basicConfig(level=logging.INFO)

def test_pipeline():
    print("Testing Analysis Pipeline...")
    
    # Create a dummy file with a vulnerability
    test_file_path = "vulnerable_test.py"
    with open(test_file_path, "w") as f:
        f.write("x = eval('1 + 1')\n")
        f.write("api_key = '12345'\n")

    try:
        pipeline = AnalysisPipeline()
        # Run on current directory
        findings = pipeline.run(".")
        
        print(f"\nFound {len(findings)} findings.")
        for f in findings:
            print(f"[{f.validation_status.value}] {f.raw.rule_id}: {f.reasoning_notes}")

    finally:
        # Cleanup
        if os.path.exists(test_file_path):
            os.remove(test_file_path)

if __name__ == "__main__":
    test_pipeline()
