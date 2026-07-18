import os
import sys
import time
import json
import asyncio
from unittest.mock import MagicMock

# Add parent directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from orchestrator.pipeline.analysis_pipeline import AnalysisPipeline
from orchestrator.models.sql_models import FileHash, CachedFinding
from orchestrator.services.db import create_db_and_tables
from sqlmodel import Session, select
from orchestrator.db.engine import engine

async def verify_phase4():
    print("--- Phase 4: Extreme Industrial Optimization Verification ---")
    create_db_and_tables()
    
    project_path = os.path.abspath("temp_test_project")
    os.makedirs(project_path, exist_ok=True)
    
    file1 = os.path.join(project_path, "vuln1.py")
    file2 = os.path.join(project_path, "vuln2.py")
    
    with open(file1, "w") as f:
        f.write("eval('x + 1')\n")
    
    with open(file2, "w") as f:
        f.write("import os\nos.system('ls')\n")
        
    pipeline = AnalysisPipeline()
    
    # --- Test 1: Initial Scan (Cold) ---
    print("\n[Test 1] Initial Scan (Cold)...")
    start = time.time()
    result1 = await pipeline.run(project_path)
    duration1 = time.time() - start
    print(f"Initial Scan Duration: {duration1:.4f}s")
    print(f"Findings: {len(result1['findings'])}")
    
    # --- Test 2: Repeat Scan (Hot - No changes) ---
    print("\n[Test 2] Repeat Scan (Hot - No changes)...")
    start = time.time()
    result2 = await pipeline.run(project_path)
    duration2 = time.time() - start
    print(f"Repeat Scan Duration: {duration2:.4f}s")
    print(f"Findings: {len(result2['findings'])}")
    
    if duration2 < duration1:
        print("Scan Optimization confirmed: Repeat scan is much faster!")
    else:
        print("Note: Repeat scan not significantly faster (project too small?)")

    # --- Test 3: Incremental Scan (One file modified) ---
    print("\n[Test 3] Incremental Scan (One file modified)...")
    with open(file1, "w") as f:
        f.write("eval('y + 2')\n# modified\n")
        
    start = time.time()
    result3 = await pipeline.run(project_path)
    duration3 = time.time() - start
    print(f"Incremental Scan Duration: {duration3:.4f}s")
    print(f"Findings: {len(result3['findings'])}")
    
    # Cleanup
    os.remove(file1)
    os.remove(file2)
    os.rmdir(project_path)

if __name__ == "__main__":
    asyncio.run(verify_phase4())
