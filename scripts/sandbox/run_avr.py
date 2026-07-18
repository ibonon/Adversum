import asyncio
import logging
import os
import sys

# Add the project root to sys.path to allow imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AVR_Runner")

from orchestrator.services.avr import AVREngine

async def main():
    logger.info("Initializing AVR Engine...")
    avr = AVREngine()
    
    target_file = os.path.abspath("adversum/test_target.py")
    if not os.path.exists(target_file):
        # Fallback for different CWD
        target_file = os.path.abspath("f:/Adversum/adversum/test_target.py")

    logger.info(f"Targeting file: {target_file}")
    
    # We manually trigger the remediation for the known finding
    # Finding Details (from analysis):
    # - File: test_target.py
    # - Line: 3
    # - Snippet: eval(data)
    # - ID: CODE_INJECTION
    
    # Updated Fix to be safer
    fix_code = "import ast\n    ast.literal_eval(data)"
    
    logger.info("Running AVR Remediation...")
    success = await avr.run_remediation(
        finding_id=999, # Dummy ID for manual trigger
        file_path=target_file,
        line_number=3,
        old_snippet="eval(data)",
        fix_code=fix_code
    )
    
    if success:
        logger.info("✅ SUCCESS: Remediation applied and verified!")
    else:
        logger.error("❌ FAILURE: Remediation failed or verification rejected the fix.")

if __name__ == "__main__":
    asyncio.run(main())
