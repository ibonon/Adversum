from orchestrator.scanner.project_scanner import ProjectScanner
import logging

logging.basicConfig(level=logging.INFO)

scanner = ProjectScanner("f:/Adversum/adversum/stress_test_project_v2")
files = scanner.scan()
print(f"Scanned files: {len(files)}")

if len(files) > 0:
    print(f"Sample file: {files[0]}")
