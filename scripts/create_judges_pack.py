import os
import zipfile

base_dir = r"c:\Users\SMC-DXB\Projects\Adversum"
zip_path = os.path.join(base_dir, "Adversum_Judges_Benchmark_Pack.zip")

files_to_pack = [
    # (source_path, arcname_in_zip)
    (os.path.join(base_dir, "README_FOR_JUDGES.md"), "README_FOR_JUDGES.md"),
    (os.path.join(base_dir, "BENCHMARK.md"), "BENCHMARKS/BENCHMARK.md"),
    (os.path.join(base_dir, "benchmarks", "z3_scan_proof.html"), "BENCHMARKS/z3_scan_proof.html"),
    (os.path.join(base_dir, "benchmarks", "z3_scan_proof.json"), "BENCHMARKS/z3_scan_proof.json"),
    (os.path.join(base_dir, "benchmarks", "results", "smartbugs_report.json"), "BENCHMARKS/smartbugs_report.json"),
    (os.path.join(base_dir, "benchmarks", "results", "smartbugs_report.md"), "BENCHMARKS/smartbugs_report.md"),
    
    (os.path.join(base_dir, "docs", "NVIDIA_NEMOTRON_ARCHITECTURE.md"), "ARCHITECTURE_AND_DOCS/NVIDIA_NEMOTRON_ARCHITECTURE.md"),
    (os.path.join(base_dir, "docs", "DEPLOYMENT_NEBIUS.md"), "ARCHITECTURE_AND_DOCS/DEPLOYMENT_NEBIUS.md"),
    (os.path.join(base_dir, "docs", "ARCHITECTURE.md"), "ARCHITECTURE_AND_DOCS/ARCHITECTURE.md"),
    (os.path.join(base_dir, "docs", "DETERMINISTIC_VALIDATION.md"), "ARCHITECTURE_AND_DOCS/DETERMINISTIC_VALIDATION.md"),
    
    (os.path.join(base_dir, "docs", "media", "presentation", "06_z3_formal_proof_report.png"), "FORMAL_VERIFICATION_PROOFS/06_z3_formal_proof_report.png"),
    (os.path.join(base_dir, "docs", "media", "presentation", "01_landing_hero.png"), "FORMAL_VERIFICATION_PROOFS/01_landing_hero.png"),
    (os.path.join(base_dir, "docs", "media", "presentation", "02_soc_dashboard.png"), "FORMAL_VERIFICATION_PROOFS/02_soc_dashboard.png"),
    (os.path.join(base_dir, "docs", "media", "presentation", "03_war_room.png"), "FORMAL_VERIFICATION_PROOFS/03_war_room.png"),
    (os.path.join(base_dir, "docs", "media", "presentation", "04_analytics.png"), "FORMAL_VERIFICATION_PROOFS/04_analytics.png"),
]

with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
    for src, arc in files_to_pack:
        if os.path.exists(src):
            zipf.write(src, arc)
            print(f"Added: {arc} ({os.path.getsize(src)} bytes)")
        else:
            print(f"Warning: File not found: {src}")

size_mb = os.path.getsize(zip_path) / (1024 * 1024)
print(f"\nSuccessfully created {zip_path}")
print(f"Total archive size: {size_mb:.2f} MB")
