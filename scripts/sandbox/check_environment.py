import os
import sys
import logging
import importlib
import subprocess

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("Adversum-Check")

def check_rust():
    print("\n[RUST CORE STATUS]")
    try:
        import adversum_core
        print("✅ adversum_core extension found.")
        if hasattr(adversum_core, "Finding"):
            print("✅ Core version is up-to-date and fully functional.")
        else:
            print("⚠️  Core version is OUTDATED (missing 'Finding' exports).")
            print("   Action: Run `maturin develop` in `adversum/core`.")
    except ImportError:
        print("❌ adversum_core extension NOT found.")
        print("   Action: Run `maturin develop` in `adversum/core`.")

    print("\n[BUILD TOOLS STATUS]")
    try:
        rustc_v = subprocess.check_output(["rustc", "--version"]).decode().strip()
        print(f"✅ Rust compiler: {rustc_v}")
    except:
        print("❌ Rust compiler (rustc) NOT found.")

    try:
        # Check for linker
        import platform
        if platform.system() == "Windows":
            print("🔍 Checking for MSVC Linker (link.exe)...")
            # Usually found in PATH if VS Build Tools are installed correctly
            try:
                subprocess.check_output(["link", "/?"], stderr=subprocess.STDOUT)
                print("✅ MSVC Linker (link.exe) found.")
            except:
                print("❌ MSVC Linker (link.exe) NOT found in PATH.")
                print("   Industrial Performance requires Visual Studio Build Tools with C++ workload.")
    except:
        pass

def check_ai():
    print("\n[AI / LLM STATUS — Nebius Token Factory / NVIDIA Nemotron]")
    keys = {
        "NEBIUS_API_KEY": os.getenv("NEBIUS_API_KEY"),
        "NEBIUS_MODEL":   os.getenv("NEBIUS_MODEL", "nvidia/Nemotron-3_5-Lightning (default)"),
        "OLLAMA_BASE_URL": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    }

    for key, val in keys.items():
        if val and "key" in key.lower() and val not in ("mock-key", "your_nebius_token_factory_api_key_here", ""):
             print(f"✅ {key}: Configured")
        elif "url" in key.lower() or "model" in key.lower():
             print(f"🔍 {key}: {val}")
        else:
             print(f"⚠️  {key}: NOT SET (Using Mock Fallback)")

    import httpx
    try:
        resp = httpx.get(f"{keys['OLLAMA_BASE_URL']}/api/tags", timeout=2.0)
        if resp.status_code == 200:
             print("✅ Ollama: Running and responsive (optional local fallback).")
        else:
             print(f"⚠️  Ollama: Not responding (Status {resp.status_code}).")
    except:
        print("⚠️  Ollama: Not responsive or not installed (optional).")

def main():
    print("="*50)
    print("        ADVERSUM SYSTEM DIAGNOSIS")
    print("="*50)

    print(f"Python version: {sys.version.split()[0]}")
    print(f"Project root: {os.getcwd()}")

    check_rust()
    check_ai()

    print("\n" + "="*50)
    nebius_ok = bool(os.getenv("NEBIUS_API_KEY", "").strip())
    if "adversum_core" in sys.modules and nebius_ok:
        print("🚀 STATUS: OPTIMAL — Rust Core + NVIDIA Nemotron via Nebius")
    elif nebius_ok:
        print("✅ STATUS: OPERATIONAL — Python fallback + NVIDIA Nemotron via Nebius")
    else:
        print("⚠️  STATUS: FALLBACK / DEGRADED MODE")
        print("Adversum is functional but using simulated reasoning and regex analysis.")
        print("Set NEBIUS_API_KEY to enable NVIDIA Nemotron AI inference.")
    print("="*50)

if __name__ == "__main__":
    main()
