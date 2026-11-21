"""Halmos execution service (Step 2) — real symbolic witnesses or UNKNOWN.

Runs the versioned Foundry harnesses in ``harnesses/`` through Halmos
and maps the *actual* tool outcome onto the Step-1 verdicts:

- counterexample found (check FAILS with a model) -> candidate PROVEN
  witness (``halmos_counterexample``) with the concrete model values;
- no counterexample within Halmos bounds -> ``no_counterexample``:
  the finding stays DETECTED_UNPROVEN, never "proven safe";
- timeout, missing toolchain, solver error -> ``unknown`` (UNKNOWN
  verdict), never silence and never a fabricated witness.

Nothing here invents a result: without forge+halmos it reports
``unavailable`` and every caller must surface UNKNOWN.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent
REPO_ROOT = PROJECT_ROOT.parent.parent

HARNESS_BY_RULE = {
    "SOL-004": ("HalmosSOL004Test", "check_vulnerable_add_no_overflow"),
    "SOL-001": ("HalmosSOL001Test", "check_vulnerable_no_drain"),
    "SOL-003": ("HalmosSOL003Test", "check_vulnerable_nonowner_cannot_kill"),
    "SOL-012": ("HalmosSOL003Test", "check_vulnerable_nonowner_can_withdraw"),
    "SOL-007": ("HalmosSOL007Test", "check_vulnerable_failed_call_not_paid"),
    "SOL-002": ("HalmosSOL002Test", "check_vulnerable_trap_cannot_drain"),
}

# Step 3 (intermediate group): independence checks whose failure shows
# a source->sink dependency — never an exploit proof.
DEPENDENCY_HARNESS_BY_RULE = {
    "SOL-006": ("HalmosSOL006DependencyTest", "check_vulnerable_payout_time_independent"),
    "SOL-011": ("HalmosSOL011DependencyTest", "check_vulnerable_winner_entropy_independent"),
    "SOL-009": ("HalmosSOL009DependencyTest", "check_vulnerable_limit_spot_independent"),
    "SOL-013": ("HalmosSOL013DependencyTest", "check_vulnerable_bound_attacker_independent"),
}


def _find_binary(name: str) -> Optional[str]:
    env = os.getenv(f"{name.upper()}_BIN") or os.getenv("FOUNDRY_BIN" if name in ("forge", "anvil") else "")
    if env and Path(env).exists():
        return env
    found = shutil.which(name)
    if found:
        return found
    for cand in (Path.home() / ".foundry" / "bin" / (name + (".exe" if os.name == "nt" else "")),
                 Path(f"/usr/local/bin/{name}"), Path(f"/root/.foundry/bin/{name}")):
        if cand.exists():
            return str(cand)
    if name == "halmos":
        # pip-installed console script next to the interpreter.
        import sys
        cand = Path(sys.executable).parent / ("halmos.exe" if os.name == "nt" else "halmos")
        if cand.exists():
            return str(cand)
    return None


def halmos_available() -> dict:
    return {"forge": _find_binary("forge"), "anvil": _find_binary("anvil"), "halmos": _find_binary("halmos")}


def run_dependency_harness(rule_id: str, timeout: int = 180) -> dict:
    """Run a Step-3 independence check; failure shows dependency only."""
    spec = DEPENDENCY_HARNESS_BY_RULE.get(rule_id)
    if spec is None:
        return {"status": "error", "error": f"no dependency harness for {rule_id}", "rule_id": rule_id}
    contract, check_fn = spec
    result = _run_halmos_contract(contract, check_fn, rule_id, timeout)
    if result.get("status") == "counterexample":
        fragment = {
            "proof_verdict": "DEPENDENCY_PROVEN",
            "witness": {
                "kind": "dependency_path",
                "solver": "halmos (independence check)",
                "entry_point": check_fn,
                "call_path": [check_fn, f"harness:{contract}"],
                "counterexample": {"source": f"independence refuted for {rule_id}",
                                   "sink": "decision/payment/selection/gas sink in harness target",
                                   "model": result.get("counterexample")},
                "scope": "Dependency demonstrated on the versioned harness target; exploitability NOT proven.",
                "artifact": f"modules/halmos/harnesses ({contract})",
            },
            "verdict_reason": "Halmos refuted independence: the sink depends on the source. Exploitability not proven.",
        }
        result["verdict_fragment"] = fragment
    elif result.get("status") == "no_counterexample":
        result["verdict_fragment"] = {"proof_verdict": "DETECTED_UNPROVEN", "witness": None,
                                      "verdict_reason": "No dependency shown within Halmos bounds on the harness; exploitability not proven."}
    else:
        result["verdict_fragment"] = {"proof_verdict": "UNKNOWN", "witness": None,
                                      "verdict_reason": f"Halmos could not decide ({result.get('status')}) — UNKNOWN, never safe."}
    return result


def _run_halmos_contract(contract: str, check_fn: str, rule_id: str, timeout: int = 180) -> dict:
    return _run_halmos_impl(contract, check_fn, rule_id, timeout)


def run_halmos_harness(rule_id: str, timeout: int = 180) -> dict:
    """Execute the Halmos harness for ``rule_id`` for real.

    Return dict always carries ``status`` in:
    counterexample | no_counterexample | timeout | unavailable | error
    plus the parsed model (when any) and bounded raw output.
    """
    spec = HARNESS_BY_RULE.get(rule_id)
    if spec is None:
        return {"status": "error", "error": f"no Halmos harness for {rule_id}", "rule_id": rule_id}
    contract, check_fn = spec
    return _run_halmos_impl(contract, check_fn, rule_id, timeout)


def _run_halmos_impl(contract: str, check_fn: str, rule_id: str, timeout: int = 180) -> dict:
    bins = halmos_available()
    if not bins["halmos"] or not bins["forge"]:
        return {"status": "unavailable", "rule_id": rule_id, "binaries": bins,
                "error": "forge/halmos not found (install Foundry + pip install halmos)"}
    out_json = PROJECT_ROOT / "out" / f"halmos_{rule_id}.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["PATH"] = str(Path(bins["forge"]).parent) + os.pathsep + env.get("PATH", "")
    try:
        proc = subprocess.run(
            [bins["halmos"], "--root", str(PROJECT_ROOT),
             "--contract", contract, "--json-output", str(out_json)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, env=env,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "rule_id": rule_id,
                "error": f"halmos exceeded {timeout}s — verdict UNKNOWN, not safe"}
    except Exception as exc:
        return {"status": "error", "rule_id": rule_id, "error": f"{type(exc).__name__}: {exc}"}

    result = {"status": "error", "rule_id": rule_id, "contract": contract,
              "check_function": check_fn, "stdout_tail": (proc.stdout or "")[-1500:],
              "stderr_tail": (proc.stderr or "")[-500:]}
    try:
        data = json.loads(out_json.read_text(encoding="utf-8"))
    except Exception as exc:
        result["error"] = f"unparseable halmos json: {exc}"
        return result
    for _file, tests in (data.get("test_results") or {}).items():
        for test in tests:
            if not test.get("name", "").startswith(check_fn):
                continue
            models = []
            for m in test.get("models") or []:
                model = (m.get("model") or {})
                models.append({
                    str(v.get("variable_name") or k): v.get("value")
                    for k, v in model.items() if isinstance(v, dict)
                })
            if test.get("exitcode") == 1:
                result.update({"status": "counterexample", "counterexample": models,
                               "num_paths": test.get("num_paths"), "time_s": (test.get("time") or [None])[0]})
            elif test.get("exitcode") == 0:
                result.update({"status": "no_counterexample", "counterexample": [],
                               "num_paths": test.get("num_paths"), "time_s": (test.get("time") or [None])[0]})
            else:
                # e.g. HalmosException (unsupported SELFDESTRUCT in 0.3.3):
                # an engine error is UNKNOWN, never a silent pass.
                note = "unsupported opcode SELFDESTRUCT (halmos 0.3.3)" if "SELFDESTRUCT" in (proc.stdout or "") else f"halmos exitcode {test.get('exitcode')}"
                result.update({"status": "error", "error": note, "counterexample": []})
            return result
    result["error"] = f"check {check_fn} not found in halmos output"
    return result


def halmos_result_to_verdict(halmos_result: dict) -> dict:
    """Map a real Halmos outcome to Step-1 verdict fields (dict fragment)."""
    status = halmos_result.get("status")
    if status == "counterexample":
        counterexample = {}
        for model in halmos_result.get("counterexample") or []:
            counterexample.update({k: v for k, v in model.items()})
        witness = {
            "kind": "halmos_counterexample",
            "solver": "halmos",
            "entry_point": halmos_result.get("check_function"),
            "call_path": [halmos_result.get("check_function", "?"),
                          f"harness:{halmos_result.get('contract', '?')}"],
            "counterexample": counterexample,
            "scope": "Halmos bounded symbolic execution of the versioned harness; "
                     "counterexample is concrete for the harness target, "
                     "whole-contract completeness is not claimed.",
            "artifact": f"modules/halmos/harnesses ({halmos_result.get('contract')})",
        }
        return {"proof_verdict": "PROVEN", "witness": witness,
                "verdict_reason": "Halmos found a concrete counterexample (entry -> sink) in the versioned harness."}
    if status == "no_counterexample":
        return {"proof_verdict": "DETECTED_UNPROVEN", "witness": None,
                "verdict_reason": "Halmos found no counterexample within its bounds — bounded absence, not a proof of safety; finding stays unproven."}
    return {"proof_verdict": "UNKNOWN", "witness": None,
            "verdict_reason": f"Halmos could not decide ({status}: {halmos_result.get('error', '')}) — UNKNOWN, never safe."}
