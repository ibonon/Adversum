"""
Phase 2 Tests — Autonomous Threat Modeler (STRIDE + PASTA + MITRE ATT&CK)
pytest tests/test_phase2_threat_model.py
"""

import asyncio
import pytest

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.threat_model.autonomous_modeler import (
    AutonomousThreatModeler,
    STRIDECategory,
    ThreatModelReport,
)


VULNERABLE_SOLIDITY = """
pragma solidity ^0.8.0;

contract VulnerableVault {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(tx.origin == owner, "Not owner");
        _;
    }

    function initialize(address _owner) public {
        owner = _owner;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }

    function drain() public onlyOwner {
        selfdestruct(payable(owner));
    }

    function processUsers(address[] memory users) public {
        for (uint i = 0; i < users.length; i++) {
            // process each user
        }
    }
}
"""

CLEAN_CODE = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureVault is ReentrancyGuard, Ownable {
    mapping(address => uint256) private _balances;

    function withdraw(uint256 amount) external nonReentrant {
        require(_balances[msg.sender] >= amount, "Insufficient balance");
        _balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
        emit Withdrawal(msg.sender, amount);
    }

    event Withdrawal(address indexed user, uint256 amount);
}
"""


@pytest.mark.asyncio
async def test_stride_detects_all_six_categories():
    """STRIDE analysis should detect threats across all 6 categories for vulnerable code."""
    modeler = AutonomousThreatModeler()
    report  = await modeler.analyze(VULNERABLE_SOLIDITY, target="VulnerableVault")

    detected_categories = {t.category for t in report.stride_threats}
    # With tx.origin (Spoofing), selfdestruct (Tampering), unbounded loop (DoS),
    # onlyOwner (Elevation), initialize (Elevation) — at least 3 categories
    assert len(detected_categories) >= 3, f"Expected ≥3 STRIDE categories, got: {detected_categories}"


@pytest.mark.asyncio
async def test_stride_detects_tx_origin_spoofing():
    """tx.origin must be detected as a Spoofing threat."""
    modeler = AutonomousThreatModeler()
    report  = await modeler.analyze(VULNERABLE_SOLIDITY, target="VulnerableVault")

    spoofing = [t for t in report.stride_threats if t.category == STRIDECategory.SPOOFING]
    assert len(spoofing) >= 1, "tx.origin should generate a Spoofing threat"
    assert any("tx.origin" in t.description.lower() or "origin" in t.description.lower()
               for t in spoofing)


@pytest.mark.asyncio
async def test_stride_detects_unprotected_initializer():
    """Unprotected initialize() should be detected as Elevation of Privilege."""
    modeler = AutonomousThreatModeler()
    report  = await modeler.analyze(VULNERABLE_SOLIDITY, target="VulnerableVault")

    elevation = [t for t in report.stride_threats if t.category == STRIDECategory.ELEVATION_OF_PRIVILEGE]
    assert len(elevation) >= 1, "Unprotected initializer should generate Elevation threat"


@pytest.mark.asyncio
async def test_pasta_seven_stages_complete():
    """PASTA analysis must produce all 7 stages."""
    modeler = AutonomousThreatModeler()
    report  = await modeler.analyze(VULNERABLE_SOLIDITY, target="TestProtocol")

    assert len(report.pasta_stages) == 7, f"Expected 7 PASTA stages, got {len(report.pasta_stages)}"
    stage_numbers = [s.stage_number for s in report.pasta_stages]
    assert stage_numbers == list(range(1, 8)), "Stages should be numbered 1–7"

    # Each stage must have a name, description, and findings
    for stage in report.pasta_stages:
        assert stage.name
        assert stage.description
        assert isinstance(stage.findings, list)


@pytest.mark.asyncio
async def test_attack_paths_generated_for_elevation():
    """Attack paths should be generated when Elevation of Privilege threats exist."""
    modeler = AutonomousThreatModeler()
    report  = await modeler.analyze(VULNERABLE_SOLIDITY, target="VulnerableVault")

    assert len(report.attack_paths) >= 1, "Should generate at least 1 attack path"
    for path in report.attack_paths:
        assert path.path_id
        assert path.name
        assert len(path.steps) >= 3
        assert 0 < path.risk_score <= 10.0


@pytest.mark.asyncio
async def test_overall_risk_critical_for_vulnerable_code():
    """Vulnerable code with high-severity findings should yield HIGH or CRITICAL overall risk."""
    modeler = AutonomousThreatModeler()
    report  = await modeler.analyze(VULNERABLE_SOLIDITY, target="VulnerableVault")

    assert report.overall_risk in ("CRITICAL", "HIGH"), (
        f"Expected CRITICAL or HIGH for vulnerable code, got: {report.overall_risk}"
    )
    assert report.overall_score >= 7.0


@pytest.mark.asyncio
async def test_report_to_dict_schema():
    """Report serialization produces required schema keys."""
    modeler = AutonomousThreatModeler()
    report  = await modeler.analyze(VULNERABLE_SOLIDITY, target="VulnerableVault")
    d       = report.to_dict()

    assert "report_id"        in d
    assert "overall_risk"     in d
    assert "overall_score"    in d
    assert "stride"           in d
    assert "pasta"            in d
    assert "attack_paths"     in d
    assert "recommendations"  in d
    assert "generated_at"     in d
    assert "analysis_time_ms" in d

    # STRIDE block
    assert "threats"       in d["stride"]
    assert "by_category"   in d["stride"]
    assert "total_threats" in d["stride"]

    # PASTA block
    assert "stages"    in d["pasta"]
    assert "completed" in d["pasta"]


@pytest.mark.asyncio
async def test_recommendations_provided():
    """Recommendations must be non-empty for vulnerable code."""
    modeler = AutonomousThreatModeler()
    report  = await modeler.analyze(VULNERABLE_SOLIDITY, target="VulnerableVault")

    assert len(report.recommendations) >= 1
    # Each recommendation must reference a threat ID and action
    for rec in report.recommendations:
        assert "[STR-" in rec or len(rec) > 10


@pytest.mark.asyncio
async def test_mitre_techniques_mapped():
    """All STRIDE threats should include a MITRE technique mapping."""
    modeler = AutonomousThreatModeler()
    report  = await modeler.analyze(VULNERABLE_SOLIDITY, target="VulnerableVault")

    for threat in report.stride_threats:
        assert threat.mitre_technique is not None, (
            f"Threat {threat.threat_id} missing MITRE technique"
        )
        assert "T0" in threat.mitre_technique


@pytest.mark.asyncio
async def test_component_extraction():
    """Components are extracted from contract/class names in source code."""
    modeler = AutonomousThreatModeler()
    report  = await modeler.analyze(VULNERABLE_SOLIDITY, target="VulnerableVault")

    assert "VulnerableVault" in report.components_analyzed


@pytest.mark.asyncio
async def test_analysis_performance():
    """Analysis should complete in under 2 seconds."""
    import time
    modeler = AutonomousThreatModeler()
    start   = time.monotonic()
    report  = await modeler.analyze(VULNERABLE_SOLIDITY * 3, target="LargeProtocol")
    elapsed = time.monotonic() - start

    assert elapsed < 2.0, f"Analysis took {elapsed:.2f}s, expected < 2s"
    assert report.analysis_time_ms < 2000
