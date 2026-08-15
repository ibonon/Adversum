import os
import sys
import pytest

# Add parent directory to path so imports work
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scanner import SolidityScanner
import rules

def test_reentrancy_detection():
    scanner = SolidityScanner(rules, os.path.join(os.path.dirname(__file__), '../kb/vulnerabilities.json'))
    contract_path = os.path.join(os.path.dirname(__file__), 'test_contracts/reentrancy.sol')
    findings = scanner.scan_file(contract_path)
    
    assert any(f.rule_id == 'SOL-001' for f in findings), "Should detect reentrancy"

def test_tx_origin_detection():
    scanner = SolidityScanner(rules, os.path.join(os.path.dirname(__file__), '../kb/vulnerabilities.json'))
    contract_path = os.path.join(os.path.dirname(__file__), 'test_contracts/tx_origin.sol')
    findings = scanner.scan_file(contract_path)
    
    assert any(f.rule_id == 'SOL-002' for f in findings), "Should detect tx.origin"

def test_overflow_detection():
    scanner = SolidityScanner(rules, os.path.join(os.path.dirname(__file__), '../kb/vulnerabilities.json'))
    contract_path = os.path.join(os.path.dirname(__file__), 'test_contracts/overflow.sol')
    findings = scanner.scan_file(contract_path)
    
    assert any(f.rule_id == 'SOL-004' for f in findings), "Should detect arithmetic overflow"
