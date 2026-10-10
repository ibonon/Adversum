import os
import sys
import pytest

# Add parent directory to path so imports work
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scanner import SolidityScanner
import rules

KB_PATH = os.path.join(os.path.dirname(__file__), '../kb/vulnerabilities.json')


def test_reentrancy_detection(tmp_path):
    f = tmp_path / "reentrancy.sol"
    f.write_text("""pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint) public balances;
    function withdraw(uint amount) public {
        (bool s, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }
}
""")
    scanner = SolidityScanner(rules, KB_PATH)
    findings = scanner.scan_file(str(f))
    assert any(f.rule_id == 'SOL-001' for f in findings), "Should detect reentrancy"


def test_tx_origin_detection(tmp_path):
    f = tmp_path / "tx_origin.sol"
    f.write_text("""pragma solidity ^0.8.0;
contract Wallet {
    address public owner;
    function transfer(address to, uint amount) public {
        require(tx.origin == owner);
    }
}
""")
    scanner = SolidityScanner(rules, KB_PATH)
    findings = scanner.scan_file(str(f))
    assert any(f.rule_id == 'SOL-002' for f in findings), "Should detect tx.origin"


def test_overflow_detection(tmp_path):
    f = tmp_path / "overflow.sol"
    f.write_text("""pragma solidity ^0.7.0;
contract Token {
    mapping(address => uint256) public balances;
    function batchTransfer(address[] memory receivers, uint256 value) public {
        uint256 total = receivers.length * value;
        balances[msg.sender] -= total;
    }
}
""")
    scanner = SolidityScanner(rules, KB_PATH)
    findings = scanner.scan_file(str(f))
    assert any(f.rule_id == 'SOL-004' for f in findings), "Should detect arithmetic overflow"
