// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// SOL-002 harness (Step 2): tx.origin authentication vs msg.sender.
/// The trap contract is the direct caller (msg.sender); tx.origin stays
/// the initiating account that deployed/authorised the vault.
contract TxOriginVulnerable {
    address public owner;
    constructor() { owner = tx.origin; }
    function withdrawAll(address payable to) public {
        require(tx.origin == owner, "not origin");
        to.transfer(address(this).balance);
    }
    receive() external payable {}
}

contract TxOriginSafe {
    address public owner;
    constructor() { owner = msg.sender; }
    function withdrawAll(address payable to) public {
        require(msg.sender == owner, "not owner");
        to.transfer(address(this).balance);
    }
    receive() external payable {}
}

contract PhishingTrap {
    function claim(address vault, address payable attacker) public {
        (bool ok, ) = vault.call(abi.encodeWithSignature("withdrawAll(address)", attacker));
        ok;
    }
}

contract HalmosSOL002Test {
    function check_vulnerable_trap_cannot_drain() public {
        TxOriginVulnerable v = new TxOriginVulnerable();
        (bool f, ) = address(v).call{value: 1 ether}("");
        require(f);
        address payable attacker = payable(address(0xA77A));
        new PhishingTrap().claim(address(v), attacker);
        assert(attacker.balance == 0);
    }

    function check_safe_trap_cannot_drain() public {
        TxOriginSafe v = new TxOriginSafe();
        (bool f, ) = address(v).call{value: 1 ether}("");
        require(f);
        address payable attacker = payable(address(0xA77A));
        new PhishingTrap().claim(address(v), attacker);
        assert(attacker.balance == 0);
    }
}
