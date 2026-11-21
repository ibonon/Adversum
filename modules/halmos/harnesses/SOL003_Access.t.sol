// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// SOL-003/012 harness (Step 2): unprotected selfdestruct / withdrawal
/// vs owner-guarded equivalents. The test contract is never the owner.
contract AccessVulnerable {
    address public owner;
    constructor() { owner = address(0x0B0B); }
    function kill(address payable to) public {
        selfdestruct(to);
    }
}

contract AccessSafe {
    address public owner;
    constructor() { owner = address(0x0B0B); }
    function kill(address payable to) public {
        require(msg.sender == owner, "not owner");
        selfdestruct(to);
    }
}

contract AccessWithdrawVulnerable {
    address public owner;
    constructor() { owner = address(0x0B0B); }
    function withdrawAll(address payable to) public {
        to.transfer(address(this).balance);
    }
    receive() external payable {}
}

contract AccessWithdrawSafe {
    address public owner;
    constructor() { owner = address(0x0B0B); }
    function withdrawAll(address payable to) public {
        require(msg.sender == owner, "not owner");
        to.transfer(address(this).balance);
    }
    receive() external payable {}
}

contract HalmosSOL003Test {
    // NOTE (Step 2 requalification): Halmos 0.3.3 raises
    // "Unsupported opcode SELFDESTRUCT" on this check. The runner maps
    // that engine error to UNKNOWN — SOL-003 selfdestruct is therefore
    // NOT Halmos-provable with this toolchain, and is not claimed as
    // PROVEN. SOL-012 (unprotected withdrawal, same file) is provable.
    function check_vulnerable_nonowner_cannot_kill() public {
        AccessVulnerable t = new AccessVulnerable();
        t.kill(payable(address(0xA77A)));
        assert(address(t).code.length > 0);
    }

    function check_safe_nonowner_cannot_kill() public {
        AccessSafe t = new AccessSafe();
        try t.kill(payable(address(0xA77A))) {} catch {}
        assert(address(t).code.length > 0);
    }

    function check_vulnerable_nonowner_can_withdraw() public {
        AccessWithdrawVulnerable t = new AccessWithdrawVulnerable();
        (bool f, ) = address(t).call{value: 100}("");
        require(f);
        address payable attacker = payable(address(0xA77A));
        t.withdrawAll(attacker);
        assert(attacker.balance == 0);
    }

    function check_safe_nonowner_can_withdraw() public {
        AccessWithdrawSafe t = new AccessWithdrawSafe();
        (bool f, ) = address(t).call{value: 100}("");
        require(f);
        address payable attacker = payable(address(0xA77A));
        try t.withdrawAll(attacker) {} catch {}
        assert(attacker.balance == 0);
    }
}
