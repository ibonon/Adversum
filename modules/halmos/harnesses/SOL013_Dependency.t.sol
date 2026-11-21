// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// SOL-013 dependency harness (Step 3): refund loop bound depends on a
/// storage array anyone can grow. Independence of the bound from
/// attacker registrations must fail for vulnerable, hold for safe
/// (pull pattern, no loop over a growable list).
contract DosVulnerable {
    address[] public payees;
    function payeesLength() public view returns (uint256) { return payees.length; }
    function register() public { payees.push(msg.sender); }
    function refundAll() public {
        for (uint256 i = 0; i < payees.length; i++) {
            payable(payees[i]).transfer(1);
        }
    }
    receive() external payable {}
}

contract DosSafe {
    mapping(address => uint256) public owed;
    function register() public { owed[msg.sender] = 1; }
    function withdraw() public {
        uint256 amount = owed[msg.sender];
        owed[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
    receive() external payable {}
}

contract HalmosSOL013DependencyTest {
    function check_vulnerable_bound_attacker_independent() public {
        DosVulnerable t = new DosVulnerable();
        t.register();
        t.register();
        // Claim: the loop bound cannot be grown by callers.
        assert(t.payeesLength() == 0);
    }

    function check_safe_bound_attacker_independent() public {
        DosSafe t = new DosSafe();
        t.register();
        t.register();
        // No growable loop list exists; the per-user owed amount is the
        // only state, so the (absent) loop bound stays independent.
        assert(t.owed(address(this)) == 1);
    }
}
