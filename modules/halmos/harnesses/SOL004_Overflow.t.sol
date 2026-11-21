// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// SOL-004 harness (Step 2). Vulnerable target models pre-0.8 unchecked
/// arithmetic via `unchecked`; safe target relies on checked arithmetic.
/// Halmos must find a counterexample for the vulnerable check and none
/// (within bounds) for the safe check.
contract OverflowVulnerable {
    uint256 public total;
    function add(uint256 amount) public {
        unchecked { total = total + amount; }
    }
}

contract OverflowSafe {
    uint256 public total;
    function add(uint256 amount) public {
        total = total + amount; // checked in >=0.8: reverts on overflow
    }
}

contract HalmosSOL004Test {
    function check_vulnerable_add_no_overflow(uint256 amount) public {
        OverflowVulnerable t = new OverflowVulnerable();
        t.add(type(uint256).max);
        uint256 before = t.total();
        t.add(amount);
        assert(t.total() >= before);
    }

    function check_safe_add_no_overflow(uint256 amount) public {
        OverflowSafe t = new OverflowSafe();
        t.add(type(uint256).max);
        uint256 before = t.total();
        t.add(amount);
        assert(t.total() >= before);
    }
}
