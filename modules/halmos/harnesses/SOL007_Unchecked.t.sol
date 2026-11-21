// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// SOL-007 harness (Step 2): payment recorded without checking the
/// low-level call result vs checked equivalent.
contract FailingCallee {
    receive() external payable { revert("no"); }
}

contract UncheckedVulnerable {
    bool public paid;
    function pay(address target) public {
        target.call{value: 1 ether}("");
        paid = true; // recorded even when the call failed
    }
}

contract UncheckedSafe {
    bool public paid;
    function pay(address target) public {
        (bool ok, ) = target.call{value: 1 ether}("");
        require(ok, "call failed");
        paid = true;
    }
}

contract HalmosSOL007Test {
    function check_vulnerable_failed_call_not_paid() public {
        UncheckedVulnerable t = new UncheckedVulnerable();
        t.pay(address(new FailingCallee()));
        assert(!t.paid());
    }

    function check_safe_failed_call_not_paid() public {
        UncheckedSafe t = new UncheckedSafe();
        try t.pay(address(new FailingCallee())) {} catch {}
        assert(!t.paid());
    }
}
