// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// SOL-006 dependency harness (Step 3): payout depends on block.timestamp.
/// The check asserts independence; Halmos must refute it for the
/// vulnerable target (dependency shown) and hold it for the safe one.
contract TimeGateVulnerable {
    uint256 public constant DEADLINE = 1700000000;
    function claimFor(address payable to) public {
        if (block.timestamp >= DEADLINE) {
            to.transfer(100);
        }
    }
    receive() external payable {}
}

contract TimeGateSafe {
    address public owner = address(0x0B0B);
    uint256 public lastClaim;
    function claimFor(address payable to) public {
        require(msg.sender == owner, "not owner");
        lastClaim = block.timestamp; // recorded, never gating the payout
        to.transfer(100);
    }
    receive() external payable {}
}

interface VmWarp {
    function warp(uint256 newTimestamp) external;
    function roll(uint256 newHeight) external;
}

contract HalmosSOL006DependencyTest {
    VmWarp constant vm = VmWarp(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    function check_vulnerable_payout_time_independent() public {
        TimeGateVulnerable t = new TimeGateVulnerable();
        (bool f, ) = address(t).call{value: 100}("");
        require(f);
        address payable beneficiary = payable(address(0xA77A));
        vm.warp(1800000000); // after the deadline: payout must open if time-gated
        t.claimFor(beneficiary);
        assert(beneficiary.balance == 0);
    }

    function check_safe_payout_time_independent() public {
        TimeGateSafe t = new TimeGateSafe();
        (bool f, ) = address(t).call{value: 100}("");
        require(f);
        address payable beneficiary = payable(address(0xA77A));
        try t.claimFor(beneficiary) {} catch {}
        assert(beneficiary.balance == 0);
    }
}
