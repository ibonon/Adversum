// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// SOL-009 dependency harness (Step 3): borrow limit depends on the
/// AMM spot price (reserve ratio). Independence from reserves must
/// fail for vulnerable, hold for the fixed-price (TWAP-like) target.
contract SpotOracleVulnerable {
    uint256 public reserve0;
    uint256 public reserve1;
    function setReserves(uint256 r0, uint256 r1) public { reserve0 = r0; reserve1 = r1; }
    function borrowLimit(uint256 collateral) public view returns (uint256) {
        uint256 spot = reserve0 / reserve1;
        return collateral * spot;
    }
}

contract SpotOracleSafe {
    uint256 public fixedPrice = 2; // e.g. TWAP snapshot, not live reserves
    function setReserves(uint256, uint256) public {}
    function borrowLimit(uint256 collateral) public view returns (uint256) {
        return collateral * fixedPrice;
    }
}

contract HalmosSOL009DependencyTest {
    function check_vulnerable_limit_spot_independent(uint256 r0, uint256 r1) public {
        // Halmos: assume sane reserves via bounds on the symbolic inputs.
        if (r1 == 0 || r0 == 0) return;
        SpotOracleVulnerable t = new SpotOracleVulnerable();
        t.setReserves(r0, r1);
        assert(t.borrowLimit(100) == 200);
    }

    function check_safe_limit_spot_independent(uint256 r0, uint256 r1) public {
        SpotOracleSafe t = new SpotOracleSafe();
        t.setReserves(r0, r1);
        assert(t.borrowLimit(100) == 200);
    }
}
