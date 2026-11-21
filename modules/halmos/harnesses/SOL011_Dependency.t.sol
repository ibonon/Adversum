// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// SOL-011 dependency harness (Step 3): winner selection depends on
/// block entropy. Independence assertion must fail for vulnerable.
contract LotteryVulnerable {
    address[] public players;
    constructor() { players.push(address(0x1111)); players.push(address(0x2222)); players.push(address(0x3333)); }
    function pickWinner() public view returns (address) {
        uint256 r = uint256(keccak256(abi.encodePacked(block.timestamp, block.number))) % players.length;
        return players[r];
    }
}

contract LotterySafe {
    address[] public players;
    uint256 public round;
    constructor() { players.push(address(0x1111)); players.push(address(0x2222)); players.push(address(0x3333)); }
    function pickWinner() public view returns (address) {
        return players[round % players.length]; // deterministic rotation, no entropy
    }
}

interface VmRoll {
    function warp(uint256 newTimestamp) external;
    function roll(uint256 newHeight) external;
}

contract HalmosSOL011DependencyTest {
    VmRoll constant vm = VmRoll(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    function check_vulnerable_winner_entropy_independent() public {
        LotteryVulnerable t = new LotteryVulnerable();
        address w1 = t.pickWinner();
        vm.warp(1800000000);
        vm.roll(1); // keccak(ts=1800000000, number=1) % 3 == 1, unlike the first pick
        address w2 = t.pickWinner();
        // Independence claim: the winner never depends on block entropy.
        assert(w1 == address(0x1111) && w2 == address(0x1111));
    }

    function check_safe_winner_entropy_independent() public {
        LotterySafe t = new LotterySafe();
        assert(t.pickWinner() == address(0x1111));
    }
}
