// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

// Fixture minimal pour SOL-004 (integer overflow / underflow, pre-0.8.0).
// Aucun SafeMath, aucune garde : totalSupply peut déborder.
contract InsecureCounter {
    uint256 public totalSupply;

    function add(uint256 amount) public {
        totalSupply = totalSupply + amount;
    }

    function sub(uint256 amount) public {
        totalSupply = totalSupply - amount;
    }
}
