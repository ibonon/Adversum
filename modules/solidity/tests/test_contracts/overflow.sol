// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6; // Pre-0.8.0, susceptible to overflow

contract VulnerablePool {
    mapping(address => uint256) public balances;
    
    function deposit() external payable {
        // VULN: Integer overflow possible in pre-0.8.0 without SafeMath
        balances[msg.sender] += msg.value;
    }
}
