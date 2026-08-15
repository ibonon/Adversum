// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PhishableAuth {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    function transferOwnership(address newOwner) external {
        // VULN: Using tx.origin for authentication
        require(tx.origin == owner, "Not owner");
        owner = newOwner;
    }
}
