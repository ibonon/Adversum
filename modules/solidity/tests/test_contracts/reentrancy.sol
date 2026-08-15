// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Vulnérable : withdraw sans ReentrancyGuard
// Contexte CEX : hot wallet withdrawal
contract VulnerableWithdraw {
    mapping(address => uint256) public balances;
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        // VULN : appel externe avant modification d'etat
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount; // trop tard !
    }
}
