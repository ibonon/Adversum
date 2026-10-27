// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture SOL-001 — reentrancy classique (pattern DAO hack).
// La balance est décrémentée APRÈS l'appel externe : l'appel précède les effets
// (violation de Checks-Effects-Interactions). Aucun modificateur nonReentrant.
contract VulnerableVault {
    mapping(address => uint256) public balances;

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
}
