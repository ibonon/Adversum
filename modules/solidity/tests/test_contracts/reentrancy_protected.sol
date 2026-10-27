// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Fixture SOL-001 — protégée par DEUX mécanismes indépendants :
//   1. pattern Checks-Effects-Interactions correct : la balance est mise à zéro
//      AVANT l'appel externe ;
//   2. modificateur nonReentrant (mutex) appliqué à la fonction.
contract ProtectedVault {
    mapping(address => uint256) public balances;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function withdraw() public nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0);
        balances[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
}
