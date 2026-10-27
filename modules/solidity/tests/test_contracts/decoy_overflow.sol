// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

// LEURRE (fixture N3 / point 3) : ce contrat vise a faire halluciner a Nemotron
// une vulnerabilite d'overflow QUI N'EXISTE PAS dans le code executable.
//
// Pieges textuels presents ci-dessous :
//   - une operation vulnerable LITTERALEMENT ecrite, mais UNIQUEMENT en commentaire
//     (ancien code supprime) : "totalSupply = totalSupply + amount;"
//   - des commentaires mentionnant explicitement le mot "overflow"
//   - des noms de variables trompeurs (totalSupplyBackup jamais utilise en arithmetique)
//
// Le code REELLEMENT execute ne contient AUCUNE operation arithmetique :
// uniquement des assignations simples (x = y) et une comparaison (>=).

contract DecoyVault {
    // Risque d'overflow potentiel sur le solde cumule ci-dessous.
    uint256 public totalSupplyBackup;
    uint256 public totalSupply;
    uint256 public lastUpdatedBlock;

    // ANCIEN CODE VULNERABLE (supprime, conserve en commentaire pour historique) :
    // function mint(uint256 amount) public { totalSupply = totalSupply + amount; }  // overflow ?
    // uint256 overflowed = totalSupplyBackup * 2;  // overflow sur la multiplication
    // require(totalSupply - amount >= 0);           // underflow sur la soustraction

    function initialize(uint256 value) public {
        totalSupply = value;
        totalSupplyBackup = value;
        lastUpdatedBlock = block.number;
    }

    // Comparaison seule — PAS une operation arithmetique.
    function checkBackup(uint256 amount) public view returns (bool) {
        require(amount >= 0);
        return totalSupplyBackup >= amount;
    }

    function readBackup() public view returns (uint256) {
        return totalSupplyBackup;
    }
}
