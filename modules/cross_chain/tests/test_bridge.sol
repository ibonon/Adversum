// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableBridge {
    mapping(bytes32 => bool) public acceptableRoots;
    address public relayer;

    // VULN 1 (BRIDGE-003): Acceptable root without zero-check
    function executeTransfer(bytes32 root, bytes32 leaf, bytes32[] calldata proof) external {
        require(acceptableRoots[root], "Root not approved");
        // Merkle verification
    }

    // VULN 2 (BRIDGE-001): ecrecover without chainId domain separator
    function processSignedPacket(bytes32 msgHash, uint8 v, bytes32 r, bytes32 s) external {
        address signer = ecrecover(msgHash, v, r, s);
        require(signer == relayer, "Invalid signature");
    }

    // VULN 3 (BRIDGE-006): setRelayer without timelock
    function setRelayer(address _newRelayer) external {
        relayer = _newRelayer;
    }
}
