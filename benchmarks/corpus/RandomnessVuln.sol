pragma solidity ^0.8.0;
contract RandomnessVuln {
    address[] public players;
    function pickWinner() public returns (address) {
        uint256 random = uint256(keccak256(abi.encodePacked(block.timestamp, block.number))) % players.length;
        return players[random];
    }
}
