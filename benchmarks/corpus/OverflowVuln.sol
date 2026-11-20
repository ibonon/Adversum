pragma solidity ^0.7.0;
contract OverflowVuln {
    mapping(address => uint256) public balances;
    function batchTransfer(address[] memory receivers, uint256 value) public {
        uint256 total = receivers.length * value;
        balances[msg.sender] -= total;
    }
}
