pragma solidity ^0.8.0;
contract ReentrancyVuln {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) public {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
