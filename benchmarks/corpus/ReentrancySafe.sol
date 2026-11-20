pragma solidity ^0.8.0;
contract ReentrancySafe {
    mapping(address => uint256) public balances;
    bool private locked;
    modifier noReenter() { require(!locked); locked = true; _; locked = false; }
    function withdraw(uint256 amount) public noReenter {
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }
}
