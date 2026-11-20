pragma solidity ^0.8.0;
contract AccessVuln {
    address public owner;
    function withdrawAll(address to) public {
        require(tx.origin == owner);
        payable(to).transfer(address(this).balance);
    }
    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}
