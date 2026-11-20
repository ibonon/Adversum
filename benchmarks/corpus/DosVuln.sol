pragma solidity ^0.8.0;
contract DosVuln {
    address[] public payees;
    function refundAll() public {
        for (uint256 i = 0; i < payees.length; i++) {
            payable(payees[i]).transfer(1 ether);
        }
    }
}
