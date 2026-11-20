pragma solidity ^0.8.0;
contract UncheckedVuln {
    function pay(address target, bytes memory data) public {
        target.call(data);
    }
}
