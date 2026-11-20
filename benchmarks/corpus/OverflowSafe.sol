pragma solidity ^0.7.0;
library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256 c) { c = a + b; require(c >= a); }
}
contract OverflowSafe {
    using SafeMath for uint256;
    uint256 public total;
    function addTotal(uint256 amount) public {
        total = total.add(amount);
    }
}
