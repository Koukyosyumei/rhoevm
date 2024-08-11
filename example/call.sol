// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Callee {
    function check(uint x) public pure {
        assert(x + 10 != 100);
    }
}

contract Caller {
    Callee callee;

    function setUp() public {
        callee = new Callee();
    }

    function callcheck(uint y) public view {
        callee.check(y);
    }
}

