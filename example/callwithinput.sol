// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CalleeWithInput {
    function check(uint x) public pure {
        assert(x + 10 != 100);
    }
}

contract CallerWithInput {
    CalleeWithInput callee;

    function setUp() public {
        callee = new CalleeWithInput();
    }

    function callcheck(uint y) public view {
        callee.check(y);
    }
}

