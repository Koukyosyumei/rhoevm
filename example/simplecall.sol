// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleCallee {
    function check() public pure {
        assert(20 >= 100);
    }
}

contract SimpleCalleeTest {
    SimpleCallee callee;

    function setUp() public {
        callee = new SimpleCallee();
    }

    function callcheck() public view {
        callee.check();
    }
}

