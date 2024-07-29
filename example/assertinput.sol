// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AssertInput {
    function check(uint32 x) public pure {
        assert(x >= 142);
    }
}
