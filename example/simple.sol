// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleContract {
    function check(uint32 x, uint32 y) public pure {
        if (x > 0 && x < 100 && y > 0 && y < 100) {
            assert(x + y != 142);
        }
    }
}