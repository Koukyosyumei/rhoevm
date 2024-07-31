// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract WhileContract {
    function check(uint32 n) public pure {
        uint32 x = n;
        uint32 s = 0;
        while (x > 0) {
            s += x;
            x -= 1;
        }
        assert(s == n * (n + 1) / 2);
    }
}
