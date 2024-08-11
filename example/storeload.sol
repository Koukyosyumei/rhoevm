// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract StoreLoad {
    uint s;

    function store(uint x) public {
        s = x;
    }

    function load(uint y) public view {
        if (s > 1 && y > 1 && s < 100 && y < 100) {
            assert(s * y != 225);
        }
    }
}
