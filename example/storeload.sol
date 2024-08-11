// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract StoreLoad {
    uint s;
    uint t;

    function store(uint x, uint y) public {
        s = x;
        t = y;
    }

    function load(uint z) public view {
        if (s > 1 && t > 1 &&  z > 1 && s < 100 && t < 100 && z < 100) {
            assert(s * t * z != 30);
        }
    }
}
