// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract StoreLoad {
    uint s;

    function store(uint x) public {
        s = x;
    }

    function load() public view {
        assert(s != 100);
        /*
        if (s > 1 && y > 1 && s < 100 && y < 100) {
            assert (s * y != 35);
        }
        */
    }
}
