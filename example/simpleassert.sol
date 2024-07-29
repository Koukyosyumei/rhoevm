// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleAssert {
    function set() public pure {
        assert(20 >= 100);
    }
}
