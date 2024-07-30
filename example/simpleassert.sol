// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleAssert {
    function check() public pure {
        assert(20 >= 100);
    }
}
