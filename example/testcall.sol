// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./call.sol"; // Import DS-Test, a simple testing framework for Ethereum

interface ICallee {
    function setValue(uint256 _value) external payable;
}

contract CalleeTest {
    Callee callee;

    function setUp() public {
        callee = new Callee();
    }

    function testSetValue() public {
        callee.setValue{value: 1 ether}(42);

        assert(callee.value() == 42);
        assert(callee.sender() == address(this));
        assert(callee.sentValue() == 1 ether);
    }
}

contract CallerTest {
    Caller caller;
    Callee callee;

    function setUp() public {
        caller = new Caller();
        callee = new Callee();
    }

    function testCallSetValue() public {
        // Call setValue using Caller contract
        caller.callSetValue{value: 1 ether}(payable(address(callee)), 42);

        // Verify results
        assert(callee.value() == 42);
        assert(callee.sender() == address(caller));
        assert(callee.sentValue() == 1 ether);
    }

    function testFailCallSetValueWithZeroEther() public {
        // Attempt to call setValue with less than 1 ether
        caller.callSetValue{value: 0.5 ether}(payable(address(callee)), 42);
    }

    function testFailCallSetValueWithZeroValue() public {
        // Attempt to call setValue with zero value
        caller.callSetValue{value: 1 ether}(payable(address(callee)), 0);
    }
}