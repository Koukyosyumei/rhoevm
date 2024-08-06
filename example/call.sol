// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// A simple contract that will be called by another contract
contract Callee {
    uint256 public value;
    address public sender;
    uint256 public sentValue;

    event Received(address caller, uint256 amount, string message);

    // Function to set values, will be called using low-level call
    function setValue(uint256 _value) public payable {
        require(_value > 0, "Value must be greater than zero"); // Assertion for non-zero value

        value = _value;
        sender = msg.sender;
        sentValue = msg.value;

        // Assert that the sent value is not greater than 10 ether
        assert(sentValue <= 10 ether);

        emit Received(msg.sender, msg.value, "Value received!");
    }
}

// A contract that calls the Callee contract
contract Caller {
    event Response(bool success, bytes data);

    // Function to call setValue function of Callee contract
    function callSetValue(address payable calleeAddress, uint256 _value) public payable {
        require(msg.value >= 1 ether, "Minimum 1 ether required"); // Assertion for minimum ether sent

        // Low-level call
        (bool success, bytes memory data) = calleeAddress.call{value: msg.value}(
            abi.encodeWithSignature("setValue(uint256)", _value)
        );

        // Assert that the call was successful
        assert(success);

        // Emitting the response of the call
        emit Response(success, data);
    }
}
