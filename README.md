
# rhoevm

```
   ╭───────────────╮
   │  R H O  │
   │  E V M  │
   ╰───────────────╯
  ╱🦀╱╱╱╲╱╲╱╲ 
 ╱ 🦀╲╲╲╲╲╲  ╲
╱   🦀╲╲╲╲╲╲  ╲ symbolic EVM 
╲    ╱🦀╱╱╱╱  ╱ execution engine
 ╲  ╱🦀╱╱╱╱╱ ╱  written in Rust
  ╲╱🦀╱╱╱╱╱╲╱
   ╲🦀╲╲╲╲╲╱
    ╲🦀╲╲╲╱
     ╲🦀╲
      ╲🦀
       ╲
```

`rhoevm` is a symbolic EVM execution engine written in Rust. It is inspired by [`hevm`](https://github.com/ethereum/hevm), which is implemented in Haskell. This project aims to provide a robust tool for analyzing Ethereum smart contracts by symbolically executing the EVM bytecode.


> [!CAUTION]
> This project is still in work in progress.

## install

Ensure you have Rust installed on your machine. Then, build and install rhoevm using the following commands:

```bash
cargo build --release
# sudo cp ./target/release/rhoevm /usr/local/bin/rhoevm
```

## usage

Below is an example of how to use rhoevm with a simple Solidity smart contract.

- Example Solidity Contract

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AssertInput {
    function check(uint32 x, uint32 y) public pure {
        if (x > 0 && x < 100 && y > 0 && y < 100) {
            assert(x + y != 142);
        }
    }
}
```

- Symbolic Execution with rhoevm

```bash
# Compile the Solidity contract using solc or any preferred compiler.
# Assuming the compiled binary and ABI are located in ./example/build

$ RUST_LOG=info rhoevm ./example/build/SimpleAssert "check"
```

- Output

```bash
   ╭───────────────╮
   │  R H O  │
   │  E V M  │
   ╰───────────────╯
  ╱🦀╱╱╱╲╱╲╱╲
 ╱ 🦀╲╲╲╲╲╲  ╲
╱   🦀╲╲╲╲╲╲  ╲ symbolic EVM
╲    ╱🦀╱╱╱╱  ╱ execution engine
 ╲  ╱🦀╱╱╱╱╱ ╱  written in Rust
  ╲╱🦀╱╱╱╱╱╲╱
   ╲🦀╲╲╲╲╲╱
    ╲🦀╲╲╲╱
     ╲🦀╲
      ╲🦀
       ╲
[2024-07-30T09:20:13Z INFO  rhoevm] Loading binary from file: ./example/build/AssertInput.bin
[2024-07-30T09:20:13Z INFO  rhoevm] Loading abi from file: ./example/build/AssertInput.abi
[2024-07-30T09:20:13Z INFO  rhoevm] Using function signature: check(uint32,uint32)
[2024-07-30T09:20:13Z INFO  rhoevm] Calculated function selector: 0xc5eb648f
[2024-07-30T09:20:13Z INFO  rhoevm] Calldata constructed successfully for function 'check(uint32,uint32)'

[2024-07-30T09:20:13Z INFO  rhoevm] Starting EVM symbolic execution...
[2024-07-30T09:20:18Z ERROR rhoevm] REVERT DETECTED @ PC = 0x1db
[2024-07-30T09:20:18Z ERROR rhoevm] model: check(arg1=50,arg2=92)
[2024-07-30T09:20:18Z INFO  rhoevm] EVM execution completed.
```

In the above example, rhoevm analyzes the `check` function of the SimpleAssert contract, highlighting a revert condition due to the failed assertion.