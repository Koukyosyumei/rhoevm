
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

contract SimpleAssert {
    function check() public pure {
        assert(20 >= 100);
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
╱   🦀╲╲╲╲╲╲  ╲
╲    ╱🦀╱╱╱╱  ╱
 ╲  ╱🦀╱╱╱╱╱ ╱
  ╲╱🦀╱╱╱╱╱╲╱
   ╲🦀╲╲╲╲╲╱
    ╲🦀╲╲╲╱
     ╲🦀╲
      ╲🦀
       ╲
[2024-07-29T15:16:56Z INFO  rhoevm] Loading binary from file: ./example/build/SimpleAssert.bin
[2024-07-29T15:16:56Z INFO  rhoevm] Loading abi from file: ./example/build/SimpleAssert.abi
[2024-07-29T15:16:56Z INFO  rhoevm] Using function signature: set()
[2024-07-29T15:16:56Z INFO  rhoevm] Calculated function selector: 0xb8e010de
[2024-07-29T15:16:56Z INFO  rhoevm] Callcode: WriteByte(Lit(0x3), LitByte(0xde), WriteByte(Lit(0x2), LitByte(0x10), WriteByte(Lit(0x1), LitByte(0xe0), WriteByte(Lit(0x0), LitByte(0xb8), AbstractBuf(txdata)))))
[2024-07-29T15:16:56Z INFO  rhoevm] Calldata constructed successfully for function 'set()'

[2024-07-29T15:16:56Z INFO  rhoevm] Starting EVM symbolic execution...
[2024-07-29T15:16:56Z ERROR rhoevm] REVERT DETECTED
    Constraints (Raw Format):=
     true && IsZero(Lit(0x0))
     && Not(LT(Max(Lit(0x4), BufLength(AbstractBuf(txdata))), Lit(0x4)))
     && Eq(Lit(0xb8e010de), SHR(Lit(0xe0), ReadWord(Lit(0x0), WriteByte(Lit(0x3), LitByte(0xde), WriteByte(Lit(0x2), LitByte(0x10), WriteByte(Lit(0x1), LitByte(0xe0), WriteByte(Lit(0x0), LitByte(0xb8), AbstractBuf(txdata))))))))
     && Not(IsZero(LT(Lit(0x14), Lit(0x64))))

[2024-07-29T15:16:56Z INFO  rhoevm] EVM execution completed.
```

In the above example, rhoevm analyzes the `check` function of the SimpleAssert contract, highlighting a revert condition due to the failed assertion.