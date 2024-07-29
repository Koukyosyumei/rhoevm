
# rhoevm

```
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
```

[WIP] symbolic EVM execution engine written in Rust

- install

```bash
cargo test 2>/dev/null
sudo cp ./target/debug/rhoevm /usr/local/bin/rhoevm
```

- usage

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleAssert {
    function set() public pure {
        assert(20 >= 100);
    }
}
```

```bash
$ RUST_LOG=info ./target/debug/rhoevm ./example/build/SimpleAssert "set"
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
