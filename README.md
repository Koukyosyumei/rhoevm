
# rhoevm

.. ╭───────────────╮  
.. │..R H O..│  
.. │..E V M..│  
.. ╰───────────────╯  
..╱╲╱╲╱╲╱╲╱╲  
./..╲╲╲╲╲╲╲╲..\  
/....╲╲╲╲╲╲╲....\  
\/....╱╱╱╱╱╱╱..../  
.\/..╱╱╱╱╱╱╱../  
..╲╱╱╱╱╱╱╱╲╱  
...╲╲╲╲╲╲╲╲  
....╲╲╲╲╲╲  
.... ╲╲╲╲  
......╲╲  
...... ╲  

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
$RUST_LOG=info rhoevm SimpleAssert.bin "set()"
[2024-07-29T01:35:43Z INFO  rhoevm] Loading binary from file: ../mytest/build/SimpleAssert.bin
[2024-07-29T01:35:43Z INFO  rhoevm] Using function signature: set()
[2024-07-29T01:35:43Z INFO  rhoevm] Calculated function selector: 0xb8e010de
[2024-07-29T01:35:43Z INFO  rhoevm] Calldata constructed successfully for function 'set()'

[2024-07-29T01:35:43Z INFO  rhoevm] Starting EVM symbolic execution...
[2024-07-29T01:35:44Z ERROR rhoevm] REVERT DETECTED
    Constraints (Raw Format):=
     true && IsZero(Lit(0x0))
     && Not(LT(Lit(0x4), Lit(0x4)))
     && Eq(Lit(0xb8e010de), SHR(Lit(0xe0), Lit(0xb8e010de00000000000000000000000000000000000000000000000000000000)))
     && Not(IsZero(LT(Lit(0x14), Lit(0x64))))

[2024-07-29T01:35:44Z INFO  rhoevm] EVM execution completed.
```
