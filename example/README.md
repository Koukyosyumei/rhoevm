# Examples

## Call

- source

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Callee {
    function check(uint x) public pure {
        assert(x + 10 != 100);
    }
}

contract Caller {
    Callee callee;

    function setUp() public {
        callee = new Callee();
    }

    function callcheck(uint y) public view {
        callee.check(y);
    }
}
```

- output

```bash
$  ./target/release/rhoevm ./example/build/Caller.bin "setUp()|callcheck(uint)"
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
[2024-08-12T18:23:41Z WARN  rhoevm] Currently, this project is a work in progress.
[2024-08-12T18:23:41Z INFO  rhoevm] Loading binary from file: ./example/build/Caller.bin
[2024-08-12T18:23:41Z INFO  rhoevm] Target function signature: setUp()
[2024-08-12T18:23:41Z INFO  rhoevm] fname: setUp
[2024-08-12T18:23:41Z INFO  rhoevm::modules::symexec] sig: setUp()
[2024-08-12T18:23:41Z INFO  rhoevm] Calldata constructed successfully for function 'setUp()'
[2024-08-12T18:23:41Z INFO  rhoevm] Number of initial environments: 1
[2024-08-12T18:23:41Z INFO  rhoevm] Starting EVM symbolic execution...
[2024-08-12T18:23:41Z INFO  rhoevm] Execution of `setUp()` completed.

[2024-08-12T18:23:41Z INFO  rhoevm] Target function signature: callcheck(uint256)
[2024-08-12T18:23:41Z INFO  rhoevm] fname: callcheck
[2024-08-12T18:23:41Z INFO  rhoevm::modules::symexec] sig: callcheck(uint256)
[2024-08-12T18:23:41Z INFO  rhoevm] Calldata constructed successfully for function 'callcheck(uint256)'
[2024-08-12T18:23:41Z INFO  rhoevm] Number of initial environments: 1
[2024-08-12T18:23:41Z INFO  rhoevm] Starting EVM symbolic execution...
[2024-08-12T18:23:42Z ERROR rhoevm] REACHABLE REVERT DETECTED @ PC=0x153
[2024-08-12T18:23:42Z ERROR rhoevm] model: setUp() -> callcheck(arg1=0x5a)
[2024-08-12T18:23:42Z INFO  rhoevm] Execution of `callcheck(uint256)` completed.
```

## Store & Load

- source

```javascript
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
```

- output

```bash
$  ./target/release/rhoevm ./example/build/StoreLoad.bin "store(uint,uint)|load(uint)"
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
[2024-08-12T18:21:51Z WARN  rhoevm] Currently, this project is a work in progress.
[2024-08-12T18:21:51Z INFO  rhoevm] Loading binary from file: ./example/build/StoreLoad.bin
[2024-08-12T18:21:51Z INFO  rhoevm] Target function signature: store(uint256,uint256)
[2024-08-12T18:21:51Z INFO  rhoevm] fname: store
[2024-08-12T18:21:51Z INFO  rhoevm::modules::symexec] sig: store(uint256,uint256)
[2024-08-12T18:21:51Z INFO  rhoevm] Calldata constructed successfully for function 'store(uint256,uint256)'
[2024-08-12T18:21:51Z INFO  rhoevm] Number of initial environments: 1
[2024-08-12T18:21:51Z INFO  rhoevm] Starting EVM symbolic execution...
[2024-08-12T18:21:51Z INFO  rhoevm] Execution of `store(uint256,uint256)` completed.

[2024-08-12T18:21:51Z INFO  rhoevm] Target function signature: load(uint256)
[2024-08-12T18:21:51Z INFO  rhoevm] fname: load
[2024-08-12T18:21:51Z INFO  rhoevm::modules::symexec] sig: load(uint256)
[2024-08-12T18:21:51Z INFO  rhoevm] Calldata constructed successfully for function 'load(uint256)'
[2024-08-12T18:21:51Z INFO  rhoevm] Number of initial environments: 1
[2024-08-12T18:21:51Z INFO  rhoevm] Starting EVM symbolic execution...
[2024-08-12T18:21:57Z ERROR rhoevm] REACHABLE REVERT DETECTED @ PC=0x250
[2024-08-12T18:21:57Z ERROR rhoevm] model: store(arg2=0x2,arg1=0x5) -> load(arg3=0x3)
[2024-08-12T18:21:57Z INFO  rhoevm] Execution of `load(uint256)` completed.
```

## While

- source

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract WhileContract {
    function check(uint32 n) public pure {
        if (n < 10) {
            uint32 x = n;
            uint32 s = 0;
            while (x > 0) {
                s += x;
                x -= 1;
            }
            if (n == 3) {
                s = s - 1;
            }
            assert(s == n * (n + 1) / 2);
        }
    }
}
```

- output

```bash
$  ./target/release/rhoevm ./example/build/WhileContract.bin "check(uint32)"
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
[2024-08-12T18:20:43Z WARN  rhoevm] Currently, this project is a work in progress.
[2024-08-12T18:20:43Z INFO  rhoevm] Loading binary from file: ./example/build/WhileContract.bin
[2024-08-12T18:20:43Z INFO  rhoevm] Target function signature: check(uint32)
[2024-08-12T18:20:43Z INFO  rhoevm] fname: check
[2024-08-12T18:20:43Z INFO  rhoevm::modules::symexec] sig: check(uint32)
[2024-08-12T18:20:43Z INFO  rhoevm] Calldata constructed successfully for function 'check(uint32)'
[2024-08-12T18:20:43Z INFO  rhoevm] Number of initial environments: 1
[2024-08-12T18:20:43Z INFO  rhoevm] Starting EVM symbolic execution...
[2024-08-12T18:20:44Z WARN  rhoevm::modules::evm] LOOP DETECTED @ PC=0x137
[2024-08-12T18:20:44Z WARN  rhoevm::modules::evm] LOOP DETECTED @ PC=0x459
[2024-08-12T18:20:44Z ERROR rhoevm] REACHABLE REVERT DETECTED @ PC=0x2d6
[2024-08-12T18:20:44Z ERROR rhoevm] model: check(arg1=0x3)
[2024-08-12T18:20:44Z INFO  rhoevm] Execution of `check(uint32)` completed.
```