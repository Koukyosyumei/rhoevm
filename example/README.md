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
$  ./target/debug/rhoevm Caller "setUp,callcheck" -d
 ./example/build/
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
[2024-08-11T13:09:43Z WARN  rhoevm] Currently, this project is a work in progress.
[2024-08-11T13:09:43Z INFO  rhoevm] Loading binary from file: ./example/build/Caller.bin
[2024-08-11T13:09:43Z INFO  rhoevm] Loading abi from file: ./example/build/Caller.abi

[2024-08-11T13:09:43Z INFO  rhoevm] Using function signature: setUp()
[2024-08-11T13:09:43Z INFO  rhoevm] Calculated function selector: 0x0a9254e4
[2024-08-11T13:09:43Z INFO  rhoevm] Calldata constructed successfully for function 'setUp()'
[2024-08-11T13:09:43Z INFO  rhoevm] Number of initial environments: 1
[2024-08-11T13:09:43Z INFO  rhoevm] Starting EVM symbolic execution...
[2024-08-11T13:09:43Z INFO  rhoevm] Execution of `setUp` completed.

[2024-08-11T13:09:43Z INFO  rhoevm] Using function signature: callcheck(uint256)
[2024-08-11T13:09:43Z INFO  rhoevm] Calculated function selector: 0x3f67f6b2
[2024-08-11T13:09:43Z INFO  rhoevm] Calldata constructed successfully for function 'callcheck(uint256)'
[2024-08-11T13:09:43Z INFO  rhoevm] Number of initial environments: 1
[2024-08-11T13:09:43Z INFO  rhoevm] Starting EVM symbolic execution...
[2024-08-11T13:09:45Z ERROR rhoevm] REACHABLE REVERT DETECTED @ PC=0x157
[2024-08-11T13:09:45Z ERROR rhoevm] model: setUp() -> callcheck(arg1=0x5a)
[2024-08-11T13:09:45Z INFO  rhoevm] Execution of `callcheck` completed.
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
$  ./target/debug/rhoevm StoreLoad "store,load" -d ./example/build/
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
[2024-08-11T13:07:28Z WARN  rhoevm] Currently, this project is a work in progress.
[2024-08-11T13:07:28Z INFO  rhoevm] Loading binary from file: ./example/build/StoreLoad.bin
[2024-08-11T13:07:28Z INFO  rhoevm] Loading abi from file: ./example/build/StoreLoad.abi

[2024-08-11T13:07:28Z INFO  rhoevm] Using function signature: store(uint256,uint256)
[2024-08-11T13:07:28Z INFO  rhoevm] Calculated function selector: 0x6ed28ed0
[2024-08-11T13:07:28Z INFO  rhoevm] Calldata constructed successfully for function 'store(uint256,uint256)'
[2024-08-11T13:07:28Z INFO  rhoevm] Number of initial environments: 1
[2024-08-11T13:07:28Z INFO  rhoevm] Starting EVM symbolic execution...
[2024-08-11T13:07:29Z INFO  rhoevm] Execution of `store` completed.

[2024-08-11T13:07:29Z INFO  rhoevm] Using function signature: load(uint256)
[2024-08-11T13:07:29Z INFO  rhoevm] Calculated function selector: 0x99d548aa
[2024-08-11T13:07:29Z INFO  rhoevm] Calldata constructed successfully for function 'load(uint256)'
[2024-08-11T13:07:29Z INFO  rhoevm] Number of initial environments: 1
[2024-08-11T13:07:29Z INFO  rhoevm] Starting EVM symbolic execution...
[2024-08-11T13:08:09Z ERROR rhoevm] REACHABLE REVERT DETECTED @ PC=0x250
[2024-08-11T13:08:09Z ERROR rhoevm] model: store(arg2=0x2,arg1=0x3) -> load(arg3=0x5)
[2024-08-11T13:08:09Z INFO  rhoevm] Execution of `load` completed.
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
$  ./target/debug/rhoevm WhileContract "check" -d ./
example/build/
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
[2024-08-11T13:11:00Z WARN  rhoevm] Currently, this project is a work in progress.
[2024-08-11T13:11:00Z INFO  rhoevm] Loading binary from file: ./example/build/WhileContract.bin
[2024-08-11T13:11:00Z INFO  rhoevm] Loading abi from file: ./example/build/WhileContract.abi

[2024-08-11T13:11:00Z INFO  rhoevm] Using function signature: check(uint32)
[2024-08-11T13:11:00Z INFO  rhoevm] Calculated function selector: 0x2b1f2f00
[2024-08-11T13:11:00Z INFO  rhoevm] Calldata constructed successfully for function 'check(uint32)'
[2024-08-11T13:11:00Z INFO  rhoevm] Number of initial environments: 1
[2024-08-11T13:11:00Z INFO  rhoevm] Starting EVM symbolic execution...
[2024-08-11T13:11:09Z ERROR rhoevm] REACHABLE REVERT DETECTED @ PC=0x2d6
[2024-08-11T13:11:09Z ERROR rhoevm] model: check(arg1=0x3)
[2024-08-11T13:11:09Z INFO  rhoevm] Execution of `check` completed.
```