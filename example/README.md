# Examples

### SimpleAssert

- source

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleAssert {
    function check() public pure {
        assert(20 >= 100);
    }
}
```

- output

```bash
./target/debug/rhoevm ./example/build/SimpleAssert "check"
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
[2024-08-10T16:16:53Z WARN  rhoevm] Currently, this project is a work in progress.
[2024-08-10T16:16:53Z INFO  rhoevm] Loading binary from file: ././example/build/SimpleAssert.bin
[2024-08-10T16:16:53Z INFO  rhoevm] Loading abi from file: ././example/build/SimpleAssert.abi

[2024-08-10T16:16:53Z INFO  rhoevm] Using function signature: check()
[2024-08-10T16:16:53Z INFO  rhoevm] Calculated function selector: 0x919840ad
[2024-08-10T16:16:53Z INFO  rhoevm] Calldata constructed successfully for function 'check()'
[2024-08-10T16:16:53Z INFO  rhoevm] Number of initial environments: 1
[2024-08-10T16:16:53Z INFO  rhoevm] Starting EVM symbolic execution...
[2024-08-10T16:16:53Z ERROR rhoevm] REACHABLE REVERT DETECTED @ PC=0x8b
[2024-08-10T16:16:53Z ERROR rhoevm] model:  -> check()
[2024-08-10T16:16:53Z INFO  rhoevm] Execution of `check` completed.
```

### AssertInput

- source

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

- output

```bash
./target/debug/rhoevm ./example/build/AssertInput "check"
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
[2024-08-10T16:18:00Z WARN  rhoevm] Currently, this project is a work in progress.
[2024-08-10T16:18:00Z INFO  rhoevm] Loading binary from file: ././example/build/AssertInput.bin
[2024-08-10T16:18:00Z INFO  rhoevm] Loading abi from file: ././example/build/AssertInput.abi

[2024-08-10T16:18:00Z INFO  rhoevm] Using function signature: check(uint32,uint32)
[2024-08-10T16:18:00Z INFO  rhoevm] Calculated function selector: 0xc5eb648f
[2024-08-10T16:18:00Z INFO  rhoevm] Calldata constructed successfully for function 'check(uint32,uint32)'
[2024-08-10T16:18:00Z INFO  rhoevm] Number of initial environments: 1
[2024-08-10T16:18:00Z INFO  rhoevm] Starting EVM symbolic execution...
[2024-08-10T16:18:06Z ERROR rhoevm] REACHABLE REVERT DETECTED @ PC=0x1db
[2024-08-10T16:18:06Z ERROR rhoevm] model:  -> check(arg1=66,arg2=76)
[2024-08-10T16:18:06Z INFO  rhoevm] Execution of `check` completed.
```

### SimpleCallTest

- source

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleCallee {
    function check() public pure {
        assert(20 >= 100);
    }
}

contract SimpleCalleeTest {
    SimpleCallee callee;

    function setUp() public {
        callee = new SimpleCallee();
    }

    function callcheck() public view {
        callee.check();
    }
}
```

- output

```bash
./target/debug/rhoevm ./example/build/SimpleCalleeTest "setUp,callcheck"
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
[2024-08-10T16:21:52Z WARN  rhoevm] Currently, this project is a work in progress.
[2024-08-10T16:21:52Z INFO  rhoevm] Loading binary from file: ././example/build/SimpleCalleeTest.bin
[2024-08-10T16:21:52Z INFO  rhoevm] Loading abi from file: ././example/build/SimpleCalleeTest.abi

[2024-08-10T16:21:52Z INFO  rhoevm] Using function signature: setUp()
[2024-08-10T16:21:52Z INFO  rhoevm] Calculated function selector: 0x0a9254e4
[2024-08-10T16:21:52Z INFO  rhoevm] Calldata constructed successfully for function 'setUp()'
[2024-08-10T16:21:52Z INFO  rhoevm] Number of initial environments: 1
[2024-08-10T16:21:52Z INFO  rhoevm] Starting EVM symbolic execution...
[2024-08-10T16:21:52Z INFO  rhoevm] Execution of `setUp` completed.

[2024-08-10T16:21:52Z INFO  rhoevm] Using function signature: callcheck()
[2024-08-10T16:21:52Z INFO  rhoevm] Calculated function selector: 0x2e2eb030
[2024-08-10T16:21:52Z INFO  rhoevm] Calldata constructed successfully for function 'callcheck()'
[2024-08-10T16:21:52Z INFO  rhoevm] Number of initial environments: 1
[2024-08-10T16:21:52Z INFO  rhoevm] Starting EVM symbolic execution...
[2024-08-10T16:21:53Z ERROR rhoevm] REACHABLE REVERT DETECTED @ PC=0x70
[2024-08-10T16:21:53Z ERROR rhoevm] model: setUp() -> callcheck()
[2024-08-10T16:21:53Z INFO  rhoevm] Execution of `callcheck` completed.
```

### CallerWithInput

- source

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CalleeWithInput {
    function check(uint x) public pure {
        assert(x + 10 != 100);
    }
}

contract CallerWithInput {
    CalleeWithInput callee;

    function setUp() public {
        callee = new CalleeWithInput();
    }

    function callcheck(uint y) public view {
        callee.check(y);
    }
}
```

- output

```bash
./target/debug/rhoevm ./example/build/CallerWithInput "setUp,callcheck"
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
[2024-08-10T16:13:44Z WARN  rhoevm] Currently, this project is a work in progress.
[2024-08-10T16:13:44Z INFO  rhoevm] Loading binary from file: ././example/build/CallerWithInput.bin
[2024-08-10T16:13:44Z INFO  rhoevm] Loading abi from file: ././example/build/CallerWithInput.abi

[2024-08-10T16:13:44Z INFO  rhoevm] Using function signature: setUp()
[2024-08-10T16:13:44Z INFO  rhoevm] Calculated function selector: 0x0a9254e4
[2024-08-10T16:13:44Z INFO  rhoevm] Calldata constructed successfully for function 'setUp()'
[2024-08-10T16:13:44Z INFO  rhoevm] Number of initial environments: 1
[2024-08-10T16:13:44Z INFO  rhoevm] Starting EVM symbolic execution...
[2024-08-10T16:13:44Z INFO  rhoevm] Execution of `setUp` completed.

[2024-08-10T16:13:44Z INFO  rhoevm] Using function signature: callcheck(uint256)
[2024-08-10T16:13:44Z INFO  rhoevm] Calculated function selector: 0x3f67f6b2
[2024-08-10T16:13:44Z INFO  rhoevm] Calldata constructed successfully for function 'callcheck(uint256)'
[2024-08-10T16:13:44Z INFO  rhoevm] Number of initial environments: 1
[2024-08-10T16:13:44Z INFO  rhoevm] Starting EVM symbolic execution...
[2024-08-10T16:13:46Z ERROR rhoevm] REACHABLE REVERT DETECTED @ PC=0x157
[2024-08-10T16:13:46Z ERROR rhoevm] model: setUp() -> callcheck(arg1=90)
[2024-08-10T16:13:46Z INFO  rhoevm] Execution of `callcheck` completed.
```

### WhileContract

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
./target/debug/rhoevm ./example/build/WhileContract "check"
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
[2024-08-10T16:19:38Z WARN  rhoevm] Currently, this project is a work in progress.
[2024-08-10T16:19:38Z INFO  rhoevm] Loading binary from file: ././example/build/WhileContract.bin
[2024-08-10T16:19:38Z INFO  rhoevm] Loading abi from file: ././example/build/WhileContract.abi

[2024-08-10T16:19:38Z INFO  rhoevm] Using function signature: check(uint32)
[2024-08-10T16:19:38Z INFO  rhoevm] Calculated function selector: 0x2b1f2f00
[2024-08-10T16:19:38Z INFO  rhoevm] Calldata constructed successfully for function 'check(uint32)'
[2024-08-10T16:19:38Z INFO  rhoevm] Number of initial environments: 1
[2024-08-10T16:19:38Z INFO  rhoevm] Starting EVM symbolic execution...
[2024-08-10T16:19:49Z ERROR rhoevm] REACHABLE REVERT DETECTED @ PC=0x2d6
[2024-08-10T16:19:49Z ERROR rhoevm] model:  -> check(arg1=3)
[2024-08-10T16:19:49Z INFO  rhoevm] Execution of `check` completed.
```