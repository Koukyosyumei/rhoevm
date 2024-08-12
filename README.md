# rhoevm

```
.---------------------------------------------------------------------------------------------------------.
|                           _               _   _            _____  __     __  __  __                     |
| ___   _   _   _ __ ___   | |__     ___   | | (_)   ___    | ____| \ \   / / |  \/  |                    |
|/ __| | | | | | '_ ` _ \  | '_ \   / _ \  | | | |  / __|   |  _|    \ \ / /  | |\/| |                    |
|\__ \ | |_| | | | | | | | | |_) | | (_) | | | | | | (__    | |___    \ V /   | |  | |                    |
||___/  \__, | |_| |_| |_| |_.__/   \___/  |_| |_|  \___|   |_____|    \_/    |_|  |_|                    |
|       |___/                         _     _                                            _                |
|  ___  __  __   ___    ___   _   _  | |_  (_)   ___    _ __       ___   _ __     __ _  (_)  _ __     ___ |
| / _ \ \ \/ /  / _ \  / __| | | | | | __| | |  / _ \  | '_ \     / _ \ | '_ \   / _` | | | | '_ \   / _ \|
||  __/  >  <  |  __/ | (__  | |_| | | |_  | | | (_) | | | | |   |  __/ | | | | | (_| | | | | | | | |  __/|
| \___| /_/\_\  \___|  \___|  \__,_|  \__| |_|  \___/  |_| |_|    \___| |_| |_|  \__, | |_| |_| |_|  \___||
|                   _   _     _                      _             ____          |___/   _                |
|__      __  _ __  (_) | |_  | |_    ___   _ __     (_)  _ __     |  _ \   _   _   ___  | |_              |
|\ \ /\ / / | '__| | | | __| | __|  / _ \ | '_ \    | | | '_ \    | |_) | | | | | / __| | __|             |
| \ V  V /  | |    | | | |_  | |_  |  __/ | | | |   | | | | | |   |  _ <  | |_| | \__ \ | |_              |
|  \_/\_/   |_|    |_|  \__|  \__|  \___| |_| |_|   |_| |_| |_|   |_| \_\  \__,_| |___/  \__|             |
'---------------------------------------------------------------------------------------------------------'
```

`rhoevm` is a symbolic EVM execution engine written in Rust. It is inspired by [`hevm`](https://github.com/ethereum/hevm), which is implemented in Haskell. This project aims to provide a robust tool for analyzing Ethereum smart contracts by symbolically executing the EVM bytecode.


> [!NOTE]
> This project is currently under active development. Some features may be incomplete or subject to change.

## 1. Install

### 1.1 Prerequisites

Before building and running rhoevm, ensure you have the following installed:

- Rust: Download and install from [rust-lang.org](https://www.rust-lang.org/).
- Cargo: Comes with Rust as its package manager.
- Z3 Solver: Required for constraint solving. Download from the [Z3 GitHub repository](https://github.com/Z3Prover/z3).

### 1.2 Building from Source

Clone the repository and build the project using Cargo:

```bash
git clone https://github.com/Koukyosyumei/rhoevm.git
cd rhoevm
cargo build --release

# Optionally, copy the binary to a directory in your PATH
# sudo cp ./target/release/rhoevm /usr/local/bin/rhoevm
```

### 1.3 Running Tests

After building, you can run the tests to verify that everything is working correctly:

```bash
cargo test
```

## 2. Usage

### 2.1 Command-Line Interface

`rhoevm` provides a command-line interface for executing smart contract bytecode symbolically. The basic usage is as follows:

```bash
rhoevm <BINARY_FILE_PATH> <FUNCTION_SIGNATURES> [options]
```

- Options

```
`-i, --max_num_iterations MAX_NUM_ITER`: Set the maximum number of iterations for loops.
`-v, --verbose LEVEL`: Set the verbosity level (0: error, 1: warn, 2: info, 3: debug, 4: trace).
`-h, --help`: Display help information.
```

Ensure that your environment is configured to locate the `.bin` and `.abi` files for the contracts. The filenames should match the contract name provided.

### 2.2 Example

Below is an example of how to use `rhoevm` with a simple Solidity smart contract.

- Example Solidity Contract

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleContract {
    function check(uint32 x, uint32 y) public pure {
        if (x > 0 && x < 100 && y > 0 && y < 100) {
            assert(x + y != 142);
        }
    }
}
```

- Symbolic Execution with `rhoevm`

```bash
# Compile the Solidity contract using solc or any preferred compiler.
# Assuming the compiled binary and ABI are located in ./example/build

$ rhoevm SimpleContract "check" -d ./example/build/
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
[2024-08-11T13:21:39Z WARN  rhoevm] Currently, this project is a work in progress.
[2024-08-11T13:21:39Z INFO  rhoevm] Loading binary from file: ./example/build/SimpleContract.bin
[2024-08-11T13:21:39Z INFO  rhoevm] Loading abi from file: ./example/build/SimpleContract.abi

[2024-08-11T13:21:39Z INFO  rhoevm] Using function signature: check(uint32,uint32)
[2024-08-11T13:21:39Z INFO  rhoevm] Calculated function selector: 0xc5eb648f
[2024-08-11T13:21:39Z INFO  rhoevm] Calldata constructed successfully for function 'check(uint32,uint32)'
[2024-08-11T13:21:39Z INFO  rhoevm] Number of initial environments: 1
[2024-08-11T13:21:39Z INFO  rhoevm] Starting EVM symbolic execution...
[2024-08-11T13:21:45Z ERROR rhoevm] REACHABLE REVERT DETECTED @ PC=0x1db
[2024-08-11T13:21:45Z ERROR rhoevm] model: check(arg2=0x54,arg1=0x3a)
[2024-08-11T13:21:45Z INFO  rhoevm] Execution of `check` completed.
```

In the above example, `rhoevm` analyzes the `check` function of the SimpleAssert contract, highlighting a revert condition due to the failed assertion.

You can find more examples in [example](example).

## 3. License

This project is licensed under the AGPL-3.0 license. See the [LICENSE](LICENSE) file for details.


