use std::clone;
use std::collections::{hash_set, HashMap, HashSet};
use std::convert::TryFrom;
use std::hash::Hash;
use std::sync::Arc;

#[path = "./types.rs"]
mod types;
use types::{
  Addr, Block, Buf, Cache, Contract, ContractCode, EAddr, Env, Expr, ForkState, FrameState, Gas, Memory,
  RuntimeCodeStruct, RuntimeConfig, SubState, Trace, TreePos, TxState, VMOpts, VM,
};

fn initial_gas() -> u64 {
  10000 // Placeholder value
}

fn blank_state() -> FrameState {
  FrameState {
    contract: Expr::LitAddr(0),
    code_contract: Expr::LitAddr(0),
    code: ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(Vec::new())),
    pc: 0,
    stack: Vec::new(),
    memory: Memory::ConcreteMemory(Vec::new()),
    memory_size: 0,
    calldata: Expr::Mempty,
    callvalue: Expr::Lit(0),
    caller: Box::new(Expr::LitAddr(0)),
    gas: Gas::Concerete(initial_gas()),
    returndata: Expr::Mempty,
    static_flag: false,
  }
}

fn bytecode(contract: &Contract) -> Option<Expr> {
  match &contract.code {
    ContractCode::InitCode(_, _) => Some(Expr::Mempty),
    ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(buf)) => Some(Expr::ConcreteBuf(buf.to_vec())),
    _ => None,
  }
}

fn current_contract(vm: &VM) -> Option<Contract> {
  vm.env.contracts.get(&vm.state.code_contract).cloned()
}

fn make_vm(opts: VMOpts) -> VM {
  let txaccess_list = &opts.tx_access_list;
  let txorigin = opts.origin.clone();
  let txto_addr = opts.address.clone();
  let initial_accessed_addrs = HashSet::from([txorigin.clone(), txto_addr.clone(), opts.coinbase.clone()]);
  let initial_accessed_storage_keys: HashSet<_> =
    txaccess_list.iter().flat_map(|(k, v)| v.iter().map(move |v| (k.clone(), v.clone()))).collect();
  let touched = if opts.create {
    vec![txorigin.clone()]
  } else {
    vec![txorigin.clone(), txto_addr.clone()]
  };

  let memory = Memory::ConcreteMemory(Vec::new());

  VM {
    result: None,
    frames: Vec::new(),
    tx: TxState {
      gasprice: opts.gasprice,
      gaslimit: opts.gaslimit,
      priority_fee: opts.priority_fee,
      origin: txorigin.clone(),
      to_addr: txto_addr.clone(),
      value: opts.value.clone(),
      substate: SubState {
        selfdestructs: Vec::new(),
        touched_accounts: touched,
        accessed_addresses: initial_accessed_addrs,
        accessed_storage_keys: initial_accessed_storage_keys,
        refunds: Vec::new(),
      },
      is_create: opts.create,
      tx_reversion: opts.other_contracts.iter().cloned().collect(),
    },
    logs: Vec::new(),
    // traces: TreePos::<Trace>::new(),
    block: Block {
      coinbase: opts.coinbase.clone(),
      timestamp: opts.timestamp,
      number: opts.number,
      prev_randao: opts.prev_randao.clone(),
      max_code_size: opts.max_code_size,
      gaslimit: opts.block_gaslimit,
      base_fee: opts.base_fee,
      schedule: opts.schedule.clone(),
    },
    state: FrameState {
      pc: 0,
      stack: Vec::new(),
      memory,
      memory_size: 0,
      code: opts.contract.code.clone(),
      contract: opts.address.clone(),
      code_contract: opts.address.clone(),
      calldata: opts.calldata.0.clone(),
      callvalue: opts.value.clone(),
      caller: opts.caller.clone(),
      gas: opts.gas,
      returndata: Expr::Mempty,
      static_flag: false,
    },
    env: Env {
      chain_id: opts.chain_id,
      contracts: opts.other_contracts.iter().cloned().collect(),
      fresh_address: 0,
      fresh_gas_vals: 0,
    },
    cache: Cache {
      fetched: HashMap::new(),
      path: HashMap::new(),
    },
    burned: Gas::Concerete(initial_gas()),
    constraints: opts.calldata.1.clone(),
    iterations: HashMap::new(),
    config: RuntimeConfig {
      allow_ffi: opts.allow_ffi,
      reset_caller: true,
      override_caller: None,
      base_state: opts.base_state.clone(),
    },
    forks: vec![ForkState {
      env: Env {
        contracts: opts.other_contracts.iter().cloned().collect(),
        chain_id: opts.chain_id,
        fresh_address: 0,
        fresh_gas_vals: 0,
      },
      block: Block {
        coinbase: opts.coinbase.clone(),
        timestamp: opts.timestamp.clone(),
        number: opts.number,
        prev_randao: opts.prev_randao.clone(),
        max_code_size: opts.max_code_size,
        gaslimit: opts.block_gaslimit,
        base_fee: opts.base_fee,
        schedule: opts.schedule.clone(),
      },
      cache: Cache {
        fetched: HashMap::new(),
        path: HashMap::new(),
      },
      urlaor_alias: String::new(),
    }],
    current_fork: 0,
    labels: HashMap::new(),
  }
}

fn unknown_contract(addr: Box<dyn ExprTrait<EAddr>>) -> Contract {
  Contract {
    code: ContractCode::UnKnownCode(addr.clone()),
    storage: Storage(HashMap::new()),
    orig_storage: Storage(HashMap::new()),
    balance: Expr(addr.0.clone()),
    nonce: None,
    codehash: CodeHash(hashcode(&ContractCode::UnknownCode(addr.clone()))),
    op_ix_map: OpIxMap(HashMap::new()),
    code_ops: CodeOps(Vec::new()),
    external: false,
  }
}

fn abstract_contract(code: ContractCode, addr: Expr) -> Contract {
  Contract {
    code: code.clone(),
    storage: Storage(HashMap::new()),
    orig_storage: Storage(HashMap::new()),
    balance: Expr(addr.0.clone()),
    nonce: if is_creation(&code) { Some(1) } else { Some(0) },
    codehash: CodeHash(hashcode(&code)),
    op_ix_map: OpIxMap(HashMap::new()),
    code_ops: CodeOps(Vec::new()),
    external: false,
  }
}

fn empty_contract() -> Contract {
  initial_contract(ContractCode::RuntimeCode(RuntimeCode { data: Vec::new() }))
}

fn initial_contract(code: ContractCode) -> Contract {
  Contract {
    code: code.clone(),
    storage: Expr::Storage(HashMap::new()),
    orig_storage: Expr::Storage(HashMap::new()),
    balance: Expr("0".to_string()),
    nonce: if is_creation(&code) { Some(1) } else { Some(0) },
    codehash: CodeHash(hashcode(&code)),
    op_idx_map: OpIxMap(HashMap::new()),
    code_ops: CodeOps(Vec::new()),
    external: false,
  }
}

fn is_creation(code: &ContractCode) -> bool {
  match code {
    ContractCode::InitCode(_, _) => true,
    _ => false,
  }
}

fn next(op: u8) {
  // Update the program counter with the size of the opcode
  // Example:
  // let pc = state.pc;
  // state.pc += op_size(op);
}

/*

        Some(Box::new(ExprLit { value: 0 })) => {
          fetch_account(self_contract, |c| {
            touch_account(self_contract);
            vm_error("PrecompileFailure");
          });
        }
        Some(Box::new(ExprLit(_))) => {
          fetch_account(self_contract, |c| {
            touch_account(self_contract);
            let out = vm.state.returndata.clone();
            finish_frame("FrameReturned", out);
          });
        }
        Some(e) => partial(
          "UnexpectedSymbolicArg",
          vm.state.pc,
          "precompile returned a symbolic value",
          vec![e.clone()],
        ),
*/

fn exec1(vm: &mut VM) {
  let stk = &vm.state.stack;
  let self_contract = &vm.state.contract;
  let this_contract = vm.env.contracts.get(self_contract).unwrap();
  let fees = &vm.block.schedule;

  if let Some(lit_self) = maybe_lit_addr(self_contract) {
    if lit_self > 0x0 && lit_self <= 0x9 {
      let calldatasize = vm.state.calldata.len();
      copy_bytes_to_memory(&vm.state.calldata, calldatasize, 0, 0);
      execute_precompile(lit_self, vm.state.gas, 0, calldatasize, 0, 0, vec![]);
      match vm.state.stack.first() {
        Some(boxed_expr) => if let Some(expr_lit) = Expr::Lit(0) {},
        None => underrun(),
      }
    }
  } else if vm.state.pc >= opslen(&vm.state.code) {
    finish_frame("FrameReturned", vec![]);
  } else {
    let op = match &vm.state.code {
      ContractCode::UnknownCode(_) => internal_error("Cannot execute unknown code"),
      ContractCode::InitCode(conc, _) => conc[vm.state.pc],
      ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(data)) => data[vm.state.pc],
    };

    match get_op(op) {
      "OpPush0" => {
        limit_stack(1, || {
          burn(fees.g_base, || {
            next(vm);
            push_sym(vm, Expr::Lit(0));
          });
        });
      }
      "OpPush" => {
        let n = usize::try_from(op).unwrap();
        let xs = match &vm.state.code {
          ContractCode::UnknownCode(_) => internal_error("Cannot execute unknown code"),
          ContractCode::InitCode(conc, _) => Expr::Word(conc[vm.state.pc + 1..vm.state.pc + 1 + n].to_vec()),
          ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(data)) => {
            Expr::Word(data[vm.state.pc + 1..vm.state.pc + 1 + n].to_vec())
          }
        };
        limit_stack(1, || {
          burn(fees.g_verylow, || {
            next(vm);
            push_sym(vm, xs);
          });
        });
      }
      "OpDup" => {
        let i = usize::try_from(op).unwrap();
        if let Some(y) = stk.get(i - 1) {
          limit_stack(1, || {
            burn(fees.g_verylow, || {
              next(vm);
              push_sym(vm, y.clone());
            });
          });
        } else {
          underrun();
        }
      }
      "OpSwap" => {
        let i = usize::try_from(op).unwrap();
        if stk.len() < i + 1 {
          underrun();
        } else {
          burn(fees.g_verylow, || {
            next(vm);
            let a = stk[0].clone();
            let b = stk[i].clone();
            vm.state.stack[0] = b;
            vm.state.stack[i] = a;
          });
        }
      }
      "OpLog" => {
        not_static(vm, || {
          if let Some((x_offset, x_size, xs)) =
            stk.split_first().and_then(|(a, b)| b.split_first().map(|(c, d)| (a, c, d)))
          {
            if xs.len() < usize::try_from(op).unwrap() {
              underrun();
            } else {
              let bytes = read_memory(x_offset, x_size);
              let (topics, xs) = xs.split_at(usize::try_from(op).unwrap());
              let logs = vec![LogEntry {
                addr: vm.state.contract.clone(),
                data: bytes,
                topics: topics.to_vec(),
              }];
              burn_log(x_size, op, || {
                access_memory_range(x_offset, x_size, || {
                  trace_top_log(logs.clone());
                  next(vm);
                  vm.state.stack = xs.to_vec();
                  vm.logs = logs;
                });
              });
            }
          } else {
            underrun();
          }
        });
      }
      "OpStop" => {
        finish_frame("FrameReturned", vec![]);
      }
      "OpAdd" => stack_op2(vm, fees.g_verylow, "add"),
      "OpMul" => stack_op2(vm, fees.g_low, "mul"),
      "OpSub" => stack_op2(vm, fees.g_verylow, "sub"),
      "OpDiv" => stack_op2(vm, fees.g_low, "div"),
      "OpSdiv" => stack_op2(vm, fees.g_low, "sdiv"),
      "OpMod" => stack_op2(vm, fees.g_low, "nmod"),
      "OpSmod" => stack_op2(vm, fees.g_low, "smod"),
      "OpAddmod" => stack_op3(vm, fees.g_mid, Expr::addmod),
      "OpMulmod" => stack_op3(vm, fees.g_mid, Expr::mulmod),
      "OpLt" => stack_op2(vm, fees.g_verylow, "lt"),
      "OpGt" => stack_op2(vm, fees.g_verylow, "gt"),
      "OpSlt" => stack_op2(vm, fees.g_verylow, "slt"),
      "OpSgt" => stack_op2(vm, fees.g_verylow, "sgt"),
      "OpEq" => stack_op2(vm, fees.g_verylow, "eq"),
      "OpIszero" => stack_op1(vm, fees.g_verylow, "iszero"),
      "OpAnd" => stack_op2(vm, fees.g_verylow, "and"),
      "OpOr" => stack_op2(vm, fees.g_verylow, "or"),
      "OpXor" => stack_op2(vm, fees.g_verylow, "xor"),
      "OpNot" => stack_op1(vm, fees.g_verylow, "not"),
      "OpByte" => stack_op2(vm, fees.g_verylow, |i, w| Expr::pad_byte(Expr::index_word(i, w))),
      "OpShl" => stack_op2(vm, fees.g_verylow, "shl"),
      "OpShr" => stack_op2(vm, fees.g_verylow, "shr"),
      "OpSar" => stack_op2(vm, fees.g_verylow, "sar"),
      "OpSha3" => {
        if let Some((x_offset, x_size, xs)) =
          stk.split_first().and_then(|(a, b)| b.split_first().map(|(c, d)| (a, c, d)))
        {
          burn_sha3(x_size, || {
            access_memory_range(x_offset, x_size, || {
              let hash = read_memory(x_offset, x_size).map_or_else(|orig| Keccak::new(orig), |buf| Keccak::new(buf));
              next(vm);
              vm.state.stack = std::iter::once(hash).chain(xs.iter().cloned()).collect();
            });
          });
        } else {
          underrun();
        }
      }
      "OpAddress" => {
        limit_stack(1, || {
          burn(fees.g_base, || {
            next(vm);
            push_addr(vm, self_contract.clone());
          });
        });
      }
      "OpBalance" => {
        if let Some(x) = stk.first() {
          force_addr(x, "BALANCE", |a| {
            access_and_burn(a, || {
              fetch_account(*a, |c| {
                next(vm);
                vm.state.stack = stk[1..].to_vec();
                push_sym(vm, c.balance);
              });
            });
          });
        } else {
          underrun();
        }
      }
      "OpOrigin" => {
        limit_stack(1, || {
          burn(fees.g_base, || {
            next(vm);
            push_addr(vm, vm.tx.origin.clone());
          });
        });
      }
      "OpCaller" => {
        limit_stack(1, || {
          burn(fees.g_base, || {
            next(vm);
            push_addr(vm, vm.state.caller.clone());
          });
        });
      }
      "OpCallvalue" => {
        limit_stack(1, || {
          burn(fees.g_base, || {
            next(vm);
            push_sym(vm, vm.state.callvalue.clone());
          });
        });
      }
      "OpCalldataload" => stack_op1(vm, fees.g_verylow, |ind| Expr::read_word(ind, &vm.state.calldata)),
      "OpCalldatasize" => {
        limit_stack(1, || {
          burn(fees.g_base, || {
            next(vm);
            push_sym(vm, vm.state.calldata.len());
          });
        });
      }
      "OpCalldatacopy" => {
        if let Some((x_to, rest)) = stk.split_first() {
          if let Some((x_from, rest)) = rest.split_first() {
            if let Some((x_size, xs)) = rest.split_first() {
              burn_calldatacopy(x_size, || {
                access_memory_range(x_to, x_size, || {
                  next(vm);
                  vm.state.stack = xs.to_vec();
                  copy_bytes_to_memory(&vm.state.calldata, *x_size, *x_from, *x_to);
                });
              });
            } else {
              underrun();
            }
          } else {
            underrun();
          }
        } else {
          underrun();
        }
      }
      "OpCodesize" => {
        limit_stack(1, || {
          burn(fees.g_base, || {
            next(vm);
            push_sym(vm, vm.state.code.len());
          });
        });
      }
      "OpCodecopy" => {
        if let Some((mem_offset, rest)) = stk.split_first() {
          if let Some((code_offset, rest)) = rest.split_first() {
            if let Some((n, xs)) = rest.split_first() {
              burn_codecopy(n, || {
                access_memory_range(mem_offset, n, || {
                  next(vm);
                  vm.state.stack = xs.to_vec();
                  if let Some(b) = to_buf(&vm.state.code) {
                    copy_bytes_to_memory(b, n, code_offset, mem_offset);
                  } else {
                    internal_error("Cannot produce a buffer from UnknownCode");
                  }
                });
              });
            } else {
              underrun();
            }
          } else {
            underrun();
          }
        } else {
          underrun();
        }
      }
      "OpGasprice" => {
        limit_stack(1, || {
          burn(fees.g_base, || {
            next(vm);
            push_sym(vm, vm.tx.gasprice);
          });
        });
      }
      "OpExtcodesize" => {
        if let Some(x) = stk.first() {
          force_addr(x, "EXTCODESIZE", |a| {
            access_and_burn(a, || {
              fetch_account(a, |c| {
                next(vm);
                vm.state.stack = stk[1..].to_vec();
                if let Some(b) = &c.bytecode {
                  push_sym(vm, b.len());
                } else {
                  push_sym(vm, CodeSize::new(a));
                }
              });
            });
          });
        } else {
          underrun();
        }
      }
      "OpExtcodecopy" => {
        if let Some((ext_account, rest)) = stk.split_first() {
          if let Some((mem_offset, rest)) = rest.split_first() {
            if let Some((code_offset, rest)) = rest.split_first() {
              if let Some((code_size, xs)) = rest.split_first() {
                force_addr(ext_account, "EXTCODECOPY", |a| {
                  burn_extcodecopy(a, code_size, || {
                    access_memory_range(mem_offset, code_size, || {
                      fetch_account(a, |c| {
                        next(vm);
                        vm.state.stack = xs.to_vec();
                        if let Some(b) = &c.bytecode {
                          copy_bytes_to_memory(b, code_size, code_offset, mem_offset);
                        } else {
                          internal_error("Cannot copy from unknown code");
                        }
                      });
                    });
                  });
                });
              } else {
                underrun();
              }
            } else {
              underrun();
            }
          } else {
            underrun();
          }
        } else {
          underrun();
        }
      }
      "OpReturndatasize" => {
        limit_stack(1, || {
          burn(fees.g_base, || {
            next(vm);
            push_sym(vm, vm.state.returndata.len());
          });
        });
      }
      _ => unimplemented!(),
    }
  }
}

// Helper functions
fn get_op(op: u8) -> &'static str {
  match op {
    0x00 => "OpStop",
    0x01 => "OpAdd",
    0x02 => "OpMul",
    // Add all other opcodes here...
    _ => "UnknownOp",
  }
}

fn maybe_lit_addr(addr: &Expr) -> Option<u64> {
  if let Expr::Addr(s) = addr {
    Some(u64::from_str_radix(s, 16).unwrap_or(0))
  } else {
    None
  }
}

fn copy_bytes_to_memory(src: &[u8], size: usize, from: usize, to: usize) {
  // Implement memory copy logic
}

fn execute_precompile(lit_self: u64, gas: u64, a: u64, calldatasize: usize, b: u64, c: u64, d: Vec<u8>) {
  // Implement precompile logic
}

fn fetch_account<F: FnOnce(&Contract)>(addr: &Expr, f: F) {
  // Implement account fetching logic
}

fn touch_account(addr: &Expr) {
  // Implement account touching logic
}

fn vm_error(error: &str) {
  // Implement VM error handling
}

fn finish_frame(result: &str, out: Vec<u8>) {
  // Implement frame finishing logic
}

fn opslen(code: &ContractCode) -> usize {
  match code {
    ContractCode::InitCode(conc, _) => conc.len(),
    ContractCode::RuntimeCode(RuntimeCode { data }) => data.len(),
    _ => 0,
  }
}

fn limit_stack<F: FnOnce()>(n: usize, f: F) {
  // Implement stack limit check
}

fn burn<F: FnOnce()>(gas: u64, f: F) {
  // Implement gas burning logic
}

fn next(vm: &mut VM) {
  vm.state.pc += 1;
}

fn push_sym(vm: &mut VM, expr: Expr) {
  vm.state.stack.push(expr);
}

fn read_memory(offset: &Expr, size: &Expr) -> Expr {
  // Implement memory reading logic
  Expr::Lit(0) // Placeholder
}

fn burn_log(size: &Expr, n: u8, f: impl FnOnce()) {
  // Implement log burning logic
}

fn access_memory_range(offset: &Expr, size: &Expr, f: impl FnOnce()) {
  // Implement memory range access logic
}

fn trace_top_log(logs: Vec<Log>) {
  // Implement log tracing logic
}

fn stack_op2<F>(vm: &mut VM, gas: u64, op: &str) {
  if let Some((a, b)) = vm.state.stack.split_first().and_then(|(a, rest)| rest.split_first().map(|(b, rest)| (a, b))) {
    burn(gas, || {
      next(vm);
      let res = match op {
        "add" => Expr::Add(a.clone(), b.clone()),
      };
      vm.state.stack = std::iter::once(res).chain(vm.state.stack.iter().skip(2).cloned()).collect();
    });
  } else {
    underrun();
  }
}

fn stack_op3<F>(vm: &mut VM, gas: u64, op: F)
where
  F: FnOnce(Expr, Expr, Expr) -> Expr,
{
  if let Some((a, rest)) = vm.state.stack.split_first() {
    if let Some((b, rest)) = rest.split_first() {
      if let Some((c, rest)) = rest.split_first() {
        burn(gas, || {
          next(vm);
          let res = op(a.clone(), b.clone(), c.clone());
          vm.state.stack = std::iter::once(res).chain(rest.iter().cloned()).collect();
        });
      } else {
        underrun();
      }
    } else {
      underrun();
    }
  } else {
    underrun();
  }
}

fn stack_op1<F>(vm: &mut VM, gas: u64, op: F)
where
  F: FnOnce(Expr) -> Expr,
{
  if let Some(a) = vm.state.stack.first() {
    burn(gas, || {
      next(vm);
      let res = op(a.clone());
      vm.state.stack[0] = res;
    });
  } else {
    underrun();
  }
}

fn force_addr<F: FnOnce(Expr)>(x: &Expr, name: &str, f: F) {
  // Implement address forcing logic
}

fn access_and_burn(addr: Expr, f: impl FnOnce()) {
  // Implement access and burn logic
}

fn underrun() {
  // Implement stack underrun handling
}

fn push_addr(vm: &mut VM, addr: Expr) {
  vm.state.stack.push(addr);
}

fn push_sym(vm: &mut VM, sym: impl Into<Expr>) {
  vm.state.stack.push(sym.into());
}

fn copy_bytes_to_memory(src: &[u8], size: usize, from: usize, to: usize) {
  // Implement memory copy logic
}

fn internal_error(msg: &str) {
  // Implement internal error handling
}

fn to_buf(code: &ContractCode) -> Option<&[u8]> {
  match code {
    ContractCode::InitCode(conc, _) => Some(conc),
    ContractCode::RuntimeCode(RuntimeCode { data }) => Some(data),
    _ => None,
  }
}

// Define other necessary structs, enums, and functions here...
