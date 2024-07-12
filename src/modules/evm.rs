use std::cmp::max;
use std::collections::{hash_set, HashMap, HashSet};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::hash::Hash;
use std::iter;
use std::sync::Arc;
use std::{clone, ops};
use tiny_keccak::{Hasher, Keccak};

#[path = "./types.rs"]
mod types;
use types::{
  from_list, len_buf, Addr, Block, Buf, Cache, Contract, ContractCode, EAddr, Env, Expr, ExprSet, ExprW256Set,
  FeeSchedule, ForkState, FrameState, GVar, Gas, Memory, MutableMemory, RuntimeCodeStruct, RuntimeConfig, SubState,
  Trace, TreePos, TxState, VMOpts, W256W256Map, Word64, Word8, VM,
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
    caller: Expr::LitAddr(0),
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
  let initial_accessed_addrs = ExprSet::from([txorigin.clone(), txto_addr.clone(), opts.coinbase.clone()]);
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
        accessed_storage_keys: initial_accessed_storage_keys.iter().cloned().collect(),
        refunds: Vec::new(),
      },
      is_create: opts.create,
      tx_reversion: opts.other_contracts.iter().cloned().collect(),
    },
    logs: Vec::new(),
    // traces: TreePos::<Trace>::new(),
    block: Block {
      coinbase: opts.coinbase.clone(),
      time_stamp: opts.time_stamp.clone(),
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
        time_stamp: opts.time_stamp.clone(),
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

fn unknown_contract(addr: Expr) -> Contract {
  Contract {
    code: ContractCode::UnKnownCode(Box::new(addr.clone())),
    storage: Expr::AbstractStore(Box::new(addr.clone()), None),
    orig_storage: Expr::AbstractStore(Box::new(addr.clone()), None),
    balance: Expr::Balance(Box::new(addr.clone())),
    nonce: None,
    codehash: Expr::CodeHash(Box::new(hashcode(&ContractCode::UnKnownCode(Box::new(addr.clone()))))),
    op_idx_map: Vec::new(),
    code_ops: Vec::new(),
    external: false,
  }
}

fn abstract_contract(code: ContractCode, addr: Expr) -> Contract {
  Contract {
    code: code.clone(),
    storage: Expr::AbstractStore(Box::new(addr.clone()), None),
    orig_storage: Expr::AbstractStore(Box::new(addr.clone()), None),
    balance: Expr::Balance(Box::new(addr.clone())),
    nonce: if is_creation(&code) { Some(1) } else { Some(0) },
    codehash: Expr::CodeHash(Box::new(hashcode(&code))),
    op_idx_map: Vec::new(),
    code_ops: Vec::new(),
    external: false,
  }
}

fn empty_contract() -> Contract {
  initial_contract(ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(
    Vec::new(),
  )))
}

fn initial_contract(code: ContractCode) -> Contract {
  Contract {
    code: code.clone(),
    storage: Expr::ConcreteStore(W256W256Map::new()),
    orig_storage: Expr::ConcreteStore(W256W256Map::new()),
    balance: Expr::Lit(0),
    nonce: if is_creation(&code) { Some(1) } else { Some(0) },
    codehash: Expr::CodeHash(Box::new(hashcode(&code))),
    op_idx_map: Vec::new(),
    code_ops: Vec::new(),
    external: false,
  }
}

fn is_creation(code: &ContractCode) -> bool {
  match code {
    ContractCode::InitCode(_, _) => true,
    _ => false,
  }
}

fn unbox<T>(value: Box<T>) -> T {
  *value
}

fn exec1(vm: &mut VM) {
  // let mut vm.state.stack = &vm.state.stack;
  let self_contract = &vm.state.contract;
  let this_contract = vm.env.contracts.get(self_contract).unwrap();
  let fees = &vm.block.schedule;

  if let Some(lit_self) = maybe_lit_addr(self_contract) {
    if lit_self > 0x0 && lit_self <= 0x9 {
      let calldatasize = len_buf(&vm.state.calldata);
      copy_bytes_to_memory(
        vm.state.calldata.clone(),
        Expr::Lit(calldatasize as u32),
        Expr::Lit(0),
        Expr::Lit(0),
        vm,
      );
      execute_precompile(
        lit_self,
        vm.state.gas.clone(),
        Expr::Lit(0),
        Expr::Lit(calldatasize as u32),
        Expr::Lit(0),
        Expr::Lit(0),
        vec![],
      );
      match vm.state.stack.first() {
        Some(boxed_expr) => if let Some(expr_lit) = Some(Expr::Lit(0)) {},
        None => underrun(),
      }
    }
  } else if vm.state.pc >= opslen(&vm.state.code) {
    finish_frame("FrameReturned", vec![]);
  } else {
    let op = match &vm.state.code {
      ContractCode::UnKnownCode(_) => panic!("cannot execute unknown code"),
      ContractCode::InitCode(conc, _) => conc[vm.state.pc],
      ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(data)) => data[vm.state.pc],
      ContractCode::RuntimeCode(RuntimeCodeStruct::SymbolicRuntimeCode(ops)) => {
        match maybe_lit_byte(&ops[vm.state.pc]) {
          Some(b) => b,
          None => panic!("could not analyze symbolic code"),
        }
      }
    };

    match get_op(op) {
      "OpPush0" => {
        //limit_stack(1, || {
        burn(fees.g_base, || {
          next(vm);
          push_sym(vm, Box::new(Expr::Lit(0)));
        });

        //});
      }
      "OpPush" => {
        let n = usize::try_from(op).unwrap();
        let xs = match &vm.state.code {
          ContractCode::UnKnownCode(_) => panic!("Cannot execute unknown code"),
          ContractCode::InitCode(conc, _) => {
            let bytes = pad_right(n, conc.clone());
            Expr::Lit(word32(&bytes))
          }
          ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(bs)) => {
            let bytes = bs.get((1 + vm.state.pc)..).ok_or("Index out of bounds");
            Expr::Lit(word32(&bytes.unwrap()))
          }
          ContractCode::RuntimeCode(RuntimeCodeStruct::SymbolicRuntimeCode(ops)) => {
            let bytes = ops.get((1 + vm.state.pc)..(1 + vm.state.pc + n)).ok_or("Index out of bounds");
            let padded_bytes = pad_left_prime(32, bytes.unwrap().to_vec());
            from_list(padded_bytes)
          }
        };
        //limit_stack(1, || {
        burn(fees.g_verylow, || {
          next(vm);
          push_sym(vm, Box::new(xs));
        });
        //});
      }
      "OpDup" => {
        let i = usize::try_from(op).unwrap();
        if let Some(y) = vm.state.stack.get(i - 1).cloned() {
          //limit_stack(1, || {
          burn(fees.g_verylow, || {
            next(vm);
            push_sym(vm, y.clone());
          });
          //});
        } else {
          underrun();
        }
      }
      "OpSwap" => {
        let i = usize::try_from(op).unwrap();
        if vm.state.stack.len() < i + 1 {
          underrun();
        } else {
          burn(fees.g_verylow, || {
            let a = vm.state.stack[0].clone();
            let b = vm.state.stack[i].clone();
            vm.state.stack[0] = b;
            vm.state.stack[i] = a;
            next(vm);
          });
        }
      }
      "OpLog" => {
        not_static(vm, || {});
        if let Some((x_offset, x_size, xs)) =
          vm.state.stack.split_first().clone().and_then(|(a, b)| b.split_first().map(|(c, d)| (a, c, d)))
        {
          if xs.len() < usize::try_from(op).unwrap() {
            underrun();
          } else {
            let bytes = read_memory(x_offset, x_size);
            let (topics, xs) = xs.split_at(usize::try_from(op).unwrap());
            let logs = vec![Expr::LogEntry(
              Box::new(vm.state.contract.clone()),
              Box::new(bytes),
              topics.to_vec(),
            )];
            burn_log(x_size, op, || {});
            access_memory_range(x_offset, x_size, || {});
            trace_top_log(logs.clone());
            vm.state.stack = xs.to_vec();
            vm.logs = logs;
            next(vm);
          }
        } else {
          underrun();
        }
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
      "OpAddmod" => stack_op3(vm, fees.g_mid, "addmod"),
      "OpMulmod" => stack_op3(vm, fees.g_mid, "mulmod"),
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
      "OpByte" => stack_op2(vm, fees.g_verylow, "byte"),
      "OpShl" => stack_op2(vm, fees.g_verylow, "shl"),
      "OpShr" => stack_op2(vm, fees.g_verylow, "shr"),
      "OpSar" => stack_op2(vm, fees.g_verylow, "sar"),
      "OpSha3" => {
        if let Some((x_offset, x_size, xs)) =
          vm.state.stack.split_first().and_then(|(a, b)| b.split_first().map(|(c, d)| (a, c, d)))
        {
          burn_sha3(unbox(x_size.clone()), vm.block.schedule.clone(), || {});
          access_memory_range(x_offset, x_size, || {});
          let buffer = read_memory(x_offset, x_size);
          let hash = match buffer {
            Expr::ConcreteBuf(bs) => Expr::Lit(word32(&keccak_prime(&bs.to_vec()))),
            _ => keccak(buffer).unwrap(),
          };
          vm.state.stack = std::iter::once(Box::new(hash)).chain(xs.iter().cloned()).collect();
          next(vm);
        } else {
          underrun();
        }
      }
      "OpAddress" => {
        //limit_stack(1, || {
        burn(fees.g_base, || {});
        push_addr(vm, self_contract.clone());
        next(vm);
        //});
      }
      "OpBalance" => {
        if let Some(x) = vm.state.stack.first() {
          /*
          force_addr(x, "BALANCE", |a| {
            access_and_burn(a, || {
              fetch_account(&a, |c| {
                next(vm);
                vm.state.stack = vm.state.stack[1..].to_vec();
                push_sym(vm, Box::new(c.balance.clone()));
              });
            });
          });
          */
        } else {
          underrun();
        }
      }
      "OpOrigin" => {
        //limit_stack(1, || {
        burn(fees.g_base, || {
          next(vm);
          push_addr(vm, vm.tx.origin.clone());
        });
        //});
      }
      "OpCaller" => {
        //limit_stack(1, || {
        burn(fees.g_base, || {
          next(vm);
          push_addr(vm, vm.state.caller.clone());
        });
        //});
      }
      "OpCallvalue" => {
        //limit_stack(1, || {
        burn(fees.g_base, || {
          next(vm);
          push_sym(vm, Box::new(vm.state.callvalue.clone()));
        });
        //});
      }
      "OpCalldataload" => stack_op1(vm, fees.g_verylow, "calldataload"),
      "OpCalldatasize" => {
        //limit_stack(1, || {
        burn(fees.g_base, || {
          next(vm);
          push_sym(vm, Box::new(Expr::Lit(len_buf(&vm.state.calldata) as u32)));
        });
        //});
      }
      "OpCalldatacopy" => {
        if let Some((x_to, rest)) = vm.state.stack.clone().split_first() {
          if let Some((x_from, rest)) = rest.split_first() {
            if let Some((x_size, xs)) = rest.split_first() {
              burn_calldatacopy(unbox(x_size.clone()), vm.block.schedule.clone(), || {});
              access_memory_range(x_to, x_size, || {});
              vm.state.stack = xs.to_vec();
              copy_bytes_to_memory(
                vm.state.calldata.clone(),
                unbox(x_size.clone()),
                unbox(x_from.clone()),
                unbox(x_to.clone()),
                vm,
              );
              next(vm);
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
        //limit_stack(1, || {
        burn(fees.g_base, || {
          next(vm);
          push_sym(vm, Box::new(codelen(&vm.state.code)));
        });
        //});
      }
      "OpCodecopy" => {
        if let Some((mem_offset, rest1)) = (vm.state.stack).split_first() {
          let mem_offset = mem_offset.clone();
          let rest1 = rest1.to_vec();
          if let Some((code_offset, rest)) = rest1.split_first().clone() {
            if let Some((n, xs)) = rest.split_first().clone() {
              burn_codecopy(unbox(n.clone()), vm.block.schedule.clone(), || {
                access_memory_range(&mem_offset.clone(), &n.clone(), || {
                  next(vm);
                  vm.state.stack = xs.to_vec();
                });
              });
              if let Some(b) = to_buf(&vm.state.code) {
                copy_bytes_to_memory(
                  Expr::ConcreteBuf(b.to_vec()),
                  unbox(n.clone()),
                  unbox(code_offset.clone().clone()),
                  unbox(mem_offset.clone().clone()),
                  vm,
                );
              } else {
                internal_error("Cannot produce a buffer from UnknownCode");
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
      "OpGasprice" => {
        //limit_stack(1, || {
        burn(fees.g_base, || {
          next(vm);
          push_sym(vm, Box::new(Expr::Lit(vm.tx.gasprice)));
        });
        //});
      }
      "OpExtcodesize" => {
        if let Some(x) = vm.state.stack.first().clone() {
          /*
          force_addr(x, "EXTCODESIZE", |a| {
            access_and_burn(a, || {
              fetch_account(&a, |c| {
                next(vm);
                vm.state.stack = vm.state.stack[1..].to_vec();
                if let Some(b) = &c.bytecode() {
                  push_sym(vm, Box::new(buf_length(b.clone())));
                } else {
                  push_sym(vm, Box::new(Expr::CodeSize(Box::new(a))));
                }
              });
            });
          });
          */
        } else {
          underrun();
        }
      }
      "OpExtcodecopy" => {
        if let Some((ext_account, rest1)) = vm.state.stack.split_first() {
          let ext_account = ext_account.clone();
          let rest1 = rest1.to_vec();
          if let Some((mem_offset, rest2)) = rest1.split_first() {
            let mem_offset = mem_offset.clone();
            let rest2 = rest2.to_vec();
            if let Some((code_offset, rest)) = rest2.split_first() {
              if let Some((code_size, xs)) = rest.split_first() {
                force_addr(&ext_account, "EXTCODECOPY", |a| {
                  burn_extcodecopy(
                    vm,
                    unbox(ext_account.clone()),
                    unbox(code_size.clone()),
                    vm.block.schedule.clone(),
                    || {},
                  );
                  access_memory_range(&mem_offset, code_size, || {
                    fetch_account(&a, |c| {
                      next(vm);
                      vm.state.stack = xs.to_vec();
                      if let Some(b) = &c.bytecode() {
                        copy_bytes_to_memory(
                          b.clone(),
                          unbox(code_size.clone()),
                          unbox(code_offset.clone()),
                          unbox(mem_offset.clone()),
                          vm,
                        );
                      } else {
                        internal_error("Cannot copy from unknown code");
                      }
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
        //limit_stack(1, || {
        burn(fees.g_base, || {
          next(vm);
          push_sym(vm, Box::new(Expr::Lit(len_buf(&vm.state.returndata) as u32)));
        });
        //});
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

fn maybe_lit_byte(byte: &Expr) -> Option<Word8> {
  if let Expr::LitByte(b) = byte {
    Some(*b)
  } else {
    None
  }
}

fn maybe_lit_addr(addr: &Expr) -> Option<Addr> {
  if let Expr::LitAddr(s) = addr {
    Some(*s)
  } else {
    None
  }
}

fn write_memory(memory: &mut MutableMemory, offset: usize, buf: &Vec<u8>) {
  expand_memory(memory, offset + buf.len());
  // Write buf into memory starting from offset
  for (i, &byte) in buf.iter().enumerate() {
    memory[offset + i] = byte;
  }
}

fn expand_memory(memory: &mut MutableMemory, target_size: usize) {
  let current_size = memory.len();
  if target_size > current_size {
    memory.resize(target_size, 0);
  }
}

fn freeze_memory(memory: &MutableMemory) -> MutableMemory {
  memory.clone() // Clone the memory vector to freeze it
}

fn copy_bytes_to_memory(bs: Expr, size: Expr, src_offset: Expr, mem_offset: Expr, vm: &mut VM) {
  if size == Expr::Lit(0) {
    return;
  }

  match &vm.state.memory {
    Memory::ConcreteMemory(mem) => {
      match (&bs, &size, &src_offset, &mem_offset) {
        (Expr::ConcreteBuf(b), Expr::Lit(size_val), Expr::Lit(src_offset_val), Expr::Lit(mem_offset_val)) => {
          let src = if *src_offset_val >= (b.len() as u32) {
            vec![0; *size_val as usize]
          } else {
            let mut src_tmp = b[(*src_offset_val as usize)..].to_vec();
            src_tmp.resize((*size_val as usize), 0);
            src_tmp
          };
          if let Some(concrete_mem) = vm.state.memory.as_mut_concrete_memory() {
            write_memory(concrete_mem, *mem_offset_val as usize, &src);
          }
        }
        _ => {
          // Copy out and move to symbolic memory
          let buf = freeze_memory(&mem);
          // assign(/* Define your assignment here */);
        }
      }
    }
    Memory::SymbolicMemory(mem) => {
      // Implement the logic for symbolic memory
      // assign(/* Define your assignment here */);
    }
  }
}

fn execute_precompile(
  pre_compile_addr: Addr,
  gas: Gas,
  in_offset: Expr,
  in_size: Expr,
  out_offset: Expr,
  out_size: Expr,
  xs: Vec<Expr>,
) {
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
    ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(data)) => data.len(),
    _ => 0,
  }
}

fn limit_stack<F: FnOnce()>(n: usize, f: F) {
  // Implement stack limit check
}

fn burn<F: FnOnce()>(gas: u64, f: F) {
  // Implement gas burning logic
  f()
}

fn burn_sha3<F: FnOnce()>(x_size: Expr, schedule: FeeSchedule<Word64>, f: F) {
  let cost = match x_size {
    Expr::Lit(c) => schedule.g_sha3 + schedule.g_sha3word * (((c as u64) + 31) / 32),
    _ => panic!("illegal expression"),
  };
  burn(cost, f)
}

fn burn_codecopy<F: FnOnce()>(n: Expr, schedule: FeeSchedule<Word64>, f: F) {
  let max_word64 = u64::MAX;
  let cost = match n {
    Expr::Lit(c) => {
      if (c as u64) <= (max_word64 - (schedule.g_verylow as u64)) / ((schedule.g_copy as u64) * 32) {
        schedule.g_verylow + schedule.g_copy * (((c as u64) + 31) / 32)
      } else {
        panic!("overflow")
      }
    }
    _ => panic!("illegal expression"),
  };
  burn(cost, f)
}

fn ceil_div(x: u64, y: u64) -> u64 {
  (x + y - 1) / y
}

fn burn_calldatacopy<F: FnOnce()>(x_size: Expr, schedule: FeeSchedule<Word64>, f: F) {
  let cost = match x_size {
    Expr::Lit(c) => schedule.g_verylow + schedule.g_copy * ceil_div(c as u64, 32),
    _ => panic!("illegal expression"),
  };
  burn(cost, f)
}

fn burn_extcodecopy<F: FnOnce()>(vm: &mut VM, ext_account: Expr, code_size: Expr, schedule: FeeSchedule<Word64>, f: F) {
  let ceiled_c = match code_size {
    Expr::Lit(c) => ceil_div(c as u64, 32),
    _ => panic!("illegal expression"),
  };

  let cost = match ext_account {
    Expr::LitAddr(_) => {
      let acc = access_account_for_gas(vm, ext_account);
      let acc_cost = if acc {
        schedule.g_warm_storage_read
      } else {
        schedule.g_cold_account_access
      };
      acc_cost + schedule.g_copy * ceiled_c
    }
    _ => panic!("illegal expression"),
  };
  burn(cost, f)
}

fn not_static<F: FnOnce()>(vm: &mut VM, f: F) {
  if vm.state.static_flag {
    panic!("vmError StateChangeWhileStatic")
  } else {
    f()
  }
}

fn access_account_for_gas(vm: &mut VM, addr: Expr) -> bool {
  let accessed = vm.tx.substate.accessed_addresses.contains(&addr);
  vm.tx.substate.accessed_addresses.insert(addr);
  accessed
}

/*
  burnExtcodecopy extAccount (forceLit -> codeSize) continue = do
    FeeSchedule {..} <- gets (.block.schedule)
    acc <- accessAccountForGas extAccount
    let cost = if acc then g_warm_storage_read else g_cold_account_access
    burn (cost + g_copy * ceilDiv (unsafeInto codeSize) 32) continue

*/

fn next(vm: &mut VM) {
  vm.state.pc += 1;
}

fn push_sym(vm: &mut VM, expr: Box<Expr>) {
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

fn trace_top_log(logs: Vec<Expr>) {
  // Implement log tracing logic
}

fn stack_op2(vm: &mut VM, gas: u64, op: &str) {
  if let Some((a, b)) = vm.state.stack.split_first().and_then(|(a, rest)| rest.split_first().map(|(b, rest)| (a, b))) {
    //burn(gas)
    let res = match op {
      "add" => Box::new(Expr::Add(a.clone(), b.clone())),
      _ => Box::new(Expr::Mempty),
    };
    next(vm);
    vm.state.stack = std::iter::once(res).chain(vm.state.stack.iter().skip(2).cloned()).collect();
  } else {
    underrun();
  }
}

fn stack_op3(vm: &mut VM, gas: u64, op: &str) {
  if let Some((a, rest)) = vm.state.stack.split_first() {
    if let Some((b, rest)) = rest.split_first() {
      if let Some((c, rest)) = rest.split_first() {
        // burn(gas)
        let res = match op {
          "addmod" => Box::new(Expr::AddMod(a.clone(), b.clone(), c.clone())),
          "mulmod" => Box::new(Expr::MulMod(a.clone(), b.clone(), c.clone())),
          _ => Box::new(Expr::Mempty),
        };
        next(vm);
        vm.state.stack = std::iter::once(res).chain(vm.state.stack.iter().skip(3).cloned()).collect();
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

fn stack_op1(vm: &mut VM, gas: u64, op: &str) {
  if let Some(a) = vm.state.stack.first() {
    // burn(gas)
    let res = match op {
      "iszero" => Box::new(Expr::IsZero(a.clone())),
      "not" => Box::new(Expr::Not(a.clone())),
      "calldataload" => Box::new(Expr::Mempty),
      _ => Box::new(Expr::Mempty),
    };
    next(vm);
    vm.state.stack[0] = res;
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
  vm.state.stack.push(Box::new(addr.clone()));
}

fn internal_error(msg: &str) {
  // Implement internal error handling
}

fn to_buf(code: &ContractCode) -> Option<&[u8]> {
  match code {
    ContractCode::InitCode(conc, _) => Some(conc),
    ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(data)) => Some(data),
    _ => None,
  }
}

// Define other necessary structs, enums, and functions here...

fn keccak_bytes(input: &[u8]) -> Vec<u8> {
  let mut keccak = Keccak::v256();
  keccak.update(input);
  let mut result = vec![0u8; 32]; // Keccak-256 produces a 256-bit (32-byte) hash
  keccak.finalize(&mut result);
  result
}

fn word32(xs: &[u8]) -> u32 {
  xs.iter().enumerate().fold(0, |acc, (n, &x)| acc | (u32::from(x) << (8 * n)))
}

fn keccak(buf: Expr) -> Result<Expr, &'static str> {
  match buf {
    Expr::ConcreteBuf(bs) => {
      let hash_result = keccak_bytes(&bs);
      let byte_array: [u8; 4] = hash_result[..4].try_into().map_err(|_| "Conversion failed")?;
      // Convert the byte array to a u32 (assuming the bytes are in little-endian order)
      Ok(Expr::Lit(u32::from_le_bytes(byte_array)))
    }
    _ => Ok(Expr::Keccak(Box::new(buf))), // Assuming Expr has a variant for Keccak
  }
}

fn keccak_prime(input: &[u8]) -> Vec<u8> {
  let hash_result = keccak_bytes(input);
  hash_result[..32].to_vec()
}

struct FunctionSelector(u32); // Define FunctionSelector appropriately

fn abi_keccak(input: &[u8]) -> FunctionSelector {
  let hash_result = keccak_bytes(input);
  let selector_bytes = &hash_result[..4];
  let selector = word32(selector_bytes);
  FunctionSelector(selector)
}

fn hashcode(cc: &ContractCode) -> Expr {
  match cc {
    ContractCode::UnKnownCode(a) => Expr::CodeHash(a.clone()),
    ContractCode::InitCode(ops, args) => keccak(Expr::ConcreteBuf(ops.clone())).unwrap(),
    ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(ops)) => {
      keccak(Expr::ConcreteBuf(ops.clone())).unwrap()
    }
    ContractCode::RuntimeCode(RuntimeCodeStruct::SymbolicRuntimeCode(ops)) => keccak(from_list(ops.clone())).unwrap(),
  }
}

fn codelen(cc: &ContractCode) -> Expr {
  match cc {
    ContractCode::UnKnownCode(a) => Expr::CodeSize(a.clone()),
    ContractCode::InitCode(ops, args) => keccak(Expr::ConcreteBuf(ops.clone())).unwrap(),
    ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(ops)) => Expr::Lit(ops.len() as u32),
    ContractCode::RuntimeCode(RuntimeCodeStruct::SymbolicRuntimeCode(ops)) => Expr::Lit(ops.len() as u32),
  }
}

fn pad_left(n: usize, xs: Vec<u8>) -> Vec<u8> {
  if xs.len() >= n {
    return xs; // No padding needed if already of sufficient length
  }
  let padding_length = n - xs.len();
  let padding = iter::repeat(0u8).take(padding_length);
  padding.chain(xs.into_iter()).collect()
}

fn pad_left_prime(n: usize, xs: Vec<Expr>) -> Vec<Expr> {
  if xs.len() >= n {
    return xs; // No padding needed if already of sufficient length
  }
  let padding_length = n - xs.len();
  let padding = iter::repeat(Expr::LitByte(0)).take(padding_length);
  padding.chain(xs.into_iter()).collect()
}

fn pad_right(n: usize, mut xs: Vec<u8>) -> Vec<u8> {
  if xs.len() >= n {
    return xs; // No padding needed if already of sufficient length
  }
  let padding_length = n - xs.len();
  xs.extend(iter::repeat(0u8).take(padding_length));
  xs
}

fn add(a: Expr, b: Expr) -> Expr {
  Expr::Add(Box::new(a), Box::new(b))
}

fn buf_length(buf: Expr) -> Expr {
  buf_length_env(HashMap::new(), false, buf)
}

fn buf_length_env(env: HashMap<i32, Expr>, use_env: bool, buf: Expr) -> Expr {
  fn go(l: Expr, buf: Expr, env: &HashMap<i32, Expr>, use_env: bool) -> Expr {
    match buf {
      Expr::ConcreteBuf(b) => max_expr(l, Expr::Lit(b.len() as u32)),
      Expr::AbstractBuf(b) => max_expr(l, Expr::BufLength(Box::new(Expr::AbstractBuf(b)))),
      Expr::WriteWord(idx, _, b) => go(max_expr(l, add(*idx, Expr::Lit(32))), *b, env, use_env),
      Expr::WriteByte(idx, _, b) => go(max_expr(l, add(*idx, Expr::Lit(1))), *b, env, use_env),
      Expr::CopySlice(_, dst_offset, size, _, dst) => go(max_expr(l, add(*dst_offset, *size)), *dst, env, use_env),
      Expr::GVar(GVar::BufVar(a)) => {
        if use_env {
          if let Some(b) = env.get(&a) {
            go(l, b.clone(), env, use_env)
          } else {
            panic!("Cannot compute length of open expression")
          }
        } else {
          max_expr(l, Expr::BufLength(Box::new(Expr::GVar(GVar::BufVar(a)))))
        }
      }
      _ => panic!("unsupported expression"),
    }
  }

  go(Expr::Lit(0), buf, &env, use_env)
}

fn max_expr(a: Expr, b: Expr) -> Expr {
  // Implement the logic to compute the maximum of two ExprWord values
  // This is a placeholder implementation
  if let Expr::Lit(a_val) = a {
    if let Expr::Lit(b_val) = b {
      Expr::Lit(max(a_val, b_val))
    } else {
      b
    }
  } else {
    a
  }
}
