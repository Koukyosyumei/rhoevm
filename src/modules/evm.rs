use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::hash::Hash;
use std::iter;
use tiny_keccak::{Hasher, Keccak};

use crate::modules::expr::{emin, index_word, read_word_from_bytes, word256_bytes, write_byte, write_word};
use crate::modules::feeschedule::FeeSchedule;
use crate::modules::op::{get_op, op_size, op_string, Op};
use crate::modules::types::{
  from_list, len_buf, maybe_lit_addr, maybe_lit_byte, pad_left, pad_left_prime, pad_right, unbox, Addr, Block, Cache,
  CodeLocation, Contract, ContractCode, Env, Expr, ExprSet, ForkState, FrameState, GVar, Gas, Memory, MutableMemory,
  RuntimeCodeStruct, RuntimeConfig, SubState, TxState, VMOpts, W256W256Map, Word8, VM,
};

use super::types::W256;

fn initial_gas() -> u64 {
  10000 // Placeholder value
}

pub fn blank_state() -> FrameState {
  FrameState {
    contract: Expr::LitAddr(W256(0, 0)),
    code_contract: Expr::LitAddr(W256(0, 0)),
    code: ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(Vec::new())),
    pc: 0,
    stack: Vec::new(),
    memory: Memory::ConcreteMemory(Vec::new()),
    memory_size: 0,
    calldata: Expr::Mempty,
    callvalue: Expr::Lit(W256(0, 0)),
    caller: Expr::LitAddr(W256(0, 0)),
    gas: Gas::Concerete(initial_gas()),
    returndata: Expr::Mempty,
    static_flag: false,
  }
}

pub fn bytecode(contract: &Contract) -> Option<Expr> {
  match &contract.code {
    ContractCode::InitCode(_, _) => Some(Expr::Mempty),
    ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(buf)) => Some(Expr::ConcreteBuf(buf.to_vec())),
    _ => None,
  }
}

pub fn current_contract(vm: &VM) -> Option<Contract> {
  vm.env.contracts.get(&vm.state.code_contract).cloned()
}

pub fn make_vm(opts: VMOpts) -> VM {
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
      number: opts.number.clone(),
      prev_randao: opts.prev_randao.clone(),
      max_code_size: opts.max_code_size.clone(),
      gaslimit: opts.block_gaslimit,
      base_fee: opts.base_fee.clone(),
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
      chain_id: opts.chain_id.clone(),
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
        chain_id: opts.chain_id.clone(),
        fresh_address: 0,
        fresh_gas_vals: 0,
      },
      block: Block {
        coinbase: opts.coinbase.clone(),
        time_stamp: opts.time_stamp.clone(),
        number: opts.number.clone(),
        prev_randao: opts.prev_randao.clone(),
        max_code_size: opts.max_code_size.clone(),
        gaslimit: opts.block_gaslimit,
        base_fee: opts.base_fee.clone(),
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
    decoded_opcodes: Vec::new(),
  }
}

pub fn unknown_contract(addr: Expr) -> Contract {
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

pub fn abstract_contract(code: ContractCode, addr: Expr) -> Contract {
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

pub fn empty_contract() -> Contract {
  initial_contract(ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(
    Vec::new(),
  )))
}

pub fn initial_contract(code: ContractCode) -> Contract {
  Contract {
    code: code.clone(),
    storage: Expr::ConcreteStore(W256W256Map::new()),
    orig_storage: Expr::ConcreteStore(W256W256Map::new()),
    balance: Expr::Lit(W256(0, 0)),
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

fn is_precompile(expr: &Expr) -> bool {
  if let Some(lit_self) = maybe_lit_addr(expr.clone()) {
    return lit_self > W256(0x0, 0) && lit_self <= W256(0x9, 0);
  }
  return false;
}

impl VM {
  pub fn exec1(&mut self) {
    // let mut vm.state.stack = &vm.state.stack;
    let self_contract = self.state.contract.clone();
    let binding = self.env.clone();
    let this_contract = binding.contracts.get(&self_contract).unwrap();
    let fees = self.block.schedule.clone();

    if is_precompile(&self_contract) {
      if let Some(lit_self) = maybe_lit_addr(self_contract) {
        // call to precompile
        let calldatasize = len_buf(&self.state.calldata);
        copy_bytes_to_memory(
          self.state.calldata.clone(),
          Expr::Lit(W256(calldatasize as u128, 0)),
          Expr::Lit(W256(0, 0)),
          Expr::Lit(W256(0, 0)),
          self,
        );
        execute_precompile(
          lit_self,
          self.state.gas.clone(),
          Expr::Lit(W256(0, 0)),
          Expr::Lit(W256(calldatasize as u128, 0)),
          Expr::Lit(W256(0, 0)),
          Expr::Lit(W256(0, 0)),
          vec![],
        );
        match self.state.stack.first() {
          Some(boxed_expr) => {
            if **boxed_expr == Expr::Lit(W256(0, 0)) {
              todo!()
              /*
                          fetchAccount self $ \_ -> do
              touchAccount self
              vmError PrecompileFailure
              */
            } else {
              todo!()
              /*
                          fetchAccount self $ \_ -> do
              touchAccount self
              out <- use (#state % #returndata)
              finishFrame (FrameReturned out)
                 */
            }
          }
          None => underrun(),
        }
      }
    } else if self.state.pc >= opslen(&self.state.code) {
      finish_frame("FrameReturned", vec![]);
    } else {
      let op = match &self.state.code {
        ContractCode::UnKnownCode(_) => panic!("cannot execute unknown code"),
        ContractCode::InitCode(conc, _) => conc[self.state.pc],
        ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(bs)) => bs[self.state.pc],
        ContractCode::RuntimeCode(RuntimeCodeStruct::SymbolicRuntimeCode(ops)) => {
          match maybe_lit_byte(ops[self.state.pc].clone()) {
            Some(b) => b,
            None => panic!("could not analyze symbolic code"),
          }
        }
      };

      let decoded_op = get_op(op);
      self.decoded_opcodes.push(op_string(self.state.pc as u64, decoded_op.clone()).to_string());

      match decoded_op {
        Op::Push0 => {
          // stack output
          // - value: pushed value, equal to 0.
          limit_stack(1, self.state.stack.len(), || {
            burn(self, fees.g_base, || {});
            next(self, op);
            push_sym(self, Box::new(Expr::Lit(W256(0, 0))));
          });
        }
        Op::Push(n) => {
          let xs = match &self.state.code {
            ContractCode::UnKnownCode(_) => panic!("Cannot execute unknown code"),
            ContractCode::InitCode(conc, _) => {
              let bytes = pad_right(n as usize, (&conc[(1 + self.state.pc)..]).to_vec());
              Expr::Lit(W256(word32(&bytes) as u128, 0))
            }
            ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(bs)) => {
              let bytes = bs
                .get((1 + self.state.pc)..(1 + self.state.pc + n as usize))
                .unwrap_or_else(|| panic!("Index out of bounds"));
              Expr::Lit(W256(word32(&bytes) as u128, 0))
            }
            ContractCode::RuntimeCode(RuntimeCodeStruct::SymbolicRuntimeCode(ops)) => {
              let bytes = ops
                .get((1 + self.state.pc)..(1 + self.state.pc + n as usize))
                .unwrap_or_else(|| panic!("Index out of bounds"));
              let padded_bytes = pad_left_prime(32, bytes.to_vec());
              from_list(padded_bytes)
            }
          };
          self.decoded_opcodes.push(xs.to_string());

          limit_stack(1, self.state.stack.len(), || {
            burn(self, fees.g_verylow, || {});
            next(self, op);
            push_sym(self, Box::new(xs.clone()));
          });
        }
        Op::Dup(i) => {
          if let Some(y) = self.state.stack.get(i as usize - 1).cloned() {
            limit_stack(1, self.state.stack.len(), || {
              burn(self, fees.g_verylow, || {});
              next(self, op);
              push_sym(self, y.clone());
            });
          } else {
            underrun();
          }
        }
        Op::Swap(i) => {
          if self.state.stack.len() < i as usize + 1 {
            underrun();
          } else {
            burn(self, fees.g_verylow, || {});
            next(self, op);
            let a = self.state.stack[0].clone();
            let b = self.state.stack[i as usize].clone();
            self.state.stack[0] = b;
            self.state.stack[i as usize] = a;
          }
        }
        Op::Log(n) => {
          not_static(self, || {});
          if let Some((x_offset, x_size, xs)) =
            self.state.stack.clone().split_first().clone().and_then(|(a, b)| b.split_first().map(|(c, d)| (a, c, d)))
          {
            if xs.len() < n as usize {
              underrun();
            } else {
              let bytes = read_memory(x_offset, x_size);
              let (topics, xs) = xs.split_at(n as usize);
              let logs = vec![Expr::LogEntry(
                Box::new(self.state.contract.clone()),
                Box::new(bytes),
                topics.to_vec(),
              )];
              burn_log(x_size, op, || {});
              access_memory_range(self, *x_offset.clone(), *x_size.clone(), || {});
              trace_top_log(logs.clone());
              self.state.stack = xs.to_vec();
              self.logs = logs;
              next(self, op);
            }
          } else {
            underrun();
          }
        }
        Op::Stop => {
          finish_frame("FrameReturned", vec![]);
        }
        Op::Add => stack_op2(self, fees.g_verylow, "add"),
        Op::Mul => stack_op2(self, fees.g_low, "mul"),
        Op::Sub => stack_op2(self, fees.g_verylow, "sub"),
        Op::Div => stack_op2(self, fees.g_low, "div"),
        Op::Sdiv => stack_op2(self, fees.g_low, "sdiv"),
        Op::Mod => stack_op2(self, fees.g_low, "nmod"),
        Op::Smod => stack_op2(self, fees.g_low, "smod"),
        Op::Addmod => stack_op3(self, fees.g_mid, "addmod"),
        Op::Mulmod => stack_op3(self, fees.g_mid, "mulmod"),
        Op::Lt => stack_op2(self, fees.g_verylow, "lt"),
        Op::Gt => stack_op2(self, fees.g_verylow, "gt"),
        Op::Slt => stack_op2(self, fees.g_verylow, "slt"),
        Op::Sgt => stack_op2(self, fees.g_verylow, "sgt"),
        Op::Eq => stack_op2(self, fees.g_verylow, "eq"),
        Op::Iszero => stack_op1(self, fees.g_verylow, "iszero"),
        Op::And => stack_op2(self, fees.g_verylow, "and"),
        Op::Or => stack_op2(self, fees.g_verylow, "or"),
        Op::Xor => stack_op2(self, fees.g_verylow, "xor"),
        Op::Not => stack_op1(self, fees.g_verylow, "not"),
        Op::Byte => stack_op2(self, fees.g_verylow, "byte"),
        Op::Shl => stack_op2(self, fees.g_verylow, "shl"),
        Op::Shr => stack_op2(self, fees.g_verylow, "shr"),
        Op::Sar => stack_op2(self, fees.g_verylow, "sar"),
        Op::Sha3 => {
          if let Some((x_offset, x_size, xs)) =
            self.state.stack.clone().split_first().and_then(|(a, b)| b.split_first().map(|(c, d)| (a, c, d)))
          {
            //burn_sha3(self, unbox(x_size.clone()), self.block.schedule.clone(), || {
            //  access_memory_range(self, **x_offset, **x_size, || {
            let buffer = read_memory(x_offset, x_size);
            let hash = match buffer {
              orig @ Expr::ConcreteBuf(_) => Expr::Keccak(Box::new(orig)),
              // orig @ Expr::ConcreteBuf(bs) => Expr::Lit(word32(&keccak_prime(&bs.to_vec()))),
              _ => keccak(buffer).unwrap(),
            };
            next(self, op);
            self.state.stack = std::iter::once(Box::new(hash)).chain(xs.iter().cloned()).collect();
            //  });
            //});
          } else {
            underrun();
          }
        }
        Op::Address => {
          limit_stack(1, self.state.stack.len(), || {
            burn(self, fees.g_base, || {});
            next(self, op);
            push_addr(self, self_contract.clone());
          });
        }
        Op::Balance => {
          if let Some(x) = self.state.stack.clone().first() {
            force_addr(x, "BALANCE", |a| {
              access_and_burn(&a, || {
                fetch_account(&a, |c| {
                  next(self, op);
                  self.state.stack = self.state.stack[1..].to_vec();
                  push_sym(self, Box::new(c.balance.clone()));
                });
              });
            });
          } else {
            underrun();
          }
        }
        Op::Origin => {
          /*
          Stack output
          - address: the 20-byte address of the sender of the transaction. It can only be an account without code.
          */
          limit_stack(1, self.state.stack.len(), || {
            burn(self, fees.g_base, || {});
            next(self, op);
            push_addr(self, self.tx.origin.clone());
          });
        }
        Op::Caller => {
          /*
          Stack output
          - address: the 20-byte address of the caller account. This is the account that did the last call (except delegate call).
           */
          limit_stack(1, self.state.stack.len(), || {
            burn(self, fees.g_base, || {});
            next(self, op);
            push_addr(self, self.state.caller.clone());
          });
        }
        Op::Callvalue => {
          /*
          Stack output
          - value: the value of the current call in wei.
           */
          limit_stack(1, self.state.stack.len(), || {
            burn(self, fees.g_base, || {});
            next(self, op);
            push_sym(self, Box::new(self.state.callvalue.clone()));
          });
        }
        Op::Calldataload => stack_op1(self, fees.g_verylow, "calldataload"),
        Op::Calldatasize => {
          /*
          size: byte size of the calldata.
           */
          limit_stack(1, self.state.stack.len(), || {
            burn(self, fees.g_base, || {});
            next(self, op);
            push_sym(
              self,
              Box::new(Expr::Lit(W256(len_buf(&self.state.calldata) as u128, 0))),
            );
          });
        }
        Op::Calldatacopy => {
          if let Some((x_to, rest)) = self.state.stack.clone().split_first() {
            if let Some((x_from, rest)) = rest.split_first() {
              if let Some((x_size, xs)) = rest.split_first() {
                burn_calldatacopy(self, unbox(x_size.clone()), self.block.schedule.clone(), || {});
                access_memory_range(self, *x_to.clone(), *x_size.clone(), || {});
                self.state.stack = xs.to_vec();
                copy_bytes_to_memory(
                  self.state.calldata.clone(),
                  unbox(x_size.clone()),
                  unbox(x_from.clone()),
                  unbox(x_to.clone()),
                  self,
                );
                next(self, op);
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
        Op::Codesize => {
          limit_stack(1, self.state.stack.len(), || {
            burn(self, fees.g_base, || {});
            next(self, op);
            push_sym(self, Box::new(codelen(&self.state.code)));
          });
        }
        Op::Codecopy => {
          if let Some((mem_offset, rest1)) = (self.state.stack).split_first() {
            let mem_offset = mem_offset.clone();
            let rest1 = rest1.to_vec();
            if let Some((code_offset, rest)) = rest1.split_first().clone() {
              if let Some((n, xs)) = rest.split_first().clone() {
                next(self, op);
                self.state.stack = xs.to_vec();
                burn_codecopy(self, unbox(n.clone()), self.block.schedule.clone(), || {});
                access_memory_range(self, *mem_offset.clone(), *n.clone(), || {});
                if let Some(b) = to_buf(&self.state.code) {
                  copy_bytes_to_memory(
                    Expr::ConcreteBuf(b.to_vec()),
                    unbox(n.clone()),
                    unbox(code_offset.clone().clone()),
                    unbox(mem_offset.clone().clone()),
                    self,
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
        Op::Gasprice => {
          limit_stack(1, self.state.stack.len(), || {
            burn(self, fees.g_base, || {});
            next(self, op);
            push_sym(self, Box::new(Expr::Lit(self.tx.gasprice.clone())));
          });
        }
        Op::Extcodesize => {
          if let Some(x) = self.state.stack.clone().first().clone() {
            force_addr(x, "EXTCODESIZE", |a| {
              access_and_burn(&a, || {
                fetch_account(&a, |c| {
                  next(self, op);
                  self.state.stack = self.state.stack[1..].to_vec();
                  if let Some(b) = &c.bytecode() {
                    push_sym(self, Box::new(buf_length(b.clone())));
                  } else {
                    push_sym(self, Box::new(Expr::CodeSize(Box::new(a.clone()))));
                  }
                });
              });
            });
          } else {
            underrun();
          }
        }
        Op::Extcodecopy => {
          if let Some((ext_account, rest1)) = self.state.stack.split_first() {
            let ext_account = ext_account.clone();
            let rest1 = rest1.to_vec();
            if let Some((mem_offset, rest2)) = rest1.split_first() {
              let mem_offset = mem_offset.clone();
              let rest2 = rest2.to_vec();
              if let Some((code_offset, rest)) = rest2.split_first() {
                if let Some((code_size, xs)) = rest.split_first() {
                  force_addr(&ext_account, "EXTCODECOPY", |a| {
                    burn_extcodecopy(
                      self,
                      unbox(ext_account.clone()),
                      unbox(code_size.clone()),
                      self.block.schedule.clone(),
                      || {},
                    );
                    fetch_account(&a, |c| {
                      next(self, op);
                      self.state.stack = xs.to_vec();
                      if let Some(b) = &c.bytecode() {
                        copy_bytes_to_memory(
                          b.clone(),
                          unbox(code_size.clone()),
                          unbox(code_offset.clone()),
                          unbox(mem_offset.clone()),
                          self,
                        );
                      } else {
                        internal_error("Cannot copy from unknown code");
                      }
                    });
                    access_memory_range(self, *mem_offset, *code_size.clone(), || {});
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
        Op::Returndatasize => {
          limit_stack(1, self.state.stack.len(), || {
            burn(self, fees.g_base, || {});
            next(self, op);
            push_sym(
              self,
              Box::new(Expr::Lit(W256(len_buf(&self.state.returndata) as u128, 0))),
            );
          });
        }
        Op::Coinbase => {
          /*
          Stack otuput
          - address: miner's 20-byte address.
           */
          limit_stack(1, self.state.stack.len(), || {
            burn(self, fees.g_base, || {});
            next(self, op);
            push_addr(self, self.block.coinbase.clone())
          });
        }
        Op::Timestamp => {
          limit_stack(1, self.state.stack.len(), || {
            burn(self, fees.g_base, || {});
            next(self, op);
            push_sym(self, Box::new(self.block.time_stamp.clone()))
          });
        }
        Op::Number => {
          limit_stack(1, self.state.stack.len(), || {
            burn(self, fees.g_base, || {});
            next(self, op);
            push(self, self.block.number.clone())
          });
        }
        Op::PrevRandao => {
          limit_stack(1, self.state.stack.len(), || {
            burn(self, fees.g_base, || {});
            next(self, op);
            push(self, self.block.prev_randao.clone())
          });
        }
        Op::Gaslimit => {
          limit_stack(1, self.state.stack.len(), || {
            burn(self, fees.g_base, || {});
            next(self, op);
            push(self, W256(self.block.gaslimit as u128, 0))
          });
        }
        Op::Chainid => {
          limit_stack(1, self.state.stack.len(), || {
            burn(self, fees.g_base, || {});
            next(self, op);
            push(self, self.env.chain_id.clone())
          });
        }
        Op::Selfbalance => {
          limit_stack(1, self.state.stack.clone().len(), || {
            burn(self, fees.g_base, || {});
            next(self, op);
            push_sym(self, Box::new(this_contract.balance.clone()))
          });
        }
        Op::BaseFee => {
          limit_stack(1, self.state.stack.len(), || {
            burn(self, fees.g_base, || {});
            next(self, op);
            push(self, self.block.base_fee.clone())
          });
        }
        Op::Pc => {
          limit_stack(1, self.state.stack.len(), || {
            burn(self, fees.g_base, || {});
            next(self, op);
            push(self, W256(self.state.pc as u128, 0))
          });
        }
        Op::Msize => {
          limit_stack(1, self.state.stack.len(), || {
            burn(self, fees.g_base, || {});
            next(self, op);
            push(self, W256(self.state.memory_size as u128, 0))
          });
        }
        Op::Pop => {
          if let Some((_, xs)) = self.state.stack.split_first() {
            self.state.stack = xs.to_vec();
            next(self, op);
            burn(self, fees.g_base, || {});
          } else {
            underrun();
          }
        }
        Op::Mload => {
          if let Some((x, xs)) = self.state.stack.clone().split_first() {
            let buf = read_memory(x, &Expr::Lit(W256(32, 0)));
            let w = read_word_from_bytes(Expr::Lit(W256(0, 0)), buf);
            self.state.stack = std::iter::once(Box::new(w)).chain(xs.iter().cloned()).collect();
            next(self, op);
            access_memory_word(self, *x.clone(), || {});
            burn(self, fees.g_verylow, || {});
          } else {
            underrun();
          }
        }
        Op::Mstore => {
          /*
          Save word to memory

          - Stack input
            * offset: offset in the memory in bytes.
            * value: 32-byte value to write in the memory.
          */
          if let Some((x, rest)) = self.state.stack.clone().split_first() {
            if let Some((y, xs)) = rest.split_first() {
              next(self, op);
              match &self.state.memory {
                Memory::ConcreteMemory(mem) => match *y.clone() {
                  Expr::Lit(w) => {
                    copy_bytes_to_memory(
                      Expr::ConcreteBuf(word256_bytes(w.into())),
                      Expr::Lit(W256(32, 0)),
                      Expr::Lit(W256(0, 0)),
                      *x.clone(),
                      self,
                    );
                  }
                  _ => {
                    let buf = freeze_memory(&mem);
                    self.state.memory = Memory::SymbolicMemory(write_word(*x.clone(), *y.clone(), buf));
                  }
                },
                Memory::SymbolicMemory(mem) => {
                  self.state.memory = Memory::SymbolicMemory(write_word(*x.clone(), *y.clone(), mem.clone()));
                }
              }
              self.state.stack = xs.to_vec();
              access_memory_word(self, *x.clone(), || {});
              burn(self, fees.g_verylow, || {});
            } else {
              underrun();
            }
          } else {
            underrun();
          }
        }
        Op::Mstore8 => {
          if let Some((x, rest)) = self.state.stack.clone().split_first() {
            if let Some((y, xs)) = rest.split_first() {
              let y_byte = index_word(Expr::Lit(W256(31, 0)), *y.clone());
              next(self, op);
              match &self.state.memory {
                Memory::ConcreteMemory(mem) => match y_byte {
                  Expr::LitByte(byte) => {
                    copy_bytes_to_memory(
                      Expr::ConcreteBuf(vec![byte]),
                      Expr::Lit(W256(1, 0)),
                      Expr::Lit(W256(0, 0)),
                      *x.clone(),
                      self,
                    );
                  }
                  _ => {
                    let buf = freeze_memory(&mem);
                    self.state.memory = Memory::SymbolicMemory(write_byte(*x.clone(), y_byte, buf));
                  }
                },
                Memory::SymbolicMemory(mem) => {
                  self.state.memory = Memory::SymbolicMemory(write_byte(*x.clone(), y_byte, mem.clone()));
                }
              }
              self.state.stack = xs.to_vec();
              access_memory_range(self, *x.clone(), Expr::Lit(W256(1, 0)), || {});
              burn(self, fees.g_verylow, || {});
            } else {
              underrun();
            }
          } else {
            underrun();
          }
        }
        _ => panic!("unsupported op"),
        /*
        Op::Sload => {
          if let Some((x, xs)) = self.state.stack.split_first() {
            let acc = access_storage_for_gas(self, x);
            let cost = if acc {
              fees.g_warm_storage_read
            } else {
              fees.g_cold_sload
            };
            burn(self, cost, || {
              access_storage(self, x, |y| {
                next(self, op);
                self.state.stack = std::iter::once(Box::new(y)).chain(xs.iter().cloned()).collect();
              });
            });
          } else {
            underrun();
          }
        }
        Op::Jump => {
          if let Some((x, xs)) = self.state.stack.split_first() {
            burn(self, fees.g_mid, || {
              force_concrete(x, "JUMP: symbolic jumpdest", |x_| match to_int(x_) {
                None => vm_error(BadJumpDestination),
                Some(i) => check_jump(self, i, xs),
              });
            });
          } else {
            underrun();
          }
        }
        Op::Jumpi => {
          if let Some((x, rest)) = self.state.stack.split_first() {
            if let Some((y, xs)) = rest.split_first() {
              force_concrete(x, "JUMPI: symbolic jumpdest", |x_| {
                burn(self, fees.g_high, || {
                  let jump = |condition: bool| {
                    if condition {
                      match to_int(x_) {
                        None => vm_error(BadJumpDestination),
                        Some(i) => check_jump(self, i, xs),
                      }
                    } else {
                      self.state.stack = xs.to_vec();
                      next(self, op);
                    }
                  };
                  branch(y, jump);
                });
              });
            } else {
              underrun();
            }
          } else {
            underrun();
          }
        }
        */
      }
    }
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

fn freeze_memory(memory: &MutableMemory) -> Expr {
  Expr::ConcreteBuf(memory.clone()) // Clone the memory vector to freeze it
}

fn copy_bytes_to_memory(bs: Expr, size: Expr, src_offset: Expr, mem_offset: Expr, vm: &mut VM) {
  if size == Expr::Lit(W256(0, 0)) {
    return;
  }

  match &vm.state.memory {
    Memory::ConcreteMemory(mem) => {
      match (&bs, &size, &src_offset, &mem_offset) {
        (Expr::ConcreteBuf(b), Expr::Lit(size_val), Expr::Lit(src_offset_val), Expr::Lit(mem_offset_val)) => {
          let src = if *src_offset_val >= (W256(b.len() as u128, 0)) {
            vec![0; size_val.0 as usize]
          } else {
            let mut src_tmp = b[(src_offset_val.0 as usize)..].to_vec();
            src_tmp.resize((size_val.0 as usize), 0);
            src_tmp
          };
          if let Some(concrete_mem) = vm.state.memory.as_mut_concrete_memory() {
            write_memory(concrete_mem, mem_offset_val.0 as usize, &src);
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

fn limit_stack<F: FnOnce()>(n: usize, stack_len: usize, f: F) {
  // Implement stack limit check
  if stack_len + n > 1024 {
    panic!("stack limit exceeded")
  } else {
    f()
  }
}

fn burn<F: FnOnce()>(vm: &mut VM, gas: u64, f: F) {
  match vm.state.gas {
    Gas::Symbolic => f(),
    Gas::Concerete(available_gas_val) => match vm.burned {
      Gas::Symbolic => f(),
      Gas::Concerete(burned_gas_val) => {
        if gas <= available_gas_val {
          vm.state.gas = Gas::Concerete(available_gas_val - gas);
          vm.burned = Gas::Concerete(burned_gas_val + gas);
          f()
        } else {
          panic!("out of gas")
        }
      }
    },
  };
}

fn burn_sha3<F: FnOnce()>(vm: &mut VM, x_size: Expr, schedule: FeeSchedule, f: F) {
  let cost = match x_size {
    Expr::Lit(c) => schedule.g_sha3 + schedule.g_sha3word * (((c.0 as u64) + 31) / 32),
    _ => panic!("illegal expression"),
  };
  burn(vm, cost, f)
}

fn burn_codecopy<F: FnOnce()>(vm: &mut VM, n: Expr, schedule: FeeSchedule, f: F) {
  let max_word64 = u64::MAX;
  let cost = match n {
    Expr::Lit(c) => {
      if (c.0 as u64) <= (max_word64 - (schedule.g_verylow as u64)) / ((schedule.g_copy as u64) * 32) {
        schedule.g_verylow + schedule.g_copy * (((c.0 as u64) + 31) / 32)
      } else {
        panic!("overflow")
      }
    }
    _ => panic!("illegal expression"),
  };
  burn(vm, cost, f)
}

fn ceil_div(x: u64, y: u64) -> u64 {
  (x + y - 1) / y
}

fn burn_calldatacopy<F: FnOnce()>(vm: &mut VM, x_size: Expr, schedule: FeeSchedule, f: F) {
  let cost = match x_size {
    Expr::Lit(c) => schedule.g_verylow + schedule.g_copy * ceil_div(c.0 as u64, 32),
    _ => panic!("illegal expression"),
  };
  burn(vm, cost, f)
}

fn burn_extcodecopy<F: FnOnce()>(vm: &mut VM, ext_account: Expr, code_size: Expr, schedule: FeeSchedule, f: F) {
  let ceiled_c = match code_size {
    Expr::Lit(c) => ceil_div(c.0 as u64, 32),
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
  burn(vm, cost, f)
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

fn next(vm: &mut VM, op: u8) {
  vm.state.pc += op_size(op);
}

fn push(vm: &mut VM, val: W256) {
  push_sym(vm, Box::new(Expr::Lit(val)))
}

fn push_sym(vm: &mut VM, expr: Box<Expr>) {
  vm.state.stack.push(expr);
}

fn memory_cost(schedule: &FeeSchedule, byte_count: u64) -> u64 {
  let word_count = ceil_div(byte_count, 32);
  let linear_cost = schedule.g_memory * word_count;
  let quadratic_cost = (word_count * word_count) / 512;
  linear_cost + quadratic_cost
}

fn to_word64(expr: Expr) -> Option<u64> {
  // Implement conversion from Expr<EWord> to u64
  unimplemented!()
}

fn access_unbounded_memory_range(vm: &mut VM, f: u64, l: u64, continue_fn: impl Fn()) {
  if l == 0 {
    continue_fn();
  } else {
    let m0 = vm.state.memory_size;
    let fees = &vm.block.schedule;
    let m1 = 32 * ((m0.max(f + l) + 31) / 32); // ceilDiv equivalent
    let cost_diff = memory_cost(fees, m1) - memory_cost(fees, m0);
    burn(vm, cost_diff, || {});
    vm.state.memory_size = m1;
    continue_fn();
  }
}

fn access_memory_range(vm: &mut VM, offs: Expr, sz: Expr, continue_fn: impl Fn()) {
  match (offs, sz) {
    (Expr::Lit(W256(0, 0)), Expr::Lit(W256(0, 0))) => continue_fn(),
    (Expr::Lit(offs), Expr::Lit(sz)) => match ((offs.0 as u64), (sz.0 as u64)) {
      (offs64, sz64) if offs64.checked_add(sz64).is_some() && offs64 < 0x0fffffff && sz64 < 0x0fffffff => {
        access_unbounded_memory_range(vm, offs64, sz64, continue_fn);
      }
      _ => panic!("illegal overflow error"),
    },
    _ => continue_fn(),
  }
}

fn access_memory_word(vm: &mut VM, x: Expr, continue_fn: impl Fn()) {
  access_memory_range(vm, x, Expr::Lit(W256(32, 0)), continue_fn);
}

fn copy_call_bytes_to_memory(vm: &mut VM, bs: Expr, size: Expr, y_offset: Expr) {
  let size_min = emin(size, buf_length(bs.clone()));
  copy_bytes_to_memory(bs, size_min, Expr::Lit(W256(0, 0)), y_offset, vm);
}

fn read_memory(offset: &Expr, size: &Expr) -> Expr {
  // Implement memory reading logic
  Expr::Lit(W256(0, 0)) // Placeholder
}

fn burn_log(size: &Expr, n: u8, f: impl FnOnce()) {
  // Implement log burning logic
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
    next(vm, 1);
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
        next(vm, 1);
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
    next(vm, 1);
    vm.state.stack[0] = res;
  } else {
    underrun();
  }
}

fn force_addr<F: FnOnce(Expr)>(n: &Expr, msg: &str, f: F) {
  // Implement address forcing logic
  todo!()
}

fn force_concrete<F: FnOnce(Expr)>(n: &Expr, msg: &str, f: F) {
  // Implement address forcing logic
  todo!()
}

fn access_and_burn(addr: &Expr, f: impl FnOnce()) {
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

pub fn keccak(buf: Expr) -> Result<Expr, &'static str> {
  match buf {
    Expr::ConcreteBuf(bs) => {
      let hash_result = keccak_bytes(&bs);
      let byte_array: [u8; 4] = hash_result[..4].try_into().map_err(|_| "Conversion failed")?;
      // Convert the byte array to a u32 (assuming the bytes are in little-endian order)
      Ok(Expr::Lit(W256(u32::from_le_bytes(byte_array) as u128, 0)))
    }
    _ => Ok(Expr::Keccak(Box::new(buf))), // Assuming Expr has a variant for Keccak
  }
}

pub fn keccak_prime(input: &[u8]) -> Vec<u8> {
  let hash_result = keccak_bytes(input);
  hash_result[..32].to_vec()
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct FunctionSelector(u32); // Define FunctionSelector appropriately

pub fn abi_keccak(input: &[u8]) -> FunctionSelector {
  let hash_result = keccak_bytes(input);
  let selector_bytes = &hash_result[..4];
  let selector = word32(selector_bytes);
  FunctionSelector(selector)
}

pub fn hashcode(cc: &ContractCode) -> Expr {
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
    ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(ops)) => Expr::Lit(W256(ops.len() as u128, 0)),
    ContractCode::RuntimeCode(RuntimeCodeStruct::SymbolicRuntimeCode(ops)) => Expr::Lit(W256(ops.len() as u128, 0)),
  }
}

fn add(a: Expr, b: Expr) -> Expr {
  Expr::Add(Box::new(a), Box::new(b))
}

pub fn buf_length(buf: Expr) -> Expr {
  buf_length_env(HashMap::new(), false, buf)
}

fn buf_length_env(env: HashMap<i32, Expr>, use_env: bool, buf: Expr) -> Expr {
  fn go(l: Expr, buf: Expr, env: &HashMap<i32, Expr>, use_env: bool) -> Expr {
    match buf {
      Expr::ConcreteBuf(b) => max_expr(l, Expr::Lit(W256(b.len() as u128, 0))),
      Expr::AbstractBuf(b) => max_expr(l, Expr::BufLength(Box::new(Expr::AbstractBuf(b)))),
      Expr::WriteWord(idx, _, b) => go(max_expr(l, add(*idx, Expr::Lit(W256(32, 0)))), *b, env, use_env),
      Expr::WriteByte(idx, _, b) => go(max_expr(l, add(*idx, Expr::Lit(W256(1, 0)))), *b, env, use_env),
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

  go(Expr::Lit(W256(0, 0)), buf, &env, use_env)
}

fn max_expr(a: Expr, b: Expr) -> Expr {
  // Implement the logic to compute the maximum of two ExprWord values
  // This is a placeholder implementation
  if let Expr::Lit(a_val) = a {
    if let Expr::Lit(b_val) = b {
      Expr::Lit(a_val.max(b_val))
    } else {
      b
    }
  } else {
    a
  }
}

pub fn get_code_location(vm: &VM) -> CodeLocation {
  (vm.state.contract.clone(), vm.state.pc as i64)
}

/*
getCodeLocation :: VM t s -> CodeLocation
getCodeLocation vm = (vm.state.contract, vm.state.pc)
*/
