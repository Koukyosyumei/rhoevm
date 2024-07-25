use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::hash::Hash;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::vec;

use crate::modules::effects::Config;
use crate::modules::expr::copy_slice;
use crate::modules::expr::{
  add, conc_keccak_simp_expr, concrete_prefix, create2_address_, create_address_, drop, emin, eq, gt, index_word,
  read_byte, read_bytes, read_storage, read_word_from_bytes, simplify, sub, to_list, word_to_addr, write_byte,
  write_storage, write_word, MAX_BYTES,
};
use crate::modules::feeschedule::FeeSchedule;
use crate::modules::op::{get_op, op_size, op_string, Op};
use crate::modules::smt::{assert_props, format_smt2};
use crate::modules::types::{
  from_list, keccak, keccak_bytes, keccak_prime, len_buf, maybe_lit_addr, maybe_lit_byte, maybe_lit_word,
  pad_left_prime, pad_right, unbox, word256_bytes, Addr, BaseState, Block, BranchCondition, ByteString, Cache,
  CodeLocation, Contract, ContractCode, Env, EvmError, Expr, ExprSet, ForkState, Frame, FrameContext, FrameState, GVar,
  Gas, Memory, MutableMemory, PartialExec, Prop, Query, RuntimeCodeStruct, RuntimeConfig, SubState, Trace, TraceData,
  TxState, VMOpts, VMResult, W256W256Map, VM, W256, W64,
};

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
  let touched = if opts.create { vec![txorigin.clone()] } else { vec![txorigin.clone(), txto_addr.clone()] };

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
    traces: Vec::<Trace>::new(),
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
    cache: Cache { fetched: HashMap::new(), path: HashMap::new() },
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
      cache: Cache { fetched: HashMap::new(), path: HashMap::new() },
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
  initial_contract(ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(Vec::new())))
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
  pub fn exec1(&mut self, vm_queue: &mut Vec<VM>) {
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
      finish_frame(self, FrameResult::FrameReturned(Expr::Mempty));
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
          if let Some(y) = self.state.stack.get(self.state.stack.len() - (i as usize)).cloned() {
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
            self.state.stack.clone().split_last().clone().and_then(|(a, b)| b.split_last().map(|(c, d)| (a, c, d)))
          {
            if xs.len() < n as usize {
              underrun();
            } else {
              let bytes = read_memory(self, *x_offset.clone(), *x_size.clone());
              let (topics, xs) = xs.split_at(n as usize);
              let logs = vec![Expr::LogEntry(Box::new(self.state.contract.clone()), Box::new(bytes), topics.to_vec())];
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
          finish_frame(self, FrameResult::FrameReturned(Expr::Mempty));
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
          /*
          Stack input
          - offset: byte offset in the memory.
          - size: byte size to read in the memory.

          Stack output
          - hash: Keccak-256 hash of the given data in memory.
          */
          if let Some((x_offset, x_size, xs)) =
            self.state.stack.clone().split_last().and_then(|(a, b)| b.split_last().map(|(c, d)| (a, c, d)))
          {
            //burn_sha3(self, unbox(x_size.clone()), self.block.schedule.clone(), || {
            access_memory_range(self, *x_offset.clone(), *x_size.clone(), || {});
            let buffer = read_memory(self, *x_offset.clone(), *x_size.clone());
            let hash = match buffer {
              orig @ Expr::ConcreteBuf(_) => Expr::Keccak(Box::new(orig)),
              _ => Expr::Keccak(Box::new(buffer)),
            };
            next(self, op);
            self.state.stack = std::iter::once(Box::new(hash)).chain(xs.iter().cloned()).collect();
            //  });
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
                let mut c = empty_contract();
                fetch_account(self, &a, |c_| c = c_.clone());
                next(self, op);
                self.state.stack = self.state.stack[1..].to_vec();
                push_sym(self, Box::new(c.balance.clone()));
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
            push_sym(self, Box::new(Expr::Lit(W256(len_buf(&self.state.calldata) as u128, 0))));
          });
        }
        Op::Calldatacopy => {
          if let Some((x_to, rest)) = self.state.stack.clone().split_last() {
            if let Some((x_from, rest)) = rest.split_last() {
              if let Some((x_size, xs)) = rest.split_last() {
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
          if let Some((mem_offset, rest1)) = (self.state.stack).split_last() {
            let mem_offset = mem_offset.clone();
            let rest1 = rest1.to_vec();
            if let Some((code_offset, rest)) = rest1.split_last().clone() {
              if let Some((n, xs)) = rest.split_last().clone() {
                next(self, op);
                self.state.stack = xs.to_vec();
                burn_codecopy(self, unbox(n.clone()), self.block.schedule.clone(), || {});
                access_memory_range(self, *mem_offset.clone(), *n.clone(), || {});
                if let Some(b) = to_buf(&self.state.code) {
                  copy_bytes_to_memory(
                    b,
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
        Op::Gas => {
          limit_stack(1, self.state.stack.len(), || {
            burn(self, fees.g_base, || {});
            next(self, op);
            self.env.fresh_gas_vals += 1;
            let n = self.env.fresh_gas_vals;
            push_sym(self, Box::new(Expr::Gas(n)));
          });
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
                let mut c = empty_contract();
                fetch_account(self, &a, |c_| c = c_.clone());
                next(self, op);
                self.state.stack = self.state.stack[1..].to_vec();
                if let Some(b) = &c.bytecode() {
                  push_sym(self, Box::new(buf_length(b.clone())));
                } else {
                  push_sym(self, Box::new(Expr::CodeSize(Box::new(a.clone()))));
                }
              });
            });
          } else {
            underrun();
          }
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
            push(self, W256(self.state.pc as u128, 0));
            next(self, op)
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
          if let Some((_, xs)) = self.state.stack.split_last() {
            self.state.stack = xs.to_vec();
            next(self, op);
            burn(self, fees.g_base, || {});
          } else {
            underrun();
          }
        }
        Op::Mload => {
          if let Some((x, xs)) = self.state.stack.clone().split_last() {
            let buf = read_memory(self, *x.clone(), Expr::Lit(W256(32, 0)));
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
          if let Some((x, rest)) = self.state.stack.clone().split_last() {
            if let Some((y, xs)) = rest.split_last() {
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
          if let Some((x, rest)) = self.state.stack.clone().split_last() {
            if let Some((y, xs)) = rest.split_last() {
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
        Op::Sload => {
          if let Some((x, xs)) = self.state.stack.clone().split_last() {
            let acc = access_storage_for_gas(self, self_contract.clone(), *x.clone());
            let cost = if acc { fees.g_warm_storage_read } else { fees.g_cold_sload };

            let mut stack_item = None;
            access_storage(self, self_contract, *x.clone(), |y| {
              stack_item = Some(y); // Capture y for later use
            });
            next(self, op);
            burn(self, cost, || {});
            if let Some(y) = stack_item {
              self.state.stack = std::iter::once(Box::new(y)).chain(xs.iter().cloned()).collect();
            }
          } else {
            underrun();
          }
        }
        Op::Sstore => {
          // Ensure we're not in a static context
          not_static(self, || {});
          if let Some((x, rest)) = self.state.stack.clone().split_last() {
            if let Some((new, xs)) = rest.split_last() {
              // Access current storage
              let mut current: Expr = Expr::Mempty;
              access_storage(self, self_contract.clone(), *x.clone(), |current_| current = current_);
              let original = match conc_keccak_simp_expr(Expr::SLoad(
                Box::new(*x.clone()),
                Box::new(this_contract.orig_storage.clone()),
              )) {
                Expr::Lit(v) => v,
                _ => W256(0, 0),
              };

              // Calculate storage cost
              let storage_cost = match (maybe_lit_word(current.clone()), maybe_lit_word(*new.clone())) {
                (Some(current_), Some(new_)) => {
                  if current_ == new_ {
                    fees.g_sload
                  } else if current_ == original && original == W256(0, 0) {
                    fees.g_sset
                  } else if current_ == original {
                    fees.g_sreset
                  } else {
                    fees.g_sload
                  }
                }
                // Worst-case scenario for symbolic arguments
                _ => fees.g_sset,
              };

              // Access storage for gas
              let acc = access_storage_for_gas(self, self_contract.clone(), *x.clone());
              let cold_storage_cost = if acc { 0 } else { fees.g_cold_sload };

              // Burn gas
              burn(self, storage_cost + cold_storage_cost, || {});
              next(self, op);
              self.state.stack = xs.to_vec();
              self.env.contracts.get_mut(&self_contract.clone()).unwrap().storage = write_storage(
                *x.clone(),
                *new.clone(),
                self.env.contracts.get_mut(&self_contract.clone()).unwrap().storage.clone(),
              );

              match (maybe_lit_word(current), maybe_lit_word(*new.clone())) {
                (Some(current_), Some(new_)) => {
                  if current_ != new_ {
                    if current_ == original {
                      if original != W256(0, 0) && new_ == W256(0, 0) {
                        refund(self, fees.g_sreset + fees.g_access_list_storage_key);
                      }
                    } else {
                      if original != W256(0, 0) {
                        if current_ == W256(0, 0) {
                          un_refund(self, fees.g_sreset + fees.g_access_list_storage_key);
                        } else if new_ == W256(0, 0) {
                          refund(self, fees.g_sreset + fees.g_access_list_storage_key);
                        }
                      }
                      if original == new_ {
                        if original == W256(0, 0) {
                          refund(self, fees.g_sset - fees.g_sload);
                        } else {
                          refund(self, fees.g_sreset - fees.g_sload);
                        }
                      }
                    }
                  }
                }
                // No refund changes for symbolic arguments
                _ => {}
              }
            } else {
              underrun();
            }
          } else {
            underrun();
          }
        }
        Op::Jump => {
          if let Some((x, xs)) = self.state.stack.clone().split_last() {
            burn(self, fees.g_mid, || {});
            let mut x_int = None;
            force_concrete(self, x, "JUMP: symbolic jumpdest", |x_| {
              x_int = x_.to_int();
            });
            let _ = match x_int {
              None => Err(EvmError::BadJumpDestination),
              Some(i) => check_jump(self, i as usize, xs.to_vec()),
            };
          } else {
            underrun();
          }
        }
        Op::Jumpi => {
          if let Some((x, rest)) = self.state.stack.clone().split_last() {
            if let Some((y, xs)) = rest.split_last() {
              burn(self, fees.g_high, || {});
              let mut x_int = None;
              force_concrete(self, x, "JUMPI: symbolic jumpdest", |x_| x_int = x_.to_int());

              let mut condition = BranchReachability::NONE;
              let else_vm_ = branch(self, y, |condition_| Ok(condition = condition_));

              if condition == BranchReachability::ONLYTHEN || condition == BranchReachability::BOTH {
                match x_int {
                  None => {
                    panic!("bad jump destination");
                    //Err(EvmError::BadJumpDestination);
                  }
                  Some(i) => {
                    let _ = check_jump(self, i as usize, xs.to_vec());
                  }
                }
              }
              if condition == BranchReachability::ONLYELSE || condition == BranchReachability::BOTH {
                {
                  let mut else_vm = else_vm_.unwrap();
                  next(&mut else_vm, op);
                  else_vm.state.stack = xs.to_vec();
                  vm_queue.push(else_vm);
                }
              }
            } else {
              underrun();
            }
          } else {
            underrun();
          }
        }
        Op::Exp => {
          // NOTE: this can be done symbolically using unrolling like this:
          //       https://hackage.haskell.org/package/sbv-9.0/docs/src/Data.SBV.Core.Model.html#.%5E
          //       However, it requires symbolic gas, since the gas depends on the exponent
          if let [base, exponent, xs @ ..] = &self.state.stack.clone()[..] {
            //burn_exp(exponent, || {
            next(self, op);
            self.state.stack = xs.to_vec();
            self.state.stack.push(Box::new(Expr::Exp(base.clone(), exponent.clone())));
            //});
          } else {
            underrun();
          }
        }
        Op::Signextend => {
          // stackOp2(g_low, Expr::Sex);
        }
        Op::Create => {
          not_static(self, || {});
          if let [x_value, x_offset, x_size, xs @ ..] = &self.state.stack.clone()[..] {
            access_memory_range(self, *x_offset.clone(), *x_size.clone(), || {});
            let available_gas = 0; // Example available gas
            let (cost, gas) = (0, Gas::Symbolic); //cost_of_create(0, available_gas, x_size, false); // Example fees
            let new_addr = create_address(self, self_contract.clone(), this_contract.nonce); // Example self and nonce
            let _ = access_account_for_gas(self, new_addr.clone());
            let init_code = read_memory(self, *x_offset.clone(), *x_size.clone());
            burn(self, cost, || {});
            create(
              self,
              op,
              self_contract,
              this_contract.clone(),
              *x_size.clone(),
              gas,
              *x_value.clone(),
              vec![],
              new_addr,
              init_code,
            );
          } else {
            underrun();
          }
        }
        Op::Call => {
          if let [x_gas, x_to, x_value, x_in_offset, x_in_size, x_out_offset, x_out_size, xs @ ..] =
            &self.state.stack.clone()[..]
          {
            let mut gt0 = BranchReachability::NONE;
            let else_vm_ = branch(self, &gt(*x_value.clone(), Expr::Lit(W256(0, 0))), |gt0_| Ok(gt0 = gt0_));
            if gt0 == BranchReachability::ONLYTHEN || gt0 == BranchReachability::BOTH {
              not_static(self, || {});
            }
            if gt0 == BranchReachability::ONLYELSE || gt0 == BranchReachability::BOTH {
              let mut else_vm = else_vm_.unwrap();
              force_addr(x_to, "unable to determine a call target", |x_to| match Some(x_gas) {
                None => vm_error("IllegalOverflow"),
                _ => {
                  let mut callee: Expr = Expr::Mempty;
                  delegate_call(
                    &mut else_vm,
                    op,
                    this_contract.clone(),
                    Gas::Concerete(0),
                    x_to.clone(),
                    x_to.clone(),
                    *x_value.clone(),
                    *x_in_offset.clone(),
                    *x_in_size.clone(),
                    *x_out_offset.clone(),
                    *x_out_size.clone(),
                    xs.to_vec(),
                    |callee_| callee = callee_,
                  );
                  let from_ = else_vm.config.override_caller.clone();
                  else_vm.state.callvalue = *x_value.clone();
                  else_vm.state.caller = from_.clone().unwrap();
                  else_vm.state.contract = callee.clone();
                  let reset_caller = else_vm.config.reset_caller;
                  if reset_caller {
                    else_vm.config.override_caller = None;
                  }
                  touch_account(&mut else_vm, &from_.clone().unwrap());
                  touch_account(&mut else_vm, &callee);
                  let _ = transfer(&mut else_vm, from_.unwrap(), callee, *x_value.clone());
                }
              });
              vm_queue.push(else_vm);
            }
          } else {
            underrun();
          }
        }
        Op::Callcode => {
          if let [x_gas, x_to, x_value, x_in_offset, x_in_size, x_out_offset, x_out_size, xs @ ..] =
            &self.state.stack.clone()[..]
          {
            force_addr(x_to, "unable to determine a call target", |x_to_| {});
            // gasTryFrom(x_gas)
            delegate_call(
              self,
              op,
              this_contract.clone(),
              Gas::Concerete(0),
              *x_to.clone(),
              self_contract.clone(),
              *x_value.clone(),
              *x_in_offset.clone(),
              *x_in_size.clone(),
              *x_out_offset.clone(),
              *x_out_size.clone(),
              xs.to_vec(),
              |_| {},
            );
            self.state.callvalue = *x_value.clone();
            self.state.caller = self.config.override_caller.clone().unwrap();
            if self.config.reset_caller {
              self.config.override_caller = None;
            }
            touch_account(self, &self_contract)
          } else {
            underrun();
          }
        }
        Op::Return => {
          if let [x_offset, x_size, _] = &self.state.stack.clone()[..] {
            access_memory_range(self, *x_offset.clone(), *x_size.clone(), || {});
            let output = read_memory(self, *x_offset.clone(), *x_size.clone());
            let codesize = maybe_lit_word(buf_length(output.clone())).unwrap().0 as u32;
            let maxsize = self.block.max_code_size.0 as u32;
            let creation = false; // Determine if creation context
            if creation {
              if codesize > maxsize {
                finish_frame(self, FrameResult::FrameErrored(EvmError::MaxCodeSizeExceeded(codesize, maxsize)));
              } else {
                let frame_returned = finish_frame(self, FrameResult::FrameReturned(output.clone()));
                let frame_errored = finish_frame(self, FrameResult::FrameErrored(EvmError::InvalidFormat));
                match read_byte(Expr::Lit(W256(0, 0)), output) {
                  Expr::Lit(W256(0xef, 0)) => frame_errored,
                  _ => frame_returned,
                }
              }
            } else {
              finish_frame(self, FrameResult::FrameReturned(output));
            }
          } else {
            underrun();
          }
        }
        Op::Delegatecall => {
          if let [x_gas, x_to, x_in_offset, x_in_size, x_out_offset, x_out_size, xs @ ..] =
            &self.state.stack.clone()[..]
          {
            match 0 {
              // wordToAddr(x_to)
              0 => {
                let loc = codeloc(self);
                let msg = "Unable to determine a call target";
                self.result = Some(VMResult::Unfinished(PartialExec::UnexpectedSymbolicArg {
                  pc: loc.1 as usize,
                  msg: msg.to_string(),
                  args: vec![],
                }));
              }
              _ => {
                match 0 {
                  // gasTryFrom(x_gas)
                  0 => vm_error("IllegalOverflow"),
                  _ => {
                    delegate_call(
                      self,
                      op,
                      this_contract.clone(),
                      Gas::Concerete(0),
                      *x_to.clone(),
                      self_contract.clone(),
                      Expr::Lit(W256(0, 0)),
                      *x_in_offset.clone(),
                      *x_in_size.clone(),
                      *x_out_offset.clone(),
                      *x_out_size.clone(),
                      vec![],
                      |_| {},
                    );
                    touch_account(self, &self_contract);
                  }
                }
              }
            }
          } else {
            underrun();
          }
        }
        Op::Create2 => {
          not_static(self, || {});
          if let [x_value, x_offset, x_size, x_salt, _xs @ ..] = &self.state.stack.clone()[..] {
            let mut x_salt_val = W256(0, 0);
            force_concrete(self, x_salt, "CREATE2", |x_salt_val_| x_salt_val = x_salt_val_);
            access_memory_range(self, *x_offset.clone(), *x_size.clone(), || {});
            //let available_gas = 0; // use(state.gas)
            let buf = read_memory(self, *x_offset.clone(), *x_size.clone());
            let mut init_code: Vec<u8> = vec![];
            force_concrete_buf(self, &buf, "CREATE2", |init_code_| init_code = init_code_);
            let (cost, gas) = (0, Gas::Symbolic); // cost_of_create(0, available_gas, x_size, true);
            let new_addr = create2_address(self, self_contract.clone(), x_salt_val, &init_code.clone());
            let _ = access_account_for_gas(self, new_addr.clone());
            burn(self, cost, || {});
            create(
              self,
              op,
              self_contract.clone(),
              this_contract.clone(),
              *x_size.clone(),
              gas,
              *x_value.clone(),
              vec![],
              new_addr,
              Expr::ConcreteBuf(init_code.clone()),
            );
          } else {
            underrun();
          }
        }
        Op::Staticcall => {
          if let [x_gas, x_to, x_in_offset, x_in_size, x_out_offset, x_out_size, xs @ ..] = &self.state.stack[..] {
            match word_to_addr(*x_to.clone()) {
              // wordToAddr(x_to)
              None => {
                let loc = codeloc(self);
                let msg = "Unable to determine a call target";
                self.result = Some(VMResult::Unfinished(PartialExec::UnexpectedSymbolicArg {
                  pc: loc.1 as usize,
                  msg: msg.to_string(),
                  args: vec![],
                }));
              }
              _ => {
                match Some(x_gas) {
                  // gasTryFrom(x_gas)
                  None => vm_error("IllegalOverflow"),
                  _ => {
                    let mut callee = Expr::Mempty;
                    delegate_call(
                      self,
                      op,
                      this_contract.clone(),
                      Gas::Concerete(0),
                      *x_to.clone(),
                      *x_to.clone(),
                      Expr::Lit(W256(0, 0)),
                      *x_in_offset.clone(),
                      *x_in_size.clone(),
                      *x_out_offset.clone(),
                      *x_out_size.clone(),
                      xs.to_vec(),
                      |callee_| callee = callee_,
                    );
                    // zoom(state, || {
                    //     assign(callvalue, Expr::Lit(W256(0, 0)));
                    //     assign(caller, fromMaybe(self, vm.config.overrideCaller));
                    //     assign(contract, callee);
                    //     assign(static, true);
                    // });
                    // let reset_caller = use(config.resetCaller);
                    // if reset_caller { assign(config.overrideCaller, None); }
                    touch_account(self, &self_contract);
                    touch_account(self, &callee);
                  }
                }
              }
            }
          } else {
            underrun();
          }
        }
        Op::Selfdestruct => {
          not_static(self, || {});
          if let [x_to, ..] = &self.state.stack.clone()[..] {
            force_addr(x_to, "SELFDESTRUCT", |x_to| {
              if let Expr::WAddr(_) = x_to {
                let acc = access_account_for_gas(self, x_to.clone());
                let cost = if acc { 0 } else { 0 }; // g_cold_account_access
                let funds = this_contract.balance.clone(); // this.balance
                let recipient_exists = false; // accountExists(x_to, vm)
                let mut has_funds = BranchReachability::NONE;
                let else_vm_ = branch(self, &eq(funds, Expr::Lit(W256(0, 0))), |has_funds_| Ok(has_funds = has_funds_));
                let c_new = if !recipient_exists
                  && (has_funds == BranchReachability::ONLYTHEN || has_funds == BranchReachability::BOTH)
                {
                  0 // g_selfdestruct_newaccount
                } else {
                  0
                };
                burn(self, 0 + c_new + cost, || {});
                self.tx.substate.selfdestructs.push(self_contract);
                touch_account(self, &x_to);
                if has_funds == BranchReachability::ONLYTHEN || has_funds == BranchReachability::BOTH {
                  // fetchAccount(x_to, |_| {
                  //     env.contracts[x_to].balance += funds;
                  //     env.contracts[self].balance = Expr::Lit(W256(0, 0));
                  //     doStop();
                  // });
                } else {
                  let mut else_vm = else_vm_.unwrap();
                  finish_frame(&mut else_vm, FrameResult::FrameReturned(Expr::Mempty))
                }
              } else {
                let pc = 0; // use(state.pc)
                self.result = Some(VMResult::Unfinished(PartialExec::UnexpectedSymbolicArg {
                  pc: pc,
                  msg: "trying to self destruct to a symbolic address".to_string(),
                  args: vec![],
                }));
              }
            });
          } else {
            underrun();
          }
        }
        Op::Revert => {
          if let [x_offset, x_size, ..] = &self.state.stack.clone()[..] {
            access_memory_range(self, *x_offset.clone(), *x_size.clone(), || {});
            let output = read_memory(self, *x_offset.clone(), *x_size.clone());
            finish_frame(self, FrameResult::FrameReverted(output));
          } else {
            underrun();
          }
        }
        Op::Extcodecopy => {
          if let [ext_account, mem_offset, code_offset, code_size, xs @ ..] = &self.state.stack.clone()[..] {
            force_addr(ext_account, "EXTCODECOPY", |ext_account| {
              burn_extcodecopy(self, ext_account.clone(), *code_size.clone(), self.block.schedule.clone(), || {});
              access_memory_range(self, *mem_offset.clone(), *code_size.clone(), || {});
              let mut account = empty_contract();
              fetch_account(self, &ext_account, |account_| account = account_.clone());
              next(self, op);
              self.state.stack = xs.to_vec();
              if let Some(bytecode) = &account.bytecode() {
                copy_bytes_to_memory(
                  bytecode.clone(),
                  *code_size.clone(),
                  *code_offset.clone(),
                  *mem_offset.clone(),
                  self,
                )
              } else {
                self.result = Some(VMResult::Unfinished(PartialExec::UnexpectedSymbolicArg {
                  pc: self.state.pc,
                  msg: "Cannot copy from unknown code".to_string(),
                  args: vec![ext_account.clone()],
                }))
              }
            });
          } else {
            underrun();
          }
        }
        Op::Returndatasize => {
          limit_stack(1, self.state.stack.len(), || {
            burn(self, fees.g_base, || {});
            next(self, op);
            push_sym(self, Box::new(buf_length(self.state.returndata.clone())));
          });
        }
        Op::Returndatacopy => {
          if let [x_to, x_from, x_size, xs @ ..] = &self.state.stack.clone()[..] {
            burn(self, 0, || {});
            access_memory_range(self, *x_to.clone(), *x_size.clone(), || {});
            next(self, op);
            self.state.stack = xs.to_vec();
            let sr = self.state.returndata.clone();

            let mut jump = |out_of_bounds: bool| {
              if out_of_bounds {
                vm_error("ReturnDataOutOfBounds");
              } else {
                copy_bytes_to_memory(
                  self.state.returndata.clone(),
                  *x_size.clone(),
                  *x_from.clone(),
                  *x_to.clone(),
                  self,
                );
              }
            };

            match (*x_from.clone(), buf_length(sr.clone()), *x_size.clone()) {
              (Expr::Lit(f), Expr::Lit(l), Expr::Lit(sz)) => {
                jump(l < f.clone() + sz.clone() || f.clone() + sz < f);
              }
              _ => {
                let oob = Expr::LT(
                  Box::new(buf_length(sr)),
                  Box::new(Expr::Add(Box::new(*x_from.clone()), Box::new(*x_size.clone()))),
                );
                let overflow = Expr::LT(
                  Box::new(Expr::Add(Box::new(*x_from.clone()), Box::new(*x_size.clone()))),
                  Box::new(*x_from.clone()),
                );
                //branch(self, &or(oob, overflow), jump);
              }
            }
          } else {
            underrun();
          }
        }
        Op::Extcodehash => {
          if let Some((x, xs)) = self.state.stack.clone().split_last() {
            force_addr(x, "EXTCODEHASH", |addr| {
              access_and_burn(&addr, || {
                next(self, op);
                self.state.stack = xs.to_vec();
                let mut account = empty_contract();
                fetch_account(self, &addr, |account_| account = account_.clone());
                if account_empty(&account) {
                  push(self, W256(0, 0));
                } else {
                  match &account.bytecode() {
                    Some(bytecode) => push_sym(self, Box::new(keccak(bytecode.clone()).unwrap())),
                    None => push_sym(self, Box::new(Expr::Var(format!("CodeHash({})", addr)))),
                  }
                }
              });
            });
          } else {
            underrun();
          }
        }
        Op::Blockhash => {
          if let [i, ..] = &self.state.stack.clone()[..] {
            match *i.clone() {
              Expr::Lit(block_number) => {
                let current_block_number = self.block.number.clone();
                if block_number.clone() + W256(256, 0) < current_block_number || block_number >= current_block_number {
                  push(self, W256(0, 0));
                } else {
                  let block_number_str = block_number.to_string();
                  push(self, keccak_prime(&block_number_str.as_bytes().to_vec()));
                }
              }
              _ => push_sym(self, Box::new(Expr::BlockHash(i.clone()))),
            }
          } else {
            underrun();
          }
        }
        Op::Jumpdest => {
          next(self, op);
          /*
          OpJumpdest -> burn g_jumpdest next
           */
        }
        _ => todo!(),
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
            src_tmp.resize(size_val.0 as usize, 0);
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

fn fetch_account<F: FnOnce(&Contract)>(vm: &mut VM, addr: &Expr, f: F) {
  // Implement account fetching logic
  match vm.env.contracts.get(&addr.clone()) {
    Some(c) => f(c),
    None => match addr.clone() {
      Expr::SymAddr(_) => {
        vm.result = Some(VMResult::Unfinished(PartialExec::UnexpectedSymbolicArg {
          pc: vm.state.pc,
          msg: "trying to access a symbolic address that isn't already present in storage".to_string(),
          args: vec![addr.clone()],
        }))
      }
      Expr::LitAddr(a) => match vm.cache.fetched.get(&a) {
        Some(c) => {
          *vm.env.contracts.entry(addr.clone()).or_insert(empty_contract()) = c.clone();
          f(c)
        }
        None => {
          let base = vm.config.base_state.clone();
          vm.result = Some(VMResult::HandleEffect);
        }
      },
      Expr::GVar(_) => panic!("unexpected GVar"),
      _ => panic!("unexpected expr"),
    },
  }
}

fn touch_account(vm: &mut VM, addr: &Expr) {
  // Implement account touching logic
  vm.tx.substate.touched_accounts.push(addr.clone());
}

fn vm_error(error: &str) {
  panic!("{}", error.to_string())
}

// FrameResult definition
#[derive(Debug, Clone)]
enum FrameResult {
  FrameReturned(Expr),
  FrameReverted(Expr),
  FrameErrored(EvmError),
}

// This function defines how to pop the current stack frame in either of the ways specified by 'FrameResult'.
// It also handles the case when the current stack frame is the only one;
// in this case, we set the final '_result' of the VM execution.
fn finish_frame(vm: &mut VM, result: FrameResult) {
  match vm.frames.clone().as_slice() {
    // Is the current frame the only one?
    [] => {
      match result.clone() {
        FrameResult::FrameReturned(output) => vm.result = Some(VMResult::VMSuccess(output)),
        FrameResult::FrameReverted(buffer) => vm.result = Some(VMResult::VMFailure(EvmError::Revert(Box::new(buffer)))),
        FrameResult::FrameErrored(e) => vm.result = Some(VMResult::VMFailure(e)),
      }
      //vm.finalize();
    }
    // Are there some remaining frames?
    [next_frame, remaining_frames @ ..] => {
      // Insert a debug trace.
      vm.traces.push(match result.clone() {
        FrameResult::FrameErrored(e) => with_trace_location(vm, TraceData::ErrorTrace(e)),
        FrameResult::FrameReverted(e) => with_trace_location(vm, TraceData::ErrorTrace(EvmError::Revert(Box::new(e)))),
        FrameResult::FrameReturned(output) => {
          with_trace_location(vm, TraceData::ReturnTrace(output, next_frame.context.clone()))
        }
      });
      // Pop to the previous level of the debug trace stack.
      vm.traces.pop();

      // Pop the top frame.
      vm.frames = remaining_frames.to_vec();
      // Install the state of the frame to which we shall return.
      vm.state = next_frame.state.clone();

      // Now dispatch on whether we were creating or calling,
      // and whether we shall return, revert, or internalError (six cases).
      match &next_frame.context {
        // Were we calling?
        FrameContext::CallContext {
          target,
          context,
          offset,
          size,
          codehash,
          abi,
          calldata,
          callreversion,
          substate,
        } => {
          let touched_accounts = vm.tx.substate.touched_accounts.clone();
          let substate_modified = substate.clone(); //touch_address(3);

          match result.clone() {
            // Case 1: Returning from a call?
            FrameResult::FrameReturned(output) => {
              vm.state.returndata = output.clone();
              copy_call_bytes_to_memory(vm, output, size.clone(), offset.clone());
              push(vm, W256(1, 0));
            }
            // Case 2: Reverting during a call?
            FrameResult::FrameReverted(output) => {
              vm.env.contracts = callreversion.clone();
              vm.tx.substate = substate.clone();
              vm.state.returndata = output.clone();
              copy_call_bytes_to_memory(vm, output.clone(), size.clone(), offset.clone());
              push(vm, W256(0, 0));
            }
            // Case 3: Error during a call?
            FrameResult::FrameErrored(_) => {
              vm.env.contracts = callreversion.clone();
              vm.tx.substate = substate.clone();
              vm.state.returndata = Expr::Mempty;
              push(vm, W256(0, 0));
            }
          }
        }
        // Or were we creating?
        // (_, _, reversion, substate)
        FrameContext::CreationContext { address, codehash, createversion, substate } => {
          let creator = vm.state.contract.clone();
          let createe = vm.state.contract.clone(); // oldvm.state.contract
          let reversion_prime = createversion.clone(); //createversion.clone();

          /*
          for (k, v) in reversion_prime.iter() {
            let mut v_new = v.clone();
            v_new.nonce = if let Some(n) = v_new.nonce { Some(n + 1) } else { None };
            reversion_prime.insert(k.clone(), v_new);
          }*/

          match result.clone() {
            // Case 4: Returning during a creation?
            FrameResult::FrameReturned(output) => {
              let mut on_contract_code = |contract_code| {
                //vm.replace_code(&createe, contract_code);
                vm.state.returndata = Expr::Mempty;
                push_addr(vm, createe.clone());
              };
              match output {
                Expr::ConcreteBuf(bs) => {
                  on_contract_code(ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(bs)))
                }
                _ => match to_list(output.clone()) {
                  None => {
                    vm.result = Some(VMResult::Unfinished(PartialExec::UnexpectedSymbolicArg {
                      pc: vm.state.pc.clone(),
                      msg: "runtime code cannot have an abstract length".to_string(),
                      args: vec![output],
                    }))
                  }
                  Some(new_code) => {
                    on_contract_code(ContractCode::RuntimeCode(RuntimeCodeStruct::SymbolicRuntimeCode(new_code)))
                  }
                },
              }
            }
            // Case 5: Reverting during a creation?
            FrameResult::FrameReverted(output) => {
              vm.env.contracts = reversion_prime;
              vm.tx.substate = substate.clone();
              vm.state.returndata = output.clone();
              push(vm, W256(0, 0));
            }
            // Case 6: Error during a creation?
            FrameResult::FrameErrored(_) => {
              vm.env.contracts = reversion_prime;
              vm.tx.substate = substate.clone();
              vm.state.returndata = Expr::Mempty;
              push(vm, W256(0, 0));
            }
          }
        }
      }
    }
  }
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
      let acc_cost = if acc { schedule.g_warm_storage_read } else { schedule.g_cold_account_access };
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

fn access_storage_for_gas(vm: &mut VM, addr: Expr, key: Expr) -> bool {
  let accessd_str_keys = &vm.tx.substate.accessed_storage_keys;
  match maybe_lit_word(key) {
    Some(litword) => {
      let accessed = accessd_str_keys.contains(&(addr.clone(), litword.clone()));
      vm.tx.substate.accessed_storage_keys.insert((addr, litword));
      accessed
    }
    _ => false,
  }
}

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
  // Implement conversion from Expr to u64
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

fn read_memory(vm: &mut VM, offset_: Expr, size_: Expr) -> Expr {
  match &vm.state.memory {
    Memory::ConcreteMemory(mem) => match (offset_.clone(), size_.clone()) {
      (Expr::Lit(offset_val), Expr::Lit(size_val)) => {
        if size_val.clone() > MAX_BYTES
          || offset_val.clone() + size_val.clone() > MAX_BYTES
          || offset_val >= W256(mem.len() as u128, 0)
        {
          Expr::ConcreteBuf(vec![0; size_val.0 as usize])
        } else {
          let mem_size: usize = mem.len();
          let (from_mem_size, past_end) = if offset_val.clone() + size_val.clone() > W256(mem_size as u128, 0) {
            (
              W256(mem_size as u128, 0) - offset_val.clone(),
              offset_val.clone() + size_val.clone() - W256(mem_size as u128, 0),
            )
          } else {
            (size_val, W256(0, 0))
          };

          let mut data_from_mem: Vec<u8> =
            mem.clone()[(offset_val.0 as usize)..(offset_val.0 as usize) + (from_mem_size.0 as usize)].to_vec();
          let pad = vec![0; past_end.0 as usize];
          data_from_mem.extend(pad);
          Expr::ConcreteBuf(data_from_mem)
        }
      }
      _ => {
        let buf = freeze_memory(mem);
        copy_slice(offset_, Expr::Lit(W256(0, 0)), size_, buf, Expr::Mempty)
      }
    },
    Memory::SymbolicMemory(mem) => copy_slice(offset_, Expr::Lit(W256(0, 0)), size_, mem.clone(), Expr::Mempty),
  }
}

fn burn_log(size: &Expr, n: u8, f: impl FnOnce()) {
  // Implement log burning logic
}

fn trace_top_log(logs: Vec<Expr>) {
  // Implement log tracing logic
}

fn stack_op2(vm: &mut VM, gas: u64, op: &str) {
  if let Some((a, b)) = vm.state.stack.split_last().and_then(|(a, rest)| rest.split_last().map(|(b, rest)| (a, b))) {
    let res = match op {
      "add" => Box::new(Expr::Add(a.clone(), b.clone())),
      "mul" => Box::new(Expr::Mul(a.clone(), b.clone())),
      "sub" => Box::new(Expr::Sub(a.clone(), b.clone())),
      "div" => Box::new(Expr::Div(a.clone(), b.clone())),
      "sdiv" => Box::new(Expr::SDiv(a.clone(), b.clone())),
      "nmod" => Box::new(Expr::Mod(a.clone(), b.clone())),
      "smod" => Box::new(Expr::SMod(a.clone(), b.clone())),
      "lt" => Box::new(Expr::LT(a.clone(), b.clone())),
      "gt" => Box::new(Expr::GT(a.clone(), b.clone())),
      "slt" => Box::new(Expr::SLT(a.clone(), b.clone())),
      "sgt" => Box::new(Expr::SGT(a.clone(), b.clone())),
      "eq" => Box::new(Expr::Eq(a.clone(), b.clone())),
      "and" => Box::new(Expr::And(a.clone(), b.clone())),
      "or" => Box::new(Expr::Or(a.clone(), b.clone())),
      "xor" => Box::new(Expr::Xor(a.clone(), b.clone())),
      //"byte" => Box::new(Expr::Byte(a.clone(), b.clone())),
      "shl" => Box::new(Expr::SHL(a.clone(), b.clone())),
      "shr" => Box::new(Expr::SHR(a.clone(), b.clone())),
      "sar" => Box::new(Expr::SAR(a.clone(), b.clone())),
      _ => Box::new(Expr::Mempty),
    };
    next(vm, 1);
    burn(vm, gas, || {});
    vm.state.stack = std::iter::once(res).chain(vm.state.stack.iter().skip(2).cloned()).collect();
  } else {
    underrun();
  }
}

fn stack_op3(vm: &mut VM, gas: u64, op: &str) {
  if let Some((a, rest)) = vm.state.stack.split_last() {
    if let Some((b, rest)) = rest.split_last() {
      if let Some((c, rest)) = rest.split_last() {
        // burn(gas)
        let res = match op {
          "addmod" => Box::new(Expr::AddMod(a.clone(), b.clone(), c.clone())),
          "mulmod" => Box::new(Expr::MulMod(a.clone(), b.clone(), c.clone())),
          _ => Box::new(Expr::Mempty),
        };
        next(vm, 1);
        burn(vm, gas, || {});
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
    burn(vm, gas, || {});
    vm.state.stack[0] = res;
  } else {
    underrun();
  }
}

/*
forceAddr :: VMOps t => Expr EWord -> String -> (Expr EAddr -> EVM t s ()) -> EVM t s ()
forceAddr n msg continue = case wordToAddr n of
  Nothing -> do
    vm <- get
    partial $ UnexpectedSymbolicArg vm.state.pc msg (wrap [n])
  Just c -> continue c
*/

fn force_addr<F: FnOnce(Expr)>(n: &Expr, msg: &str, f: F) {
  // Implement address forcing logic
  todo!()
}

fn force_concrete<F: FnOnce(W256)>(vm: &mut VM, n: &Expr, msg: &str, f: F) -> bool {
  // Implement address forcing logic
  match maybe_lit_word(n.clone()) {
    Some(c) => {
      f(c);
      true
    }
    None => {
      vm.result = Some(VMResult::Unfinished(PartialExec::UnexpectedSymbolicArg {
        pc: vm.state.pc,
        msg: msg.to_string(),
        args: vec![n.clone()],
      }));
      false
    }
  }
}

fn force_concrete_buf<F: FnOnce(ByteString)>(vm: &mut VM, b: &Expr, msg: &str, f: F) {
  // Implement address forcing logic
  match b {
    Expr::ConcreteBuf(b_) => f(b_.to_vec()),
    _ => {
      vm.result = Some(VMResult::Unfinished(PartialExec::UnexpectedSymbolicArg {
        pc: vm.state.pc,
        msg: msg.to_string(),
        args: vec![b.clone()],
      }))
    }
  }
}

fn access_and_burn(addr: &Expr, f: impl FnOnce()) {
  // Implement access and burn logic
}

fn underrun() {
  panic!("stack underrun")
}

fn push_addr(vm: &mut VM, addr: Expr) {
  vm.state.stack.push(Box::new(addr.clone()));
}

fn internal_error(msg: &str) {
  panic!("{}", msg)
}

fn concatenate_bufs(a: &Expr, b: &Expr) -> Expr {
  match (a, b) {
    (Expr::ConcreteBuf(a_buf), Expr::ConcreteBuf(b_buf)) => {
      let mut result = a_buf.clone();
      result.extend(b_buf.clone());
      Expr::ConcreteBuf(result)
    }
    _ => a.clone(),
  }
}

fn to_buf(code: &ContractCode) -> Option<Expr> {
  match code {
    ContractCode::InitCode(ops, args) => Some(concatenate_bufs(&Expr::ConcreteBuf(ops.to_vec()), &args.clone())),
    ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(ops)) => Some(Expr::ConcreteBuf(ops.to_vec())),
    ContractCode::RuntimeCode(RuntimeCodeStruct::SymbolicRuntimeCode(ops)) => todo!(),
    _ => None,
  }
}

// Define other necessary structs, enums, and functions here...

fn word32(xs: &[u8]) -> u32 {
  xs.iter().enumerate().fold(0, |acc, (n, &x)| acc | (u32::from(x) << (8 * n)))
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct FunctionSelector(u32); // Define FunctionSelector appropriately

pub fn abi_keccak(input: &[u8]) -> FunctionSelector {
  let hash_result = keccak_bytes(&input.to_vec());
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

pub fn access_storage<F>(vm: &mut VM, addr: Expr, slot: Expr, continue_fn: F)
where
  F: FnOnce(Expr),
{
  let slot_conc = conc_keccak_simp_expr(slot.clone());

  match vm.env.contracts.get(&addr) {
    Some(c) => match read_storage(&slot, &c.storage) {
      Some(x) => match read_storage(&slot_conc, &c.storage) {
        Some(_) => continue_fn(x),
        None => rpc_call(vm, addr, slot.clone(), c.clone(), slot_conc, continue_fn),
      },
      None => rpc_call(vm, addr, slot.clone(), c.clone(), slot_conc, continue_fn),
    },
    None => {
      fetch_account(vm, &addr.clone(), |_| {});
      access_storage(vm, addr, slot, continue_fn)
    }
  }
}

fn rpc_call<F>(vm: &mut VM, addr: Expr, slot: Expr, c: Contract, slot_conc: Expr, continue_fn: F)
where
  F: FnOnce(Expr),
{
  if c.external {
    if let Some(addr_) = maybe_lit_addr(addr.clone()) {
      if force_concrete(vm, &slot_conc.clone(), "cannot read symbolic slots via RPC", |_| {}) {
        match vm.cache.fetched.clone().get(&addr_) {
          Some(fetched) => match read_storage(&slot, &fetched.storage) {
            Some(val) => continue_fn(val),
            None => mk_query(vm, addr, maybe_lit_word(slot_conc.clone()).unwrap().0 as u64, continue_fn),
          },
          None => internal_error("contract marked external not found in cache"),
        }
      }
    } else {
      vm.result = Some(VMResult::Unfinished(PartialExec::UnexpectedSymbolicArg {
        pc: vm.state.pc,
        msg: "cannot read storage from symbolic addresses via rpc".to_string(),
        args: vec![addr.clone()],
      }));
    }
  } else {
    vm.env.contracts.entry(addr).or_insert(empty_contract()).storage =
      write_storage(slot, Expr::Lit(W256(0, 0)), vm.env.contracts.get(&addr).unwrap().storage.clone());
    continue_fn(Expr::Lit(W256(0, 0)))
  }
}

/*
query :: Query t s -> EVM t s ()
query = assign #result . Just . HandleEffect . Query
*/

fn query(q: Query) {}

fn mk_query<F>(vm: &mut VM, addr: Expr, slot: u64, continue_fn: F)
where
  F: FnOnce(Expr),
{
  let a = if let Expr::LitAddr(a_) = addr { a_ } else { panic!("unuexpected expr") };
  /*
  let q = Query::PleaseFetchSlot(
    a,
    W256(slot as u128, 0),
    Box::new(|x| {
      vm.cache.fetched.entry(a).or_insert(empty_contract()).storage =
        write_storage(Expr::Lit(W256(slot as u128, 0)), Expr::Lit(x), vm.cache.fetched.get(&a).unwrap().storage);
      // modify_storage(addr.clone(), slot, Expr::Lit(x))?;
      vm.env.contracts.entry(addr).or_insert(empty_contract()).storage =
        write_storage(Expr::Lit(W256(slot as u128, 0)), Expr::Lit(x), vm.env.contracts.get(&addr).unwrap().storage);
      vm.result = None;
      continue_fn(Expr::Lit(x))
    }),
  );
  */
}

fn is_precompile_addr(addr: &Expr) -> bool {
  // Dummy implementation
  false
}

// Implement the delegateCall function in Rust
fn delegate_call(
  vm: &mut VM,
  op: u8,
  this: Contract,
  gas_given: Gas,
  x_to: Expr,
  x_context: Expr,
  x_value: Expr,
  x_in_offset: Expr,
  x_in_size: Expr,
  x_out_offset: Expr,
  x_out_size: Expr,
  xs: Vec<Box<Expr>>,
  continue_fn: impl FnOnce(Expr),
) {
  if is_precompile_addr(&x_to) {
    force_concrete_addr2(
      vm,
      (x_to, x_context),
      "Cannot call precompile with symbolic addresses".to_string(),
      |(x_to, x_context)| {
        /*
        precompiled_contract(
          vm,
          &this,
          gas_given,
          x_to,
          x_context,
          x_value,
          x_in_offset,
          x_in_size,
          x_out_offset,
          x_out_size,
          xs,
        );
        */
      },
    );
  } else if x_to == cheat_code() {
    vm.state.stack = xs;
    todo!()
    // cheat(vm, x_in_offset, x_in_size, x_out_offset, x_out_size);
  } else {
    let mut x_gas = Gas::Concerete(0);
    call_checks(
      vm,
      op,
      &this,
      gas_given,
      x_context.clone(),
      x_to.clone(),
      x_value.clone(),
      x_in_offset.clone(),
      x_in_size.clone(),
      x_out_offset.clone(),
      x_out_size.clone(),
      &xs,
      |x_gas_| x_gas = x_gas_,
    );
    let mut target_code = ContractCode::UnKnownCode(Box::new(Expr::Mempty));
    let mut taregt_codehash = Expr::Mempty;
    fetch_account(vm, &x_to.clone(), |target| {
      target_code = target.code.clone();
      taregt_codehash = target.codehash.clone();
    });
    match target_code {
      ContractCode::UnKnownCode(_) => {
        vm.result = Some(VMResult::Unfinished(PartialExec::UnexpectedSymbolicArg {
          pc: vm.state.pc,
          msg: "call target has unknown code".to_string(),
          args: vec![x_to.clone()],
        }));
      }
      _ => {
        //burn(vm, 0, || {});
        let calldata = read_memory(vm, x_in_offset.clone(), x_in_size);
        let abi =
          maybe_lit_word(read_bytes(4, Expr::Lit(W256(0, 0)), read_memory(vm, x_in_offset, Expr::Lit(W256(4, 0)))));
        let new_context = FrameContext::CallContext {
          target: x_to.clone(),
          context: x_context.clone(),
          offset: x_out_offset,
          size: x_out_size,
          codehash: taregt_codehash,
          callreversion: vm.env.contracts.clone(),
          substate: vm.tx.substate.clone(),
          abi,
          calldata: calldata.clone(),
        };
        vm.traces.push(with_trace_location(vm, TraceData::FrameTrace(new_context.clone())));
        next(vm, op);
        vm.frames.push(Frame { state: vm.state.clone(), context: new_context.clone() });
        let new_memory = Memory::ConcreteMemory(vec![]);
        let cleared_init_code = match target_code {
          ContractCode::InitCode(_, _) => ContractCode::InitCode(vec![], Box::new(Expr::Mempty)),
          a => a.clone(),
        };
        vm.state = FrameState {
          gas: x_gas.clone(),
          pc: 0,
          code: cleared_init_code,
          code_contract: x_to.clone(),
          stack: vec![],
          memory: new_memory,
          memory_size: 0,
          returndata: Expr::Mempty,
          calldata: calldata.clone(),
          contract: vm.state.contract.clone(),
          callvalue: vm.state.callvalue.clone(),
          caller: vm.state.caller.clone(),
          static_flag: vm.state.static_flag.clone(),
        };
        continue_fn(x_to);
      }
    }
  }
}

// Implement the create function in Rust
fn create(
  vm: &mut VM,
  op: u8,
  self_addr: Expr,
  this: Contract,
  x_size: Expr,
  x_gas: Gas,
  x_value: Expr,
  xs: Vec<Expr>,
  new_addr: Expr,
  init_code: Expr,
) {
  let x_size_val = match x_size {
    Expr::Lit(v) => v,
    _ => W256(0, 0),
  };
  if x_size_val > vm.block.max_code_size.clone() * W256(2, 0) {
    vm.state.stack = vec![Box::new(Expr::Lit(W256(0, 0)))];
    vm.state.returndata = Expr::Mempty;
    // vm_error(EvmError::MaxInitCodeSizeExceeded(vm0.block.max_code_size * 2, x_size));
  } else if this.nonce == Some(u64::max_value()) {
    vm.state.stack = vec![Box::new(Expr::Lit(W256(0, 0)))];
    vm.state.returndata = Expr::Mempty;
    vm.traces.push(with_trace_location(vm, TraceData::ErrorTrace(EvmError::NonceOverflow)));
    next(vm, op);
  } else if vm.frames.len() >= 1024 {
    vm.state.stack = vec![Box::new(Expr::Lit(W256(0, 0)))];
    vm.state.returndata = Expr::Mempty;
    vm.traces.push(with_trace_location(vm, TraceData::ErrorTrace(EvmError::CallDepthLimitReached)));
    next(vm, op);
  } else if collision(vm.env.contracts.get(&new_addr).cloned()) {
    let x_gas_val = if let Gas::Concerete(g) = x_gas { g } else { 0 };
    burn(vm, x_gas_val, || {});
    vm.state.stack = vec![Box::new(Expr::Lit(W256(0, 0)))];
    vm.state.returndata = Expr::Mempty;
    let n = vm.env.contracts.entry(self_addr.clone()).or_insert(empty_contract()).nonce;
    let new_nonce = if let Some(n_) = n { Some(n_ + 1) } else { None };
    vm.env.contracts.entry(self_addr).or_insert(empty_contract()).nonce = new_nonce;
    next(vm, op);
  } else {
    let mut condition = BranchReachability::NONE;
    branch(vm, &gt(x_value.clone(), this.balance.clone()), |condition_| Ok(condition = condition_));
    if condition == BranchReachability::ONLYTHEN || condition == BranchReachability::BOTH {
      vm.state.stack = vec![Box::new(Expr::Lit(W256(0, 0)))];
      vm.state.returndata = Expr::Mempty;
      vm.traces.push(with_trace_location(
        vm,
        TraceData::ErrorTrace(EvmError::BalanceTooLow(Box::new(x_value.clone()), Box::new(this.balance.clone()))),
      ));
      next(vm, op);
      touch_account(vm, &self_addr.clone());
      touch_account(vm, &new_addr.clone());
    }
    if condition == BranchReachability::ONLYELSE || condition == BranchReachability::BOTH {
      {
        burn(vm, 0, || {});
        match parse_init_code(init_code.clone()) {
          None => {
            vm.result = Some(VMResult::Unfinished(PartialExec::UnexpectedSymbolicArg {
              pc: vm.state.pc,
              msg: "initcode must have a concrete prefix".to_string(),
              args: vec![],
            }));
          }
          Some(c) => {
            let new_contract = initial_contract(c.clone());
            let new_context = FrameContext::CreationContext {
              address: new_addr.clone(),
              codehash: new_contract.codehash.clone(),
              createversion: vm.env.contracts.clone(),
              substate: vm.tx.substate.clone(),
            };

            let old_acc = vm.env.contracts.get(&new_addr).cloned();
            let old_bal = old_acc.map_or(Expr::Lit(W256(0, 0)), |acc| acc.balance.clone());
            vm.env.contracts.insert(new_addr.clone(), Contract { balance: old_bal.clone(), ..new_contract });
            vm.env.contracts.insert(self_addr.clone(), Contract { nonce: this.nonce.map(|n| n + 1), ..this });

            let _ = transfer(vm, self_addr.clone(), new_addr.clone(), x_value.clone());
            vm.traces.push(with_trace_location(vm, TraceData::FrameTrace(new_context.clone())));
            next(vm, op);
            vm.frames.push(Frame { state: vm.state.clone(), context: new_context.clone() });
            let state = blank_state();
            vm.state = FrameState {
              contract: new_addr.clone(),
              code_contract: new_addr.clone(),
              code: c.clone(),
              callvalue: x_value.clone(),
              caller: self_addr.clone(),
              gas: x_gas.clone(),
              ..state
            };
          }
        }
      }
    }
  }
}

fn force_concrete_addr<F>(vm: &mut VM, n: Expr, msg: String, continue_fn: F)
where
  F: FnOnce(Addr),
{
  match maybe_lit_addr(n.clone()) {
    None => {
      vm.result =
        Some(VMResult::Unfinished(PartialExec::UnexpectedSymbolicArg { pc: vm.state.pc, msg, args: vec![n] }));
    }
    Some(c) => continue_fn(c),
  }
}

fn force_concrete_addr2<F>(vm: &mut VM, addrs: (Expr, Expr), msg: String, continue_fn: F)
where
  F: FnOnce((Addr, Addr)),
{
  match (maybe_lit_addr(addrs.0.clone()), maybe_lit_addr(addrs.1.clone())) {
    (Some(c), Some(d)) => continue_fn((c, d)),
    _ => {
      vm.result = Some(VMResult::Unfinished(PartialExec::UnexpectedSymbolicArg {
        pc: vm.state.pc,
        msg,
        args: vec![addrs.0, addrs.1],
      }));
    }
  }
}

fn codeloc(vm: &VM) -> CodeLocation {
  (vm.state.contract.clone(), vm.state.pc as i64)
}

fn check_jump(vm: &mut VM, x: usize, xs: Vec<Box<Expr>>) -> Result<(), EvmError> {
  match &vm.state.code {
    ContractCode::InitCode(ops, buf_) => match *buf_.clone() {
      Expr::ConcreteBuf(b) if b.len() == 0 => {
        if is_valid_jump_dest(vm, x) {
          vm.state.stack = xs;
          vm.state.pc = x;
          return Ok(());
        } else {
          return Err(EvmError::BadJumpDestination);
        }
        // return Ok(());
      }
      _ => {
        if x > ops.len() {
          vm.result = Some(VMResult::Unfinished(PartialExec::JumpIntoSymbolicCode { pc: vm.state.pc, jump_dst: x }));
          return Ok(());
        } else {
          if is_valid_jump_dest(vm, x) {
            vm.state.stack = xs;
            vm.state.pc = x;
            return Ok(());
          } else {
            return Err(EvmError::BadJumpDestination);
          }
        }
      }
    },
    _ => {
      if is_valid_jump_dest(vm, x) {
        vm.state.stack = xs;
        vm.state.pc = x;
        return Ok(());
      } else {
        return Err(EvmError::BadJumpDestination);
      }
    }
  }
}

fn is_valid_jump_dest(vm: &mut VM, x: usize) -> bool {
  let code = &vm.state.code;
  let self_addr = vm.state.code_contract.clone();
  let contract = vm.env.contracts.get(&self_addr).expect("self not found in current contracts");

  let op = match code {
    ContractCode::UnKnownCode(_) => panic!("Cannot analyze jumpdests for unknown code"),
    ContractCode::InitCode(ops, _) => ops.get(x).cloned(),
    ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(ops)) => ops.get(x).cloned(),
    ContractCode::RuntimeCode(RuntimeCodeStruct::SymbolicRuntimeCode(ops)) => {
      ops.get(x).and_then(|byte| maybe_lit_byte(byte.clone()))
    }
  };

  match op {
    Some(0x5b) if contract.code_ops[contract.op_idx_map[x as usize] as usize].1 == Op::Jumpdest => true,
    _ => false,
  }
}

// Handles transfers of value between accounts
fn transfer(vm: &mut VM, src: Expr, dst: Expr, val: Expr) -> Result<(), EvmError> {
  if let Expr::Lit(W256(0, 0)) = val {
    return Ok(());
  }

  let src_balance = vm.env.contracts.get(&src).map(|contract| contract.balance.clone());
  let dst_balance = vm.env.contracts.get(&dst).map(|contract| contract.balance.clone());
  let base_state = vm.config.base_state.clone();

  let mkc = match base_state {
    BaseState::AbstractBase => unknown_contract,
    BaseState::EmptyBase => |addr| empty_contract(),
  };

  match (src_balance, dst_balance.clone()) {
    (Some(src_bal), Some(_)) => {
      branch(vm, &gt(val.clone(), src_bal.clone()), |cond| {
        if cond == BranchReachability::ONLYTHEN || cond == BranchReachability::BOTH {
          Err(EvmError::BalanceTooLow(Box::new(val.clone()), Box::new(src_bal.clone())))
        } else {
          Ok(())
        }
      });
      vm.env.contracts.entry(src).or_insert(empty_contract()).balance = sub(src_bal, val.clone());
      vm.env.contracts.entry(dst).or_insert(empty_contract()).balance = add(dst_balance.unwrap(), val.clone());
      Ok(())
    }
    (None, Some(_)) => match src {
      Expr::LitAddr(_) => {
        vm.env.contracts.insert(src.clone(), mkc(src.clone()));
        transfer(vm, src, dst, val)
      }
      Expr::SymAddr(_) => {
        let pc = vm.state.pc;
        vm.result = Some(VMResult::Unfinished(PartialExec::UnexpectedSymbolicArg {
          pc,
          msg: "Attempting to transfer eth from a symbolic address that is not present in the state".to_string(),
          args: vec![src],
        }));
        Ok(())
      }
      Expr::GVar(_) => panic!("Unexpected GVar"),
      _ => panic!("unexpected error"),
    },
    (_, None) => match dst {
      Expr::LitAddr(_) => {
        vm.env.contracts.insert(dst.clone(), mkc(dst.clone()));
        transfer(vm, src, dst, val)
      }
      Expr::SymAddr(_) => {
        let pc = vm.state.pc;
        vm.result = Some(VMResult::Unfinished(PartialExec::UnexpectedSymbolicArg {
          pc: pc,
          msg: "Attempting to transfer eth to a symbolic address that is not present in the state".to_string(),
          args: vec![dst],
        }));
        Ok(())
      }
      Expr::GVar(_) => panic!("Unexpected GVar"),
      _ => panic!("unexpected error"),
    },
  }
}

fn with_trace_location(vm: &VM, trace_data: TraceData) -> Trace {
  let current_contract = vm.env.contracts.get(&vm.state.code_contract).unwrap();
  let op_ix = current_contract.op_idx_map.get(vm.state.pc).cloned().unwrap_or(0);
  Trace { tracedata: trace_data, contract: current_contract.clone(), op_ix: op_ix }
}

fn account_empty(c: &Contract) -> bool {
  let cc = match &c.code {
    ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(rc)) => rc.len() == 0,
    ContractCode::RuntimeCode(RuntimeCodeStruct::SymbolicRuntimeCode(b)) => false,
    _ => false,
  };
  cc && c.nonce == Some(0) && c.balance == Expr::Lit(W256(1, 0))
}

fn solve_constraints(vm: &VM, pathconds: &Vec<Prop>) -> bool {
  let config = Config::default();
  let smt2 = assert_props(&config, pathconds.to_vec());
  let content = format_smt2(smt2) + "\n\n(check-sat)";

  let dir_path = Path::new("./.rhoevm");
  if !dir_path.exists() {
    let _ = fs::create_dir_all(&dir_path);
  }
  let _ = fs::write(dir_path.join("query.smt2"), content);

  let output = Command::new("z3")
    .args(["-smt2", "query.smt2"]) // Pass the arguments to the command
    .stdout(Stdio::piped()) // Capture standard output
    .stderr(Stdio::piped()) // Capture standard error
    .output()
    .unwrap(); // Run the command and capture the output

  if output.status.success() {
    // Convert the standard output to a String
    let stdout = String::from_utf8(output.stdout);
    return stdout.unwrap() == "sat".to_string();
  }
  false
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BranchReachability {
  ONLYTHEN,
  ONLYELSE,
  BOTH,
  NONE,
}

fn branch<F>(vm: &mut VM, cond: &Expr, continue_fn: F) -> Option<VM>
where
  F: FnOnce(BranchReachability) -> Result<(), EvmError>,
{
  // let loc = codeloc(vm); // (contract, pc)

  let mut new_vm = None;
  let mut branchcond = BranchReachability::NONE;

  let cond_simp = simplify(cond);
  let cond_simp_conc = conc_keccak_simp_expr(cond_simp);
  let then_branch_cond = Prop::PNeg(Box::new(Prop::PEq(cond_simp_conc.clone(), Expr::Lit(W256(0, 0)))));
  let else_branch_cond = Prop::PEq(cond_simp_conc, Expr::Lit(W256(0, 0)));

  let mut pathconds = vm.constraints.clone();
  pathconds.push(then_branch_cond.clone());
  let v = solve_constraints(vm, &pathconds);
  if v {
    vm.constraints.push(then_branch_cond);
  }

  pathconds.pop();
  pathconds.push(else_branch_cond.clone());
  let u = solve_constraints(vm, &pathconds);
  if u {
    let mut new_vm_ = vm.clone();
    new_vm_.constraints.push(else_branch_cond);
    new_vm = Some(new_vm_);
  }

  if v && u {
    branchcond = BranchReachability::BOTH;
  } else if v {
    branchcond = BranchReachability::ONLYTHEN;
  } else if u {
    branchcond = BranchReachability::ONLYELSE;
  }

  let _ = continue_fn(branchcond);

  new_vm
}

/*
fn choose_path(loc: CodeLocation, bc: BranchCondition) {
  match (loc, bc) {
    (loc, BranchCondition::Case(v)) => {}
    (loc, BranchCondition::Unknown) => {}
  }
}*/

fn collision(c_: Option<Contract>) -> bool {
  match c_ {
    Some(c) => {
      c.nonce != Some(0) || {
        match c.code {
          ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(v)) => v.len() != 0,
          ContractCode::RuntimeCode(RuntimeCodeStruct::SymbolicRuntimeCode(b)) => !b.is_empty(),
          _ => true,
        }
      }
    }
    _ => false,
  }
}

fn create_address(vm: &mut VM, e: Expr, n_: Option<W64>) -> Expr {
  match (e, n_) {
    (Expr::LitAddr(a), Some(n)) => create_address_(a, n),
    (Expr::GVar(_), _) => panic!("unexpected GVar"),
    _ => fresh_sym_addr(vm),
  }
}

fn create2_address(vm: &mut VM, e: Expr, s: W256, b: &ByteString) -> Expr {
  match (e, s, b) {
    (Expr::LitAddr(a), s, b) => create2_address_(a, s, b.to_vec()),
    (Expr::SymAddr(_), _, _) => fresh_sym_addr(vm),
    (Expr::GVar(_), _, _) => panic!("unexpected GVar"),
    _ => fresh_sym_addr(vm),
  }
}

fn fresh_sym_addr(vm: &mut VM) -> Expr {
  vm.env.fresh_address += 1;
  let n = vm.env.fresh_address;
  Expr::SymAddr(format!("freshSymAddr {}", n))
}

fn cheat_code() -> Expr {
  Expr::LitAddr(keccak_prime(&"hevm cheat code".as_bytes().to_vec()))
}

fn parse_init_code(buf: Expr) -> Option<ContractCode> {
  match buf {
    Expr::ConcreteBuf(b) => Some(ContractCode::InitCode(b, Box::new(Expr::Mempty))),
    _ => {
      let conc = concrete_prefix(&buf);
      if conc.is_empty() {
        None
      } else {
        let sym = drop(W256(conc.len() as u128, 0), buf);
        Some(ContractCode::InitCode(conc, Box::new(sym)))
      }
    }
  }
}

fn account_exists(addr: Expr, vm: &VM) -> bool {
  match vm.env.contracts.get(&addr) {
    Some(c) => !(account_empty(c)),
    None => false,
  }
}

// Checks a *CALL for failure; OOG, too many callframes, memory access etc.
fn call_checks<F>(
  vm: &mut VM,
  op: u8,
  this: &Contract,
  x_gas: Gas,
  x_context: Expr,
  x_to: Expr,
  x_value: Expr,
  x_in_offset: Expr,
  x_in_size: Expr,
  x_out_offset: Expr,
  x_out_size: Expr,
  xs: &Vec<Box<Expr>>,
  continue_fn: F,
) where
  F: FnOnce(Gas),
{
  let fees = vm.block.schedule.clone();
  access_memory_range(vm, x_in_offset.clone(), x_in_size.clone(), || {});
  access_memory_range(vm, x_out_offset.clone(), x_out_size.clone(), || {});
  let available_gas = vm.state.gas.clone();
  let recipient_exists = account_exists(x_context.clone(), vm);
  let from = vm.config.override_caller.clone().unwrap_or(vm.state.contract.clone());
  let from_maybe = vm.env.contracts.get(&from);
  let from_balance = if let Some(fm) = from_maybe { Some(fm.balance.clone()) } else { None };

  let cost = 0;
  let gas_left = 0;

  match (from_balance.clone(), x_value.clone()) {
    (_, Expr::Lit(W256(0, 0))) => {
      burn(vm, cost - gas_left, || {});
      if vm.frames.len() >= 1024 {
        vm.state.stack = xs.to_vec();
        vm.state.stack.push(Box::new(Expr::Lit(W256(0, 0))));
        vm.state.returndata = Expr::Mempty;
        vm.traces.push(with_trace_location(vm, TraceData::ErrorTrace(EvmError::CallDepthLimitReached)));
        next(vm, op);
      } else {
        continue_fn(Gas::Concerete(gas_left));
      }
    }
    (Some(fb), _) => {
      burn(vm, cost - gas_left, || {});
      let mut is_greater = BranchReachability::NONE;
      let else_vm_ = branch(vm, &gt(x_value.clone(), fb), |is_greater_| Ok(is_greater = is_greater_));
      if is_greater == BranchReachability::ONLYELSE || is_greater == BranchReachability::BOTH {
        vm.state.stack = xs.to_vec();
        vm.state.stack.push(Box::new(Expr::Lit(W256(0, 0))));
        vm.state.returndata = Expr::Mempty;
        vm.traces.push(with_trace_location(
          vm,
          TraceData::ErrorTrace(EvmError::BalanceTooLow(Box::new(x_value), Box::new(this.balance.clone()))),
        ));
        next(vm, op);
      }
      if is_greater == BranchReachability::ONLYELSE || is_greater == BranchReachability::BOTH {
        let mut else_vm = else_vm_.unwrap();
        if else_vm.frames.len() >= 1024 {
          else_vm.state.stack = xs.to_vec();
          else_vm.state.stack.push(Box::new(Expr::Lit(W256(0, 0))));
          else_vm.state.returndata = Expr::Mempty;
          else_vm.traces.push(with_trace_location(&else_vm, TraceData::ErrorTrace(EvmError::CallDepthLimitReached)));
          next(&mut else_vm, op);
        } else {
          continue_fn(Gas::Concerete(gas_left));
        }
      }
    }
    (None, _) => match from.clone() {
      Expr::LitAddr(_) => {
        let contract = match vm.config.base_state {
          BaseState::AbstractBase => unknown_contract(from.clone()),
          BaseState::EmptyBase => empty_contract(),
        };
        vm.env.contracts.insert(from, contract);
        call_checks(
          vm,
          op,
          this,
          x_gas,
          x_context,
          x_to,
          x_value,
          x_in_offset,
          x_in_size,
          x_out_offset,
          x_out_size,
          xs,
          continue_fn,
        );
      }
      Expr::SymAddr(_) => {
        vm.result = Some(VMResult::Unfinished(PartialExec::UnexpectedSymbolicArg {
          pc: vm.state.pc,
          msg: "Attempting to transfer eth from a symbolic address that is not present in the state".to_string(),
          args: vec![from],
        }))
      }
      Expr::GVar(_) => internal_error("Unexpected GVar"),
      _ => panic!("unexpected expr"),
    },
  }
  //cost_of_call(fees, recipient_exists, x_value, available_gas, x_gas, x_to, |cost, gas_left| {});
}

/// Refund a specific amount of gas to the current contract's substate.
fn refund(vm: &mut VM, n: u64) {
  let self_contract = vm.state.contract.clone();
  let refund_entry = (self_contract, n);

  vm.tx.substate.refunds.push(refund_entry);
}

/// Remove a specific refund amount from the current contract's substate.
fn un_refund(vm: &mut VM, n: u64) {
  let self_contract = vm.state.contract.clone();

  vm.tx.substate.refunds.retain(|(contract, amount)| !(*contract == self_contract && *amount == n));
}
