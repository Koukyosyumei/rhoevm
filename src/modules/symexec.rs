use derive_more::From;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;

use crate::modules::abi::Sig;
use crate::modules::abi::{make_abi_value, selector, AbiType, AbiValue};
use crate::modules::evm::{abstract_contract, buf_length, get_code_location, initial_contract};
use crate::modules::expr::{add, geq, in_range, lt, read_byte, write_byte, write_word};
use crate::modules::feeschedule::FEE_SCHEDULE;
use crate::modules::fetch::{BlockNumber, Fetcher, RpcInfo};
use crate::modules::types::{BaseState, ByteString, ContractCode, Expr, Prop, VMOpts, W256};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CalldataFragment {
  St(Vec<Prop>, Expr),
  Dy(Vec<Prop>, Expr, Expr),
  Comp(Vec<CalldataFragment>),
}

pub fn to_bool(e: Expr) -> Prop {
  Prop::POr(Box::new(Prop::PEq(e.clone(), Expr::Lit(W256(1, 0)))), Box::new(Prop::PEq(e, Expr::Lit(W256(0, 0)))))
}

pub fn sym_abi_arg(name: &str, abi_type: AbiType) -> CalldataFragment {
  match abi_type {
    AbiType::AbiUIntType(n) => {
      if n % 8 == 0 && n <= 256 {
        let v = Expr::Var(name.into());
        CalldataFragment::St(vec![in_range(n as u32, Box::new(v.clone()))], v)
      } else {
        panic!("bad type")
      }
    }
    AbiType::AbiIntType(n) => {
      if n % 8 == 0 && n <= 256 {
        let v = Expr::Var(name.into());
        CalldataFragment::St(vec![in_range(n as u32, Box::new(v.clone()))], v)
      } else {
        panic!("bad type")
      }
    }
    AbiType::AbiBoolType => {
      let v = Expr::Var(name.into());
      CalldataFragment::St(vec![to_bool(v.clone())], v)
    }
    AbiType::AbiAddressType => CalldataFragment::St(vec![], Expr::SymAddr(name.into())),
    AbiType::AbiBytesType(n) => {
      if n > 0 && n <= 32 {
        let v = Expr::Var(name.into());
        CalldataFragment::St(vec![in_range((n * 8) as u32, Box::new(v.clone()))], v)
      } else {
        panic!("bad type")
      }
    }
    AbiType::AbiArrayType(sz, tp) => {
      CalldataFragment::Comp((0..sz).map(|n| sym_abi_arg(&format!("{}{}", name, n), *tp.clone())).collect())
    }
    _ => panic!("TODO: symbolic abi encoding for {:?}", abi_type),
  }
}

fn is_st(cf: &CalldataFragment) -> bool {
  match cf {
    CalldataFragment::St(_, _) => true,
    _ => false,
  }
}

// Function to combine calldata fragments
fn combine_fragments(fragments: &[CalldataFragment], base: Expr) -> (Expr, Vec<Prop>) {
  fn go(idx: Expr, fragments: &[CalldataFragment], acc: (Expr, Vec<Prop>)) -> (Expr, Vec<Prop>) {
    if fragments.is_empty() {
      return acc;
    }

    let (buf, ps) = acc;

    let (fragment, rest) = fragments.split_first().unwrap();
    match fragment {
      // Static fragments get written as a word in place
      CalldataFragment::St(p, w) => {
        let new_idx = add(Box::new(idx.clone()), Box::new(Expr::Lit(W256(32, 0)))); // Add 32 to index
        let new_buf = write_word(Box::new(idx), Box::new(w.clone()), Box::new(buf));
        go(new_idx, &rest.to_vec(), (new_buf, [p.clone(), ps].concat()))
      }
      // Compound fragments that contain only static fragments get written in place
      CalldataFragment::Comp(xs) if xs.iter().all(is_st) => {
        let mut new_xs = xs.clone();
        new_xs.extend(rest.to_vec());
        go(idx, &new_xs, (buf, ps))
      }
      // Dynamic fragments are not yet supported
      s => {
        panic!("{}", &format!("unsupported cd fragment: {:?}", s));
      }
    }
  }

  // Initial call to go with starting index and fragments
  go(Expr::Lit(W256(4, 0)), fragments, (base, vec![]))
}

fn write_selector(buf: Expr, sig: &str) -> Expr {
  let selector = selector(&(sig.to_string()));
  (0..4).fold(buf, |buf, idx| {
    write_byte(
      Box::new(buf),
      Box::new(Expr::Lit(W256(idx, 0))),
      Box::new(read_byte(Box::new(Expr::Lit(W256(idx, 0))), Box::new(Expr::ConcreteBuf(selector.clone())))),
    )
  })
}

/*
-- | Generates calldata matching given type signature, optionally specialized
-- with concrete arguments.
-- Any argument given as "<symbolic>" or omitted at the tail of the list are
-- kept symbolic.
*/
pub fn sym_calldata(sig: &str, type_signature: &[AbiType], concrete_args: &[String], base: Expr) -> (Expr, Vec<Prop>) {
  let binding = "<symbolic>".to_string();
  let args = concrete_args.iter().chain(std::iter::repeat(&binding)).take(type_signature.len()).collect::<Vec<_>>();
  let mk_arg = |typ: &AbiType, arg: &String, n: usize| -> CalldataFragment {
    match arg.as_str() {
      "<symbolic>" => sym_abi_arg(&format!("arg{}", n), typ.clone()),
      _ => match make_abi_value(typ, arg) {
        AbiValue::AbiUInt(_, w) => CalldataFragment::St(vec![], Expr::Lit(W256(w as u128, 0))),
        AbiValue::AbiInt(_, w) => CalldataFragment::St(vec![], Expr::Lit(W256(w as u128, 0))),
        AbiValue::AbiAddress(w) => CalldataFragment::St(vec![], Expr::Lit(w)),
        AbiValue::AbiBool(w) => CalldataFragment::St(vec![], Expr::Lit(if w { W256(1, 0) } else { W256(0, 0) })),
        _ => panic!("TODO"),
      },
    }
  };
  let calldatas: Vec<CalldataFragment> =
    type_signature.iter().zip(args.iter()).enumerate().map(|(i, (typ, arg))| mk_arg(typ, arg, i + 1)).collect();
  let (cd_buf, props) = combine_fragments(&calldatas, base);
  let with_selector = write_selector(cd_buf, sig);
  let size_constraints = Prop::PAnd(
    Box::new(Prop::PGEq(
      (Expr::BufLength(Box::new(with_selector.clone()))),
      (Expr::Lit(W256((calldatas.len() as u128 * 32 + 4 as u128).into(), 0))),
    )),
    Box::new(Prop::PLT((Expr::BufLength(Box::new(with_selector.clone()))), (Expr::Lit(W256(2_u128.pow(64), 0))))),
  );
  (with_selector, vec![size_constraints].into_iter().chain(props).collect())
}

pub fn mk_calldata(sig: Option<Sig>, args: &[String]) -> (Expr, Vec<Prop>) {
  match sig {
    Some(Sig { method_signature: name, inputs: types }) => {
      sym_calldata(&name, &types, args, Expr::AbstractBuf("txdata".to_string()))
    }
    None => (
      Expr::AbstractBuf("txdata".to_string()),
      vec![Prop::PLEq(buf_length(Expr::AbstractBuf("txdata".to_string())), Expr::Lit(W256(2 ^ 64, 0)))],
    ),
  }
}

/*

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum LoopHeuristic {
  Naive,
  StackBased,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProofResult<A, B, C> {
  Qed(A),
  Cex(B),
  Timeout(C),
}

pub type VerifyResult = ProofResult<(), (Expr, SMTCex), Expr>;
pub type EquivResult = ProofResult<(), SMTCex, ()>;

impl<A, B, C> ProofResult<A, B, C> {
  pub fn is_timeout(&self) -> bool {
    matches!(self, ProofResult::Timeout(_))
  }

  pub fn is_cex(&self) -> bool {
    matches!(self, ProofResult::Cex(_))
  }

  pub fn is_qed(&self) -> bool {
    matches!(self, ProofResult::Qed(_))
  }
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct VeriOpts {
  pub simp: bool,
  pub max_iter: Option<i64>,
  pub ask_smt_iters: i64,
  pub loop_heuristic: LoopHeuristic,
  pub rpc_info: RpcInfo,
}

impl Default for VeriOpts {
  fn default() -> Self {
    VeriOpts { simp: true, max_iter: None, ask_smt_iters: 1, loop_heuristic: LoopHeuristic::StackBased, rpc_info: None }
  }
}

pub fn rpc_veri_opts(info: (BlockNumber, String)) -> VeriOpts {
  VeriOpts { rpc_info: Some(info.into()), ..VeriOpts::default() }
}

pub fn extract_cex(result: VerifyResult) -> Option<(Expr, SMTCex)> {
  if let ProofResult::Cex(cex) = result {
    Some(cex)
  } else {
    None
  }
}

fn load_sym_vm(x: ContractCode, callvalue: Expr, cd: (Expr, Vec<Prop>), create: bool) -> VM {
  let contract = if create {
    initial_contract(x.clone())
  } else {
    abstract_contract(x.clone(), Expr::SymAddr("entrypoint".to_string()))
  };

  let opts = VMOpts {
    contract,
    other_contracts: vec![],
    calldata: cd,
    value: callvalue,
    base_state: BaseState::AbstractBase,
    address: Expr::SymAddr("entrypoint".to_string()),
    caller: Expr::SymAddr("caller".to_string()),
    origin: Expr::SymAddr("origin".to_string()),
    coinbase: Expr::SymAddr("coinbase".to_string()),
    number: 0,
    time_stamp: Expr::Lit(0),
    block_gaslimit: 0,
    gasprice: 0,
    prev_randao: 42069,
    gas: (),
    gaslimit: 0xffffffffffffffff,
    base_fee: 0,
    priority_fee: 0,
    max_code_size: 0xffffffff,
    schedule: FEE_SCHEDULE,
    chain_id: 1,
    create,
    tx_access_list: HashMap::new(),
    allow_ffi: false,
  };

  make_vm(opts)
}

fn interpret(
  fetcher: Fetcher,
  max_iter: Option<u64>,
  ask_smt_iters: u64,
  heuristic: LoopHeuristic,
  vm: &mut VM,
  stepper: Stepper<Expr>,
) -> Expr {
  todo!()
}

fn max_iterations_reached(vm: &VM, max_iter: Option<u64>) -> Option<bool> {
  if let Some(max_iter) = max_iter {
    let codelocation = get_code_location(vm);
    let (iters, _) = vm.iterations.get(&codelocation).unwrap_or(&(0, vec![]));
    if (*iters as u64) >= max_iter {
      vm.cache.path.get(&(codelocation, *iters - 1)).copied()
    } else {
      None
    }
  } else {
    None
  }
}

fn ask_smt_iters_reached(vm: &VM, ask_smt_iters: u64) -> bool {
  let codelocation = get_code_location(vm);
  let (iters, _) = vm.iterations.get(&codelocation).unwrap_or(&(0, vec![]));
  (*iters as u64) >= ask_smt_iters
}

fn is_loop_head(heuristic: LoopHeuristic, vm: &VM) -> Option<bool> {
  match heuristic {
    LoopHeuristic::Naive => Some(true),
    LoopHeuristic::StackBased => {
      let loc = get_code_location(vm);
      let old_iters = vm.iterations.get(&loc);
      match old_iters {
        Some((_, old_stack)) => {
          let is_valid = |wrd| wrd <= u64::MAX && is_valid_jump_dest(vm, wrd);
          Some(old_stack.iter().filter(|&&wrd| is_valid(wrd)).eq(vm.state.stack.iter().filter(|&&wrd| is_valid(wrd))))
        }
        None => None,
      }
    }
  }
}

async fn check_assert(
  solvers: SolverGroup,
  errs: Vec<u64>,
  c: ByteString,
  signature: Option<Sig>,
  concrete_args: Vec<String>,
  opts: VeriOpts,
) -> (Expr, Vec<VerifyResult>) {
  verify_contract(solvers, c, signature, concrete_args, opts, None, Some(check_assertions(errs))).await
}

async fn get_expr(
  solvers: SolverGroup,
  c: ByteString,
  signature: Option<Sig>,
  concrete_args: Vec<String>,
  opts: VeriOpts,
) -> Expr {
  let pre_state = abstract_vm(mk_calldata(signature, concrete_args), c, None, false).await;
  let expr_inter =
    interpret(fetcher, opts.max_iter, opts.ask_smt_iters, opts.loop_heuristic, pre_state, run_expr()).await;
  if opts.simp {
    simplify_expr(expr_inter)
  } else {
    expr_inter
  }
}

fn check_assertions(errs: Vec<u64>) -> Postcondition {
  Box::new(move |_, expr| match expr {
    Failure(_, _, Revert(msg)) => !errs.contains(&msg),
    Failure(_, _, Revert(b)) => !errs.iter().any(|&e| b == e),
    _ => true,
  })
}

fn default_panic_codes() -> Vec<u64> {
  vec![0x01]
}

fn all_panic_codes() -> Vec<u64> {
  vec![0x00, 0x01, 0x11, 0x12, 0x21, 0x22, 0x31, 0x32, 0x41, 0x51]
}

fn panic_msg(err: u64) -> ByteString {
  let mut msg = selector(&"Panic(uint256)".to_string());
  msg.extend_from_slice(&encode_abi_value(AbiUInt(256, err)));
  msg
}

*/
