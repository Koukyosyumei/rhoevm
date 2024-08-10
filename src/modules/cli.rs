use std::collections::HashMap;
use std::error::Error;
use std::process::exit;

use crate::modules::abi::Sig;
use crate::modules::evm::{abstract_contract, initial_contract, make_vm};
use crate::modules::feeschedule::FEE_SCHEDULE;
use crate::modules::fetch::{fetch_block_from, fetch_contract_from, BlockNumber};
use crate::modules::format::{hex_byte_string, strip_0x};
//use crate::modules::solvers::{with_solvers, Solver};
use crate::modules::symexec::mk_calldata;
use crate::modules::transactions::init_tx;
use crate::modules::types::{
  Addr, BaseState, Contract, ContractCode, Expr, Gas, Prop, RuntimeCodeStruct, VMOpts, VM, W256,
};

type URL = String;

#[derive(Debug, Clone)]
pub enum InitialStorage {
  Empty,
  Abstract,
}

#[derive(Debug, Default)]
pub struct SymbolicCommand {
  // VM opts
  pub code: Option<Vec<u8>>,       // Program bytecode
  pub calldata: Option<Vec<u8>>,   // Tx: calldata
  pub address: Option<Addr>,       // Tx: address
  pub caller: Option<Addr>,        // Tx: caller
  pub origin: Option<Addr>,        // Tx: origin
  pub coinbase: Option<Addr>,      // Block: coinbase
  pub value: Option<W256>,         // Tx: Eth amount
  pub nonce: Option<u64>,          // Nonce of origin
  pub gas: Option<u64>,            // Tx: gas amount
  pub number: Option<W256>,        // Block: number
  pub timestamp: Option<W256>,     // Block: timestamp
  pub basefee: Option<W256>,       // Block: base fee
  pub priority_fee: Option<W256>,  // Tx: priority fee
  pub gaslimit: Option<u64>,       // Tx: gas limit
  pub gasprice: Option<W256>,      // Tx: gas price
  pub create: bool,                // Tx: creation
  pub max_code_size: Option<W256>, // Block: max code size
  pub prev_randao: Option<W256>,   // Block: prevRandao
  pub chainid: Option<W256>,       // Env: chainId
  // Remote state opts
  pub rpc: Option<URL>,    // Fetch state from a remote node
  pub block: Option<W256>, // Block state to be fetched from

  // Symbolic execution opts
  pub root: Option<String>, // Path to project root directory (default: .)
  // project_type: Option<ProjectType>,       // Is this a Foundry or DappTools project (default: Foundry)
  pub initial_storage: Option<InitialStorage>, // Starting state for storage: Empty, Abstract (default Abstract)
  pub sig: Option<Sig>,                        // Signature of types to decode/encode
  pub concrete_arg: Vec<String>,               // Values to encode
  pub get_models: bool,                        // Print example testcase for each execution path
  pub show_tree: bool,                         // Print branches explored in tree view
  pub show_reachable_tree: bool,               // Print only reachable branches explored in tree view
  pub smt_timeout: Option<usize>,              // Timeout given to SMT solver in seconds (default: 300)
  pub max_iterations: Option<i64>,             // Number of times we may revisit a particular branching point
  pub solver: Option<String>,                  // Used SMT solver: z3 (default), cvc5, or bitwuzla
  pub smt_debug: bool,                         // Print smt queries sent to the solver
  pub debug: bool,                             // Debug printing of internal behaviour
  pub trace: bool,                             // Dump trace
  pub assertions: Option<Vec<W256>>, // List of solc panic codes to check for (default: user defined assertion violations only)
  pub ask_smt_iterations: i64, // Number of times we may revisit a particular branching point before consulting the SMT solver to check reachability (default: 1)
  pub num_cex_fuzz: i64,       // Number of fuzzing tries to generate a counterexample (default: 3)
  pub num_solvers: Option<u64>, // Number of solver instances to use (default: number of CPU cores)
  // loop_detection_heuristic: LoopHeuristic, // Heuristic to determine if we are in a loop: StackBased (default) or Naive
  pub abstract_arithmetic: bool, // Use abstraction-refinement for complicated arithmetic functions
  pub abstract_memory: bool,     // Use abstraction-refinement for Memory
  pub no_decompose: bool,        // Don't decompose storage slots into separate arrays
}

pub async fn symvm_from_command(cmd: &SymbolicCommand, calldata: (Expr, Vec<Prop>)) -> Result<VM, Box<dyn Error>> {
  let (miner, block_num, base_fee, prev_ran) = match &cmd.rpc {
    None => (Expr::SymAddr("miner".to_string()), W256(0, 0), W256(0, 0), W256(0, 0)),
    Some(url) => {
      let block = if let Some(block_number) = cmd.block.clone() {
        BlockNumber::BlockNumber(block_number)
      } else {
        BlockNumber::Latest
      };
      let res = fetch_block_from(block, url).await;
      match res {
        None => return Err("Error: Could not fetch block".into()),
        Some(block) => (block.coinbase, block.number, block.base_fee, block.prev_randao),
      }
    }
  };

  let caller = Expr::SymAddr("caller".to_string());
  let ts = if let Some(t) = cmd.timestamp.clone() { Expr::Lit(t) } else { Expr::Timestamp };

  let callvalue = if let Some(v) = cmd.value.clone() { Expr::Lit(v) } else { Expr::TxValue };

  let contract = match (&cmd.rpc, &cmd.address, &cmd.code) {
    (Some(url), Some(addr), _) => {
      let block = if let Some(block_number) = cmd.block.clone() {
        BlockNumber::BlockNumber(block_number)
      } else {
        BlockNumber::Latest
      };
      let res = fetch_contract_from(block, url, addr.clone()).await;
      match res {
        None => return Err("Error: contract not found".into()),
        Some(contract_) => match &cmd.code {
          None => contract_,
          Some(code) => {
            let bs = hex_byte_string("bytes", &strip_0x(code));
            let mc = if cmd.create {
              ContractCode::InitCode(Box::new(bs), Box::new(Expr::Mempty))
            } else {
              ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(Box::new(bs)))
            };
            let mut contract = initial_contract(mc);
            contract.orig_storage = contract_.orig_storage;
            contract.balance = contract_.balance;
            contract.nonce = contract_.nonce;
            contract.external = contract_.external;
            contract
          }
        },
      }
    }
    (_, _, Some(code)) => {
      let bs = hex_byte_string("bytes", &strip_0x(code));
      let mc = if cmd.create {
        ContractCode::InitCode(Box::new(bs), Box::new(Expr::Mempty))
      } else {
        ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(Box::new(bs)))
      };
      let address =
        if let Some(a) = cmd.origin.clone() { Expr::LitAddr(a) } else { Expr::SymAddr("origin".to_string()) };
      abstract_contract(mc, address)
    }
    _ => return Err("Error: must provide at least (rpc + address) or code".into()),
  };

  let mut vm = vm0(base_fee, miner, ts, block_num, prev_ran, calldata, callvalue, caller, contract, cmd);
  init_tx(&mut vm);
  Ok(vm)
}

pub fn vm0(
  base_fee: W256,
  miner: Expr,
  ts: Expr,
  block_num: W256,
  prev_ran: W256,
  calldata: (Expr, Vec<Prop>),
  callvalue: Expr,
  caller: Expr,
  c: Contract,
  cmd: &SymbolicCommand,
) -> VM {
  let opts = VMOpts {
    contract: c,
    other_contracts: Vec::new(),
    calldata: calldata,
    value: callvalue,
    address: if let Some(a) = cmd.address.clone() { Expr::LitAddr(a) } else { Expr::SymAddr("entrypoint".to_string()) },
    caller: caller,
    origin: if let Some(a) = cmd.origin.clone() { Expr::LitAddr(a) } else { Expr::SymAddr("origin".to_string()) },
    gas: Gas::Symbolic,
    gaslimit: if let Some(gl) = cmd.gaslimit { gl } else { 0xffffffffffffffff },
    base_fee: base_fee,
    priority_fee: if let Some(pf) = cmd.priority_fee.clone() { pf } else { W256(0, 0) },
    coinbase: if let Some(c) = cmd.coinbase.clone() { Expr::LitAddr(c) } else { miner },
    number: if let Some(n) = cmd.number.clone() { n } else { block_num },
    time_stamp: ts,
    block_gaslimit: if let Some(b) = cmd.gaslimit { b } else { 0xffffffffffffffff },
    gasprice: if let Some(g) = cmd.gasprice.clone() { g } else { W256(0, 0) },
    max_code_size: if let Some(m) = cmd.max_code_size.clone() { m } else { W256(0xffffffff, 0) },
    prev_randao: if let Some(p) = cmd.prev_randao.clone() { p } else { prev_ran },
    schedule: FEE_SCHEDULE,
    chain_id: if let Some(i) = cmd.chainid.clone() { i } else { W256(1, 0) },
    create: cmd.create,
    base_state: if let Some(is) = &cmd.initial_storage {
      parse_initial_storage(is.clone())
    } else {
      BaseState::AbstractBase
    },
    tx_access_list: HashMap::new(),
    allow_ffi: false,
  };
  make_vm(opts)
}

fn parse_initial_storage(is: InitialStorage) -> BaseState {
  match is {
    InitialStorage::Empty => BaseState::EmptyBase,
    InitialStorage::Abstract => BaseState::AbstractBase,
  }
}

pub fn build_calldata(cmd: &SymbolicCommand) -> Result<(Expr, Vec<Prop>), Box<dyn std::error::Error>> {
  match (&cmd.calldata, &cmd.sig) {
    // Fully abstract calldata
    (None, None) => Ok(mk_calldata(&None, &[])),

    // Fully concrete calldata
    (Some(c), None) => {
      let concrete_buf = Expr::ConcreteBuf(hex_byte_string("bytes", &strip_0x(c)));
      Ok((concrete_buf, vec![]))
    }

    // Calldata according to given ABI with possible specializations from the `arg` list
    (None, Some(sig)) => Ok(mk_calldata(&Some(sig.clone()), &cmd.concrete_arg)),

    // Both args provided
    (_, _) => {
      eprintln!("incompatible options provided: --calldata and --sig");
      exit(1);
    }
  }
}
