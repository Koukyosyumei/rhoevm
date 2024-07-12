use std::cmp::max;
use std::collections::{hash_set, HashMap, HashSet};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::error::Error;
use std::hash::Hash;
use std::iter;
use std::sync::Arc;
use std::{clone, ops};
use tiny_keccak::{Hasher, Keccak};

use crate::modules::evm::{abstract_contract, initial_contract};
use crate::modules::fetch::{fetch_block_from, fetch_contract_from, BlockNumber};
use crate::modules::format::{hex_byte_string, strip_0x};
use crate::modules::types::{Addr, ContractCode, Expr, Prop, RuntimeCodeStruct, VM, W256};

type URL = String;

#[derive(Debug, Default)]
pub struct SymbolicCommand {
  // VM opts
  code: Option<Vec<u8>>,       // Program bytecode
  calldata: Option<Vec<u8>>,   // Tx: calldata
  address: Option<Addr>,       // Tx: address
  caller: Option<Addr>,        // Tx: caller
  origin: Option<Addr>,        // Tx: origin
  coinbase: Option<Addr>,      // Block: coinbase
  value: Option<W256>,         // Tx: Eth amount
  nonce: Option<u64>,          // Nonce of origin
  gas: Option<u64>,            // Tx: gas amount
  number: Option<W256>,        // Block: number
  timestamp: Option<W256>,     // Block: timestamp
  basefee: Option<W256>,       // Block: base fee
  priority_fee: Option<W256>,  // Tx: priority fee
  gaslimit: Option<u64>,       // Tx: gas limit
  gasprice: Option<W256>,      // Tx: gas price
  create: bool,                // Tx: creation
  max_code_size: Option<W256>, // Block: max code size
  prev_randao: Option<W256>,   // Block: prevRandao
  chainid: Option<W256>,       // Env: chainId
  // Remote state opts
  rpc: Option<URL>,    // Fetch state from a remote node
  block: Option<W256>, // Block state to be fetched from

  // Symbolic execution opts
  root: Option<String>, // Path to project root directory (default: .)
  // project_type: Option<ProjectType>,       // Is this a Foundry or DappTools project (default: Foundry)
  // initial_storage: Option<InitialStorage>, // Starting state for storage: Empty, Abstract (default Abstract)
  sig: Option<String>,           // Signature of types to decode/encode
  arg: Vec<String>,              // Values to encode
  get_models: bool,              // Print example testcase for each execution path
  show_tree: bool,               // Print branches explored in tree view
  show_reachable_tree: bool,     // Print only reachable branches explored in tree view
  smt_timeout: Option<u64>,      // Timeout given to SMT solver in seconds (default: 300)
  max_iterations: Option<i64>,   // Number of times we may revisit a particular branching point
  solver: Option<String>,        // Used SMT solver: z3 (default), cvc5, or bitwuzla
  smt_debug: bool,               // Print smt queries sent to the solver
  debug: bool,                   // Debug printing of internal behaviour
  trace: bool,                   // Dump trace
  assertions: Option<Vec<W256>>, // List of solc panic codes to check for (default: user defined assertion violations only)
  ask_smt_iterations: i64, // Number of times we may revisit a particular branching point before consulting the SMT solver to check reachability (default: 1)
  num_cex_fuzz: i64,       // Number of fuzzing tries to generate a counterexample (default: 3)
  num_solvers: Option<u64>, // Number of solver instances to use (default: number of CPU cores)
  // loop_detection_heuristic: LoopHeuristic, // Heuristic to determine if we are in a loop: StackBased (default) or Naive
  abstract_arithmetic: bool, // Use abstraction-refinement for complicated arithmetic functions
  abstract_memory: bool,     // Use abstraction-refinement for Memory
  no_decompose: bool,        // Don't decompose storage slots into separate arrays
}

pub async fn symvm_from_command(cmd: SymbolicCommand, calldata: (Expr, Vec<Prop>)) -> Result<VM, Box<dyn Error>> {
  let (miner, block_num, base_fee, prev_ran) = match &cmd.rpc {
    None => (Expr::SymAddr("miner".to_string()), 0, 0, 0),
    Some(url) => {
      let block = if let Some(block_number) = cmd.block {
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
  let ts = if let Some(t) = cmd.timestamp {
    Expr::Lit(t)
  } else {
    Expr::Timestamp
  };

  let callvalue = if let Some(v) = cmd.value {
    Expr::Lit(v)
  } else {
    Expr::TxValue
  };

  let contract = match (&cmd.rpc, &cmd.address, &cmd.code) {
    (Some(url), Some(addr), _) => {
      let block = if let Some(block_number) = cmd.block {
        BlockNumber::BlockNumber(block_number)
      } else {
        BlockNumber::Latest
      };
      let res = fetch_contract_from(block, url, *addr).await;
      match res {
        None => return Err("Error: contract not found".into()),
        Some(contract) => match &cmd.code {
          None => contract,
          Some(code) => {
            let bs = hex_byte_string("bytes", &strip_0x(code));
            let mc = if cmd.create {
              ContractCode::InitCode(bs, Box::new(Expr::Mempty))
            } else {
              ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(bs))
            };
            let contract = initial_contract(mc);
            contract
              .set_orig_storage(contract.orig_storage)
              .set_balance(contract.balance)
              .set_nonce(contract.nonce)
              .set_external(contract.external)
          }
        },
      }
    }
    (_, _, Some(code)) => {
      let bs = hex_byte_string("bytes", &strip_0x(code));
      let mc = if cmd.create {
        ContractCode::InitCode(bs, Box::new(Expr::Mempty))
      } else {
        ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(bs))
      };
      abstract_contract(mc, &address)
    }
    _ => return Err("Error: must provide at least (rpc + address) or code".into()),
  };

  let vm = vm0(
    base_fee, miner, ts, block_num, prev_ran, calldata, callvalue, caller, contract,
  );
  Ok(EVM::Transaction::init_tx(vm))
}
