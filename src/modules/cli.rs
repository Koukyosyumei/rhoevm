use futures::future::join_all;
use num_cpus;
use std::cmp::max;
use std::collections::{hash_set, HashMap, HashSet};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::error::Error;
use std::hash::Hash;
use std::io::{self, Write};
use std::iter;
use std::process::exit;
use std::sync::Arc;
use std::{clone, ops};
use tiny_keccak::{Hasher, Keccak};
use tokio::runtime::Runtime;

use crate::modules::abi::Sig;
use crate::modules::evm::{abstract_contract, initial_contract, make_vm};
use crate::modules::feeschedule::FEE_SCHEDULE;
use crate::modules::fetch::{fetch_block_from, fetch_contract_from, BlockNumber};
use crate::modules::format::{hex_byte_string, strip_0x};
use crate::modules::solvers::{with_solvers, Solver};
use crate::modules::transactions::init_tx;
use crate::modules::types::{
  Addr, BaseState, Contract, ContractCode, Expr, Gas, Prop, RuntimeCodeStruct, VMOpts, VM, W256,
};

use super::types::Block;

type URL = String;

#[derive(Debug)]
pub enum InitialStorage {
  Empty,
  Abstract,
}

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
  initial_storage: Option<InitialStorage>, // Starting state for storage: Empty, Abstract (default Abstract)
  sig: Option<String>,                     // Signature of types to decode/encode
  arg: Vec<String>,                        // Values to encode
  get_models: bool,                        // Print example testcase for each execution path
  show_tree: bool,                         // Print branches explored in tree view
  show_reachable_tree: bool,               // Print only reachable branches explored in tree view
  smt_timeout: Option<usize>,              // Timeout given to SMT solver in seconds (default: 300)
  max_iterations: Option<i64>,             // Number of times we may revisit a particular branching point
  solver: Option<String>,                  // Used SMT solver: z3 (default), cvc5, or bitwuzla
  smt_debug: bool,                         // Print smt queries sent to the solver
  debug: bool,                             // Debug printing of internal behaviour
  trace: bool,                             // Dump trace
  assertions: Option<Vec<W256>>, // List of solc panic codes to check for (default: user defined assertion violations only)
  ask_smt_iterations: i64, // Number of times we may revisit a particular branching point before consulting the SMT solver to check reachability (default: 1)
  num_cex_fuzz: i64,       // Number of fuzzing tries to generate a counterexample (default: 3)
  num_solvers: Option<u64>, // Number of solver instances to use (default: number of CPU cores)
  // loop_detection_heuristic: LoopHeuristic, // Heuristic to determine if we are in a loop: StackBased (default) or Naive
  abstract_arithmetic: bool, // Use abstraction-refinement for complicated arithmetic functions
  abstract_memory: bool,     // Use abstraction-refinement for Memory
  no_decompose: bool,        // Don't decompose storage slots into separate arrays
}

async fn assert(cmd: SymbolicCommand) -> Result<(), Box<dyn std::error::Error>> {
  let block = if let Some(b) = cmd.block {
    BlockNumber::BlockNumber(b)
  } else {
    BlockNumber::Latest
  };
  let rpcinfo = cmd.rpc.map(|rpc| (block.clone(), rpc));

  let calldata = build_calldata(&cmd)?;
  let pre_state = symvm_from_command(&cmd, calldata.clone()).await?;

  let err_codes = if let Some(ec) = cmd.assertions {
    ec
  } else {
    panic!("error")
  };
  let cores = num_cpus::get();
  let solver_count = cmd.num_solvers.unwrap_or(cores as u64);
  // let solver = get_solver(&cmd).await?;

  with_solvers(Solver::Z3, solver_count as usize, cmd.smt_timeout, |solvers| async {
    let opts = VeriOpts {
      simp: true,
      max_iter: cmd.max_iterations,
      ask_smt_iters: cmd.ask_smt_iterations,
      loop_heuristic: cmd.loop_detection_heuristic,
      rpc_info: rpcinfo.clone(),
    };

    let (expr, res) = verify(
      solvers.clone(),
      opts,
      pre_state.clone(),
      Some(check_assertions(err_codes)),
    )
    .await?;

    match res.as_slice() {
      [VeriResult::Qed(_)] => {
        println!("\nQED: No reachable property violations discovered\n");
        show_extras(solvers, &cmd, calldata.clone(), expr.clone()).await?;
      }
      _ => {
        let cexs: Vec<_> = res.iter().filter_map(get_cex).collect();
        let timeouts: Vec<_> = res.iter().filter_map(get_timeout).collect();

        let counterexamples = if cexs.is_empty() {
          vec![]
        } else {
          vec![
            "".to_string(),
            "Discovered the following counterexamples:".to_string(),
            "".to_string(),
          ]
          .into_iter()
          .chain(cexs.iter().map(|cex| format_cex(&calldata.0, None, cex)))
          .collect()
        };

        let unknowns = if timeouts.is_empty() {
          vec![]
        } else {
          vec![
            "".to_string(),
            "Could not determine reachability of the following end states:".to_string(),
            "".to_string(),
          ]
          .into_iter()
          .chain(timeouts.iter().map(format_expr))
          .collect()
        };

        println!("{}", counterexamples.join("\n"));
        println!("{}", unknowns.join("\n"));
        show_extras(solvers, &cmd, calldata.clone(), expr.clone()).await?;
        std::process::exit(1);
      }
    }

    Ok(())
  })
  .await
}

pub async fn symvm_from_command(cmd: &SymbolicCommand, calldata: (Expr, Vec<Prop>)) -> Result<VM, Box<dyn Error>> {
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
        Some(contract_) => match &cmd.code {
          None => contract_,
          Some(code) => {
            let bs = hex_byte_string("bytes", &strip_0x(code));
            let mc = if cmd.create {
              ContractCode::InitCode(bs, Box::new(Expr::Mempty))
            } else {
              ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(bs))
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
        ContractCode::InitCode(bs, Box::new(Expr::Mempty))
      } else {
        ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(bs))
      };
      let address = if let Some(a) = cmd.origin {
        Expr::LitAddr(a)
      } else {
        Expr::SymAddr("origin".to_string())
      };
      abstract_contract(mc, address)
    }
    _ => return Err("Error: must provide at least (rpc + address) or code".into()),
  };

  let mut vm = vm0(
    base_fee, miner, ts, block_num, prev_ran, calldata, callvalue, caller, contract, cmd,
  );
  init_tx(&mut vm);
  Ok(vm)
}

fn vm0(
  base_fee: u32,
  miner: Expr,
  ts: Expr,
  block_num: u32,
  prev_ran: u32,
  calldata: (Expr, Vec<Prop>),
  callvalue: Expr,
  caller: Expr,
  c: Contract,
  cmd: SymbolicCommand,
) -> VM {
  let opts = VMOpts {
    contract: c,
    other_contracts: Vec::new(),
    calldata: calldata,
    value: callvalue,
    address: if let Some(a) = cmd.address {
      Expr::LitAddr(a)
    } else {
      Expr::SymAddr("entrypoint".to_string())
    },
    caller: caller,
    origin: if let Some(a) = cmd.origin {
      Expr::LitAddr(a)
    } else {
      Expr::SymAddr("origin".to_string())
    },
    gas: Gas::Symbolic,
    gaslimit: if let Some(gl) = cmd.gaslimit {
      gl
    } else {
      0xffffffffffffffff
    },
    base_fee: base_fee,
    priority_fee: if let Some(pf) = cmd.priority_fee { pf } else { 0 },
    coinbase: if let Some(c) = cmd.coinbase {
      Expr::LitAddr(c)
    } else {
      miner
    },
    number: if let Some(n) = cmd.number { n } else { block_num },
    time_stamp: ts,
    block_gaslimit: if let Some(b) = cmd.gaslimit {
      b
    } else {
      0xffffffffffffffff
    },
    gasprice: if let Some(g) = cmd.gasprice { g } else { 0 },
    max_code_size: if let Some(m) = cmd.max_code_size { m } else { 0xffffffff },
    prev_randao: if let Some(p) = cmd.prev_randao { p } else { prev_ran },
    schedule: FEE_SCHEDULE,
    chain_id: if let Some(i) = cmd.chainid { i } else { 1 },
    create: cmd.create,
    base_state: if let Some(is) = cmd.initial_storage {
      parseInitialStorage(is)
    } else {
      BaseState::AbstractBase
    },
    tx_access_list: HashMap::new(),
    allow_ffi: false,
  };
  make_vm(opts)
}

fn parseInitialStorage(is: InitialStorage) -> BaseState {
  match is {
    InitialStorage::Empty => BaseState::EmptyBase,
    InitialStorage::Abstract => BaseState::AbstractBase,
  }
}

fn build_calldata(cmd: &SymbolicCommand) -> Result<(Expr, Vec<Prop>), Box<dyn std::error::Error>> {
  match (&cmd.calldata, &cmd.sig) {
    // Fully abstract calldata
    (None, None) => Ok(mk_calldata(None, &[])),

    // Fully concrete calldata
    (Some(c), None) => {
      let concrete_buf = Expr::ConcreteBuf(hex_byte_string("bytes", &strip_0x(c)));
      Ok((concrete_buf, vec![]))
    }

    // Calldata according to given ABI with possible specializations from the `arg` list
    (None, Some(sig)) => {
      let method = function_abi(sig)?;
      let sig = Sig::new(
        &method.method_signature,
        &method.inputs.iter().map(|input| input.1.clone()).collect::<Vec<_>>(),
      );
      Ok(mk_calldata(Some(sig), &cmd.arg))
    }

    // Both args provided
    (_, _) => {
      eprintln!("incompatible options provided: --calldata and --sig");
      exit(1);
    }
  }
}

fn mk_calldata(sig: Option<Sig>, args: &[String]) -> (Expr, Vec<Prop>) {
  // Implementation here
  // (Expr::, vec![])
  todo!()
}

fn function_abi(sig: &str) -> Result<AbiMethod, Box<dyn std::error::Error>> {
  // Implementation here
  Ok(AbiMethod {
    method_signature: sig.to_string(),
    inputs: vec![],
  })
}

struct AbiMethod {
  method_signature: String,
  inputs: Vec<(String, String)>,
}
