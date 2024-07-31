use env_logger;
use log::{debug, error, info};
use std::cmp::min;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use tiny_keccak::{Hasher, Keccak};

use rhoevm::modules::cli::{build_calldata, vm0, SymbolicCommand};
use rhoevm::modules::evm::{abstract_contract, opslen, solve_constraints};
use rhoevm::modules::format::{hex_byte_string, strip_0x};
use rhoevm::modules::smt::parse_z3_output;

use rhoevm::modules::abi::{parse_abi_file, Sig};
use rhoevm::modules::transactions::init_tx;
use rhoevm::modules::types::{ContractCode, Expr, Prop, RuntimeCodeStruct, VM, W256};

fn print_ascii_art() {
  println!("   ╭───────────────╮");
  println!("   │  R H O  │");
  println!("   │  E V M  │");
  println!("   ╰───────────────╯");
  println!("  ╱🦀╱╱╱╲╱╲╱╲");
  println!(" ╱ 🦀╲╲╲╲╲╲  ╲");
  println!("╱   🦀╲╲╲╲╲╲  ╲ symbolic EVM");
  println!("╲    ╱🦀╱╱╱╱  ╱ execution engine");
  println!(" ╲  ╱🦀╱╱╱╱╱ ╱  written in Rust");
  println!("  ╲╱🦀╱╱╱╱╱╲╱");
  println!("   ╲🦀╲╲╲╲╲╱");
  println!("    ╲🦀╲╲╲╱");
  println!("     ╲🦀╲");
  println!("      ╲🦀");
  println!("       ╲");
}

fn dummy_symvm_from_command(cmd: &SymbolicCommand, calldata: (Expr, Vec<Prop>)) -> Result<VM, Box<dyn Error>> {
  let (miner, block_num, base_fee, prev_ran) = (Expr::SymAddr("miner".to_string()), W256(0, 0), W256(0, 0), W256(0, 0));

  let caller = Expr::SymAddr("caller".to_string());
  let ts = if let Some(t) = cmd.timestamp.clone() { Expr::Lit(t) } else { Expr::Timestamp };

  let callvalue = if let Some(v) = cmd.value.clone() { Expr::Lit(v) } else { Expr::TxValue };

  let contract = match (&cmd.rpc, &cmd.address, &cmd.code) {
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

fn main() {
  // Initialize the logger with the default settings.
  env_logger::init();

  // Collect command-line arguments.
  let args: Vec<String> = env::args().collect();
  if args.len() < 3 {
    error!("Usage: <program> <filename> <function_signature>");
    return;
  }

  print_ascii_art();

  let base_filename = &args[1];
  let function_name = &args[2];

  let bin_filename = base_filename.to_string() + &".bin".to_string();
  let abi_filename = base_filename.to_string() + &".abi".to_string();

  // Load the binary file.
  info!("Loading binary from file: {}", bin_filename);
  let mut f = match File::open(bin_filename.clone()) {
    Ok(file) => file,
    Err(e) => {
      error!("Failed to open file '{}': {}", bin_filename, e);
      return;
    }
  };
  let mut binary = String::new();
  if let Err(e) = f.read_to_string(&mut binary) {
    error!("Failed to read file '{}': {}", bin_filename, e);
    return;
  }
  debug!("File '{}' read successfully.", bin_filename);

  // Load the abi file.
  info!("Loading abi from file: {}", abi_filename);
  let mut j = match File::open(abi_filename.clone()) {
    Ok(file) => file,
    Err(e) => {
      error!("Failed to open file '{}': {}", abi_filename, e);
      return;
    }
  };
  let mut abi_json = String::new();
  if let Err(e) = j.read_to_string(&mut abi_json) {
    error!("Failed to read file '{}': {}", abi_filename, e);
    return;
  }
  let abi_map = parse_abi_file(&abi_json);
  debug!("File '{}' read successfully.", abi_filename);
  if !abi_map.contains_key(function_name) {
    error!("Cannot find the specified function `{}`", function_name);
    return;
  }

  let mut function_signature = function_name.clone() + "(";
  for t in abi_map[function_name].clone() {
    function_signature += &format!("{},", t);
  }
  if abi_map[function_name].len() != 0 {
    function_signature.pop();
    function_signature.push(')');
  } else {
    function_signature += ")";
  }
  info!("Using function signature: {}", function_signature);

  // Calculate the function signature.
  let mut hasher = Keccak::v256();
  hasher.update(function_signature.as_bytes());
  let mut output = [0u8; 32];
  hasher.finalize(&mut output);
  let function_selector = &output[..4];
  let function_selector_hex: String = function_selector.iter().map(|byte| format!("{:02x}", byte)).collect();
  info!("Calculated function selector: 0x{}", function_selector_hex);

  // Build command and calldata.
  let mut cmd = <SymbolicCommand as std::default::Default>::default();
  cmd.sig = Some(Sig::new(&function_signature, &abi_map[function_name]));
  cmd.value = Some(W256(0, 0));
  //cmd.calldata = Some(function_selector_hex.clone().as_bytes().to_vec());
  cmd.code = Some(binary.into());
  let callcode = match build_calldata(&cmd) {
    Ok(calldata) => calldata,
    Err(e) => {
      error!("Failed to build calldata: {}", e);
      return;
    }
  };
  info!("Calldata constructed successfully for function '{}'\n", function_signature);

  // Initialize VM and start execution.
  let mut vm = match dummy_symvm_from_command(&cmd, callcode) {
    Ok(vm) => vm,
    Err(e) => {
      error!("Failed to initialize symbolic VM: {}", e);
      return;
    }
  };
  let num_initial_constraints = vm.constraints.len();

  let mut vms = vec![];
  let mut prev_pc = 0;
  let mut do_size = 0;
  let mut end = false;
  let mut found_calldataload = false;
  let mut prev_op = "".to_string();
  let mut prev_valid_op = "".to_string();

  info!("Starting EVM symbolic execution...");
  while !end {
    loop {
      prev_pc = vm.state.pc;
      do_size = vm.decoded_opcodes.len();
      let continue_flag = vm.exec1(&mut vms, if found_calldataload { 10 } else { 1 });
      prev_op = vm.decoded_opcodes[min(do_size, vm.decoded_opcodes.len() - 1)].clone();

      if !found_calldataload && prev_valid_op == "RETURN" && prev_op != "UNKNOWN" {
        vm.state.base_pc = prev_pc;
        debug!("Base PC set to 0x{:x}", prev_pc);
      }

      if prev_op != "UNKNOWN" {
        prev_valid_op = vm.decoded_opcodes[min(do_size, vm.decoded_opcodes.len() - 1)].clone();
      }

      debug!("PC: 0x{:x}, Opcode: {}", prev_pc, prev_op);

      if !found_calldataload {
        found_calldataload = prev_valid_op == "CALLDATALOAD";
      }

      if found_calldataload && prev_op == "REVERT" {
        let (reachability, model) = solve_constraints(&vm, &vm.constraints);
        end = true;

        if reachability {
          error!("REACHABLE REVERT DETECTED @ PC=0x{:x}", prev_pc);
          if let Some(ref model_str) = model {
            let mut msg_model = function_name.to_string() + "(";
            let model = parse_z3_output(&model_str);
            let mut is_zero_args = true;
            for (k, v) in model.iter() {
              if k[..3] == *"arg" {
                msg_model += &format!("{}={},", k, v.1);
                is_zero_args = false;
              }
            }
            if !is_zero_args {
              msg_model.pop();
            }
            msg_model.push(')');
            error!("model: {}", msg_model);
          }

          let mut msg = "** Constraints (Raw Format):=\n true".to_string();
          for e in &vm.constraints_raw_expr {
            msg = msg + &format!(" && {}\n", *e);
          }
          debug!("{}", msg);
          break;
        }
      }

      if continue_flag {
        if prev_pc == vm.state.pc {
          vm.state.pc = vm.state.pc + 1;
        }
      } else if (vm.state.pc >= opslen(&vm.state.code)) && vms.len() == 0 {
        end = true;
        break;
      } else if vms.len() == 0 {
        break;
      } else {
        vm = vms.pop().unwrap();
        debug!("---------------");
      }
    }
    debug!("---------------");
    vm.constraints = vm.constraints[..num_initial_constraints].to_vec();
    //vm.constraints_raw_expr = vm.constraints_raw_expr[..num_initial_constraints].to_vec();
    vm.constraints_raw_expr.clear();
    vm.state.pc += 1;
  }
  info!("EVM execution completed.");
}
