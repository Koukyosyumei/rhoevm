use env_logger;
use getopts::Options;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time;
use std::{env, process};
use tiny_keccak::{Hasher, Keccak};
use tokio::task;

use rhoevm::modules::cli::{build_calldata, vm0, SymbolicCommand};
use rhoevm::modules::evm::{abstract_contract, opslen, solve_constraints};
use rhoevm::modules::format::{hex_byte_string, strip_0x};
use rhoevm::modules::smt::parse_z3_output;

use rhoevm::modules::abi::{parse_abi_file, Sig};
use rhoevm::modules::expr::is_function_sig_check_prop;
use rhoevm::modules::transactions::init_tx;
use rhoevm::modules::types::{ContractCode, Env, Expr, Prop, RuntimeCodeStruct, VM, W256};

#[derive(Debug)]
struct Args {
  contract_name: String,
  function_names: String,
  target_dir: Option<String>,
  max_num_iterations: Option<u32>,
  verbose_level: Option<String>,
}

fn print_usage(program: &str, opts: &Options) {
  let brief = format!("Usage: {} CONTRACT_NAME FUNCTION_NAMES [options]", program);
  print!("{}", opts.usage(&brief));
  process::exit(0);
}

const DEFAULT_MAX_NUM_ITERATIONS: u32 = 10;

fn parse_args() -> Args {
  let args: Vec<String> = env::args().collect();
  let program = args[0].clone();

  let mut opts = Options::new();
  opts.optopt("d", "dir", "target directory", "DIR");
  opts.optopt("i", "max_num_iterations", "maximum number of iterations for loop", "MAX_NUM_ITER");
  opts.optopt("v", "verbose", "level of verbose", "LEVEL");
  opts.optflag("h", "help", "print this help menu");

  let matches = match opts.parse(&args[1..]) {
    Ok(m) => m,
    Err(f) => {
      eprintln!("Error: {}", f);
      print_usage(&program, &opts);
      process::exit(1);
    }
  };

  if matches.opt_present("h") {
    print_usage(&program, &opts);
  }

  let contract_name = if !matches.free.is_empty() {
    matches.free[0].clone()
  } else {
    print_usage(&program, &opts);
    panic!("Error: CONTRACT_NAME is required.")
  };

  let function_names = if matches.free.len() > 1 {
    matches.free[1].clone()
  } else {
    print_usage(&program, &opts);
    panic!("Error: At least one FUNCTION_NAME is required.");
  };

  let target_dir = matches.opt_str("d");
  let max_num_iterations = if let Some(i) = matches.opt_str("i") {
    Some(i.parse::<u32>().unwrap_or(DEFAULT_MAX_NUM_ITERATIONS))
  } else {
    None
  };
  let verbose_level = matches.opt_str("v");

  Args { contract_name, function_names, target_dir, max_num_iterations, verbose_level }
}

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

#[tokio::main]
async fn main() {
  // Collect command-line arguments.
  let args = parse_args();

  print_ascii_art();

  let base_filename = if let Some(dir_name) = args.target_dir {
    Path::new(&dir_name)
      .join(&args.contract_name)
      .to_str()
      .unwrap_or_else(|| {
        eprintln!("Warning: Path is not valid UTF-8. Using default path.");
        "./"
      })
      .to_string()
  } else {
    Path::new("./")
      .join(&args.contract_name)
      .to_str()
      .unwrap_or_else(|| {
        eprintln!("Warning: Path is not valid UTF-8. Using default path.");
        "./"
      })
      .to_string()
  };

  // Set the verbose level
  match args.verbose_level.as_deref() {
    Some("0") | Some("error") => env::set_var("RUST_LOG", "error"),
    Some("1") | Some("warn") => env::set_var("RUST_LOG", "warn"),
    Some("2") | Some("info") => env::set_var("RUST_LOG", "info"),
    Some("3") | Some("debug") => env::set_var("RUST_LOG", "debug"),
    Some("4") | Some("trace") => env::set_var("RUST_LOG", "trace"),
    _ => env::set_var("RUST_LOG", "info"),
  }

  // Initialize the logger with the default settings.
  env_logger::init();
  warn!("Currently, this project is a work in progress.");

  // ------------- Load the binary file -------------
  let bin_filename = base_filename.to_string() + &".bin".to_string();
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

  // ------------- Load the abi file -------------
  let abi_filename = base_filename.to_string() + &".abi".to_string();
  info!("Loading abi from file: {}\n", abi_filename);
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
  debug!("File '{}' read successfully.\n", abi_filename);

  // utility variables
  let function_names_vec: Vec<String> = args.function_names.split(',').map(|s| s.to_string()).collect();
  let mut cnt_function_names = 0;
  let mut reachable_envs: Vec<Env> = vec![];
  let mut num_known_variables = 0;
  let mut variable_id_to_function_name: HashMap<usize, String> = HashMap::new();

  // ------------- MAIN PART: May rhoevm light your path to bug-free code -------------
  let start_time = time::Instant::now();
  for function_name in &function_names_vec {
    let mut next_reachable_envs: Vec<Env> = vec![];

    // ------------- Calculate the function signature -------------
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

    let mut hasher = Keccak::v256();
    hasher.update(function_signature.as_bytes());
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    let function_selector = &output[..4];
    let function_selector_hex: String = function_selector.iter().map(|byte| format!("{:02x}", byte)).collect();
    info!("Calculated function selector: 0x{}", function_selector_hex);

    // ------------- Build command and calldata -------------
    let mut cmd = <SymbolicCommand as std::default::Default>::default();
    cmd.sig = Some(Sig::new(&function_signature, &abi_map[function_name]));
    cmd.value = Some(W256(0, 0));
    //cmd.calldata = Some(function_selector_hex.clone().as_bytes().to_vec());
    cmd.code = Some(binary.clone().into());
    let callcode = match build_calldata(&cmd, num_known_variables) {
      Ok(calldata) => calldata,
      Err(e) => {
        error!("Failed to build calldata: {}", e);
        return;
      }
    };
    info!("Calldata constructed successfully for function '{}'", function_signature);

    for i in 1 + num_known_variables..=num_known_variables + abi_map[function_name].len() {
      variable_id_to_function_name.insert(i, function_name.to_string());
    }
    num_known_variables += abi_map[function_name].len();

    // ------------- Initialize VM -------------
    let vm = match dummy_symvm_from_command(&cmd, callcode.clone()) {
      Ok(vm) => vm,
      Err(e) => {
        error!("Failed to initialize symbolic VM: {}", e);
        return;
      }
    };
    if cnt_function_names == 0 {
      debug!("Generate the blank environment");
      reachable_envs.push(vm.env.clone());
    }

    info!("Number of initial environments: {}", reachable_envs.len());
    for env in &reachable_envs {
      let mut vm = match dummy_symvm_from_command(&cmd, callcode.clone()) {
        Ok(vm) => vm,
        Err(e) => {
          error!("Failed to initialize symbolic VM: {}", e);
          return;
        }
      };
      vm.env = env.clone();

      let num_initial_constraints = vm.constraints.len();

      let mut vms = vec![];
      let mut end = false;
      let mut found_calldataload = false;
      let mut prev_valid_op = "".to_string();
      let mut potential_reverts: Vec<(usize, Vec<Prop>)> = vec![];

      // ------------- Start symbolic execution -------------
      info!("Starting EVM symbolic execution...");
      while !end {
        loop {
          let prev_pc = vm.state.pc;
          let prev_addr = vm.state.contract.clone();
          // let do_size = vm.decoded_opcodes.len();
          let mut continue_flag = vm.exec1(
            &mut vms,
            if found_calldataload { args.max_num_iterations.unwrap_or(DEFAULT_MAX_NUM_ITERATIONS) } else { 1 },
          );
          let prev_op = vm.prev_opcode.clone(); //vm.decoded_opcodes[min(do_size, vm.decoded_opcodes.len() - 1)].clone();

          if !found_calldataload && prev_valid_op == "RETURN" && prev_op != "UNKNOWN" {
            vm.state.base_pc = prev_pc;
            debug!("Base PC set to 0x{:x}", prev_pc);
          }

          if prev_op != "UNKNOWN" {
            prev_valid_op = vm.prev_opcode.clone(); // vm.decoded_opcodes[min(do_size, vm.decoded_opcodes.len() - 1)].clone();
          }

          debug!("Addr: {}, PC: 0x{:x}, Opcode: {}", prev_addr, prev_pc, prev_op);

          if !found_calldataload {
            found_calldataload = prev_valid_op == "CALLDATALOAD";
          }

          if prev_op == "JUMPI" && is_function_sig_check_prop(vm.constraints.clone().last().unwrap()) {
            let (reachability, _) = solve_constraints(vm.state.pc, vm.constraints.clone()).await;
            if !reachability {
              debug!("Skip non-target function");
              continue_flag = false;
            }
          }

          if found_calldataload
            && (*prev_addr.clone() == Expr::SymAddr("entrypoint".to_string()))
            && (prev_op == "STOP" || prev_op == "RETURN")
          {
            let (reachability, _) = solve_constraints(vm.state.pc, vm.constraints.clone()).await;
            if reachability {
              debug!("REACHABLE {} @ PC=0x{:x}", prev_op, prev_pc);
              next_reachable_envs.push(vm.env.clone());
            } else {
              debug!("UNRECHABLE {} @ PC=0x{:x}", prev_op, prev_pc);
            }
          }

          if found_calldataload && prev_op == "REVERT" {
            potential_reverts.push((vm.state.pc, vm.constraints.clone()));
            end = true;
          }

          if continue_flag {
            if prev_pc == vm.state.pc {
              vm.state.pc = vm.state.pc + 1;
            }
          } else if (vm.state.pc >= opslen(&vm.state.code)) && vms.len() == 0 {
            end = true;
            break;
          } else if vms.len() == 0 && found_calldataload {
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
        //vm.constraints_raw_expr.clear();
        vm.state.pc += 1;
      }

      let mut tasks = vec![];
      for (pc, constraints) in potential_reverts {
        let constraints_clone = constraints.clone(); // Clone constraints to move into the task
        let task = task::spawn(async move {
          let (reachability, model) = solve_constraints(pc, constraints_clone).await;
          (pc, reachability, model)
        });
        tasks.push(task);
      }

      for task in tasks {
        let (pc, reachability, model) = task.await.unwrap(); // Await each task and unwrap the result
        if reachability {
          error!("\u{001b}[31mREACHABLE REVERT DETECTED @ PC=0x{:x}\u{001b}[0m", pc);
          if let Some(ref model_str) = model {
            let model = parse_z3_output(&model_str);

            let mut fname_to_args: HashMap<String, Vec<String>> = HashMap::new();
            for fname in &function_names_vec {
              fname_to_args.insert(fname.to_string(), vec![]);
            }

            for (k, v) in model.iter() {
              if k[..3] == *"arg" {
                let variable_id = k[3..].parse::<usize>().unwrap_or(0);
                if variable_id_to_function_name.contains_key(&variable_id) {
                  fname_to_args
                    .get_mut(variable_id_to_function_name.get(&variable_id).unwrap())
                    .unwrap()
                    .push(format!("{}=0x{},", k, v.trim_start_matches('0').to_string()));
                }
              }
            }

            let mut msg_model = "".to_string();
            for fname in &function_names_vec {
              if msg_model != "".to_string() {
                msg_model += " -> ";
              }
              let mut is_zero_args = true;
              msg_model += &(fname.to_string() + "(");
              for v in fname_to_args.get(fname).unwrap() {
                msg_model += v;
                is_zero_args = false;
              }
              if !is_zero_args {
                msg_model.pop();
              }
              msg_model.push(')');
            }

            error!("\u{001b}[31mmodel: {}\u{001b}[0m", msg_model);
          }

          //let mut msg = "** Constraints (Raw Format):=\n true".to_string();
          //for e in &vm.constraints_raw_expr {
          //  msg = msg + &format!(" && {}\n", *e);
          //}
          //debug!("{}", msg);
          break;
        } //else {
          //debug!("UNRECHABLE REVERT @ PC=0x{:x}", pc);
          //}
      }

      info!("Execution of `{}` completed.\n", function_name);
    }
    reachable_envs = next_reachable_envs;
    cnt_function_names += 1;
  }
  info!("Execution Time: {:?}", start_time.elapsed());
}
