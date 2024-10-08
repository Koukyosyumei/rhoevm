use env_logger;
use getopts::Options;
use log::{debug, error, info, warn};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::time;
use std::{env, process};
use tokio::task;

use rhoevm::modules::abi::{selector, AbiType, Sig};
use rhoevm::modules::cli::{build_calldata, vm0, SymbolicCommand};
use rhoevm::modules::evm::{abstract_contract, opslen, solve_constraints};
use rhoevm::modules::expr::is_function_sig_check_prop;
use rhoevm::modules::format::{hex_byte_string, strip_0x};
use rhoevm::modules::smt::parse_z3_output;
use rhoevm::modules::transactions::init_tx;
use rhoevm::modules::types::{
  ByteString, ContractCode, Env, EvmError, Expr, Prop, RuntimeCodeStruct, VMResult, EXPR_MEMPTY, VM, W256,
};

const DEFAULT_MAX_NUM_ITERATIONS: u32 = 10;
const DEFAULT_IGNORED_REVERT_LISTS: [u8; 1] = [0x11];
const DEFAULT_REVERT_STATEMENT: &str = "Panic(uint256)";

#[derive(Debug)]
struct Args {
  bin_file_path: String,
  function_signatures: String,
  max_num_iterations: Option<u32>,
  verbose_level: Option<String>,
  ignored_panic_codes: HashSet<u8>,
  execute_entire_binary: bool,
  stop_at_the_first_reachable_revert: bool,
}

fn print_usage(program: &str, opts: &Options) {
  let brief = format!("Usage: {} BINARY_FILE_PATH FUNCTION_SIGNATURES [options]", program);
  print!("{}", opts.usage(&brief));
  process::exit(0);
}

fn parse_args() -> Args {
  let args: Vec<String> = env::args().collect();
  let program = args[0].clone();

  let mut opts = Options::new();
  opts.optopt("i", "max_num_iterations", "Maximum number of iterations for loop", "MAX_NUM_ITER");
  opts.optopt("v", "verbose", "Level of verbose", "LEVEL");
  opts.optopt("p", "ignored_panic_codes", "List of ignored panic codes", "IGNORED_PANIC_CODES");
  opts.optflag(
    "e",
    "execute_entire_binary",
    "Execute the entire binary code. If not set, forcibly skip to the runtime code",
  );
  opts.optflag("s", "stop_at_the_first_reachable_revert", "Halt the execution when a reachable revert is found");
  opts.optflag("h", "help", "Print this help menu");

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

  let bin_file_path = if !matches.free.is_empty() {
    matches.free[0].clone()
  } else {
    print_usage(&program, &opts);
    panic!("Error: CONTRACT_NAME is required.")
  };

  let function_signatures = if matches.free.len() > 1 {
    matches.free[1].clone()
  } else {
    print_usage(&program, &opts);
    panic!("Error: At least one FUNCTION_NAME is required.");
  };

  let max_num_iterations = if let Some(i) = matches.opt_str("i") {
    Some(i.parse::<u32>().unwrap_or(DEFAULT_MAX_NUM_ITERATIONS))
  } else {
    None
  };

  let verbose_level = matches.opt_str("v");
  let ignored_panic_codes: HashSet<u8> = if let Some(s) = matches.opt_str("p") {
    s.split('|').map(|s| s.parse::<u8>().unwrap()).collect()
  } else {
    HashSet::from_iter(DEFAULT_IGNORED_REVERT_LISTS.to_vec().iter().cloned())
  };

  let execute_entire_binary = matches.opt_present("e");
  let stop_at_the_first_reachable_revert = matches.opt_present("s");

  Args {
    bin_file_path,
    function_signatures,
    max_num_iterations,
    verbose_level,
    ignored_panic_codes,
    execute_entire_binary,
    stop_at_the_first_reachable_revert,
  }
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

fn dummy_symvm_from_command(cmd: &SymbolicCommand, calldata: (Expr, Vec<Box<Prop>>)) -> Result<VM, Box<dyn Error>> {
  let (miner, block_num, base_fee, prev_ran) = (Expr::SymAddr("miner".to_string()), W256(0, 0), W256(0, 0), W256(0, 0));

  let caller = Expr::SymAddr("caller".to_string());
  let ts = if let Some(t) = cmd.timestamp.clone() { Expr::Lit(t) } else { Expr::Timestamp };

  let callvalue = if let Some(v) = cmd.value.clone() { Expr::Lit(v) } else { Expr::TxValue };

  let contract = match (&cmd.rpc, &cmd.address, &cmd.code) {
    (_, _, Some(code)) => {
      let bs = hex_byte_string("bytes", &strip_0x(code));
      let mc = if cmd.create {
        ContractCode::InitCode(Box::new(bs), Box::new(EXPR_MEMPTY))
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
  info!("Loading binary from file: {}", args.bin_file_path);
  let mut f = match File::open(args.bin_file_path.clone()) {
    Ok(file) => file,
    Err(e) => {
      error!("Failed to open file '{}': {}", args.bin_file_path, e);
      return;
    }
  };
  let mut binary = String::new();
  if let Err(e) = f.read_to_string(&mut binary) {
    error!("Failed to read file '{}': {}", args.bin_file_path, e);
    return;
  }
  debug!("File '{}' read successfully.", args.bin_file_path);

  let panic_bytes: ByteString = selector(DEFAULT_REVERT_STATEMENT);

  // utility variables
  let mut normalized_function_names_vec: Vec<String> = vec![];
  let mut function_names_vec: Vec<String> = vec![];
  let mut signature_to_name: HashMap<String, String> = HashMap::new();
  let mut cnt_function_signatures = 0;
  let mut reachable_envs: Vec<Env> = vec![];
  let mut num_known_variables = 0;
  let mut abi_map: HashMap<String, Vec<AbiType>> = HashMap::new();
  let mut variable_id_to_function_signature: HashMap<usize, String> = HashMap::new();

  // abi map
  let function_signatures_vec: Vec<String> = args.function_signatures.split('|').map(|s| s.to_string()).collect();
  for function_signature in &function_signatures_vec {
    if let Some(start) = function_signature.find('(') {
      if let Some(end) = function_signature.find(')') {
        let fname = &function_signature[..start];
        function_names_vec.push(fname.to_string());
        let types_str = &function_signature[start + 1..end];
        if types_str == "" {
          abi_map.insert(fname.to_string(), vec![]);
        } else {
          abi_map.insert(fname.to_string(), types_str.split(',').map(|s| AbiType::from_solidity_type(s)).collect());
        }

        let mut normalized_function_signature = fname.to_string() + "(";
        for t in abi_map[fname].clone() {
          normalized_function_signature += &format!("{},", t);
        }
        if abi_map[fname].len() != 0 {
          normalized_function_signature.pop();
          normalized_function_signature.push(')');
        } else {
          normalized_function_signature += ")";
        }
        normalized_function_names_vec.push(normalized_function_signature.clone());
        signature_to_name.insert(normalized_function_signature.to_string(), fname.to_string());
      }
    }
  }

  let pattern_push0_codecopy_push0_return_invalid_push1_0x80_push1_0x40 = "5f395ff3fe60806040";
  let skip_to_runtimecode = !args.execute_entire_binary;
  let target_binary = if skip_to_runtimecode {
    if let Some(index) = binary.find(pattern_push0_codecopy_push0_return_invalid_push1_0x80_push1_0x40) {
      binary[index + 10..].to_string()
    } else {
      binary.clone()
    }
  } else {
    binary.clone()
  };

  // ------------- MAIN PART: May rhoevm light your path to bug-free code -------------
  let start_time = time::Instant::now();
  for function_signature in &normalized_function_names_vec {
    info!("Target function signature: {}", function_signature);
    let mut next_reachable_envs: Vec<Env> = vec![];

    // ------------- Build Calldata -------------
    let fname = signature_to_name[function_signature].clone();
    let mut cmd = <SymbolicCommand as std::default::Default>::default();
    cmd.sig = Some(Sig::new(&function_signature, &abi_map[&fname]));
    cmd.value = Some(W256(0, 0));
    cmd.code = Some(target_binary.clone().into()); // Some(binary.clone().into());
    let callcode = match build_calldata(&cmd, num_known_variables) {
      Ok(calldata) => calldata,
      Err(e) => {
        error!("Failed to build calldata: {}", e);
        return;
      }
    };
    debug!("Calldata: {}", callcode.0);
    info!("Calldata constructed successfully for function '{}'", function_signature);

    for i in 1 + num_known_variables..=num_known_variables + abi_map[&fname].len() {
      variable_id_to_function_signature.insert(i, fname.to_string());
    }
    num_known_variables += abi_map[&fname].len();

    // ------------- Initialize VM -------------
    let vm = match dummy_symvm_from_command(&cmd, callcode.clone()) {
      Ok(vm) => vm,
      Err(e) => {
        error!("Failed to initialize symbolic VM: {}", e);
        return;
      }
    };
    if cnt_function_signatures == 0 {
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
      let mut found_calldataload = false || skip_to_runtimecode;
      let mut prev_valid_op = "".to_string();

      let mut potential_envs: Vec<(usize, Vec<Box<Prop>>, Env)> = vec![];
      let mut potential_reverts: Vec<(usize, Vec<Box<Prop>>)> = vec![];

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
            let (reachability, _, _) = solve_constraints(vm.state.pc, vm.constraints.clone()).await;
            if !reachability {
              debug!("Skip non-target function @ PC = 0x{:x}", vm.state.pc);
              continue_flag = false;
            }
          }

          if found_calldataload
            && (*prev_addr.clone() == Expr::SymAddr("entrypoint".to_string()))
            && (prev_op == "STOP" || prev_op == "RETURN")
          {
            potential_envs.push((vm.state.pc, vm.constraints.clone(), vm.env.clone()));
            // let (reachability, _) = solve_constraints(vm.state.pc, vm.constraints.clone()).await;
          }

          if found_calldataload && prev_op == "REVERT" {
            let mut ignore: bool = false;
            if vm.result.clone().is_some() {
              if let VMResult::VMFailure(e) = vm.result.clone().unwrap() {
                if let EvmError::Revert(r) = e {
                  if let Expr::ConcreteBuf(b) = *r {
                    if panic_bytes.len() < b.len() {
                      for i in 1..panic_bytes.len() {
                        if panic_bytes[i] != b[i] {
                          ignore = true;
                          break;
                        }
                      }
                      if !ignore {
                        ignore = args.ignored_panic_codes.contains(&b[b.len() - 1]);
                      }
                    }
                  }
                }
              }
            }
            if !ignore {
              potential_reverts.push((vm.state.pc, vm.constraints.clone()));
            }
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

      debug!("Start SMT Solving...");
      let mut tasks_check_envs = vec![];
      for (pc, constraints, env) in potential_envs {
        let constraints_clone = constraints.clone(); // Clone constraints to move into the task
        let task = task::spawn(async move {
          let (reachability, _, _) = solve_constraints(pc, constraints_clone).await;
          (pc, reachability, env)
        });
        tasks_check_envs.push(task);
      }

      for task in tasks_check_envs {
        let (_, reachability, env) = task.await.unwrap();
        if reachability {
          //debug!("REACHABLE {} @ PC=0x{:x}", prev_op, prev_pc);
          next_reachable_envs.push(env.clone());
        } else {
          //debug!("UNRECHABLE {} @ PC=0x{:x}", prev_op, prev_pc);
        }
      }

      let mut tasks_check_revert = vec![];
      for (pc, constraints) in potential_reverts {
        let constraints_clone = constraints.clone(); // Clone constraints to move into the task
        let task = task::spawn(async move {
          let (reachability, smt_file, model) = solve_constraints(pc, constraints_clone).await;
          (pc, reachability, smt_file, model)
        });
        tasks_check_revert.push(task);
      }

      for task in tasks_check_revert {
        let (pc, reachability, smt_file, model) = task.await.unwrap(); // Await each task and unwrap the result
        if reachability {
          error!("\u{001b}[31mREACHABLE REVERT DETECTED @ PC=0x{:x} (SEE {})\u{001b}[0m", pc, smt_file);
          if let Some(ref model_str) = model {
            let model = parse_z3_output(&model_str);

            let mut fname_to_args: HashMap<String, Vec<String>> = HashMap::new();
            for fname in &function_names_vec {
              fname_to_args.insert(fname.to_string(), vec![]);
            }

            for (k, v) in model.iter() {
              if k.len() >= 4 && k[..3] == *"arg" {
                let variable_id = k[3..].parse::<usize>().unwrap_or(0);
                if variable_id_to_function_signature.contains_key(&variable_id) {
                  let v_trimmed = v.trim_start_matches('0').to_string();
                  fname_to_args
                    .get_mut(variable_id_to_function_signature.get(&variable_id).unwrap())
                    .unwrap()
                    .push(format!("{}=0x{},", k, if v_trimmed.is_empty() { "0" } else { &v_trimmed }));
                }
              }
              if k.len() >= 12 && k[..11] == *"symaddr_arg" {
                let variable_id = k[11..].parse::<usize>().unwrap_or(0);
                if variable_id_to_function_signature.contains_key(&variable_id) {
                  // let v_trimmed = v.trim_start_matches('0').to_string();
                  fname_to_args
                    .get_mut(variable_id_to_function_signature.get(&variable_id).unwrap())
                    .unwrap()
                    .push(format!("{}=0x{},", k, v));
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
          if args.stop_at_the_first_reachable_revert {
            break;
          }
        } //else {
          //debug!("UNRECHABLE REVERT @ PC=0x{:x}", pc);
          //}
      }
      info!("Execution of '{}' completed.\n", function_signature);
    }
    reachable_envs = next_reachable_envs;
    cnt_function_signatures += 1;
  }
  info!("Execution Time: {:?}", start_time.elapsed());
}
