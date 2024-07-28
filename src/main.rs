use env_logger;
use log::{error, info};
use std::cmp::min;
use std::error::Error;

use rhoevm::modules::cli::{build_calldata, vm0, SymbolicCommand};
use rhoevm::modules::evm::{abstract_contract, opslen};
use rhoevm::modules::format::{hex_byte_string, strip_0x};

use rhoevm::modules::transactions::init_tx;
use rhoevm::modules::types::{ContractCode, Expr, Prop, RuntimeCodeStruct, VM, W256};

fn dummy_symvm_from_command(cmd: &SymbolicCommand, calldata: (Expr, Vec<Prop>)) -> Result<VM, Box<dyn Error>> {
  let (miner, block_num, base_fee, prev_ran) = (Expr::SymAddr("miner".to_string()), W256(0, 0), W256(0, 0), W256(0, 0));

  let caller = Expr::SymAddr("caller".to_string());
  let ts = if let Some(t) = cmd.timestamp.clone() { Expr::Lit(t) } else { Expr::Timestamp };

  let callvalue = if let Some(v) = cmd.value.clone() { Expr::Lit(v) } else { Expr::TxValue };

  let contract = match (&cmd.rpc, &cmd.address, &cmd.code) {
    (_, _, Some(code)) => {
      let bs = hex_byte_string("bytes", &strip_0x(code));
      let mc = if cmd.create {
        ContractCode::InitCode(bs, Box::new(Expr::Mempty))
      } else {
        ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(bs))
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
  let mut cmd = <SymbolicCommand as std::default::Default>::default();
  //cmd.sig = Some("set".to_string());
  cmd.value = Some(W256(0, 0));
  cmd.calldata = Some("0xb8e010de".into());
  cmd.code = Some("6080604052348015600e575f80fd5b5060a78061001b5f395ff3fe6080604052348015600e575f80fd5b50600436106026575f3560e01c8063b8e010de14602a575b5f80fd5b60306032565b005b60646014101560425760416044565b5b565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52600160045260245ffdfea264697066735822122065b7f39f5ddce2e77d2ab00791f4d370969e41f919ccaaa8b11514e85980b54764736f6c63430008180033".into());
  let callcode = build_calldata(&cmd).unwrap();

  let mut vm = dummy_symvm_from_command(&cmd, callcode).unwrap();
  let mut vms = vec![];
  let mut prev_pc = 0;
  let mut do_size = 0;
  let mut end = false;
  let mut found_calldataload = false;
  let mut prev_op = "".to_string();
  let mut prev_valid_op = "".to_string();

  env_logger::init();

  while !end {
    loop {
      prev_pc = vm.state.pc;
      do_size = vm.decoded_opcodes.len();
      let continue_flag = vm.exec1(&mut vms, if found_calldataload { 32 } else { 1 });
      prev_op = vm.decoded_opcodes[min(do_size, vm.decoded_opcodes.len() - 1)].clone();

      if !found_calldataload && prev_valid_op == "RETURN" && prev_op != "UNKNOWN" {
        vm.state.base_pc = prev_pc;
        info!("set base_pc = 0x{:x}", prev_pc);
      }

      if prev_op != "UNKNOWN" {
        prev_valid_op = vm.decoded_opcodes[min(do_size, vm.decoded_opcodes.len() - 1)].clone();
      }

      info!("pc: 0x{:x}, op: {}", prev_pc, prev_op);

      if !found_calldataload {
        found_calldataload = prev_valid_op == "CALLDATALOAD";
      }

      if found_calldataload && prev_op == "REVERT" {
        let mut msg = "REVERT DETECTED\nConstraints (Raw Format):=\n true".to_string();
        for e in &vm.constraints_raw_expr {
          msg = msg + &format!(" && {}\n", *e);
        }
        error!("{}", msg);
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
      }
    }
    info!("---------------");
    vm.constraints.clear();
    vm.constraints_raw_expr.clear();
    vm.state.pc += 1;
  }
}
