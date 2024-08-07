use std::error::Error;

use rhoevm::modules::cli::{build_calldata, vm0, SymbolicCommand};
use rhoevm::modules::evm::abstract_contract;
use rhoevm::modules::format::{hex_byte_string, strip_0x};

//use rhoevm::modules::solvers::{with_solvers, Solver};
use rhoevm::modules::transactions::init_tx;
use rhoevm::modules::types::{ContractCode, Expr, Memory, Prop, RuntimeCodeStruct, VM, W256};

const MAX_NUM_ITERATIONS: u32 = 1;

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

#[test]
fn test_vm_exec_1() {
  let mut cmd = <SymbolicCommand as std::default::Default>::default();
  cmd.code = Some("608060405234801561000f575f80fd5b506101b18061001d5f395ff3fe608060405234801561000f575f80fd5b506004361061003f575f3560e01c80632a1afcd91461004357806360fe47b1146100615780636d4ce63c1461007d575b5f80fd5b61004b61009b565b60405161005891906100dc565b60405180910390f35b61007b60048036038101906100769190610123565b6100a0565b005b6100856100bc565b60405161009291906100dc565b60405180910390f35b5f5481565b805f8190555060645f5410156100b9576100b861014e565b5b50565b5f8054905090565b5f819050919050565b6100d6816100c4565b82525050565b5f6020820190506100ef5f8301846100cd565b92915050565b5f80fd5b610102816100c4565b811461010c575f80fd5b50565b5f8135905061011d816100f9565b92915050565b5f60208284031215610138576101376100f5565b5b5f6101458482850161010f565b91505092915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52600160045260245ffdfea2646970667358221220f5cf3af85892477d264b1cc67141f37e00f71d638b17b6446bb28e85e3ccb30364736f6c63430008180033".into());
  let callcode = build_calldata(&cmd).unwrap();
  let mut vm = dummy_symvm_from_command(&cmd, callcode).unwrap();
  let mut vms = vec![];

  assert_eq!(vm.state.pc, 0);
  vm.exec1(&mut vms, MAX_NUM_ITERATIONS);
  assert_eq!(vm.decoded_opcodes.len(), 1);
  assert_eq!(vm.decoded_opcodes, vec!["PUSH1 Lit(0x80)"]);
  assert_eq!(vm.state.stack.get(0).unwrap().to_string(), "Lit(0x80)");
  assert_eq!(vm.state.pc, 2);

  vm.exec1(&mut vms, MAX_NUM_ITERATIONS);
  assert_eq!(vm.state.pc, 4);
  assert_eq!(vm.decoded_opcodes.len(), 2);
  assert_eq!(vm.decoded_opcodes, vec!["PUSH1 Lit(0x80)", "PUSH1 Lit(0x40)"]);
  assert_eq!(vm.state.stack.get(1).unwrap().to_string(), "Lit(0x40)");

  vm.exec1(&mut vms, MAX_NUM_ITERATIONS);
  assert_eq!(vm.state.pc, 5);
  assert_eq!(vm.decoded_opcodes.len(), 3);
  assert_eq!(vm.decoded_opcodes, vec!["PUSH1 Lit(0x80)", "PUSH1 Lit(0x40)", "MSTORE"]);
  let mut mem = vec![0; 96];
  mem[0x40 + 31] = 0x80;
  assert_eq!(vm.state.memory, Memory::ConcreteMemory(mem));
}

#[test]
fn test_vm_op2() {
  let mut cmd = <SymbolicCommand as std::default::Default>::default();
  cmd.code = Some("01".into());
  let callcode = build_calldata(&cmd).unwrap();
  let mut vm = dummy_symvm_from_command(&cmd, callcode).unwrap();
  let mut vms = vec![];

  vm.state.stack.push(Box::new(Expr::Lit(W256(1, 0))));
  vm.state.stack.push(Box::new(Expr::Lit(W256(2, 0))));
  vm.exec1(&mut vms, MAX_NUM_ITERATIONS);
  assert_eq!(vm.state.stack.len(), 1);
  assert_eq!(vm.state.stack.get(0).unwrap().to_string(), "Add(Lit(0x2), Lit(0x1))");
}

#[test]
fn test_vm_opsha3() {
  let mut cmd = <SymbolicCommand as std::default::Default>::default();
  cmd.code = Some("20".into());
  let callcode = build_calldata(&cmd).unwrap();
  let mut vm = dummy_symvm_from_command(&cmd, callcode).unwrap();
  let mut vms = vec![];

  vm.state.stack.push(Box::new(Expr::Lit(W256(2, 0))));
  vm.state.stack.push(Box::new(Expr::Lit(W256(0x40, 0))));
  let mut mem = vec![0; 96];
  mem[0x40] = 0x80;
  mem[0x41] = 0x70;
  vm.state.memory = Memory::ConcreteMemory(mem);

  vm.exec1(&mut vms, MAX_NUM_ITERATIONS);
  assert_eq!(vm.state.stack.len(), 1);
  assert_eq!(vm.state.stack.get(0).unwrap().to_string(), "Keccak(ConcreteBuf([80, 70]))");
}

#[test]
fn test_vm_opswap() {
  let mut cmd = <SymbolicCommand as std::default::Default>::default();
  cmd.code = Some("92".into());
  let callcode = build_calldata(&cmd).unwrap();
  let mut vm = dummy_symvm_from_command(&cmd, callcode).unwrap();
  let mut vms = vec![];

  vm.state.stack.push(Box::new(Expr::Lit(W256(1, 0))));
  vm.state.stack.push(Box::new(Expr::Lit(W256(2, 0))));
  vm.state.stack.push(Box::new(Expr::Lit(W256(3, 0))));
  vm.state.stack.push(Box::new(Expr::Lit(W256(4, 0))));

  vm.exec1(&mut vms, MAX_NUM_ITERATIONS);
  assert_eq!(vm.state.stack.len(), 4);
  assert_eq!(vm.state.stack.get(0).unwrap().to_string(), "Lit(0x4)");
  assert_eq!(vm.state.stack.get(1).unwrap().to_string(), "Lit(0x2)");
  assert_eq!(vm.state.stack.get(2).unwrap().to_string(), "Lit(0x3)");
  assert_eq!(vm.state.stack.get(3).unwrap().to_string(), "Lit(0x1)");
}

#[test]
fn test_vm_opdup() {
  let mut cmd = <SymbolicCommand as std::default::Default>::default();
  cmd.code = Some("81".into());
  let callcode = build_calldata(&cmd).unwrap();
  let mut vm = dummy_symvm_from_command(&cmd, callcode).unwrap();
  let mut vms = vec![];

  vm.state.stack.push(Box::new(Expr::Lit(W256(1, 0))));
  vm.state.stack.push(Box::new(Expr::Lit(W256(2, 0))));

  vm.exec1(&mut vms, MAX_NUM_ITERATIONS);
  assert_eq!(vm.decoded_opcodes, vec!["DUP2"]);
  assert_eq!(vm.state.stack.len(), 3);
  assert_eq!(vm.state.stack.get(0).unwrap().to_string(), "Lit(0x1)");
  assert_eq!(vm.state.stack.get(1).unwrap().to_string(), "Lit(0x2)");
  assert_eq!(vm.state.stack.get(2).unwrap().to_string(), "Lit(0x1)");
}

#[test]
fn test_vm_oppc() {
  let mut cmd = <SymbolicCommand as std::default::Default>::default();
  cmd.code = Some("000000000058".into());
  let callcode = build_calldata(&cmd).unwrap();
  let mut vm = dummy_symvm_from_command(&cmd, callcode).unwrap();
  let mut vms = vec![];

  vm.state.pc = 5;
  vm.exec1(&mut vms, MAX_NUM_ITERATIONS);
  assert_eq!(vm.decoded_opcodes, vec!["PC"]);
  assert_eq!(vm.state.stack.len(), 1);
  assert_eq!(vm.state.stack.get(0).unwrap().to_string(), "Lit(0x5)");
}

#[test]
fn test_vm_jumpi_onlythen() {
  let mut cmd = <SymbolicCommand as std::default::Default>::default();
  cmd.code = Some("6080608014600957005B00".into());
  let callcode = build_calldata(&cmd).unwrap();
  let mut vm = dummy_symvm_from_command(&cmd, callcode).unwrap();
  let mut vms = vec![];

  vm.exec1(&mut vms, MAX_NUM_ITERATIONS); // PUSH 0x80 (0x60 0x80)
  vm.exec1(&mut vms, MAX_NUM_ITERATIONS); // PUSH 0x80 (0x60 0x80)
  vm.exec1(&mut vms, MAX_NUM_ITERATIONS); // EQ        (0x14)
  vm.exec1(&mut vms, MAX_NUM_ITERATIONS); // PUSH 09   (0x60 0x09)
  assert!(vm.exec1(&mut vms, MAX_NUM_ITERATIONS)); // JUMPI     (0x57)
  assert_eq!(vm.state.pc, 9);
}

#[test]
fn test_vm_jumpi_onlyelse() {
  let mut cmd = <SymbolicCommand as std::default::Default>::default();
  cmd.code = Some("6080604014600957005B00".into());
  let callcode = build_calldata(&cmd).unwrap();
  let mut vm = dummy_symvm_from_command(&cmd, callcode).unwrap();
  let mut vms = vec![];

  vm.exec1(&mut vms, MAX_NUM_ITERATIONS); // PUSH 0x80 (0x60 0x80)
  vm.exec1(&mut vms, MAX_NUM_ITERATIONS); // PUSH 0x40 (0x60 0x40)
  vm.exec1(&mut vms, MAX_NUM_ITERATIONS); // EQ        (0x14)
  vm.exec1(&mut vms, MAX_NUM_ITERATIONS); // PUSH 09   (0x60 0x09)
  vm.exec1(&mut vms, MAX_NUM_ITERATIONS); // JUMPI     (0x57)
  assert_eq!(vm.state.pc, 9);
  assert_eq!(vms.len(), 1);
  assert_eq!(vms[0].state.pc, 8);
}
