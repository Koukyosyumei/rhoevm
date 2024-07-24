
use crate::modules::evm::initial_contract;
use crate::modules::types::{
  update_balance, Contract, ContractCode, Expr, ExprContractMap, RuntimeCodeStruct, VM, W256,
};

fn touch_account(pre_state: &mut ExprContractMap, addr: &Expr) {
  let new_account = new_account(); // Create new account using newAccount function
  pre_state.insert(addr.clone(), new_account);
}

fn new_account() -> Contract {
  let initial_code = RuntimeCodeStruct::ConcreteRuntimeCode(String::new().into());
  let runtime_code = ContractCode::RuntimeCode(initial_code);
  initial_contract(runtime_code)
}

fn setup_tx(origin: &Expr, coinbase: &Expr, gas_price: u64, gas_limit: u64, pre_state: &mut ExprContractMap) {
  let gas_cost = gas_price * gas_limit;

  // Adjust origin account in pre_state
  if let Some(account) = pre_state.get_mut(origin) {
    if let Some(n) = account.nonce {
      account.nonce = Some(n + 1)
    };
    if let Expr::Lit(b) = account.balance.clone() {
      account.balance = Expr::Lit(b - W256(gas_cost as u128, 0))
    };
  }

  // Touch accounts for origin and coinbase
  touch_account(pre_state, origin);
  touch_account(pre_state, coinbase);
}

pub fn init_tx(vm: &mut VM) -> &mut VM {
  let to_addr = vm.state.contract.clone();
  let origin = vm.tx.origin.clone();
  let gas_price = vm.tx.gasprice.clone();
  let gas_limit = vm.tx.gaslimit;
  let coinbase = vm.block.coinbase.clone();
  let value = vm.state.callvalue.clone();
  let to_contract = initial_contract(vm.state.code.clone());

  let pre_state = &mut vm.env.contracts.clone();
  setup_tx(&origin, &coinbase, gas_price.0 as u64, gas_limit, pre_state);

  let old_balance = pre_state.get(&to_addr).map_or(Expr::Lit(W256(0, 0)), |account| account.balance.clone());

  let creation = vm.tx.is_create;

  // Update state based on conditions
  let mut init_state = pre_state.clone();
  if creation {
    init_state.insert(to_addr.clone(), update_balance(to_contract, old_balance));
  } else {
    touch_account(&mut init_state, &to_addr);
  }

  if let Some(is) = init_state.get_mut(&origin) {
    if let Expr::Lit(b) = is.balance.clone() {
      if let Expr::Lit(v) = value.clone() {
        is.balance = Expr::Lit(b - v)
      }
    }
  }

  if let Some(is) = init_state.get_mut(&to_addr) {
    if let Expr::Lit(b) = is.balance.clone() {
      if let Expr::Lit(v) = value.clone() {
        is.balance = Expr::Lit(b + v)
      }
    }
  }

  vm.env.contracts = init_state;
  vm.tx.tx_reversion = pre_state.clone();

  vm
}
