use crate::modules::types::{VMResult, VM};

pub fn exec(vm: &mut VM) -> VMResult {
  while vm.result.is_none() {
    vm.exec1();
  }
  vm.result.clone().unwrap()
}
