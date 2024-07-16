use async_trait::async_trait;
use std::future::Future;
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use tokio::task::block_in_place;

use crate::modules::types::{Choose, EvmError, Expr, Query, TraceData, VMResult, EVM, VM};

pub enum Action<A> {
  Exec,
  Wait(Query),
  Ask(Choose),
  EVM(EVM<A>),
  IOAct(Box<dyn FnOnce() -> A + Send>),
}

pub type Stepper<A> = Program<Action<A>, A>;

pub struct Program<I, A> {
  actions: Vec<I>,
  result: Option<A>,
}

impl<A> Program<Action<A>, A> {
  pub fn new() -> Self {
    Program {
      actions: Vec::new(),
      result: None,
    }
  }

  pub fn exec() -> Stepper<VMResult> {
    let mut p = Program::new();
    p.actions.push(Action::Exec);
    p
  }

  pub fn run() -> Stepper<VM> {
    let mut p = Self::exec();
    p.actions.push(Action::EVM(EVM::Get));
    p
  }

  pub fn wait(query: Query) -> Stepper<()> {
    let mut p = Program::new();
    p.actions.push(Action::Wait(query));
    p
  }

  pub fn ask(choice: Choose) -> Stepper<()> {
    let mut p = Program::new();
    p.actions.push(Action::Ask(choice));
    p
  }

  pub fn evm(evm: EVM<A>) -> Stepper<A> {
    let mut p = Program::new();
    p.actions.push(Action::EVM(evm));
    p
  }

  pub fn evm_io<F: FnOnce() -> A + Send + 'static>(io_action: F) -> Stepper<A> {
    let mut p = Program::new();
    p.actions.push(Action::IOAct(Box::new(io_action)));
    p
  }

  pub fn exec_fully() -> Stepper<Result<Expr, EvmError>> {
    let mut p = Self::exec();
    p.actions.push(Action::EVM(()));
    p
  }

  pub fn run_fully() -> Stepper<VM> {
    let mut p = Self::run();
    p.actions.push(Action::EVM(()));
    p
  }

  pub fn enter(t: String) -> Stepper<()> {
    let mut p = Program::new();
    p.actions.push(Action::EVM(()));
    p
  }
}
