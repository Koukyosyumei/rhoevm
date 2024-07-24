use async_trait::async_trait;
use futures::Future;
use std::sync::Arc;

use crate::modules::types::VM;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Config {
  pub dump_queries: bool,
  pub dump_exprs: bool,
  pub dump_end_states: bool,
  pub debug: bool,
  pub abst_refine_arith: bool,
  pub abst_refine_mem: bool,
  pub dump_trace: bool,
  pub num_cex_fuzz: i64,
  pub only_cex_fuzz: bool,
  pub decompose_storage: bool,
}

impl Default for Config {
  fn default() -> Self {
    Config {
      dump_queries: false,
      dump_exprs: false,
      dump_end_states: false,
      debug: false,
      abst_refine_arith: false,
      abst_refine_mem: false,
      dump_trace: false,
      num_cex_fuzz: 10,
      only_cex_fuzz: false,
      decompose_storage: true,
    }
  }
}

pub struct Env {
  pub config: Config,
}

impl Default for Env {
  fn default() -> Self {
    Env { config: Config::default() }
  }
}

#[async_trait]
pub trait TTY {
  async fn write_output(&self, text: &str);
  async fn write_err(&self, text: &str);
}

#[async_trait]
impl<T: TTY + Sync + Send> TTY for Arc<T> {
  async fn write_output(&self, text: &str) {
    TTY::write_output(&**self, text).await;
  }

  async fn write_err(&self, text: &str) {
    TTY::write_err(&**self, text).await;
  }
}

#[async_trait]
pub trait ReadConfig {
  async fn read_config(&self) -> Config;
}

#[async_trait]
impl ReadConfig for Env {
  async fn read_config(&self) -> Config {
    self.config.clone()
  }
}

pub type App = Arc<Env>;

#[async_trait]
pub trait WriteTraceDapp {
  async fn write_trace_dapp(&self, dapp: DappInfo, vm: VM);
}

#[async_trait]
pub trait WriteTrace {
  async fn write_trace(&self, vm: VM);
}

pub struct DappInfo;

#[async_trait]
impl WriteTraceDapp for App {
  async fn write_trace_dapp(&self, _dapp: DappInfo, _vm: VM) {
    let conf = self.read_config().await;
    if conf.dump_trace {
      // Write to "VM.trace" file (use appropriate async file writing library)
    }
  }
}

#[async_trait]
impl WriteTrace for App {
  async fn write_trace(&self, _vm: VM) {
    let conf = self.read_config().await;
    if conf.dump_trace {
      // Write to "VM.trace" file (use appropriate async file writing library)
    }
  }
}

pub async fn run_app<F, Fut>(app: App, f: F) -> Fut::Output
where
  F: FnOnce(App) -> Fut,
  Fut: Future + Send,
{
  f(app).await
}
