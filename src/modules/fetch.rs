use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;

use crate::modules::types::{Addr, Block, Contract, Expr, W256};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BlockNumber {
  Latest,
  BlockNumber(W256),
}

#[derive(Debug)]
enum RpcQuery {
  QueryCode(Addr),
  QueryBlock,
  QueryBalance(Addr),
  QueryNonce(Addr),
  QuerySlot(Addr, W256),
  QueryChainId,
}

type RpcInfo = Option<(BlockNumber, String)>;

fn rpc(method: &str, args: Vec<Value>) -> Value {
  json!({
      "jsonrpc": "2.0",
      "id": 1,
      "method": method,
      "params": args
  })
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RpcRequest {
  jsonrpc: String,
  id: u64,
  method: String,
  params: Vec<Value>,
}

impl RpcRequest {
  fn new(method: String, params: Vec<Value>) -> Self {
    RpcRequest {
      jsonrpc: "2.0".to_string(),
      id: 1,
      method,
      params,
    }
  }
}

trait ToRPC {
  fn to_rpc(&self) -> Value;
}

impl ToRPC for Addr {
  fn to_rpc(&self) -> Value {
    Value::String(self.to_string())
  }
}

/*
impl ToRPC for W256 {
  fn to_rpc(&self) -> Value {
    Value::String(self.0.clone())
  }
}*/

impl ToRPC for bool {
  fn to_rpc(&self) -> Value {
    Value::Bool(*self)
  }
}

impl ToRPC for BlockNumber {
  fn to_rpc(&self) -> Value {
    match self {
      BlockNumber::Latest => Value::String("latest".to_string()),
      BlockNumber::BlockNumber(n) => Value::String(n.to_string()),
    }
  }
}

fn read_text<T: FromStr>(text: String) -> Option<T> {
  text.parse().ok()
}

pub async fn fetch_query<'a>(
  n: BlockNumber,
  f: impl Fn(Value) -> Pin<Box<dyn Future<Output = Value> + Send + 'a>> + 'a,
  q: RpcQuery,
) -> Option<String> {
  match q {
    RpcQuery::QueryCode(addr) => {
      let response = f(rpc("eth_getCode", vec![addr.to_rpc(), n.to_rpc()])).await;
      response.as_str().map(|s| s.to_string())
    }
    RpcQuery::QueryNonce(addr) => {
      let response = f(rpc("eth_getTransactionCount", vec![addr.to_rpc(), n.to_rpc()])).await;
      response.as_str().and_then(|s| read_text(s.to_string()))
    }
    RpcQuery::QueryBlock => {
      panic!("illegal query")
      //let response = f(rpc("eth_getBlockByNumber", vec![n.to_rpc(), false.to_rpc()]));
      //response.as_object().and_then(|obj| parse_block(obj.clone()))
    }
    RpcQuery::QueryBalance(addr) => {
      let response = f(rpc("eth_getBalance", vec![addr.to_rpc(), n.to_rpc()])).await;
      response.as_str().and_then(|s| read_text(s.to_string()))
    }
    RpcQuery::QuerySlot(addr, slot) => {
      let response = f(rpc("eth_getStorageAt", vec![addr.to_rpc(), slot.to_rpc(), n.to_rpc()])).await;
      response.as_str().and_then(|s| read_text(s.to_string()))
    }
    RpcQuery::QueryChainId => {
      let response = f(rpc("eth_chainId", vec![n.to_rpc()])).await;
      response.as_str().and_then(|s| read_text(s.to_string()))
    }
  }
}

pub async fn fetch_query_block<'a>(
  n: BlockNumber,
  f: impl Fn(Value) -> Pin<Box<dyn Future<Output = Value> + Send + 'a>> + 'a,
  q: RpcQuery,
) -> Option<Block> {
  match q {
    RpcQuery::QueryBlock => {
      let response = f(rpc("eth_getBlockByNumber", vec![n.to_rpc(), false.to_rpc()])).await;
      response.as_object().and_then(|obj| parse_block(obj.clone()))
    }
    _ => panic!("illegal query"),
  }
}

fn parse_block(json: serde_json::Map<String, Value>) -> Option<Block> {
  let coinbase = json.get("miner")?.as_str().and_then(|s| read_text(s.to_string()));
  let timestamp = json.get("timestamp")?.as_str().and_then(|s| read_text(s.to_string()))?;
  let number = json.get("number")?.as_str().and_then(|s| read_text(s.to_string()))?;
  let gaslimit = json.get("gasLimit")?.as_str().and_then(|s| read_text(s.to_string()))?;
  let base_fee = json.get("baseFeePerGas").and_then(|v| v.as_str().and_then(|s| read_text(s.to_string())));
  let mixhash = json.get("mixHash").and_then(|v| v.as_str().and_then(|s| read_text(s.to_string())));
  let prev_randao = json.get("prevRandao").and_then(|v| v.as_str().and_then(|s| read_text(s.to_string())));
  let difficulty = json.get("difficulty").and_then(|v| v.as_str().and_then(|s| read_text(s.to_string())));

  let prd = match (prev_randao, mixhash, difficulty) {
    (Some(p), _, _) => p,
    (None, Some(mh), Some(0x0)) => mh,
    (None, Some(_), Some(d)) => d,
    _ => return None,
  };

  Some(Block {
    coinbase: Expr::LitAddr(coinbase.unwrap_or_default()),
    time_stamp: Expr::Lit(timestamp),
    number,
    gaslimit,
    base_fee: base_fee.unwrap_or_default(),
    prev_randao: prd,
    max_code_size: todo!(),
    schedule: todo!(),
  })
}

pub async fn fetch_with_session_(url: &str, client: &Client, req: Value) -> Option<Value> {
  // Create a request with JSON body
  let response = client
    .post(url)
    .json(&req) // Serialize `req` to JSON and set as request body
    .send()
    .await // Await the asynchronous send operation
    .ok()? // Return `None` if send fails, otherwise continue
    .json::<Value>() // Deserialize the response body as JSON
    .await // Await the asynchronous JSON deserialization
    .ok()?; // Return `None` if deserialization fails, otherwise continue

  // Extract the "result" field from the response JSON object and clone it
  response.get("result").cloned()
}

pub async fn fetch_with_session(url: &str, client: &Client, req: Value) -> Value {
  fetch_with_session_(url, client, req).await.unwrap_or_default()
}

pub async fn fetch_contract_with_session(n: BlockNumber, url: &str, addr: Addr, client: &Client) -> Option<Contract> {
  let fetch_fn = |req: Value| -> Pin<Box<dyn Future<Output = Value> + Send>> {
    let af = fetch_with_session(url, client, req);
    Box::pin(af)
  };
  let fetch = |q: RpcQuery| fetch_query(n, fetch_fn, q);

  let code = fetch.clone()(RpcQuery::QueryCode(addr.clone())).await?;
  let nonce = fetch.clone()(RpcQuery::QueryNonce(addr.clone())).await?;
  let balance = fetch.clone()(RpcQuery::QueryBalance(addr.clone())).await?;

  Some(Contract {
    nonce: todo!(),
    balance: todo!(),
    external: true,
    code: todo!(),
    storage: todo!(),
    orig_storage: todo!(),
    codehash: todo!(),
    op_idx_map: todo!(),
    code_ops: todo!(),
  })
}

pub async fn fetch_slot_with_session(
  n: BlockNumber,
  url: &str,
  client: &Client,
  addr: Addr,
  slot: W256,
) -> Option<W256> {
  todo!()
  /*
  let fetch_fn = |req: Value| -> Pin<Box<dyn Future<Output = Value> + Send>> {
    let af = fetch_with_session(url, client, req);
    Box::pin(af)
  };
  fetch_query(n, fetch_fn, RpcQuery::QuerySlot(addr, slot)).await
  */
}

pub async fn fetch_block_with_session(n: BlockNumber, url: &str, client: &Client) -> Option<Block> {
  let fetch_fn = |req: Value| -> Pin<Box<dyn Future<Output = Value> + Send>> {
    let af = fetch_with_session(url, client, req);
    Box::pin(af)
  };
  fetch_query_block(n, fetch_fn, RpcQuery::QueryBlock).await
}

pub async fn fetch_block_from(n: BlockNumber, url: &str) -> Option<Block> {
  let client = Client::new();
  fetch_block_with_session(n, url, &client).await
}

pub async fn fetch_contract_from(n: BlockNumber, url: &str, addr: Addr) -> Option<Contract> {
  let client = Client::new();
  fetch_contract_with_session(n, url, addr, &client).await
}

pub async fn fetch_slot_from(n: BlockNumber, url: &str, addr: Addr, slot: W256) -> Option<W256> {
  let client = Client::new();
  fetch_slot_with_session(n, url, &client, addr, slot).await
}

pub async fn fetch_chain_id_from(url: &str) -> Option<W256> {
  todo!()
  /*
  let client = Client::new();
  fetch_query(
    BlockNumber::Latest,
    |req| fetch_with_session(url, &client, req).await.unwrap_or_default(),
    RpcQuery::QueryChainId,
  )*/
}
