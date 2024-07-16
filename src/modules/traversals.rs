// Module: evm::traversals
// Description: Generic traversal functions for Expr datatypes

use async_trait::async_trait;
use futures::future::join_all;
use std::collections::HashMap;
use std::iter::Sum;
use std::ops::Add;

use crate::modules::types::{Contract, ContractCode, Expr, Prop, RuntimeCodeStruct};

pub fn go_prop<B, F>(f: &F, p: Prop) -> B
where
  F: Fn(&Expr) -> B,
  B: Add<B, Output = B> + Clone + Default,
{
  match p {
    Prop::PBool(_) => B::default(),
    Prop::PEq(a, b) | Prop::PLT(a, b) | Prop::PGT(a, b) | Prop::PGEq(a, b) | Prop::PLEq(a, b) => {
      fold_expr(&f, B::default(), &a) + fold_expr(&f, B::default(), &b)
    }
    Prop::PNeg(a) => go_prop(f, *a),
    Prop::PAnd(a, b) | Prop::POr(a, b) | Prop::PImpl(a, b) => go_prop(f, *a) + go_prop(f, *b),
  }
}

// Function to recursively fold over a Prop type
pub fn fold_prop<B, F>(f: &F, acc: B, p: Prop) -> B
where
  F: Fn(&Expr) -> B,
  B: Add<B, Output = B> + Clone + Default,
{
  acc + go_prop(f, p)
}

// Function to recursively fold over an Expr of EContract type
pub fn fold_econtract<F, B>(f: &F, acc: B, g: &Expr) -> B
where
  F: Fn(&Expr) -> B,
  B: Add<B, Output = B> + Clone + Default,
{
  match g {
    Expr::GVar(_) => f(g),
    Expr::C {
      code, storage, balance, ..
    } => acc + fold_code(f, code) + fold_expr(f, B::default(), storage) + fold_expr(f, B::default(), balance),
    _ => panic!("unexpected expr"),
  }
}

// Function to recursively fold over a Contract type
pub fn fold_contract<F, B>(f: &F, acc: B, c: &Contract) -> B
where
  F: Fn(&Expr) -> B,
  B: Add<B, Output = B> + Clone + Default,
{
  acc
    + fold_code(f, &c.code)
    + fold_expr(f, B::default(), &c.storage)
    + fold_expr(f, B::default(), &c.orig_storage)
    + fold_expr(f, B::default(), &c.balance)
}

// Function to recursively fold over a ContractCode type
pub fn fold_code<F, B>(f: &F, code: &ContractCode) -> B
where
  F: Fn(&Expr) -> B,
  B: Add<B, Output = B> + Clone + Default,
{
  match code {
    ContractCode::RuntimeCode(runtime_code) => match runtime_code {
      RuntimeCodeStruct::ConcreteRuntimeCode(_) => B::default(),
      RuntimeCodeStruct::SymbolicRuntimeCode(c) => {
        c.iter().fold(B::default(), |acc, expr| acc + fold_expr(f, B::default(), expr))
      }
    },
    ContractCode::InitCode(_, buf) => fold_expr(f, B::default(), buf),
    ContractCode::UnKnownCode(addr) => fold_expr(f, B::default(), addr),
  }
}

fn go_expr<F, B>(f: &F, acc: B, expr: &Expr) -> B
where
  F: Fn(&Expr) -> B,
  B: Add<B, Output = B> + Clone + Default,
{
  match expr {
    // literals & variables
    Expr::Lit(_) | Expr::LitByte(_) | Expr::Var(_) | Expr::GVar(_) => f(expr),

    // contracts
    Expr::C { .. } => fold_econtract(f, acc, expr),

    // bytes
    Expr::IndexWord(a, b) | Expr::EqByte(a, b) => f(expr) + go_expr(f, acc, a) + go_expr(f, acc, b),

    Expr::JoinBytes(vec) => {
      f(expr)
        + go_expr(f, acc, &vec[0])
        + go_expr(f, acc, &vec[1])
        + go_expr(f, acc, &vec[2])
        + go_expr(f, acc, &vec[3])
        + go_expr(f, acc, &vec[4])
        + go_expr(f, acc, &vec[5])
        + go_expr(f, acc, &vec[6])
        + go_expr(f, acc, &vec[7])
        + go_expr(f, acc, &vec[8])
        + go_expr(f, acc, &vec[9])
        + go_expr(f, acc, &vec[10])
        + go_expr(f, acc, &vec[11])
        + go_expr(f, acc, &vec[12])
        + go_expr(f, acc, &vec[13])
        + go_expr(f, acc, &vec[14])
        + go_expr(f, acc, &vec[15])
        + go_expr(f, acc, &vec[16])
        + go_expr(f, acc, &vec[17])
        + go_expr(f, acc, &vec[18])
        + go_expr(f, acc, &vec[19])
        + go_expr(f, acc, &vec[20])
        + go_expr(f, acc, &vec[21])
        + go_expr(f, acc, &vec[22])
        + go_expr(f, acc, &vec[23])
        + go_expr(f, acc, &vec[24])
        + go_expr(f, acc, &vec[25])
        + go_expr(f, acc, &vec[26])
        + go_expr(f, acc, &vec[27])
        + go_expr(f, acc, &vec[28])
        + go_expr(f, acc, &vec[29])
        + go_expr(f, acc, &vec[30])
        + go_expr(f, acc, &vec[31])
    }

    // control flow
    Expr::Success(a, _, c, d) => {
      f(expr)
        + a.iter().fold(B::default(), |acc, p| acc + fold_prop(f, B::default(), p.clone()))
        + go_expr(f, acc, c)
        + d.keys().fold(B::default(), |acc, k| acc + fold_expr(f, B::default(), k))
        + d.values().fold(B::default(), |acc, v| acc + fold_econtract(f, B::default(), v))
    }
    Expr::Failure(a, _, FailureType::Revert(c)) => {
      f(expr) + a.iter().fold(B::default(), |acc, p| acc + fold_prop(f, B::default(), p.clone())) + go_expr(f, acc, c)
    }
    Expr::Failure(a, _, _) => {
      f(expr) + a.iter().fold(B::default(), |acc, p| acc + fold_prop(f, B::default(), p.clone()))
    }
    Expr::Partial(a, _, _) => {
      f(expr) + a.iter().fold(B::default(), |acc, p| acc + fold_prop(f, B::default(), p.clone()))
    }
    Expr::ITE(a, b, c) => f(expr) + go_expr(f, acc, a) + go_expr(f, acc, b) + go_expr(f, acc, c),

    // integers
    Expr::Add(a, b)
    | Expr::Sub(a, b)
    | Expr::Mul(a, b)
    | Expr::Div(a, b)
    | Expr::SDiv(a, b)
    | Expr::Mod(a, b)
    | Expr::SMod(a, b)
    | Expr::Exp(a, b)
    | Expr::SEx(a, b)
    | Expr::Min(a, b)
    | Expr::Max(a, b) => f(expr) + go_expr(f, acc, a) + go_expr(f, acc, b),

    Expr::AddMod(a, b, c) | Expr::MulMod(a, b, c) => f(expr) + go_expr(f, acc, a) + go_expr(f, acc, b),

    // booleans
    Expr::LT(a, b)
    | Expr::GT(a, b)
    | Expr::LEq(a, b)
    | Expr::GEq(a, b)
    | Expr::SLT(a, b)
    | Expr::SGT(a, b)
    | Expr::Eq(a, b) => f(expr) + go_expr(f, acc, a) + go_expr(f, acc, b),

    Expr::IsZero(a) | Expr::Not(a) => f(expr) + go_expr(f, acc, a),

    // bits
    Expr::And(a, b) | Expr::Or(a, b) | Expr::Xor(a, b) | Expr::SHL(a, b) | Expr::SHR(a, b) | Expr::SAR(a, b) => {
      f(expr) + go_expr(f, acc, a) + go_expr(f, acc, b)
    }

    // Hashes
    Expr::Keccak(a) | Expr::SHA256(a) => f(expr) + go_expr(f, acc, a),

    // block context
    Expr::Origin
    | Expr::Coinbase
    | Expr::Timestamp
    | Expr::BlockNumber
    | Expr::PrevRandao
    | Expr::GasLimit
    | Expr::ChainId
    | Expr::BaseFee => f(expr),

    Expr::BlockHash(a) => f(expr) + go_expr(f, acc, a),

    // tx context
    Expr::TxValue => f(expr),

    // frame context
    Expr::Gas(_, _) | Expr::Balance { .. } => f(expr),

    // code
    Expr::CodeSize(a) | Expr::CodeHash(a) => f(expr) + go_expr(f, acc, a),

    // logs
    Expr::LogEntry(a, b, c) => {
      f(expr) + go_expr(f, acc, a) + b.iter().fold(B::default(), |acc, v| acc + go_expr(f, acc, v)) + go_expr(f, acc, c)
    }
  }
}

// Recursively folds a given function over a given expression
pub fn fold_expr<F, B>(f: &F, acc: B, expr: &Expr) -> B
where
  F: Fn(&Expr) -> B,
  B: Add<B, Output = B> + Default + Clone,
{
  acc.clone() + go_expr(f, acc.clone(), expr)
}

#[async_trait]
pub trait ExprMappable {
  async fn map_expr_m<F, Fut>(&self, f: F) -> Expr
  where
    F: Fn(&Expr) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Expr> + Send;
}

#[async_trait]
impl ExprMappable for Expr {
  async fn map_expr_m<F, Fut>(&self, f: F) -> Expr
  where
    F: Fn(&Expr) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Expr> + Send,
  {
    match self {
      Expr::Lit(a) => f(&Expr::Lit(*a)).await,
      Expr::LitByte(a) => f(&Expr::LitByte(*a)).await,
      Expr::Var(a) => f(&Expr::Var(*a)).await,
      Expr::GVar(s) => f(&Expr::GVar(*s)).await,

      // Addresses
      Expr::C {
        code,
        storage,
        balance,
        nonce,
      } => map_econtract_m(f, self.clone()).await,

      Expr::LitAddr(a) => f(&Expr::LitAddr(*a)).await,
      Expr::SymAddr(a) => f(&Expr::SymAddr(*a)).await,
      Expr::WAddr(a) => {
        let a = a.map_expr_m(&f).await;
        f(&Expr::WAddr(Box::new(a))).await
      }

      // Bytes
      Expr::IndexWord(a, b) => {
        f(&Expr::IndexWord(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::EqByte(a, b) => {
        f(&Expr::EqByte(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }

      Expr::JoinBytes(vec) => {
        let mut parts = join_all(vec![
          vec[0].map_expr_m(&f),
          vec[1].map_expr_m(&f),
          vec[2].map_expr_m(&f),
          vec[3].map_expr_m(&f),
          vec[4].map_expr_m(&f),
          vec[5].map_expr_m(&f),
          vec[6].map_expr_m(&f),
          vec[7].map_expr_m(&f),
          vec[8].map_expr_m(&f),
          vec[9].map_expr_m(&f),
          vec[10].map_expr_m(&f),
          vec[11].map_expr_m(&f),
          vec[12].map_expr_m(&f),
          vec[13].map_expr_m(&f),
          vec[14].map_expr_m(&f),
          vec[15].map_expr_m(&f),
          vec[16].map_expr_m(&f),
          vec[17].map_expr_m(&f),
          vec[18].map_expr_m(&f),
          vec[19].map_expr_m(&f),
          vec[20].map_expr_m(&f),
          vec[21].map_expr_m(&f),
          vec[22].map_expr_m(&f),
          vec[23].map_expr_m(&f),
          vec[24].map_expr_m(&f),
          vec[25].map_expr_m(&f),
          vec[26].map_expr_m(&f),
          vec[27].map_expr_m(&f),
          vec[28].map_expr_m(&f),
          vec[29].map_expr_m(&f),
          vec[30].map_expr_m(&f),
          vec[31].map_expr_m(&f),
        ])
        .await;
        f(&Expr::JoinBytes(vec![
          parts.remove(0),
          parts.remove(1),
          parts.remove(2),
          parts.remove(3),
          parts.remove(4),
          parts.remove(5),
          parts.remove(6),
          parts.remove(7),
          parts.remove(8),
          parts.remove(9),
          parts.remove(10),
          parts.remove(11),
          parts.remove(12),
          parts.remove(13),
          parts.remove(14),
          parts.remove(15),
          parts.remove(16),
          parts.remove(17),
          parts.remove(18),
          parts.remove(19),
          parts.remove(20),
          parts.remove(21),
          parts.remove(22),
          parts.remove(23),
          parts.remove(24),
          parts.remove(25),
          parts.remove(26),
          parts.remove(27),
          parts.remove(28),
          parts.remove(29),
          parts.remove(30),
          parts.remove(31),
        ]))
        .await
      }

      // Control Flow
      Expr::Failure(a, b, c) => {
        let a = join_all(a.iter().map(|x| map_prop_m(f, x.clone()))).await;
        f(&Expr::Failure(a, *b, *c)).await
      }
      Expr::Partial(a, b, c) => {
        let a = join_all(a.iter().map(|x| map_prop_m(f, x.clone()))).await;
        f(&Expr::Partial(a, *b, *c)).await
      }
      Expr::Success(a, b, c, d) => {
        let a = join_all(a.iter().map(|x| map_prop_m(f, x.clone()))).await;
        let c = c.map_expr_m(&f).await;
        let d = join_all(d.iter().map(|(k, v)| {
          let k = f(k);
          let v = map_econtract_m(f, v.clone());
          async move { (k.await, v.await) }
        }))
        .await
        .into_iter()
        .collect::<HashMap<_, _>>();
        f(&Expr::Success(a, *b, Box::new(c), d)).await
      }
      Expr::ITE(a, b, c) => {
        let res = join_all(vec![a.map_expr_m(&f), b.map_expr_m(&f), c.map_expr_m(&f)]).await.into_iter().collect();
        f(&Expr::ITE(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
          Box::new(c.map_expr_m(&f).await),
        ))
        .await
      }

      // Integers
      Expr::Add(a, b) => {
        f(&Expr::Add(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::Sub(a, b) => {
        f(&Expr::Sub(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::Mul(a, b) => {
        f(&Expr::Mul(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::Div(a, b) => {
        f(&Expr::Div(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::SDiv(a, b) => {
        f(&Expr::SDiv(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::Mod(a, b) => {
        f(&Expr::Mod(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::SMod(a, b) => {
        f(&Expr::SMod(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::AddMod(a, b, c) => {
        f(&Expr::AddMod(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
          Box::new(c.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::MulMod(a, b, c) => {
        f(&Expr::MulMod(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
          Box::new(c.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::Exp(a, b) => {
        f(&Expr::Exp(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::SEx(a, b) => {
        f(&Expr::SEx(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::Min(a, b) => {
        f(&Expr::Min(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::Max(a, b) => {
        f(&Expr::Max(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }

      // Booleans
      Expr::LT(a, b) => {
        f(&Expr::LT(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::GT(a, b) => {
        f(&Expr::GT(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::LEq(a, b) => {
        f(&Expr::LEq(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::GEq(a, b) => {
        f(&Expr::GEq(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::SLT(a, b) => {
        f(&Expr::SLT(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::SGT(a, b) => {
        f(&Expr::SGT(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::Eq(a, b) => {
        f(&Expr::Eq(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::IsZero(a) => {
        let a = a.map_expr_m(&f).await;
        f(&Expr::IsZero(Box::new(a))).await
      }

      // Bits
      Expr::And(a, b) => {
        f(&Expr::And(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::Or(a, b) => {
        f(&Expr::Or(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::Xor(a, b) => {
        f(&Expr::Xor(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::Not(a) => {
        let a = a.map_expr_m(&f).await;
        f(&Expr::Not(Box::new(a))).await
      }
      Expr::SHL(a, b) => {
        f(&Expr::SHL(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::SHR(a, b) => {
        f(&Expr::SHR(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::SAR(a, b) => {
        f(&Expr::SAR(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }

      // Hashes
      Expr::Keccak(a) => {
        let a = a.map_expr_m(&f).await;
        f(&Expr::Keccak(Box::new(a))).await
      }
      Expr::SHA256(a) => {
        let a = a.map_expr_m(&f).await;
        f(&Expr::SHA256(Box::new(a))).await
      }

      // Block Context
      Expr::Origin => f(&Expr::Origin).await,
      Expr::Coinbase => f(&Expr::Coinbase).await,
      Expr::Timestamp => f(&Expr::Timestamp).await,
      Expr::BlockNumber => f(&Expr::BlockNumber).await,
      Expr::PrevRandao => f(&Expr::PrevRandao).await,
      Expr::GasLimit => f(&Expr::GasLimit).await,
      Expr::ChainId => f(&Expr::ChainId).await,
      Expr::BaseFee => f(&Expr::BaseFee).await,
      Expr::BlockHash(a) => {
        let a = a.map_expr_m(&f).await;
        f(&Expr::BlockHash(Box::new(a))).await
      }

      // Tx Context
      Expr::TxValue => f(&Expr::TxValue).await,

      // Frame Context
      Expr::Gas(a) => f(&Expr::Gas(*a)).await,
      Expr::Balance(a) => {
        let a = a.map_expr_m(&f).await;
        f(&Expr::Balance(Box::new(a))).await
      }

      // Code
      Expr::CodeSize(a) => {
        let a = a.map_expr_m(&f).await;
        f(&Expr::CodeSize(Box::new(a))).await
      }
      Expr::CodeHash(a) => {
        let a = a.map_expr_m(&f).await;
        f(&Expr::CodeHash(Box::new(a))).await
      }

      // Logs
      Expr::LogEntry(a, b, c) => {
        f(&Expr::LogEntry(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
          Box::new(c.map_expr_m(&f).await),
        ))
        .await
      }

      // Storage
      Expr::ConcreteStore(b) => f(&Expr::ConcreteStore(*b)).await,
      Expr::AbstractStore(a, b) => f(&Expr::AbstractStore(*a, *b)).await,
      Expr::SLoad(a, b) => {
        f(&Expr::SLoad(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::SStore(a, b, c) => {
        f(&Expr::SStore(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
          Box::new(c.map_expr_m(&f).await),
        ))
        .await
      }

      // Buffers
      Expr::ConcreteBuf(a) => f(&Expr::ConcreteBuf(*a)).await,
      Expr::AbstractBuf(a) => f(&Expr::AbstractBuf(*a)).await,
      Expr::ReadWord(a, b) => {
        f(&Expr::ReadWord(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::ReadByte(a, b) => {
        f(&Expr::ReadByte(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::WriteWord(a, b, c) => {
        f(&Expr::WriteWord(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
          Box::new(c.map_expr_m(&f).await),
        ))
        .await
      }
      Expr::WriteByte(a, b, c) => {
        f(&Expr::WriteByte(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
          Box::new(c.map_expr_m(&f).await),
        ))
        .await
      }

      Expr::CopySlice(a, b, c, d, e) => {
        let (a, b, c, d, e) = join_all(vec![
          a.map_expr_m(&f),
          b.map_expr_m(&f),
          c.map_expr_m(&f),
          d.map_expr_m(&f),
          e.map_expr_m(&f),
        ])
        .await
        .into_iter()
        .collect();
        f(&Expr::CopySlice(
          Box::new(a.map_expr_m(&f).await),
          Box::new(b.map_expr_m(&f).await),
          Box::new(c.map_expr_m(&f).await),
          Box::new(d[3].clone()),
          Box::new(e[4].clone()),
        ))
        .await
      }
      Expr::BufLength(a) => {
        let a = a.map_expr_m(&f).await;
        f(&Expr::BufLength(Box::new(a))).await
      }
      _ => panic!("unuexpected expr"),
    }
  }
}

// MapPropM function
async fn map_prop_m<F, Fut>(f: F, prop: Prop) -> Prop
where
  F: Fn(&Expr) -> Fut + Send + Sync,
  Fut: std::future::Future<Output = Expr> + Send,
{
  match prop {
    Prop::PBool(b) => Prop::PBool(b),
    Prop::PEq(a, b) => Prop::PEq(a.map_expr_m(&f).await, b.map_expr_m(&f).await),
    // Implement other Prop variants similarly
    _ => todo!(),
  }
}

// MapPropM_ function
async fn map_prop_m_<F, Fut>(f: F, prop: Prop) -> ()
where
  F: Fn(&Expr) -> Fut + Send + Sync,
  Fut: std::future::Future<Output = ()> + Send,
{
  async fn f_upd<F, Fut>(action: F, expr: &Expr) -> Expr
  where
    F: Fn(&Expr) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = ()> + Send,
  {
    action(expr).await;
    expr.clone()
  }

  let f_upd_fn = |expr: &Expr| f_upd(&f, expr);
  let _ = map_prop_m(f_upd_fn, prop).await;
}

// MapEContractM function
async fn map_econtract_m<F, Fut>(f: F, expr: Expr) -> Expr
where
  F: Fn(&Expr) -> Fut + Send + Sync,
  Fut: std::future::Future<Output = Expr> + Send,
{
  match expr {
    Expr::GVar(_) => expr,
    Expr::C(code, storage, balance, nonce) => {
      let code = map_code_m(&f, code).await;
      let storage = storage.map_expr_m(&f).await;
      let balance = balance.map_expr_m(&f).await;
      Expr::C(Box::new(code), Box::new(storage), Box::new(balance), nonce)
    }
    // Handle other Expr variants
    _ => todo!(),
  }
}

// MapContractM function
async fn map_contract_m<F, Fut>(f: F, contract: Contract) -> Contract
where
  F: Fn(&Expr) -> Fut + Send + Sync,
  Fut: std::future::Future<Output = Expr> + Send,
{
  let code = map_code_m(&f, contract.code).await;
  let storage = contract.storage.map_expr_m(&f).await;
  let orig_storage = contract.orig_storage.map_expr_m(&f).await;
  let balance = contract.balance.map_expr_m(&f).await;
  Contract {
    code,
    storage,
    orig_storage,
    balance,
    ..contract
  }
}

// MapCodeM function
async fn map_code_m<F, Fut>(f: F, code: ContractCode) -> ContractCode
where
  F: Fn(&Expr) -> Fut + Send + Sync,
  Fut: std::future::Future<Output = Expr> + Send,
{
  match code {
    ContractCode::UnKnownCode(expr) => ContractCode::UnKnownCode(Box::new(f(&expr).await)),
    ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(expr)) => {
      ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(expr))
    }
    ContractCode::RuntimeCode(RuntimeCodeStruct::SymbolicRuntimeCode(exprs)) => {
      let exprs = join_all(exprs.into_iter().map(|expr| expr.map_expr_m(&f))).await;
      ContractCode::RuntimeCode(RuntimeCodeStruct::SymbolicRuntimeCode(exprs))
    }
    ContractCode::InitCode(bytes, buf) => {
      let buf = buf.map_expr_m(&f).await;
      ContractCode::InitCode(bytes, Box::new(buf))
    }
  }
}

// Define the TraversableTerm trait and its implementations
trait TraversableTerm {
  fn map_term<F>(&self, f: F) -> Self
  where
    F: Fn(&Expr) -> Expr;

  fn fold_term<C>(&self, f: &dyn Fn(&Expr) -> C, acc: C) -> C
  where
    C: std::iter::Sum;
}

impl TraversableTerm for Expr {
  fn map_term<F>(&self, f: F) -> Self
  where
    F: Fn(&Expr) -> Expr,
  {
    // Implement map_term for Expr
    todo!()
  }

  fn fold_term<C>(&self, f: &dyn Fn(&Expr) -> C, acc: C) -> C
  where
    C: std::iter::Sum,
  {
    // Implement fold_term for Expr
    todo!()
  }
}

impl TraversableTerm for Prop {
  fn map_term<F>(&self, f: F) -> Self
  where
    F: Fn(&Expr) -> Expr,
  {
    // Implement map_term for Prop
    todo!()
  }

  fn fold_term<C>(&self, f: &dyn Fn(&Expr) -> C, acc: C) -> C
  where
    C: std::iter::Sum,
  {
    // Implement fold_term for Prop
    todo!()
  }
}
