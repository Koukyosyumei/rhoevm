// Module: evm::traversals
// Description: Generic traversal functions for Expr datatypes

use std::ops::Add;

use crate::modules::types::{Contract, ContractCode, EvmError, Expr, Prop, RuntimeCodeStruct};

// Function to recursively fold over a Prop type
pub fn fold_prop<B>(f: &mut dyn FnMut(&Expr) -> B, acc: B, p: Prop) -> B
where
  B: Add<B, Output = B> + Clone + Default,
{
  fn go_prop<B>(f: &mut dyn FnMut(&Expr) -> B, p: Prop) -> B
  where
    B: Add<B, Output = B> + Clone + Default,
  {
    match p {
      Prop::PBool(_) => B::default(),
      Prop::PEq(a, b) | Prop::PLT(a, b) | Prop::PGT(a, b) | Prop::PGEq(a, b) | Prop::PLEq(a, b) => {
        let fa = fold_expr(f, B::default(), &a);
        let fb = fold_expr(f, B::default(), &b);
        fa + fb
      }
      Prop::PNeg(a) => go_prop(f, *a),
      Prop::PAnd(a, b) | Prop::POr(a, b) | Prop::PImpl(a, b) => go_prop(f, *a) + go_prop(f, *b),
    }
  }

  acc + go_prop(f, p)
}

// Function to recursively fold over an Expr of EContract type
pub fn fold_econtract<B>(f: &mut dyn FnMut(&Expr) -> B, acc: B, g: &Expr) -> B
where
  B: Add<B, Output = B> + Clone + Default,
{
  match g {
    Expr::GVar(_) => f(g),
    Expr::C { code, storage, balance, .. } => {
      acc + fold_code(f, code) + fold_expr(f, B::default(), storage) + fold_expr(f, B::default(), balance)
    }
    _ => panic!("unexpected expr"),
  }
}

// Function to recursively fold over a Contract type
pub fn fold_contract<F, B>(f: &mut F, acc: B, c: &Contract) -> B
where
  F: FnMut(&Expr) -> B,
  B: Add<B, Output = B> + Clone + Default,
{
  acc
    + fold_code(f, &c.code)
    + fold_expr(f, B::default(), &c.storage)
    + fold_expr(f, B::default(), &c.orig_storage)
    + fold_expr(f, B::default(), &c.balance)
}

// Function to recursively fold over a ContractCode type
pub fn fold_code<B>(f: &mut dyn FnMut(&Expr) -> B, code: &ContractCode) -> B
where
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

fn go_expr<B>(f: &mut dyn FnMut(&Expr) -> B, acc: B, expr: Expr) -> B
where
  B: Add<B, Output = B> + Clone + Default,
{
  match expr.clone() {
    // Expr::Mempty => B::default(),
    // literals & variables
    Expr::Lit(_) | Expr::LitByte(_) | Expr::Var(_) | Expr::GVar(_) => f(&expr),

    // contracts
    Expr::C { .. } => fold_econtract(f, acc.clone(), &expr),

    // bytes
    Expr::IndexWord(a, b) | Expr::EqByte(a, b) => f(&expr) + go_expr(f, acc.clone(), *a) + go_expr(f, acc.clone(), *b),

    Expr::JoinBytes(vec) => {
      f(&expr)
        + go_expr(f, acc.clone(), vec[0].clone())
        + go_expr(f, acc.clone(), vec[1].clone())
        + go_expr(f, acc.clone(), vec[2].clone())
        + go_expr(f, acc.clone(), vec[3].clone())
        + go_expr(f, acc.clone(), vec[4].clone())
        + go_expr(f, acc.clone(), vec[5].clone())
        + go_expr(f, acc.clone(), vec[6].clone())
        + go_expr(f, acc.clone(), vec[7].clone())
        + go_expr(f, acc.clone(), vec[8].clone())
        + go_expr(f, acc.clone(), vec[9].clone())
        + go_expr(f, acc.clone(), vec[10].clone())
        + go_expr(f, acc.clone(), vec[11].clone())
        + go_expr(f, acc.clone(), vec[12].clone())
        + go_expr(f, acc.clone(), vec[13].clone())
        + go_expr(f, acc.clone(), vec[14].clone())
        + go_expr(f, acc.clone(), vec[15].clone())
        + go_expr(f, acc.clone(), vec[16].clone())
        + go_expr(f, acc.clone(), vec[17].clone())
        + go_expr(f, acc.clone(), vec[18].clone())
        + go_expr(f, acc.clone(), vec[19].clone())
        + go_expr(f, acc.clone(), vec[20].clone())
        + go_expr(f, acc.clone(), vec[21].clone())
        + go_expr(f, acc.clone(), vec[22].clone())
        + go_expr(f, acc.clone(), vec[23].clone())
        + go_expr(f, acc.clone(), vec[24].clone())
        + go_expr(f, acc.clone(), vec[25].clone())
        + go_expr(f, acc.clone(), vec[26].clone())
        + go_expr(f, acc.clone(), vec[27].clone())
        + go_expr(f, acc.clone(), vec[28].clone())
        + go_expr(f, acc.clone(), vec[29].clone())
        + go_expr(f, acc.clone(), vec[30].clone())
        + go_expr(f, acc.clone(), vec[31].clone())
    }

    // control flow
    Expr::Success(a, _, c, mut d) => {
      f(&expr)
        + a.iter().fold(B::default(), |acc, p| acc + fold_prop(f, B::default(), p.clone()))
        + go_expr(f, acc, *c)
        + d.keys().fold(B::default(), |acc, k| acc + fold_expr(f, B::default(), k))
        + d.values().fold(B::default(), |acc, v| acc + fold_econtract(f, B::default(), v))
    }
    Expr::Failure(a, _, EvmError::Revert(c)) => {
      f(&expr) + a.iter().fold(B::default(), |acc, p| acc + fold_prop(f, B::default(), p.clone())) + go_expr(f, acc, *c)
    }
    Expr::Failure(a, _, _) => {
      f(&expr) + a.iter().fold(B::default(), |acc, p| acc + fold_prop(f, B::default(), p.clone()))
    }
    Expr::Partial(a, _, _) => {
      f(&expr) + a.iter().fold(B::default(), |acc, p| acc + fold_prop(f, B::default(), p.clone()))
    }
    Expr::ITE(a, b, c) => f(&expr) + go_expr(f, acc.clone(), *a) + go_expr(f, acc.clone(), *b) + go_expr(f, acc, *c),

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
    | Expr::Max(a, b) => f(&expr) + go_expr(f, acc.clone(), *a) + go_expr(f, acc, *b),

    Expr::AddMod(a, b, c) | Expr::MulMod(a, b, c) => {
      f(&expr) + go_expr(f, acc.clone(), *a) + go_expr(f, acc.clone(), *b) + go_expr(f, acc, *c)
    }

    // booleans
    Expr::LT(a, b)
    | Expr::GT(a, b)
    | Expr::LEq(a, b)
    | Expr::GEq(a, b)
    | Expr::SLT(a, b)
    | Expr::SGT(a, b)
    | Expr::Eq(a, b) => f(&expr) + go_expr(f, acc.clone(), *a) + go_expr(f, acc, *b),

    Expr::IsZero(a) | Expr::Not(a) => f(&expr) + go_expr(f, acc, *a),

    // bits
    Expr::And(a, b) | Expr::Or(a, b) | Expr::Xor(a, b) | Expr::SHL(a, b) | Expr::SHR(a, b) | Expr::SAR(a, b) => {
      f(&expr) + go_expr(f, acc.clone(), *a) + go_expr(f, acc, *b)
    }

    // Hashes
    Expr::Keccak(a) | Expr::SHA256(a) => f(&expr) + go_expr(f, acc, *a),

    // block context
    Expr::Origin
    | Expr::Coinbase
    | Expr::Timestamp
    | Expr::BlockNumber
    | Expr::PrevRandao
    | Expr::GasLimit
    | Expr::ChainId
    | Expr::BaseFee => f(&expr),

    Expr::BlockHash(a) => f(&expr) + go_expr(f, acc, *a),

    // tx context
    Expr::TxValue => f(&expr),

    // frame context
    Expr::Gas(_) | Expr::Balance { .. } => f(&expr),

    // code
    Expr::CodeSize(a) | Expr::CodeHash(a) => f(&expr) + go_expr(f, acc, *a),

    // logs
    // todo: f e <> (go a) <> (go b) <> (foldl (<>) mempty (fmap f c))
    Expr::LogEntry(a, b, c) => f(&expr) + go_expr(f, acc.clone(), *a) + go_expr(f, acc.clone(), *b),

    Expr::LitAddr(_) => f(&expr),
    Expr::WAddr(a) => f(&expr) + go_expr(f, acc, *a),
    Expr::SymAddr(_) => f(&expr),

    Expr::ConcreteStore(_) | Expr::AbstractStore(_, _) => f(&expr),
    Expr::SLoad(a, b) => f(&expr) + go_expr(f, acc.clone(), *a) + go_expr(f, acc.clone(), *b),
    Expr::SStore(a, b, c) => {
      f(&expr) + go_expr(f, acc.clone(), *a) + go_expr(f, acc.clone(), *b) + go_expr(f, acc.clone(), *c)
    }

    Expr::ConcreteBuf(_) | Expr::AbstractBuf(_) => f(&expr),
    Expr::ReadByte(a, b) | Expr::ReadWord(a, b) => f(&expr) + go_expr(f, acc.clone(), *a) + go_expr(f, acc.clone(), *b),
    Expr::WriteByte(a, b, c) | Expr::WriteWord(a, b, c) => {
      f(&expr) + go_expr(f, acc.clone(), *a) + go_expr(f, acc.clone(), *b) + go_expr(f, acc.clone(), *c)
    }

    Expr::CopySlice(a, b, c, d, g) => {
      f(&expr)
        + go_expr(f, acc.clone(), *a)
        + go_expr(f, acc.clone(), *b)
        + go_expr(f, acc.clone(), *c)
        + go_expr(f, acc.clone(), *d)
        + go_expr(f, acc.clone(), *g)
    }

    // BufLength
    Expr::BufLength(a) => f(&expr) + go_expr(f, acc, *a),

    _ => panic!("{}", format!("`go_expr` does not support {}", expr.to_string())),
  }
}

// Recursively folds a given function over a given expression
pub fn fold_expr<B>(f: &mut dyn FnMut(&Expr) -> B, acc: B, expr: &Expr) -> B
where
  B: Add<B, Output = B> + Default + Clone,
{
  if *expr == Expr::Mempty {
    acc.clone()
  } else {
    acc.clone() + go_expr(f, acc.clone(), expr.clone())
  }
}

pub trait ExprMappable {
  fn map_expr_m(&self, f: &mut dyn FnMut(&Expr) -> Expr) -> Expr;
}

impl ExprMappable for Expr {
  fn map_expr_m(&self, f: &mut dyn FnMut(&Expr) -> Expr) -> Expr {
    match self {
      //Expr::Mempty => Expr::Mempty,
      Expr::Lit(a) => f(&Expr::Lit(a.clone())),
      Expr::LitByte(a) => f(&Expr::LitByte(*a)),
      Expr::Var(a) => f(&Expr::Var(a.clone())),
      Expr::GVar(s) => f(&Expr::GVar(s.clone())),

      // Addresses
      Expr::C { code: _, storage: _, balance: _, nonce: _ } => map_econtract_m(f, self.clone()),

      Expr::LitAddr(a) => f(&Expr::LitAddr(a.clone())),
      Expr::SymAddr(a) => f(&Expr::SymAddr(a.clone())),
      Expr::WAddr(a) => {
        let a = a.map_expr_m(f);
        f(&Expr::WAddr(Box::new(a)))
      }

      // Bytes
      Expr::IndexWord(a, b) => {
        let af = a.map_expr_m(f);
        let bf = b.map_expr_m(f);
        f(&Expr::IndexWord(Box::new(af), Box::new(bf)))
      }
      Expr::EqByte(a, b) => {
        let af = a.map_expr_m(f);
        let bf = b.map_expr_m(f);
        f(&Expr::EqByte(Box::new(af), Box::new(bf)))
      }

      Expr::JoinBytes(vec) => {
        let mut parts = vec![
          vec[0].map_expr_m(f),
          vec[1].map_expr_m(f),
          vec[2].map_expr_m(f),
          vec[3].map_expr_m(f),
          vec[4].map_expr_m(f),
          vec[5].map_expr_m(f),
          vec[6].map_expr_m(f),
          vec[7].map_expr_m(f),
          vec[8].map_expr_m(f),
          vec[9].map_expr_m(f),
          vec[10].map_expr_m(f),
          vec[11].map_expr_m(f),
          vec[12].map_expr_m(f),
          vec[13].map_expr_m(f),
          vec[14].map_expr_m(f),
          vec[15].map_expr_m(f),
          vec[16].map_expr_m(f),
          vec[17].map_expr_m(f),
          vec[18].map_expr_m(f),
          vec[19].map_expr_m(f),
          vec[20].map_expr_m(f),
          vec[21].map_expr_m(f),
          vec[22].map_expr_m(f),
          vec[23].map_expr_m(f),
          vec[24].map_expr_m(f),
          vec[25].map_expr_m(f),
          vec[26].map_expr_m(f),
          vec[27].map_expr_m(f),
          vec[28].map_expr_m(f),
          vec[29].map_expr_m(f),
          vec[30].map_expr_m(f),
          vec[31].map_expr_m(f),
        ];
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
      }

      // Control Flow
      Expr::Failure(a, b, c) => {
        let a = (a.iter().map(|x| map_prop_m(f, x.clone()))).into_iter().collect();
        f(&Expr::Failure(a, b.clone(), c.clone()))
      }
      Expr::Partial(a, b, c) => {
        let a = (a.iter().map(|x| map_prop_m(f, x.clone()))).into_iter().collect();
        f(&Expr::Partial(a, b.clone(), c.clone()))
      }
      Expr::Success(a, b, c, d) => {
        let a_ = (a.iter().map(|x| map_prop_m(f, x.clone()))).into_iter().collect();
        let c_ = c.map_expr_m(f);
        //let mut r = vec![];
        /*
        for (k, v) in d.clone().iter() {
          let fk = f(k);
          let fv = map_econtract_m(f, v.clone());
          r.push((fk, fv));
        }
        let d_: ExprExprMap = ExprExprMap::from(r.into_iter().collect());
        */
        f(&Expr::Success(a_, b.clone(), Box::new(c_), d.clone()))
      }
      Expr::ITE(a, b, c) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        let cm = c.map_expr_m(f);
        f(&Expr::ITE(Box::new(am), Box::new(bm), Box::new(cm)))
      }

      // Integers
      Expr::Add(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::Add(Box::new(am), Box::new(bm)))
      }
      Expr::Sub(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::Sub(Box::new(am), Box::new(bm)))
      }
      Expr::Mul(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::Mul(Box::new(am), Box::new(bm)))
      }
      Expr::Div(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::Div(Box::new(am), Box::new(bm)))
      }
      Expr::SDiv(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::SDiv(Box::new(am), Box::new(bm)))
      }
      Expr::Mod(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::Mod(Box::new(am), Box::new(bm)))
      }
      Expr::SMod(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::SMod(Box::new(am), Box::new(bm)))
      }
      Expr::AddMod(a, b, c) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        let cm = c.map_expr_m(f);
        f(&Expr::AddMod(Box::new(am), Box::new(bm), Box::new(cm)))
      }
      Expr::MulMod(a, b, c) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        let cm = c.map_expr_m(f);
        f(&Expr::MulMod(Box::new(am), Box::new(bm), Box::new(cm)))
      }
      Expr::Exp(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::Exp(Box::new(am), Box::new(bm)))
      }
      Expr::SEx(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::SEx(Box::new(am), Box::new(bm)))
      }
      Expr::Min(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::Min(Box::new(am), Box::new(bm)))
      }
      Expr::Max(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::Max(Box::new(am), Box::new(bm)))
      }

      // Booleans
      Expr::LT(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::LT(Box::new(am), Box::new(bm)))
      }
      Expr::GT(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::GT(Box::new(am), Box::new(bm)))
      }
      Expr::LEq(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::LEq(Box::new(am), Box::new(bm)))
      }
      Expr::GEq(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::GEq(Box::new(am), Box::new(bm)))
      }
      Expr::SLT(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::SLT(Box::new(am), Box::new(bm)))
      }
      Expr::SGT(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::SGT(Box::new(am), Box::new(bm)))
      }
      Expr::Eq(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::Eq(Box::new(am), Box::new(bm)))
      }
      Expr::IsZero(a) => {
        let a = a.map_expr_m(f);
        f(&Expr::IsZero(Box::new(a)))
      }

      // Bits
      Expr::And(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::And(Box::new(am), Box::new(bm)))
      }
      Expr::Or(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::Or(Box::new(am), Box::new(bm)))
      }
      Expr::Xor(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::Xor(Box::new(am), Box::new(bm)))
      }
      Expr::Not(a) => {
        let a = a.map_expr_m(f);
        f(&Expr::Not(Box::new(a)))
      }
      Expr::SHL(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::SHL(Box::new(am), Box::new(bm)))
      }
      Expr::SHR(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::SHR(Box::new(am), Box::new(bm)))
      }
      Expr::SAR(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::SAR(Box::new(am), Box::new(bm)))
      }

      // Hashes
      Expr::Keccak(a) => {
        let a = a.map_expr_m(f);
        f(&Expr::Keccak(Box::new(a)))
      }
      Expr::SHA256(a) => {
        let a = a.map_expr_m(f);
        f(&Expr::SHA256(Box::new(a)))
      }

      // Block Context
      Expr::Origin => f(&Expr::Origin),
      Expr::Coinbase => f(&Expr::Coinbase),
      Expr::Timestamp => f(&Expr::Timestamp),
      Expr::BlockNumber => f(&Expr::BlockNumber),
      Expr::PrevRandao => f(&Expr::PrevRandao),
      Expr::GasLimit => f(&Expr::GasLimit),
      Expr::ChainId => f(&Expr::ChainId),
      Expr::BaseFee => f(&Expr::BaseFee),
      Expr::BlockHash(a) => {
        let a = a.map_expr_m(f);
        f(&Expr::BlockHash(Box::new(a)))
      }

      // Tx Context
      Expr::TxValue => f(&Expr::TxValue),

      // Frame Context
      Expr::Gas(a) => f(&Expr::Gas(a.clone())),
      Expr::Balance(a) => {
        let a = a.map_expr_m(f);
        f(&Expr::Balance(Box::new(a)))
      }

      // Code
      Expr::CodeSize(a) => {
        let a = a.map_expr_m(f);
        f(&Expr::CodeSize(Box::new(a)))
      }
      Expr::CodeHash(a) => {
        let a = a.map_expr_m(f);
        f(&Expr::CodeHash(Box::new(a)))
      }

      // Logs
      Expr::LogEntry(a, b, c) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        let cm = c.into_iter().map(|v| Box::new(v.map_expr_m(f))).into_iter().collect();
        f(&Expr::LogEntry(Box::new(am), Box::new(bm), cm))
      }

      // Storage
      Expr::ConcreteStore(b) => f(&Expr::ConcreteStore(b.clone())),
      Expr::AbstractStore(a, b) => f(&Expr::AbstractStore(a.clone(), b.clone())),
      Expr::SLoad(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::SLoad(Box::new(am), Box::new(bm)))
      }
      Expr::SStore(a, b, c) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        let cm = c.map_expr_m(f);
        f(&Expr::SStore(Box::new(am), Box::new(bm), Box::new(cm)))
      }

      // Buffers
      Expr::ConcreteBuf(a) => f(&Expr::ConcreteBuf(a.clone())),
      Expr::AbstractBuf(a) => f(&Expr::AbstractBuf(a.clone())),
      Expr::ReadWord(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::ReadWord(Box::new(am), Box::new(bm)))
      }
      Expr::ReadByte(a, b) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        f(&Expr::ReadByte(Box::new(am), Box::new(bm)))
      }
      Expr::WriteWord(a, b, c) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        let cm = c.map_expr_m(f);
        f(&Expr::WriteWord(Box::new(am), Box::new(bm), Box::new(cm)))
      }
      Expr::WriteByte(a, b, c) => {
        let am = a.map_expr_m(f);
        let bm = b.map_expr_m(f);
        let cm = c.map_expr_m(f);
        f(&Expr::WriteByte(Box::new(am), Box::new(bm), Box::new(cm)))
      }

      Expr::CopySlice(a, b, c, d, e) => {
        let a_ = a.map_expr_m(f);
        let b_ = b.map_expr_m(f);
        let c_ = c.map_expr_m(f);
        let d_ = d.map_expr_m(f);
        let e_ = e.map_expr_m(f);
        let a__ = a_.map_expr_m(f);
        let b__ = b_.map_expr_m(f);
        let c__ = c_.map_expr_m(f);
        f(&Expr::CopySlice(Box::new(a__), Box::new(b__), Box::new(c__), Box::new(d_.clone()), Box::new(e_.clone())))
      }
      Expr::BufLength(a) => {
        let a = a.map_expr_m(f);
        f(&Expr::BufLength(Box::new(a)))
      }
      Expr::Mempty => Expr::Mempty,
      _ => panic!("unuexpected expr {}", self),
    }
  }
}

pub fn map_expr<F>(mut f: F, expr: Expr) -> Expr
where
  F: FnMut(&Expr) -> Expr,
{
  if expr == Expr::Mempty {
    expr
  } else {
    expr.map_expr_m(&mut f)
  }
}

pub fn map_prop(f: &mut dyn FnMut(&Expr) -> Expr, prop: Prop) -> Prop {
  match prop {
    Prop::PBool(b) => Prop::PBool(b),
    Prop::PEq(a, b) => Prop::PEq(f(&a).map_expr_m(f), f(&b).map_expr_m(f)),
    Prop::PLT(a, b) => Prop::PLT(f(&a).map_expr_m(f), f(&b).map_expr_m(f)),
    Prop::PGT(a, b) => Prop::PGT(f(&a).map_expr_m(f), f(&b).map_expr_m(f)),
    Prop::PLEq(a, b) => Prop::PLEq(f(&a).map_expr_m(f), f(&b).map_expr_m(f)),
    Prop::PGEq(a, b) => Prop::PGEq(f(&a).map_expr_m(f), f(&b).map_expr_m(f)),
    Prop::PNeg(a) => Prop::PNeg(Box::new(map_prop_m(f, *a))),
    Prop::PAnd(a, b) => Prop::PAnd(Box::new(map_prop_m(f, *a)), Box::new(map_prop_m(f, *b))),
    Prop::POr(a, b) => Prop::POr(Box::new(map_prop_m(f, *a)), Box::new(map_prop_m(f, *b))),
    Prop::PImpl(a, b) => Prop::PImpl(Box::new(map_prop_m(f, *a)), Box::new(map_prop_m(f, *b))),
  }
}

pub fn map_prop_prime(f: &mut dyn FnMut(&Prop) -> Prop, prop: Prop) -> Prop {
  match prop {
    Prop::PBool(b) => f(&Prop::PBool(b)),
    Prop::PEq(a, b) => f(&Prop::PEq(a, b)),
    Prop::PLT(a, b) => f(&Prop::PLT(a, b)),
    Prop::PGT(a, b) => f(&Prop::PGT(a, b)),
    Prop::PLEq(a, b) => f(&Prop::PLEq(a, b)),
    Prop::PGEq(a, b) => f(&Prop::PGEq(a, b)),
    Prop::PNeg(a) => {
      let af = map_prop_prime(f, *a);
      f(&Prop::PNeg(Box::new(af)))
    }
    Prop::PAnd(a, b) => {
      let af = map_prop_prime(f, *a);
      let bf = map_prop_prime(f, *b);
      f(&Prop::PAnd(Box::new(af), Box::new(bf)))
    }
    Prop::POr(a, b) => {
      let af = map_prop_prime(f, *a);
      let bf = map_prop_prime(f, *b);
      f(&Prop::POr(Box::new(af), Box::new(bf)))
    }
    Prop::PImpl(a, b) => {
      let af = map_prop_prime(f, *a);
      let bf = map_prop_prime(f, *b);
      f(&&Prop::PImpl(Box::new(af), Box::new(bf)))
    }
  }
}

// MapPropM function
pub fn map_prop_m(f: &mut dyn FnMut(&Expr) -> Expr, prop: Prop) -> Prop {
  match prop {
    Prop::PBool(b) => Prop::PBool(b),
    Prop::PEq(a, b) => Prop::PEq(a.map_expr_m(f), b.map_expr_m(f)),
    Prop::PLT(a, b) => Prop::PLT(a.map_expr_m(f), b.map_expr_m(f)),
    Prop::PGT(a, b) => Prop::PGT(a.map_expr_m(f), b.map_expr_m(f)),
    Prop::PLEq(a, b) => Prop::PLEq(a.map_expr_m(f), b.map_expr_m(f)),
    Prop::PGEq(a, b) => Prop::PGEq(a.map_expr_m(f), b.map_expr_m(f)),
    Prop::PNeg(a) => Prop::PNeg(Box::new(map_prop_m(f, *a))),
    Prop::PAnd(a, b) => Prop::PAnd(Box::new(map_prop_m(f, *a)), Box::new(map_prop_m(f, *b))),
    Prop::POr(a, b) => Prop::POr(Box::new(map_prop_m(f, *a)), Box::new(map_prop_m(f, *b))),
    Prop::PImpl(a, b) => Prop::PImpl(Box::new(map_prop_m(f, *a)), Box::new(map_prop_m(f, *b))),
  }
}

// MapEContractM function
fn map_econtract_m<F>(mut f: F, expr: Expr) -> Expr
where
  F: FnMut(&Expr) -> Expr,
{
  match expr {
    Expr::GVar(_) => expr,
    Expr::C { code, storage, balance, nonce } => {
      let code = map_code_m(&mut f, code);
      let storage = storage.map_expr_m(&mut f);
      let balance = balance.map_expr_m(&mut f);
      Expr::C { code: code, storage: Box::new(storage), balance: Box::new(balance), nonce: nonce }
    }
    // Handle other Expr variants
    _ => todo!(),
  }
}

// MapContractM function
pub fn map_contract_m<F>(mut f: F, contract: Contract) -> Contract
where
  F: FnMut(&Expr) -> Expr,
{
  let code = map_code_m(&mut f, contract.code);
  let storage = contract.storage.map_expr_m(&mut f);
  let orig_storage = contract.orig_storage.map_expr_m(&mut f);
  let balance = contract.balance.map_expr_m(&mut f);
  Contract { code, storage, orig_storage, balance, ..contract }
}

// MapCodeM function
fn map_code_m<F>(mut f: F, code: ContractCode) -> ContractCode
where
  F: FnMut(&Expr) -> Expr,
{
  match code {
    ContractCode::UnKnownCode(expr) => ContractCode::UnKnownCode(Box::new(f(&expr))),
    ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(expr)) => {
      ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(expr))
    }
    ContractCode::RuntimeCode(RuntimeCodeStruct::SymbolicRuntimeCode(exprs)) => {
      let new_exprs = (exprs.into_iter().map(|expr| Box::new(expr.map_expr_m(&mut f)))).into_iter().collect();
      ContractCode::RuntimeCode(RuntimeCodeStruct::SymbolicRuntimeCode(new_exprs))
    }
    ContractCode::InitCode(bytes, buf) => {
      let buf = buf.map_expr_m(&mut f);
      ContractCode::InitCode(bytes, Box::new(buf))
    }
  }
}

// Define the TraversableTerm trait and its implementations
pub trait TraversableTerm {
  fn map_term<F>(&self, f: F) -> Self
  where
    F: FnMut(&Expr) -> Expr;

  fn fold_term<C>(&self, f: &mut dyn FnMut(&Expr) -> C, acc: C) -> C
  where
    C: Add<C, Output = C> + Clone + Default;
}

impl TraversableTerm for Expr {
  fn map_term<F>(&self, _f: F) -> Self
  where
    F: FnMut(&Expr) -> Expr,
  {
    // map_expr(f, self.clone())
    todo!()
  }

  fn fold_term<C>(&self, f: &mut dyn FnMut(&Expr) -> C, acc: C) -> C
  where
    C: Add<C, Output = C> + Clone + Default,
  {
    fold_expr(f, acc, &self.clone())
  }
}

impl TraversableTerm for Prop {
  fn map_term<F>(&self, _f: F) -> Self
  where
    F: FnMut(&Expr) -> Expr,
  {
    // map_prop(&mut f, self.clone())
    todo!()
  }

  fn fold_term<C>(&self, f: &mut dyn FnMut(&Expr) -> C, acc: C) -> C
  where
    C: Add<C, Output = C> + Clone + Default,
  {
    fold_prop(f, acc, self.clone())
  }
}
