use crate::modules::types::{Expr, Prop, W256};

// ** Constants **

const MAX_LIT: W256 = 0xffffffffffffffffffffffffffffffff;

// ** Stack Ops ** ---------------------------------------------------------------------------------

pub fn op1<F1, F2>(symbolic: F1, concrete: F2, x: &Expr) -> Expr
where
  F1: Fn(Box<Expr>) -> Expr,
  F2: Fn(W256) -> W256,
{
  match x {
    Expr::Lit(x) => Expr::Lit(concrete(*x)),
    _ => symbolic(Box::new(x.clone())),
  }
}

pub fn op2<F1, F2>(symbolic: F1, concrete: F2, x: &Expr, y: &Expr) -> Expr
where
  F1: Fn(Box<Expr>, Box<Expr>) -> Expr,
  F2: Fn(W256, W256) -> W256,
{
  match (x, y) {
    (Expr::Lit(x), Expr::Lit(y)) => Expr::Lit(concrete(x.clone(), y.clone())),
    _ => symbolic(Box::new(x.clone()), Box::new(y.clone())),
  }
}

pub fn op3<F1, F2>(symbolic: F1, concrete: F2, x: &Expr, y: &Expr, z: &Expr) -> Expr
where
  F1: Fn(Box<Expr>, Box<Expr>, Box<Expr>) -> Expr,
  F2: Fn(W256, W256, W256) -> W256,
{
  match (x, y, z) {
    (Expr::Lit(x), Expr::Lit(y), Expr::Lit(z)) => Expr::Lit(concrete(x.clone(), y.clone(), z.clone())),
    _ => symbolic(Box::new(x.clone()), Box::new(y.clone()), Box::new(z.clone())),
  }
}

pub fn norm_args<F1, F2>(symbolic: F1, concrete: F2, l: &Expr, r: &Expr) -> Expr
where
  F1: Fn(Box<Expr>, Box<Expr>) -> Expr,
  F2: Fn(W256, W256) -> W256,
{
  match (l, r) {
    (Expr::Lit(_), _) => op2(symbolic, &concrete, l, r),
    (_, Expr::Lit(_)) => op2(symbolic, &concrete, r, l),
    _ => op2(symbolic, &concrete, l, r),
  }
}

// Integers

pub fn add(l: Expr, r: Expr) -> Expr {
  norm_args(Expr::Add, |x: W256, y: W256| x + y, &l, &r)
}

pub fn sub(l: Expr, r: Expr) -> Expr {
  op2(Expr::Sub, |x, y| x - y, &l, &r)
}

pub fn mul(l: Expr, r: Expr) -> Expr {
  norm_args(Expr::Mul, |x, y| x * y, &l, &r)
}

pub fn div(l: Expr, r: Expr) -> Expr {
  op2(Expr::Div, |x, y| if y == 0 { 0 } else { x / y }, &l, &r)
}

pub fn sdiv(l: Expr, r: Expr) -> Expr {
  op2(
    Expr::SDiv,
    |x, y| {
      let sx = x as W256;
      let sy = y as W256;
      if y == 0 {
        0
      } else {
        (sx / sy) as W256
      }
    },
    &l,
    &r,
  )
}

pub fn r#mod(l: Expr, r: Expr) -> Expr {
  op2(Expr::Mod, |x, y| if y == 0 { 0 } else { x % y }, &l, &r)
}

pub fn smod(l: Expr, r: Expr) -> Expr {
  op2(
    Expr::SMod,
    |x, y| {
      let sx = x as W256;
      let sy = y as W256;
      if y == 0 {
        0
      } else {
        (sx % sy) as W256
      }
    },
    &l,
    &r,
  )
}

pub fn addmod(x: Expr, y: Expr, z: Expr) -> Expr {
  op3(
    Expr::AddMod,
    |x, y, z| {
      if z == 0 {
        0
      } else {
        ((x as W256 + y as W256) % z as W256) as W256
      }
    },
    &x,
    &y,
    &z,
  )
}

pub fn mulmod(x: Expr, y: Expr, z: Expr) -> Expr {
  op3(
    Expr::MulMod,
    |x, y, z| {
      if z == 0 {
        0
      } else {
        ((x as W256 * y as W256) % z as W256) as W256
      }
    },
    &x,
    &y,
    &z,
  )
}

pub fn exp(x: Expr, y: Expr) -> Expr {
  op2(Expr::Exp, |x, y| x.pow(y as u32), &x, &y)
}

pub fn sex(bytes: Expr, x: Expr) -> Expr {
  op2(
    Expr::SEx,
    |bytes, x| {
      if bytes >= 32 {
        x
      } else {
        let n = bytes * 8 + 7;
        if x & (1 << n) != 0 {
          x | (!(1 << n) + 1)
        } else {
          x & ((1 << n) - 1)
        }
      }
    },
    &bytes,
    &x,
  )
}

// Booleans

pub fn lt(x: Expr, y: Expr) -> Expr {
  op2(Expr::LT, |x, y| if x < y { 1 } else { 0 }, &x, &y)
}

pub fn gt(x: Expr, y: Expr) -> Expr {
  op2(Expr::GT, |x, y| if x > y { 1 } else { 0 }, &x, &y)
}

pub fn leq(x: Expr, y: Expr) -> Expr {
  op2(Expr::LEq, |x, y| if x <= y { 1 } else { 0 }, &x, &y)
}

pub fn geq(x: Expr, y: Expr) -> Expr {
  op2(Expr::GEq, |x, y| if x >= y { 1 } else { 0 }, &x, &y)
}

pub fn slt(x: Expr, y: Expr) -> Expr {
  op2(
    Expr::SLT,
    |x, y| {
      let sx = x as W256;
      let sy = y as W256;
      if sx < sy {
        1
      } else {
        0
      }
    },
    &x,
    &y,
  )
}

pub fn sgt(x: Expr, y: Expr) -> Expr {
  op2(
    Expr::SGT,
    |x, y| {
      let sx = x as W256;
      let sy = y as W256;
      if sx > sy {
        1
      } else {
        0
      }
    },
    &x,
    &y,
  )
}

pub fn eq(x: Expr, y: Expr) -> Expr {
  norm_args(Expr::Eq, |x, y| if x == y { 1 } else { 0 }, &x, &y)
}

pub fn iszero(x: Expr) -> Expr {
  op1(Expr::IsZero, |x| if x == 0 { 1 } else { 0 }, &x)
}

// Bits

pub fn and(x: Expr, y: Expr) -> Expr {
  norm_args(Expr::And, |x, y| x & y, &x, &y)
}

pub fn or(x: Expr, y: Expr) -> Expr {
  norm_args(Expr::Or, |x, y| x | y, &x, &y)
}

pub fn xor(x: Expr, y: Expr) -> Expr {
  norm_args(Expr::Xor, |x, y| x ^ y, &x, &y)
}

pub fn not(x: Expr) -> Expr {
  op1(Expr::Not, |x| !x, &x)
}

pub fn shl(x: Expr, y: Expr) -> Expr {
  op2(Expr::SHL, |x, y| if x > 256 { 0 } else { y << x }, &x, &y)
}

pub fn shr(x: Expr, y: Expr) -> Expr {
  op2(Expr::SHR, |x, y| if x > 256 { 0 } else { y >> x }, &x, &y)
}

pub fn sar(x: Expr, y: Expr) -> Expr {
  op2(
    Expr::SAR,
    |x, y| {
      let msb = (y >> 255) & 1 != 0;
      let as_signed = y as W256;
      if x > 256 {
        if msb {
          W256::max_value()
        } else {
          0
        }
      } else {
        (as_signed >> x) as W256
      }
    },
    &x,
    &y,
  )
}

pub fn in_range(sz: u32, e: Expr) -> Prop {
  Prop::PAnd(
    Box::new(Prop::PGEq(e.clone(), Expr::Lit(0))),
    Box::new(Prop::PLEq(e.clone(), Expr::Lit(2 ^ sz - 1))),
  )
}

pub const MAX_BYTES: u32 = (u32::MAX) / 8;

pub fn write_byte(offset: Expr, byte: Expr, src: Expr) -> Expr {
  match (offset, byte, src) {
    (Expr::Lit(offset), Expr::LitByte(val), Expr::ConcreteBuf(src)) if offset < MAX_BYTES => {
      let mut buffer = vec![0; offset as usize];
      buffer.push(val);
      buffer.extend(vec![0; MAX_BYTES as usize - offset as usize - 1]);
      Expr::ConcreteBuf(buffer)
    }
    (Expr::Lit(offset), Expr::LitByte(byte), Expr::ConcreteBuf(src)) if offset < MAX_BYTES => {
      let mut buffer = src.clone();
      buffer.truncate(offset as usize);
      buffer.push(byte);
      buffer.extend(src[offset as usize + 1..].to_vec());
      Expr::ConcreteBuf(buffer)
    }
    (offset, byte, src) => Expr::WriteByte(Box::new(offset), Box::new(byte), Box::new(src)),
  }
}

pub fn conc_keccak_props(props: Vec<Prop>) -> Vec<Prop> {
  todo!()
}
