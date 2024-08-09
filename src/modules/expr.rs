use core::panic;
use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::u32;

use log::info;

use crate::modules::cse::BufEnv;
use crate::modules::rlp::{rlp_addr_full, rlp_list, rlp_word_256};
use crate::modules::traversals::{fold_expr, map_expr, map_prop, map_prop_prime};
use crate::modules::types::{
  keccak, keccak_prime, maybe_lit_byte, pad_right, until_fixpoint, word256_bytes, Addr, Expr, GVar, Prop, W256, W64,
};

use super::types::{ByteString, Word8};
// ** Constants **

const MAX_LIT: W256 = W256(0xffffffffffffffffffffffffffffffff, 0xffffffffffffffffffffffffffffffff);

// ** Stack Ops ** ---------------------------------------------------------------------------------

pub fn op1<F1, F2>(symbolic: F1, concrete: F2, x: Box<Expr>) -> Expr
where
  F1: Fn(Box<Expr>) -> Expr,
  F2: Fn(W256) -> W256,
{
  match *x {
    Expr::Lit(x) => Expr::Lit(concrete(x.clone())),
    _ => symbolic(x),
  }
}

pub fn op2<F1, F2>(symbolic: F1, concrete: F2, x: Box<Expr>, y: Box<Expr>) -> Expr
where
  F1: Fn(Box<Expr>, Box<Expr>) -> Expr,
  F2: Fn(W256, W256) -> W256,
{
  match (*x.clone(), *y.clone()) {
    (Expr::Lit(x), Expr::Lit(y)) => Expr::Lit(concrete(x.clone(), y.clone())),
    _ => symbolic(x, y),
  }
}

pub fn op3<F1, F2>(symbolic: F1, concrete: F2, x: Box<Expr>, y: Box<Expr>, z: Box<Expr>) -> Expr
where
  F1: Fn(Box<Expr>, Box<Expr>, Box<Expr>) -> Expr,
  F2: Fn(W256, W256, W256) -> W256,
{
  match (*x.clone(), *y.clone(), *z.clone()) {
    (Expr::Lit(x), Expr::Lit(y), Expr::Lit(z)) => Expr::Lit(concrete(x.clone(), y.clone(), z.clone())),
    _ => symbolic(x, y, z),
  }
}

pub fn norm_args<F1, F2>(symbolic: F1, concrete: F2, l: Box<Expr>, r: Box<Expr>) -> Expr
where
  F1: Fn(Box<Expr>, Box<Expr>) -> Expr,
  F2: Fn(W256, W256) -> W256,
{
  match (*l.clone(), *r.clone()) {
    (Expr::Lit(_), _) => op2(symbolic, &concrete, l, r),
    (_, Expr::Lit(_)) => op2(symbolic, &concrete, r, l),
    _ => op2(symbolic, &concrete, l, r),
  }
}

// Integers

pub fn add(l: Box<Expr>, r: Box<Expr>) -> Expr {
  norm_args(Expr::Add, |x: W256, y: W256| x + y, l, r)
}

pub fn sub(l: Box<Expr>, r: Box<Expr>) -> Expr {
  op2(Expr::Sub, |x, y| x - y, l, r)
}

pub fn mul(l: Box<Expr>, r: Box<Expr>) -> Expr {
  norm_args(Expr::Mul, |x, y| x * y, l, r)
}

pub fn div(l: Box<Expr>, r: Box<Expr>) -> Expr {
  op2(Expr::Div, |x, y| if y == W256(0, 0) { W256(0, 0) } else { x / y }, l, r)
}

pub fn emin(l: Box<Expr>, r: Box<Expr>) -> Expr {
  norm_args(
    Expr::Min,
    |x, y| {
      if x <= y {
        x
      } else {
        y
      }
    },
    l,
    r,
  )
}

pub fn emax(l: Box<Expr>, r: Box<Expr>) -> Expr {
  match (*l.clone(), *r.clone()) {
    (Expr::Lit(W256(0, 0)), y) => y,
    (x, Expr::Lit(W256(0, 0))) => x,
    (_, _) => norm_args(
      Expr::Max,
      |x, y| {
        if x >= y {
          x
        } else {
          y
        }
      },
      l.clone(),
      r.clone(),
    ),
  }
}

pub fn sdiv(l: Box<Expr>, r: Box<Expr>) -> Expr {
  op2(
    Expr::SDiv,
    |x, y| {
      let sx = x as W256;
      let sy = y.clone() as W256;
      if y == W256(0, 0) {
        W256(0, 0)
      } else {
        (sx / sy) as W256
      }
    },
    l,
    r,
  )
}

pub fn r#mod(l: Box<Expr>, r: Box<Expr>) -> Expr {
  op2(Expr::Mod, |x, y| if y == W256(0, 0) { W256(0, 0) } else { x % y }, l, r)
}

pub fn smod(l: Box<Expr>, r: Box<Expr>) -> Expr {
  op2(
    Expr::SMod,
    |x, y| {
      let sx = x as W256;
      let sy = y.clone() as W256;
      if y == W256(0, 0) {
        W256(0, 0)
      } else {
        (sx % sy) as W256
      }
    },
    l,
    r,
  )
}

pub fn addmod(x: Box<Expr>, y: Box<Expr>, z: Box<Expr>) -> Expr {
  op3(
    Expr::AddMod,
    |x, y, z| {
      if z == W256(0, 0) {
        W256(0, 0)
      } else {
        ((x as W256 + y as W256) % z as W256) as W256
      }
    },
    x,
    y,
    z,
  )
}

pub fn mulmod(x: Box<Expr>, y: Box<Expr>, z: Box<Expr>) -> Expr {
  op3(
    Expr::MulMod,
    |x, y, z| {
      if z == W256(0, 0) {
        W256(0, 0)
      } else {
        ((x as W256 * y as W256) % z as W256) as W256
      }
    },
    x,
    y,
    z,
  )
}

pub fn exp(x: Box<Expr>, y: Box<Expr>) -> Expr {
  op2(Expr::Exp, |x, y| W256(0, x.0.pow(y.0 as u32)), x, y)
}

pub fn sex(bytes: Box<Expr>, x: Box<Expr>) -> Expr {
  op2(
    Expr::SEx,
    |bytes, x| {
      if bytes >= W256(32, 0) {
        x
      } else {
        let n = bytes * W256(8, 0) + W256(7, 0);
        if x.clone() & (W256(1, 0) << n.0 as u32) != W256(0, 0) {
          x | (!(W256(1, 0) << n.0 as u32) + W256(1, 0))
        } else {
          x & ((W256(1, 0) << n.0 as u32) - W256(1, 0))
        }
      }
    },
    bytes,
    x,
  )
}

// Booleans

pub fn lt(x: Box<Expr>, y: Box<Expr>) -> Expr {
  op2(Expr::LT, |x, y| if x < y { W256(1, 0) } else { W256(0, 0) }, x, y)
}

pub fn gt(x: Box<Expr>, y: Box<Expr>) -> Expr {
  op2(Expr::GT, |x, y| if x > y { W256(1, 0) } else { W256(0, 0) }, x, y)
}

pub fn leq(x: Box<Expr>, y: Box<Expr>) -> Expr {
  op2(Expr::LEq, |x, y| if x <= y { W256(1, 0) } else { W256(0, 0) }, x, y)
}

pub fn geq(x: Box<Expr>, y: Box<Expr>) -> Expr {
  op2(Expr::GEq, |x, y| if x >= y { W256(1, 0) } else { W256(0, 0) }, x, y)
}

pub fn slt(x: Box<Expr>, y: Box<Expr>) -> Expr {
  op2(
    Expr::SLT,
    |x, y| {
      let sx = x as W256;
      let sy = y as W256;
      if sx < sy {
        W256(1, 0)
      } else {
        W256(0, 0)
      }
    },
    x,
    y,
  )
}

pub fn sgt(x: Box<Expr>, y: Box<Expr>) -> Expr {
  op2(
    Expr::SGT,
    |x, y| {
      let sx = x as W256;
      let sy = y as W256;
      if sx > sy {
        W256(1, 0)
      } else {
        W256(0, 0)
      }
    },
    x,
    y,
  )
}

pub fn eq(x: Box<Expr>, y: Box<Expr>) -> Expr {
  norm_args(Expr::Eq, |x, y| if x == y { W256(1, 0) } else { W256(0, 0) }, x, y)
}

pub fn iszero(x: Box<Expr>) -> Expr {
  op1(Expr::IsZero, |x| if x == W256(0, 0) { W256(1, 0) } else { W256(0, 0) }, x)
}

// Bits

pub fn and(x: Box<Expr>, y: Box<Expr>) -> Expr {
  norm_args(Expr::And, |x, y| x & y, x, y)
}

pub fn or(x: Box<Expr>, y: Box<Expr>) -> Expr {
  norm_args(Expr::Or, |x, y| x | y, x, y)
}

pub fn xor(x: Box<Expr>, y: Box<Expr>) -> Expr {
  norm_args(Expr::Xor, |x, y| x ^ y, x, y)
}

pub fn not(x: Box<Expr>) -> Expr {
  op1(Expr::Not, |x| !x, x)
}

pub fn shl(x: Box<Expr>, y: Box<Expr>) -> Expr {
  op2(
    Expr::SHL,
    |x, y| {
      if x > W256(256, 0) {
        W256(0, 0)
      } else {
        y << (x.0 as u32)
      }
    },
    x,
    y,
  )
}

pub fn shr(x: Box<Expr>, y: Box<Expr>) -> Expr {
  op2(
    Expr::SHR,
    |x, y| {
      if x > W256(256, 0) {
        W256(0, 0)
      } else {
        y >> (x.0 as u32)
      }
    },
    x,
    y,
  )
}

pub fn sar(x: Box<Expr>, y: Box<Expr>) -> Expr {
  op2(
    Expr::SAR,
    |x, y| {
      let msb = (y.clone() >> 31) & W256(1, 0) != W256(0, 0);
      let as_signed = y as W256;
      if x > W256(256, 0) {
        if msb {
          W256::max_value()
        } else {
          W256(0, 0)
        }
      } else {
        (as_signed >> x.0 as u32) as W256
      }
    },
    x,
    y,
  )
}

pub fn in_range(sz: u32, e: Box<Expr>) -> Prop {
  Prop::PAnd(
    Box::new(Prop::PGEq(*e.clone(), Expr::Lit(W256(0, 0)))),
    Box::new(Prop::PLEq(*e.clone(), Expr::Lit(W256(2_u128, 0).pow(sz)))),
  )
}

pub const MAX_WORD32: u32 = u32::MAX;
pub const MAX_BYTES: W256 = W256(MAX_WORD32 as u128 / 8, 0);

pub fn write_byte(offset: Box<Expr>, byte: Box<Expr>, src: Box<Expr>) -> Expr {
  match (*offset, *byte, *src) {
    (Expr::Lit(offset), Expr::LitByte(val), Expr::ConcreteBuf(src)) if src.len() == 0 && offset < MAX_BYTES => {
      let mut buffer = vec![0; offset.0 as usize];
      buffer.push(val);
      buffer.extend(vec![0; (MAX_BYTES - offset - W256(1, 0)).0 as usize]);
      Expr::ConcreteBuf(buffer)
    }
    (Expr::Lit(offset), Expr::LitByte(byte), Expr::ConcreteBuf(src)) if offset < MAX_BYTES => {
      let mut buffer = src.clone();
      buffer.truncate(offset.0 as usize);
      buffer.push(byte);
      buffer.extend(src[offset.0 as usize + 1..].to_vec());
      Expr::ConcreteBuf(buffer)
    }
    (offset, byte, src) => Expr::WriteByte(Box::new(offset), Box::new(byte), Box::new(src)),
  }
}

fn count_leading_zeros_(n: u128) -> u32 {
  n.leading_zeros()
}

/// Checks if any part of the `W256` value is a power of two.
pub fn is_power_of_two(n: W256) -> bool {
  n.clone() != W256(0, 0) && (n.clone() & (n.clone() - W256(1, 0))) == W256(0, 0)
  //let W256(low, high) = n;
  // is_power_of_two_(low) && is_power_of_two_(high)
}

/// Counts the number of leading zeros in both parts of the `W256` value.
pub fn count_leading_zeros(n: W256) -> u32 {
  let W256(low, high) = n;
  let low_zeros = count_leading_zeros_(low);
  let high_zeros = count_leading_zeros_(high);
  if high == 0 {
    low_zeros + 128
  } else {
    high_zeros
  }
}

/// Determines if any part of the `W256` value is byte-aligned.
pub fn is_byte_aligned(n: W256) -> bool {
  count_leading_zeros(n) % 8 == 0
}

/// Converts the `W256` value into `usize` if possible.
pub fn unsafe_into_usize(n: W256) -> usize {
  let W256(low, _) = n;
  low as usize
}

pub fn index_word(i: Box<Expr>, w: Box<Expr>) -> Expr {
  match (*i.clone(), *w.clone()) {
    (Expr::Lit(idx), Expr::And(box_mask, box_w)) => {
      let full_word_mask = MAX_LIT;
      let mask = match *box_mask {
        Expr::Lit(m) => m,
        _ => panic!("invalid expression"),
      };
      if mask.clone() == full_word_mask {
        index_word(i, box_w)
      } else {
        let unmasked_bytes = count_leading_zeros(mask.clone()) / 8;
        if idx <= W256(31, 0) && is_power_of_two(mask.clone() + W256(1, 0)) && is_byte_aligned(mask.clone()) {
          if idx >= W256(unmasked_bytes as u128, 0) {
            index_word(i, box_w)
          } else {
            Expr::LitByte(0)
          }
        } else if idx <= W256(31, 0) {
          Expr::IndexWord(Box::new(Expr::Lit(idx)), Box::new(Expr::And(Box::new(Expr::Lit(mask)), Box::new(*box_w))))
        } else {
          Expr::LitByte(0)
        }
      }
    }
    (Expr::Lit(idx), Expr::Lit(w)) => {
      if idx <= W256(31, 0) {
        Expr::LitByte((w >> (idx.0 * 8) as u32).0 as u8)
      } else {
        Expr::LitByte(0)
      }
    }
    (Expr::Lit(idx), Expr::JoinBytes(bytes)) => {
      if idx <= W256(31, 0) {
        match idx.0 {
          0 => bytes[0].clone(),
          1 => bytes[1].clone(),
          2 => bytes[2].clone(),
          3 => bytes[3].clone(),
          4 => bytes[4].clone(),
          5 => bytes[5].clone(),
          6 => bytes[6].clone(),
          7 => bytes[7].clone(),
          8 => bytes[8].clone(),
          9 => bytes[9].clone(),
          10 => bytes[10].clone(),
          11 => bytes[11].clone(),
          12 => bytes[12].clone(),
          13 => bytes[13].clone(),
          14 => bytes[14].clone(),
          15 => bytes[15].clone(),
          16 => bytes[16].clone(),
          17 => bytes[17].clone(),
          18 => bytes[18].clone(),
          19 => bytes[19].clone(),
          20 => bytes[20].clone(),
          21 => bytes[21].clone(),
          22 => bytes[22].clone(),
          23 => bytes[23].clone(),
          24 => bytes[24].clone(),
          25 => bytes[25].clone(),
          26 => bytes[26].clone(),
          27 => bytes[27].clone(),
          28 => bytes[28].clone(),
          29 => bytes[29].clone(),
          30 => bytes[30].clone(),
          31 => bytes[31].clone(),
          _ => Expr::LitByte(0),
        }
      } else {
        Expr::LitByte(0)
      }
    }
    (idx, w) => Expr::IndexWord(Box::new(idx), Box::new(w)),
  }
}

pub fn read_byte(idx: Box<Expr>, buf: Box<Expr>) -> Expr {
  match (*idx, *buf) {
    (Expr::Lit(x), Expr::ConcreteBuf(b)) => {
      let i = (x.0 as u64) as u32;
      if x.0 <= i as u128 {
        if (i as usize) < b.len() {
          return Expr::LitByte(b[i as usize]);
        }
      }
      Expr::LitByte(0)
    }
    (Expr::Lit(x), Expr::WriteByte(idx, val, src)) => {
      if Expr::Lit(x.clone()) == *idx {
        *val
      } else {
        read_byte(idx, src)
      }
    }
    (Expr::Lit(x), Expr::WriteWord(idx, val, src)) => {
      if let Expr::Lit(idx_val) = *idx {
        if x >= idx_val.clone() && x < idx_val.clone() + W256(32, 0) {
          if let Expr::Lit(_) = *val {
            index_word(Box::new(Expr::Lit(x - idx_val)), val)
          } else {
            Expr::ReadByte(Box::new(Expr::Lit(x)), Box::new(Expr::WriteWord(Box::new(Expr::Lit(idx_val)), val, src)))
          }
        } else {
          read_byte(Box::new(Expr::Lit(x)), src)
        }
      } else {
        Expr::ReadByte(Box::new(Expr::Lit(x)), Box::new(Expr::WriteWord(idx, val, src)))
      }
    }
    (Expr::Lit(x), Expr::CopySlice(src_offset, dst_offset, size, src, ref dst)) => {
      if let (Expr::Lit(src_offset_val), Expr::Lit(dst_offset_val), Expr::Lit(size_val)) =
        (*src_offset.clone(), *dst_offset.clone(), *size.clone())
      {
        if x >= dst_offset_val.clone() && x < dst_offset_val.clone() + size_val {
          read_byte(Box::new(Expr::Lit(x + src_offset_val - dst_offset_val)), src)
        } else {
          read_byte(Box::new(Expr::Lit(x)), dst.clone())
        }
      } else {
        Expr::ReadByte(
          Box::new(Expr::Lit(x)),
          Box::new(Expr::CopySlice(src_offset, dst_offset, size, src, dst.clone())),
        )
      }
    }
    (i, buf) => Expr::ReadByte(Box::new(i), Box::new(buf)),
  }
}

pub fn read_bytes(n: usize, idx: Box<Expr>, buf: Box<Expr>) -> Expr {
  let n = min(32, n);
  let bytes: Vec<Expr> = (0..n)
    .map(|i| read_byte(Box::new(add(idx.clone(), Box::new(Expr::Lit(W256(i as u128, 0))))), buf.clone()))
    .collect();
  join_bytes(bytes)
}

/*
fn pad_byte(b: Box<Expr>) -> Expr {
  match *b {
    Expr::LitByte(b) => Expr::Lit(bytes_to_w256(&[b])),
    _ => join_bytes(vec![*b]),
  }
}*/

fn bytes_to_w256(bytes: &[u8]) -> W256 {
  /*
  if bytes.len() != 32 {
    return None; // Ensure the byte slice is exactly 32 bytes
  }*/

  if bytes.len() < 16 {
    let mut low_padded_bytes = [0u8; 16];
    low_padded_bytes[16 - bytes.len()..].copy_from_slice(bytes);
    let low = u128::from_be_bytes(low_padded_bytes);
    W256(low, 0)
  } else if bytes.len() < 32 {
    todo!()
  } else {
    // Convert the first 16 bytes to the low u128
    let low = u128::from_be_bytes(bytes[0..16].try_into().unwrap());
    // Convert the last 16 bytes to the high u128
    let high = u128::from_be_bytes(bytes[16..32].try_into().unwrap());

    W256(low, high)
  }
}

fn pad_bytes_left(n: usize, mut bs: Vec<Expr>) -> Vec<Expr> {
  while bs.len() < n {
    bs.insert(0, Expr::LitByte(0));
  }
  bs.truncate(n);
  bs
}

fn join_bytes(bs: Vec<Expr>) -> Expr {
  let mut lit_bytes = vec![];
  let mut is_all_lit = true;

  for b in &bs {
    if let Expr::LitByte(_) = b {
      if let Expr::LitByte(val) = b {
        lit_bytes.push(*val);
      }
    } else {
      is_all_lit = false;
      break;
    }
  }

  if is_all_lit {
    Expr::Lit(bytes_to_w256(&lit_bytes))
  } else {
    let padded_bs = pad_bytes_left(32, bs);
    Expr::JoinBytes(vec![
      padded_bs[0].clone(),
      padded_bs[1].clone(),
      padded_bs[2].clone(),
      padded_bs[3].clone(),
      padded_bs[4].clone(),
      padded_bs[5].clone(),
      padded_bs[6].clone(),
      padded_bs[7].clone(),
      padded_bs[8].clone(),
      padded_bs[9].clone(),
      padded_bs[10].clone(),
      padded_bs[11].clone(),
      padded_bs[12].clone(),
      padded_bs[13].clone(),
      padded_bs[14].clone(),
      padded_bs[15].clone(),
      padded_bs[16].clone(),
      padded_bs[17].clone(),
      padded_bs[18].clone(),
      padded_bs[19].clone(),
      padded_bs[20].clone(),
      padded_bs[21].clone(),
      padded_bs[22].clone(),
      padded_bs[23].clone(),
      padded_bs[24].clone(),
      padded_bs[25].clone(),
      padded_bs[26].clone(),
      padded_bs[27].clone(),
      padded_bs[28].clone(),
      padded_bs[29].clone(),
      padded_bs[30].clone(),
      padded_bs[31].clone(),
    ])
  }
}

pub fn eq_byte(x: Box<Expr>, y: Box<Expr>) -> Expr {
  match (*x, *y) {
    (Expr::LitByte(x), Expr::LitByte(y)) => Expr::Lit(if x == y { W256(1, 0) } else { W256(0, 0) }),
    (x, y) => Expr::EqByte(Box::new(x), Box::new(y)),
  }
}

pub fn read_word(idx: Box<Expr>, buf: Box<Expr>) -> Box<Expr> {
  match (*idx.clone(), *buf.clone()) {
    (Expr::Lit(idx_val), Expr::WriteWord(idx2, val, buf2)) => {
      if let Expr::Lit(idx2_val) = *idx2.clone() {
        if idx_val == idx2_val {
          return val.clone();
        } else if idx2_val >= idx_val && idx2_val <= idx_val.clone() + W256(32, 0) {
          return read_word_from_bytes(idx, buf);
        } else {
          return read_word(idx, buf2);
        }
      }
    }
    (Expr::Lit(idx_val), Expr::CopySlice(src_offset, dst_offset, size, src, dst)) => {
      if let (Expr::Lit(src_offset_val), Expr::Lit(dst_offset_val), Expr::Lit(size_val)) =
        (*src_offset.clone(), *dst_offset.clone(), *size.clone())
      {
        if idx_val >= dst_offset_val && idx_val.clone() + W256(32, 0) <= dst_offset_val.clone() + size_val.clone() {
          return read_word(Box::new(Expr::Lit(idx_val.clone() - dst_offset_val + src_offset_val)), src);
        } else if idx_val >= dst_offset_val && idx_val <= dst_offset_val + size_val - W256(32, 0) {
          return read_word(Box::new(Expr::Lit(idx_val.clone())), dst);
        } else {
          return read_word_from_bytes(idx, buf);
        }
      }
    }
    _ => {}
  }
  read_word_from_bytes(idx, buf)
}

pub fn read_word_from_bytes(idx: Box<Expr>, buf: Box<Expr>) -> Box<Expr> {
  if let (Expr::Lit(idx_val), Expr::ConcreteBuf(bs)) = (*idx.clone(), *buf.clone()) {
    let end = idx_val.clone() + W256(32, 0);
    let slice = if (idx_val.0 as usize) < bs.len() {
      if end.0 as usize <= bs.len() {
        &bs[(idx_val.0 as usize)..(end.0 as usize)]
      } else {
        &bs[(idx_val.0 as usize)..]
      }
    } else {
      &[]
    };
    let padded: Vec<u8> = slice.iter().cloned().chain(std::iter::repeat(0)).take(32).collect();
    return Box::new(Expr::Lit(W256::from_bytes(padded.try_into().unwrap())));
  }
  let bytes: Vec<Expr> =
    (0..3).map(|i| read_byte(Box::new(add(idx.clone(), Box::new(Expr::Lit(W256(i, 0))))), buf.clone())).collect();
  if bytes.iter().all(|b| matches!(b, Expr::Lit(_))) {
    let result = bytes.into_iter().map(|b| if let Expr::Lit(byte) = b { byte.0 as u8 } else { 0 }).collect::<Vec<u8>>();
    Box::new(Expr::Lit(W256::from_bytes(result)))
  } else {
    Box::new(Expr::ReadWord(Box::new(*idx.clone()), Box::new(*buf)))
  }
}

pub fn write_word(offset: Box<Expr>, value: Box<Expr>, buf: Box<Expr>) -> Expr {
  let buf_clone = buf.clone();
  match (*offset, *value, *buf) {
    (Expr::Lit(offset), Expr::WAddr(addr), Expr::ConcreteBuf(_))
      if offset < MAX_BYTES && offset.clone() + W256(32, 0) < MAX_BYTES =>
    {
      let val = match *addr {
        Expr::LitAddr(v) => v,
        _ => panic!("unsupported"),
      };
      write_word(Box::new(Expr::Lit(offset)), Box::new(Expr::Lit(val)), buf_clone)
    }

    (Expr::Lit(offset), Expr::Lit(val), Expr::ConcreteBuf(ref src))
      if offset < MAX_BYTES && offset.clone() + W256(32, 0) < MAX_BYTES && src.is_empty() =>
    {
      let mut new_buf = vec![0; offset.0 as usize];
      new_buf.extend_from_slice(&word256_bytes(val));
      Expr::ConcreteBuf(new_buf)
    }

    (Expr::Lit(offset), Expr::Lit(val), Expr::ConcreteBuf(mut src))
      if offset < MAX_BYTES && offset.clone() + W256(32, 0) < MAX_BYTES =>
    {
      src.resize(offset.0 as usize, 0);
      src.extend_from_slice(&word256_bytes(val));
      Expr::ConcreteBuf(src)
    }

    (Expr::Lit(idx), val, Expr::WriteWord(idx_, _, buf)) if Expr::Lit(idx.clone()) == *idx_ => {
      Expr::WriteWord(Box::new(Expr::Lit(idx)), Box::new(val), buf)
    }

    (Expr::Lit(idx), val, Expr::WriteWord(idx_, val_, buf_)) => {
      if let Expr::Lit(i) = *idx_.clone() {
        if idx >= i + W256(32, 0) {
          return Expr::WriteWord(idx_, val_, Box::new(write_word(Box::new(Expr::Lit(idx)), Box::new(val), buf_)));
        }
      }
      Expr::WriteWord(Box::new(Expr::Lit(idx)), Box::new(val), Box::new(Expr::WriteWord(idx_, val_, buf_)))
    }

    (idx, val, buf @ Expr::WriteWord(_, _, _)) => Expr::WriteWord(Box::new(idx), Box::new(val), Box::new(buf)),

    (offset, val, src) => Expr::WriteWord(Box::new(offset), Box::new(val), Box::new(src)),
  }
}

pub fn copy_slice(
  src_offset: Box<Expr>,
  dst_offset: Box<Expr>,
  size: Box<Expr>,
  src: Box<Expr>,
  dst: Box<Expr>,
) -> Expr {
  match (*src_offset.clone(), *dst_offset.clone(), *size.clone(), *src.clone(), *dst.clone()) {
    // Copies from empty buffers
    (_, _, Expr::Lit(W256(0, 0)), Expr::ConcreteBuf(src_buf), dst) if src_buf.len() == 0 => dst,
    (a, b, Expr::Lit(size), Expr::ConcreteBuf(src_buf), Expr::ConcreteBuf(dst_buf))
      if src_buf.len() == 0 && dst_buf.len() == 0 =>
    {
      if size < MAX_BYTES {
        Expr::ConcreteBuf(vec![0; size.0 as usize])
      } else {
        Expr::CopySlice(
          Box::new(a),
          Box::new(b),
          Box::new(Expr::Lit(size)),
          Box::new(Expr::ConcreteBuf(src_buf)),
          Box::new(Expr::ConcreteBuf(dst_buf)),
        )
      }
    }
    (src_offset, dst_offset, Expr::Lit(size), Expr::ConcreteBuf(src_buf), dst) if src_buf.len() == 0 => {
      if size < MAX_BYTES {
        copy_slice(
          Box::new(src_offset),
          Box::new(dst_offset),
          Box::new(Expr::Lit(size.clone())),
          Box::new(Expr::ConcreteBuf(vec![0; size.0 as usize])),
          Box::new(dst),
        )
      } else {
        Expr::CopySlice(
          Box::new(src_offset),
          Box::new(dst_offset),
          Box::new(Expr::Lit(size)),
          Box::new(Expr::ConcreteBuf(src_buf)),
          Box::new(dst),
        )
      }
    }
    // Fully concrete copies
    (
      Expr::Lit(src_offset),
      Expr::Lit(dst_offset),
      Expr::Lit(size),
      Expr::ConcreteBuf(src_buf),
      Expr::ConcreteBuf(dst_buf),
    ) if dst_buf.len() == 0 => {
      if src_offset > W256(src_buf.len() as u128, 0) && size < MAX_BYTES {
        Expr::ConcreteBuf(vec![0; size.0 as usize])
      } else if src_offset <= W256(src_buf.len() as u128, 0) && dst_offset < MAX_BYTES && size < MAX_BYTES {
        let hd = vec![0; dst_offset.0 as usize];
        let sl = pad_right(
          size.0 as usize,
          (&src_buf[src_offset.0 as usize..src_offset.0 as usize + size.0 as usize]).to_vec(),
        );
        return Expr::ConcreteBuf([hd, sl].concat());
      } else {
        Expr::CopySlice(
          Box::new(Expr::Lit(src_offset)),
          Box::new(Expr::Lit(dst_offset)),
          Box::new(Expr::Lit(size)),
          Box::new(Expr::ConcreteBuf(src_buf)),
          Box::new(Expr::ConcreteBuf(dst_buf)),
        )
      }
    }
    (
      Expr::Lit(src_offset),
      Expr::Lit(dst_offset),
      Expr::Lit(size),
      Expr::ConcreteBuf(src_buf),
      Expr::ConcreteBuf(dst_buf),
    ) => {
      if dst_offset < MAX_BYTES && size < MAX_BYTES {
        let hd = pad_right(dst_offset.0 as usize, (&dst_buf[..dst_offset.0 as usize]).to_vec());
        let sl = if src_offset > W256(src_buf.len() as u128, 0) {
          vec![0; size.0 as usize]
        } else {
          pad_right(
            size.0 as usize,
            (&src_buf[src_offset.0 as usize..src_offset.0 as usize + size.0 as usize]).to_vec(),
          )
        };
        let tl = if (dst_offset.0 as usize + size.0 as usize) < dst_buf.len() {
          &dst_buf[dst_offset.0 as usize + size.0 as usize..]
        } else {
          &vec![]
        };
        Expr::ConcreteBuf([hd, sl, tl.to_vec()].concat())
      } else {
        Expr::CopySlice(
          Box::new(Expr::Lit(src_offset)),
          Box::new(Expr::Lit(dst_offset)),
          Box::new(Expr::Lit(size)),
          Box::new(Expr::ConcreteBuf(src_buf)),
          Box::new(Expr::ConcreteBuf(dst_buf)),
        )
      }
    }
    // copying 32 bytes can be rewritten to a WriteWord on dst (e.g. CODECOPY of args during constructors)
    (src_offset, dst_offset, Expr::Lit(W256(32, 0)), src, dst) => {
      write_word(Box::new(dst_offset), read_word(Box::new(src_offset), Box::new(src)), Box::new(dst))
    }
    // concrete indices & abstract src (may produce a concrete result if we are copying from a concrete region of src)
    (Expr::Lit(src_offset), Expr::Lit(dst_offset), Expr::Lit(size), src, Expr::ConcreteBuf(dst_buf)) => {
      if dst_offset < MAX_BYTES
        && size < MAX_BYTES
        && src_offset.clone() + size.clone() - W256(1, 0) > src_offset.clone()
      {
        let hd = pad_right(dst_offset.0 as usize, (&dst_buf[..dst_offset.0 as usize]).to_vec());
        let sl: Vec<Expr> = ((src_offset.0)..(src_offset.0) + (size.0))
          .map(|i| read_byte(Box::new(Expr::Lit(W256(i as u128, 0))), Box::new(src.clone())))
          .collect();
        let tl = &dst_buf[dst_offset.0 as usize + size.0 as usize..];

        if sl.iter().all(|arg0: &Expr| is_lit_byte(Box::new(arg0.clone()))) {
          let packed_sl: Vec<u8> = sl.into_iter().filter_map(maybe_lit_byte).collect();
          let mut result = hd;
          result.extend_from_slice(&packed_sl);
          result.extend_from_slice(tl);
          Expr::ConcreteBuf(result)
        } else {
          Expr::CopySlice(
            Box::new(Expr::Lit(src_offset)),
            Box::new(Expr::Lit(dst_offset)),
            Box::new(Expr::Lit(size)),
            Box::new(src.clone()),
            Box::new(Expr::ConcreteBuf(dst_buf)),
          )
        }
      } else {
        Expr::CopySlice(
          Box::new(Expr::Lit(src_offset)),
          Box::new(Expr::Lit(dst_offset)),
          Box::new(Expr::Lit(size)),
          Box::new(src),
          Box::new(Expr::ConcreteBuf(dst_buf)),
        )
      }
    }
    _ => {
      // abstract indices
      Expr::CopySlice(src_offset, dst_offset, size, src, dst)
    }
  }
}

pub fn is_lit_byte(e: Box<Expr>) -> bool {
  match *e {
    Expr::LitByte(_) => true,
    _ => false,
  }
}

// Concretize & simplify Keccak expressions until fixed-point.
pub fn conc_keccak_simp_expr(expr: Box<Expr>) -> Expr {
  until_fixpoint(|e| map_expr(|expr: &Expr| conc_keccak_one_pass(Box::new(expr.clone())), e.clone()), *expr)
}

// Only concretize Keccak in Props
// Needed because if it also simplified, we may not find some simplification errors, as
// simplification would always be ON
pub fn conc_keccak_props(props: Vec<Prop>) -> Vec<Prop> {
  until_fixpoint(
    |ps| {
      ps.into_iter().map(|p| map_prop(&mut |e: &Expr| conc_keccak_one_pass(Box::new(e.clone())), p.clone())).collect()
    },
    props,
  )
}

fn is_concretebuf(expr: Box<Expr>) -> bool {
  match *expr {
    Expr::ConcreteBuf(_) => true,
    _ => false,
  }
}

fn is_empty_concretebuf(expr: Box<Expr>) -> bool {
  match *expr {
    Expr::ConcreteBuf(dst_buf) => dst_buf.is_empty(),
    _ => false,
  }
}

fn is_simplifiable_ww(expr: Box<Expr>) -> bool {
  match *expr {
    Expr::WriteWord(a, _, c) if *a == Expr::Lit(W256(0, 0)) && is_concretebuf(c.clone()) => true,
    _ => false,
  }
}

fn get_len_of_bs_in_ww(expr: Box<Expr>) -> usize {
  match *expr {
    Expr::WriteWord(a, _, c) if *a == Expr::Lit(W256(0, 0)) && is_concretebuf(c.clone()) => match *c.clone() {
      Expr::ConcreteBuf(bs) => bs.len(),
      _ => 0,
    },
    _ => 0,
  }
}

// Simplifies in case the input to the Keccak is of specific array/map format and
//            can be simplified into a concrete value
// Turns (Keccak ConcreteBuf) into a Lit
fn conc_keccak_one_pass(expr: Box<Expr>) -> Expr {
  match *expr {
    Expr::Keccak(expr_) if is_concretebuf(expr_.clone()) => match *expr_.clone() {
      Expr::ConcreteBuf(_) => keccak(*expr_.clone()).unwrap(),
      _ => panic!(""),
    },
    Expr::Keccak(orig) => match *orig.clone() {
      Expr::CopySlice(
        a, //Expr::Lit(W256(0, 0)),
        b, //Expr::Lit(W256(0, 0)),
        c, // Expr::Lit(W256(64, 0)),
        d, // Expr::WriteWord(Expr::Lit(W256(0, 0)), _, (Expr::ConcreteBuf(bs))),
        e, //Expr::ConcreteBuf(dst_buf),
      ) if *a == Expr::Lit(W256(0, 0))
        && *b == Expr::Lit(W256(0, 0))
        && *c == Expr::Lit(W256(64, 0))
        && is_simplifiable_ww(d.clone())
        && is_empty_concretebuf(e.clone()) =>
      {
        match (
          get_len_of_bs_in_ww(d.clone()),
          copy_slice(
            Box::new(Expr::Lit(W256(0, 0))),
            Box::new(Expr::Lit(W256(0, 0))),
            Box::new(Expr::Lit(W256(64, 0))),
            Box::new(simplify(orig.clone())),
            Box::new(Expr::ConcreteBuf(vec![])),
          ),
        ) {
          (64, Expr::ConcreteBuf(a)) => keccak(Expr::ConcreteBuf(a)).unwrap(),
          _ => Expr::Keccak(orig),
        }
      }
      _ => Expr::Keccak(orig),
    },
    _ => *expr.clone(),
  }
}

// Main simplify function
pub fn simplify(expr: Box<Expr>) -> Expr {
  if *expr != Expr::Mempty {
    let simplified = map_expr(|arg0: &Expr| go_expr(Box::new(arg0.clone())), *expr.clone());
    if simplified == *expr {
      simplified
    } else {
      simplify(Box::new(map_expr(
        |arg0: &Expr| go_expr(Box::new(arg0.clone())),
        structure_array_slots(Box::new(*expr.clone())),
      )))
    }
  } else {
    Expr::Mempty
  }
}

fn structure_array_slots(e: Box<Expr>) -> Expr {
  fn go(a: Box<Expr>) -> Expr {
    match *a {
      ref orig @ Expr::Lit(ref key) => match lit_to_array_pre_image(key.clone()) {
        Some((array, offset)) => {
          Expr::Add(Box::new(Expr::Keccak(Box::new(Expr::ConcreteBuf(slot_pos(array))))), Box::new(Expr::Lit(offset)))
        }
        _ => orig.clone(),
      },
      _ => *a,
    }
  }
  map_expr(|a: &Expr| go(Box::new(a.clone())), *e)
}

/// Takes a value and checks if it's within 256 of a precomputed array hash value.
/// If it is, it returns (array_number, offset).
fn lit_to_array_pre_image(val: W256) -> Option<(Word8, W256)> {
  fn go(pre_images: &Vec<(W256, Word8)>, val: W256) -> Option<(Word8, W256)> {
    for (image, preimage) in pre_images {
      if val.clone() >= image.clone() && val.clone() - image.clone() <= W256(255, 0) {
        return Some((preimage.clone(), val.clone() - image.clone()));
      }
    }
    None
  }

  go(&pre_images(), val)
}

/// Precompute the hashes and store them in a HashMap
fn pre_images() -> Vec<(W256, u8)> {
  (0..=255).map(|i| (keccak_prime(&word256_bytes(W256(i, 0))), i as u8)).collect()
}

fn slot_pos(pos: Word8) -> ByteString {
  let mut res = vec![0_u8; 32];
  res[31] = pos;
  res
}

fn go_expr(expr: Box<Expr>) -> Expr {
  match *expr.clone() {
    Expr::Failure(a, b, c) => Expr::Failure(simplify_props(a.clone()), b.clone(), c.clone()),
    Expr::Partial(a, b, c) => Expr::Partial(simplify_props(a.clone()), b.clone(), c.clone()),
    Expr::Success(a, b, c, d) => Expr::Success(simplify_props(a.clone()), b.clone(), c.clone(), d.clone()),

    Expr::SLoad(slot, store) => read_storage(slot.clone(), store.clone()).unwrap(),
    Expr::SStore(slot, val, store) => write_storage(slot, val, store),

    Expr::ReadWord(idx_, buf_) => match (*idx_.clone(), *buf_.clone()) {
      (Expr::Lit(_), _) => simplify_reads(expr),
      (_, _) => *read_word(idx_, buf_),
    },

    Expr::ReadByte(idx_, buf_) => match (*idx_.clone(), *buf_.clone()) {
      (Expr::Lit(_), _) => simplify_reads(expr),
      (_, _) => read_byte(idx_, buf_),
    },

    Expr::BufLength(buf) => buf_length(*buf.clone()),

    Expr::WriteWord(a_, b_, c_) => match (*a_.clone(), *b_.clone(), *c_.clone()) {
      (Expr::Lit(idx), val, Expr::ConcreteBuf(b)) if idx < MAX_BYTES => {
        let first_part = pad_right(idx.0 as usize, b.clone()).into_iter().take(idx.0 as usize).collect::<Vec<u8>>();
        let zero_padding = vec![0; 32];
        let third_part = b.into_iter().skip(idx.0 as usize + 32).collect::<Vec<u8>>();
        let result = [first_part, zero_padding, third_part].concat();
        write_word(Box::new(Expr::Lit(idx)), Box::new(val), Box::new(Expr::ConcreteBuf(result)))
      }
      (a, b, c) => write_word(Box::new(a), Box::new(b), Box::new(c)),
    },

    Expr::WriteByte(a, b, c) => write_byte(a, b, c),

    Expr::CopySlice(src_off_, dst_off_, size_, src_, dst_) => {
      match (*src_off_.clone(), *dst_off_.clone(), *size_.clone(), *src_.clone(), *dst_.clone()) {
        (Expr::Lit(W256(0, 0)), Expr::Lit(W256(0, 0)), Expr::Lit(W256(0, 0)), _, dst) => dst.clone(),
        (Expr::Lit(W256(0, 0)), Expr::Lit(W256(0, 0)), Expr::Lit(s), src, Expr::ConcreteBuf(b))
          if b.len() == 0 && buf_length(src.clone()) == Expr::Lit(s.clone()) =>
        {
          src.clone()
        }
        (ref src_off @ Expr::Lit(_), dst_off, ref size @ Expr::Lit(_), src, dst) => {
          if let Expr::WriteWord(w_off, value, cb) = src.clone() {
            if let Expr::ConcreteBuf(buf) = *cb.clone() {
              let n = if let Expr::Lit(n) = src_off { n.clone() } else { W256(0, 0) };
              let sz = if let Expr::Lit(sz) = size { sz.clone() } else { W256(0, 0) };
              if n.clone() + sz.clone() >= n.clone()
                && n.clone() + sz.clone() >= sz.clone()
                && n.clone() + sz.clone() <= MAX_BYTES
              {
                let simplified_buf = &buf[..(n + sz).0 as usize];
                return copy_slice(
                  src_off_,
                  dst_off_,
                  size_,
                  Box::new(Expr::WriteWord(
                    w_off.clone(),
                    value.clone(),
                    Box::new(Expr::ConcreteBuf(simplified_buf.to_vec())),
                  )),
                  dst_,
                );
              } else {
                copy_slice(
                  Box::new(src_off.clone()),
                  Box::new(dst_off),
                  Box::new(size.clone()),
                  Box::new(src.clone()),
                  Box::new(dst.clone()),
                )
              }
            } else {
              copy_slice(
                Box::new(src_off.clone()),
                Box::new(dst_off),
                Box::new(size.clone()),
                Box::new(src.clone()),
                Box::new(dst.clone()),
              )
            }
          } else {
            copy_slice(
              Box::new(src_off.clone()),
              Box::new(dst_off),
              Box::new(size.clone()),
              Box::new(src.clone()),
              Box::new(dst.clone()),
            )
          }
        }
        (a, b, c, d, f) => copy_slice(Box::new(a), Box::new(b), Box::new(c), Box::new(d), Box::new(f)),
      }
    }
    Expr::IndexWord(a, b) => index_word(a, b),

    Expr::LT(a_, b_) => match (*a_.clone(), *b_.clone()) {
      (Expr::Lit(a), Expr::Lit(b)) => {
        if a < b {
          Expr::Lit(W256(1, 0))
        } else {
          Expr::Lit(W256(0, 0))
        }
      }
      (__, Expr::Lit(W256(0, 0))) => Expr::Lit(W256(0, 0)),
      (a, b) => lt(Box::new(a), Box::new(b)),
    },

    Expr::GT(a, b) => gt(a, b),
    Expr::GEq(a, b) => geq(a, b),
    Expr::LEq(a, b) => leq(a, b),
    Expr::SLT(a, b) => slt(a, b),
    Expr::SGT(a, b) => sgt(a, b),

    // TODO: check its correctness
    Expr::IsZero(a) => match *a.clone() {
      Expr::WAddr(b) => match *b.clone() {
        Expr::SymAddr(_) => Expr::Lit(W256(0, 0)),
        _ => iszero(a),
      },
      _ => iszero(a),
    },
    // Expr::IsZero(a) => iszero(a),
    Expr::Xor(a_, b_) => match (*a_.clone(), *b_.clone()) {
      (Expr::Lit(a), Expr::Lit(b)) => Expr::Lit(a ^ b),
      _ => xor(a_.clone(), b_.clone()),
    },

    Expr::Eq(a_, b_) => match (*a_.clone(), *b_.clone()) {
      (Expr::Lit(a), Expr::Lit(b)) => Expr::Lit(if a == b { W256(1, 0) } else { W256(0, 0) }),
      (_, Expr::Lit(W256(0, 0))) => iszero(expr.clone()),
      (_, _) => eq(a_, b_),
    },

    Expr::ITE(a_, b_, c_) => match (*a_.clone(), *b_.clone(), *c_.clone()) {
      (Expr::Lit(W256(0, 0)), _, c) => c,
      (Expr::Lit(_), b, _) => b,
      (_, _, _) => Expr::ITE(a_.clone(), b_.clone(), c_.clone()),
    },

    Expr::And(a_, b_) => match (*a_.clone(), *b_.clone()) {
      (Expr::Lit(a), Expr::Lit(b)) => Expr::Lit(a & b),
      (Expr::Lit(W256(0, 0)), _) => Expr::Lit(W256(0, 0)),
      (Expr::Lit(W256(0xffffffffffffffffffffffffffffffff, 0xffffffff)), Expr::WAddr(_)) => *b_.clone(),
      _ => and(a_, b_),
    },

    Expr::Or(a_, b_) => match (*a_.clone(), *b_.clone()) {
      (Expr::Lit(a), Expr::Lit(b)) => Expr::Lit(a | b),
      (Expr::Lit(W256(0, 0)), a) => a.clone(),
      _ => or(a_, b_),
    },

    Expr::Not(a_) => match *a_.clone() {
      Expr::Lit(a) => Expr::Lit(if a == W256(0, 0) { W256(1, 0) } else { W256(0, 0) }),
      _ => not(a_),
    },

    /*
        go (Div (Lit 0) _) = Lit 0 -- divide 0 by anything (including 0) is zero in EVM
    go (Div _ (Lit 0)) = Lit 0 -- divide anything by 0 is zero in EVM
    go (Div a (Lit 1)) = a
     */
    Expr::Div(a_, b_) => match (*a_.clone(), *b_.clone()) {
      (Expr::Lit(W256(0, 0)), _) => Expr::Lit(W256(0, 0)),
      (_, Expr::Lit(W256(0, 0))) => Expr::Lit(W256(0, 0)),
      (a, Expr::Lit(W256(1, 0))) => a,
      (Expr::Mul(c, d), e) if *c.clone() == e => *d.clone(),
      (Expr::Mul(c, d), e) if *d.clone() == e => *c.clone(),
      (_, _) => div(a_, b_),
    },

    Expr::SDiv(a, b) => sdiv(a, b),
    Expr::Mod(a_, b_) => match (*a_.clone(), *b_.clone()) {
      (Expr::Lit(_), Expr::Lit(_)) => r#mod(a_, b_),
      (_, Expr::Lit(W256(0, 0))) => Expr::Lit(W256(0, 0)),
      (a, b) if a == b => Expr::Lit(W256(0, 0)),
      _ => *expr.clone(),
    },
    Expr::SMod(a, b) => smod(a, b),

    Expr::Add(a_, b_) => match (*a_.clone(), *b_.clone()) {
      (Expr::Lit(W256(0, 0)), a) => a,
      (Expr::Lit(a), Expr::Lit(b)) => Expr::Lit(a + b),
      _ => add(a_, b_),
    },

    Expr::Sub(a_, b_) => match (*a_.clone(), *b_.clone()) {
      (a, Expr::Lit(W256(0, 0))) => a,
      (Expr::Lit(a), Expr::Lit(b)) => Expr::Lit(a - b),
      _ => sub(a_, b_),
    },

    Expr::SHL(a_, b_) => match (*a_.clone(), *b_.clone()) {
      (Expr::Lit(a), _) => shl(Box::new(Expr::Lit(a)), b_),
      _ => shl(a_, b_),
    },

    Expr::SHR(a_, b_) => match (*a_.clone(), *b_.clone()) {
      (Expr::Lit(a), _) => shr(Box::new(Expr::Lit(a)), b_),
      _ => shr(a_, b_),
    },

    Expr::Max(a, b) => emax(a, b),
    Expr::Min(a, b) => emin(a, b),

    Expr::Mul(a_, b_) => match (*a_.clone(), *b_.clone()) {
      (_, Expr::Lit(W256(0, 0))) => Expr::Lit(W256(0, 0)),
      (Expr::Lit(W256(0, 0)), _) => Expr::Lit(W256(0, 0)),
      (Expr::Lit(a), Expr::Lit(b)) => Expr::Lit(a * b),
      _ => mul(a_, b_),
    },

    Expr::Lit(n) => Expr::Lit(n.clone()),
    Expr::WAddr(a) => Expr::WAddr(a.clone()),
    Expr::LitAddr(a) => Expr::LitAddr(a.clone()),
    _ => *expr.clone(),
  }
}

pub fn simplify_prop(prop: Prop) -> Prop {
  let mut fp: &dyn Fn(&Prop) -> Prop = &go_prop;
  let new_prop = map_prop_prime(&mut fp, simp_inner_expr(prop.clone()));

  let sp = if new_prop == prop { prop.clone() } else { simplify_prop(new_prop) };
  sp
}

fn simp_inner_expr(prop: Prop) -> Prop {
  match prop {
    Prop::PGEq(a, b) => simp_inner_expr(Prop::PLEq(b, a)),
    Prop::PGT(a, b) => simp_inner_expr(Prop::PLT(b, a)),
    Prop::PEq(a, b) => Prop::PEq(simplify(Box::new(a)), simplify(Box::new(b))),
    Prop::PLT(a, b) => Prop::PLT(simplify(Box::new(a)), simplify(Box::new(b))),
    Prop::PLEq(a, b) => Prop::PLEq(simplify(Box::new(a)), simplify(Box::new(b))),
    Prop::PNeg(a) => Prop::PNeg(Box::new(simp_inner_expr(*a))),
    Prop::PAnd(a, b) => Prop::PAnd(Box::new(simp_inner_expr(*a)), Box::new(simp_inner_expr(*b))),
    Prop::POr(a, b) => Prop::POr(Box::new(simp_inner_expr(*a)), Box::new(simp_inner_expr(*b))),
    Prop::PImpl(a, b) => Prop::PImpl(Box::new(simp_inner_expr(*a)), Box::new(simp_inner_expr(*b))),
    Prop::PBool(_) => prop.clone(),
  }
}

fn go_prop(prop: &Prop) -> Prop {
  let _v: W256 = W256::from_dec_str("1461501637330902918203684832716283019655932542975").unwrap();
  match prop.clone() {
    // LT/LEq comparisons
    Prop::PGT(a, b) => Prop::PLT(b, a),
    Prop::PGEq(a, b) => Prop::PLEq(b, a),

    Prop::PLEq(Expr::Lit(W256(0, 0)), _) => Prop::PBool(true),
    Prop::PLEq(Expr::WAddr(_), Expr::Lit(_)) => Prop::PBool(true),
    Prop::PLEq(_, Expr::Lit(x)) if x == MAX_LIT => Prop::PBool(true),

    Prop::PLEq(Expr::Var(_), Expr::Lit(val)) if val == MAX_LIT => Prop::PBool(true),
    Prop::PLEq(Expr::Lit(l), Expr::Lit(r)) => Prop::PBool(l <= r),
    Prop::PLEq(a, Expr::Max(b, _)) if a == *b => Prop::PBool(true),
    Prop::PLEq(a, Expr::Max(_, b)) if a == *b => Prop::PBool(true),
    Prop::PLEq(Expr::Sub(a, b), c) if *a == c => Prop::PLEq(*b, *a),

    Prop::PLT(a, b) => match (a, b.clone()) {
      (Expr::Var(_), Expr::Lit(W256(0, 0))) => Prop::PBool(false),
      (Expr::Lit(W256(0, 0)), Expr::Eq(a_, b_)) => Prop::PEq(*a_, *b_),
      (Expr::Lit(l), Expr::Lit(r)) => Prop::PBool(l < r),
      (Expr::Max(a_, b_), Expr::Lit(c_)) => match *a_ {
        Expr::Lit(a_v) if (a_v < c_) => Prop::PLT(*b_, Expr::Lit(c_)),
        _ => prop.clone(),
      },
      _ => prop.clone(),
    },

    // Negations
    Prop::PNeg(x) => {
      match *x {
        Prop::PBool(b) => Prop::PBool(!b),
        Prop::PNeg(a) => *a,
        Prop::PEq(Expr::IsZero(a_), Expr::Lit(W256(0, 0))) => {
          match *a_ {
            // IsZero(a) -> (a == 0)
            // IsZero(IsZero(a)) -> ~(a == 0) -> a > 0
            // IsZero(IsZero(a)) == 0 -> ~~(a == 0) -> a == 0
            // ~(IsZero(IsZero(a)) == 0) -> ~~~(a == 0) -> ~(a == 0) -> a > 0
            Expr::IsZero(a) => Prop::PLT(Expr::Lit(W256(0, 0)), *a),
            // IsZero(a) -> (a == 0)
            // IsZero(a) == 0 -> ~(a == 0)
            // ~(IsZero(a) == 0) -> ~~(a == 0) -> a == 0
            _ => Prop::PEq(*a_, Expr::Lit(W256(0, 0))),
          }
        }
        // a < b == 0 -> ~(a < b)
        // ~(a < b == 0) -> ~~(a < b) -> a < b
        Prop::PEq(Expr::LT(a, b), Expr::Lit(W256(0, 0))) => Prop::PLT(*a, *b),
        _ => prop.clone(),
      }
    }

    // And/Or
    Prop::PAnd(a, b) => match (*a, *b) {
      (Prop::PBool(l), Prop::PBool(r)) => Prop::PBool(l && r),
      (Prop::PBool(false), _) => Prop::PBool(false),
      (_, Prop::PBool(false)) => Prop::PBool(false),
      (Prop::PBool(true), x) => x,
      (x, Prop::PBool(true)) => x,
      _ => prop.clone(),
    },
    Prop::POr(a, b) => match (*a, *b) {
      (Prop::PBool(l), Prop::PBool(r)) => Prop::PBool(l || r),
      (Prop::PBool(true), _) => Prop::PBool(true),
      (_, Prop::PBool(true)) => Prop::PBool(true),
      (Prop::PBool(false), x) => x,
      (x, Prop::PBool(false)) => x,
      _ => prop.clone(),
    },

    // Imply
    Prop::PImpl(a, b) => match (*a, *b) {
      (_, Prop::PBool(true)) => Prop::PBool(true),
      (Prop::PBool(true), b) => b,
      (Prop::PBool(false), _) => Prop::PBool(true),
      _ => prop.clone(),
    },

    // Eq
    Prop::PEq(a_, b_) => {
      match (a_, b_) {
        (Expr::IsZero(x), Expr::Lit(W256(0, 0))) => {
          // Solc specific stuff
          match *x {
            Expr::Eq(a, b) => Prop::PEq(*a, *b),
            Expr::IsZero(y) => match *y {
              Expr::Eq(a, b) => Prop::PNeg(Box::new(Prop::PEq(*a, *b))),
              _ => prop.clone(),
            },
            _ => prop.clone(),
          }
        }
        (Expr::Eq(a, b), Expr::Lit(W256(0, 0))) => Prop::PNeg(Box::new(Prop::PEq(*a, *b))),
        (Expr::Eq(a, b), Expr::Lit(W256(1, 0))) => Prop::PEq(*a, *b),
        (Expr::Sub(a, b), Expr::Lit(W256(0, 0))) => Prop::PEq(*a, *b),
        (Expr::LT(a, b), Expr::Lit(W256(0, 0))) => Prop::PLEq(*b, *a),
        (Expr::Lit(l), Expr::Lit(r)) => Prop::PBool(l == r),
        (l, r) => {
          if l == r {
            Prop::PBool(true)
          } else {
            Prop::PEq(l, r)
          }
        }
      }
    }
    _ => prop.clone(),
  }
}

// Equivalent to Haskell's pattern-matching
pub fn read_storage(w: Box<Expr>, st: Box<Expr>) -> Option<Expr> {
  fn go(slot: Expr, storage: Expr) -> Option<Expr> {
    match storage.clone() {
      Expr::AbstractStore(_, _) => Some(Expr::SLoad(Box::new(slot.clone()), Box::new(storage.clone()))),
      Expr::ConcreteStore(s) => match slot {
        Expr::Lit(l) => {
          let v = s.get(&l).cloned();
          if let Some(v_) = v {
            Some(Expr::Lit(v_))
          } else {
            None
          }
        }
        _ => Some(Expr::SLoad(Box::new(slot.clone()), Box::new(storage.clone()))),
      },
      Expr::SStore(prev_slot, val, prev) => match (*prev_slot.clone(), slot.clone()) {
        // if address and slot match then we return the val in this write
        (a, b) if a == b => Some(*val.clone()),
        // if the slots don't match (see previous guard) and are lits, we can skip this write
        (Expr::Lit(_), Expr::Lit(_)) => go(slot.clone(), *prev.clone()),
        // Fixed SMALL value will never match Keccak (well, it might, but that's VERY low chance)
        (Expr::Lit(a), Expr::Keccak(_)) if a < W256(256, 0) => go(slot.clone(), *prev.clone()),
        (Expr::Keccak(_), Expr::Lit(a)) if a < W256(256, 0) => go(slot.clone(), *prev.clone()),
        // Finding two Keccaks that are < 256 away from each other should be VERY hard
        // This simplification allows us to deal with maps of structs
        (Expr::Add(a2_, k1_), Expr::Add(b2_, k2_)) => match (*a2_.clone(), *k1_.clone(), *b2_.clone(), *k2_.clone()) {
          (Expr::Lit(a2), Expr::Keccak(_), Expr::Lit(b2), Expr::Keccak(_))
            if a2 != b2 && (a2.0 as i64 - b2.0 as i64).abs() < 256 =>
          {
            go(slot.clone(), *prev.clone())
          }
          _ => Some(Expr::SLoad(Box::new(slot.clone()), Box::new(storage.clone()))),
        },
        (Expr::Add(a2_, k1_), Expr::Keccak(_)) => match (*a2_.clone(), *k1_.clone()) {
          (Expr::Lit(a2), Expr::Keccak(_)) if a2 > W256(0, 0) && a2 < W256(256, 0) => go(slot.clone(), *prev.clone()),
          _ => Some(Expr::SLoad(Box::new(slot.clone()), Box::new(storage.clone()))),
        },
        (Expr::Keccak(_), Expr::Add(a2_, k1_)) => match (*a2_.clone(), *k1_.clone()) {
          (Expr::Lit(a2), Expr::Keccak(_)) if a2 > W256(0, 0) && a2 < W256(256, 0) => go(slot.clone(), *prev.clone()),
          _ => Some(Expr::SLoad(Box::new(slot.clone()), Box::new(storage.clone()))),
        },
        _ => Some(Expr::SLoad(Box::new(slot.clone()), Box::new(storage.clone()))),
      },
      // we are unable to determine statically whether or not we can safely move deeper in the write chain, so return an abstract term
      _ => panic!("unexpected expression: slot={}, storage={}", slot, storage),
    }
  }
  go(simplify(w), *st)
}

pub fn write_storage(k: Box<Expr>, v: Box<Expr>, store: Box<Expr>) -> Expr {
  match (*k.clone(), *v.clone(), *store.clone()) {
    (Expr::Lit(key), Expr::Lit(val), store) => match store {
      Expr::ConcreteStore(s) => {
        let mut s_ = s.clone();
        s_.insert(key, val);
        Expr::ConcreteStore(s_)
      }
      _ => Expr::SStore(k, v, Box::new(store)),
    },
    (key, val, Expr::SStore(key_, val_, prev)) => {
      if key == *key_ {
        Expr::SStore(Box::new(key), Box::new(val), prev)
      } else {
        match (key.clone(), *key_.clone()) {
          (Expr::Lit(k), Expr::Lit(k_)) => {
            if k > k_ {
              Expr::SStore(key_, val_, Box::new(write_storage(Box::new(key), Box::new(val), prev)))
            } else {
              Expr::SStore(Box::new(key), Box::new(val), store)
            }
          }
          _ => Expr::SStore(Box::new(key), Box::new(val), store),
        }
      }
    }
    _ => Expr::SStore(k, v, store),
  }
}

pub fn create_address_(a: Addr, n: W64) -> Expr {
  Expr::LitAddr(keccak_prime(&rlp_list(vec![rlp_addr_full(a), rlp_word_256(W256(n as u128, 0))])))
}

pub fn create2_address_(a: Addr, s: W256, b: ByteString) -> Expr {
  let prefix = [0xff];
  let addr_bytes = word256_bytes(a);
  let salt_bytes = word256_bytes(s);
  let code_hash_bytes = word256_bytes(keccak_prime(&b));

  let data: Vec<u8> = [&prefix[..], &addr_bytes[..], &salt_bytes[..], &code_hash_bytes[..]].concat();

  let hash = keccak_prime(&data);
  Expr::LitAddr(hash)
}

// Function to flatten PAnd
fn flatten_props(props: Vec<Prop>) -> Vec<Prop> {
  let mut result = Vec::new();

  for prop in props {
    match prop {
      Prop::PAnd(x1, x2) => {
        result.push(*x1);
        result.push(*x2);
      }
      x => result.push(x),
    }
  }

  result
}

// Function to remove redundant props
fn rem_redundant_props(props: Vec<Prop>) -> Vec<Prop> {
  // Filter out PBool(true)
  let filtered: Vec<Prop> = props.into_iter().filter(|x| *x != Prop::PBool(true)).collect();

  // Check if PBool(false) is present
  if filtered.iter().any(|x| *x == Prop::PBool(false)) {
    vec![Prop::PBool(false)] // Return only PBool(false) if it exists
  } else {
    // Use HashSet to remove duplicates
    let unique: HashSet<Prop> = filtered.into_iter().collect();
    unique.into_iter().collect()
  }
}

// Define the ConstState struct
#[derive(Debug, Clone)]
struct ConstState {
  values: HashMap<Expr, W256>,
  can_be_sat: bool,
}

impl ConstState {
  fn new() -> Self {
    ConstState { values: HashMap::new(), can_be_sat: true }
  }
}

// Function to fold constants
fn const_fold_prop(ps: Vec<Prop>) -> bool {
  // Inner function one_run to process props
  fn one_run(ps2: Vec<Prop>, start_state: &mut ConstState) -> bool {
    for p in ps2 {
      go_const_fold_prop(p, start_state);
    }
    start_state.can_be_sat
  }

  // Inner function go to handle logic
  fn go_const_fold_prop(x: Prop, state: &mut ConstState) {
    match x {
      // PEq
      Prop::PEq(Expr::Lit(l), a) => match state.values.get(&a) {
        Some(l2) => {
          if *l2 != l {
            state.can_be_sat = false;
            state.values.clear();
          }
        }
        None => {
          state.values.insert(a, l);
        }
      },
      Prop::PEq(a, Expr::Lit(l)) => {
        go_const_fold_prop(Prop::PEq(Expr::Lit(l), a), state);
      }
      // PNeg
      Prop::PNeg(boxed) => match *boxed {
        Prop::PEq(Expr::Lit(l), a) => match state.values.get(&a) {
          Some(l2) => {
            if *l2 == l {
              state.can_be_sat = false;
              state.values.clear();
            }
          }
          None => (),
        },
        Prop::PEq(a, Expr::Lit(l)) => {
          go_const_fold_prop(Prop::PNeg(Box::new(Prop::PEq(Expr::Lit(l), a))), state);
        }
        _ => (),
      },
      // PAnd
      Prop::PAnd(a, b) => {
        go_const_fold_prop(*a, state);
        go_const_fold_prop(*b, state);
      }
      // POr
      Prop::POr(a, b) => {
        let mut s = state.clone();
        let v1 = one_run(vec![*a.clone()], &mut s);
        let v2 = one_run(vec![*b.clone()], state);
        if !v1 {
          go_const_fold_prop(*b, state);
        }
        if !v2 {
          go_const_fold_prop(*a, state);
        }
        state.can_be_sat = state.can_be_sat && (v1 || v2);
      }
      // PBool
      Prop::PBool(false) => {
        state.can_be_sat = false;
        state.values.clear();
      }
      _ => (),
    }
  }

  one_run(ps.into_iter().map(simplify_prop).collect(), &mut ConstState::new())
}

pub fn simplify_props(ps: Vec<Prop>) -> Vec<Prop> {
  let simplified = rem_redundant_props(flatten_props(ps).into_iter().map(simplify_prop).collect());
  let can_be_sat = const_fold_prop(simplified.clone());
  if can_be_sat {
    simplified
  } else {
    vec![Prop::PBool(false)]
  }
}

// Simplify reads by removing irrelevant writes
fn simplify_reads(expr: Box<Expr>) -> Expr {
  match *expr.clone() {
    Expr::ReadWord(a, b) => match *a {
      Expr::Lit(idx) => *read_word(Box::new(Expr::Lit(idx.clone())), Box::new(strip_writes(idx, W256(32, 0), b))),
      _ => *expr,
    },
    Expr::ReadByte(a, b) => match *a {
      Expr::Lit(idx) => read_byte(Box::new(Expr::Lit(idx.clone())), Box::new(strip_writes(idx, W256(1, 0), b))),
      _ => *expr,
    },
    _ => *expr,
  }
}

// Strip writes that are out of range
fn strip_writes(off: W256, size: W256, buffer: Box<Expr>) -> Expr {
  match *buffer.clone() {
    Expr::AbstractBuf(s) => Expr::AbstractBuf(s),
    Expr::ConcreteBuf(b) => {
      if off.clone() <= off.clone() + size.clone() {
        match off.clone() + size.clone() < W256(u32::MAX as u128, 0) {
          true => Expr::ConcreteBuf(b.into_iter().take((off.clone() + size.clone()).0 as usize).collect()),
          false => Expr::ConcreteBuf(b),
        }
      } else {
        Expr::ConcreteBuf(b)
      }
    }
    Expr::WriteByte(idx_, v, prev) => match *idx_ {
      Expr::Lit(idx) => {
        if idx.clone() - off.clone() >= size {
          strip_writes(off, size, prev)
        } else {
          Expr::WriteByte(Box::new(Expr::Lit(idx.clone())), v, Box::new(strip_writes(off, size, prev)))
        }
      }
      _ => Expr::WriteByte(Box::new(*idx_.clone()), Box::new(*v.clone()), Box::new(strip_writes(off, size, prev))),
    },
    Expr::WriteWord(idx_, v, prev) => match *idx_ {
      Expr::Lit(idx) => {
        if idx.clone() - off.clone() >= size && idx.clone() - off.clone() <= W256::max_value() - W256(31, 0) {
          strip_writes(off, size, prev)
        } else {
          Expr::WriteWord(Box::new(Expr::Lit(idx.clone())), v, Box::new(strip_writes(off, size, prev)))
        }
      }
      _ => Expr::WriteWord(Box::new(*idx_.clone()), Box::new(*v.clone()), Box::new(strip_writes(off, size, prev))),
    },
    // Expr::CopySlice(box Expr::Lit(src_off), box Expr::Lit(dst_off), box Expr::Lit(size_), box src, box dst) => {
    Expr::CopySlice(src_off_, dst_off_, size_, src, dst) => {
      match (*src_off_.clone(), *dst_off_.clone(), *size_.clone()) {
        (Expr::Lit(src_off), Expr::Lit(dst_off), Expr::Lit(size_)) => {
          if dst_off.clone() - off.clone() >= size
            && dst_off.clone() - off.clone() <= W256::max_value() - size_.clone() - W256(1, 0)
          {
            strip_writes(off, size, dst)
          } else {
            Expr::CopySlice(
              Box::new(Expr::Lit(src_off.clone())),
              Box::new(Expr::Lit(dst_off.clone())),
              Box::new(Expr::Lit(size_.clone())),
              Box::new(strip_writes(src_off, size_, src)),
              Box::new(strip_writes(off, size, dst)),
            )
          }
        }
        _ => Expr::CopySlice(src_off_, dst_off_, size_, src, dst),
      }
    }
    Expr::GVar(_) => panic!("Unexpected GVar in stripWrites"),
    _ => *buffer,
  }
}

/*
-- returns the largest prefix that is guaranteed to be concrete (if one exists)
-- partial: will hard error if we encounter an input buf with a concrete size > 500mb
-- partial: will hard error if the prefix is > 500mb
*/
pub fn concrete_prefix(b: Box<Expr>) -> Vec<u8> {
  fn max_idx() -> i32 {
    500 * (10_i32.pow(6))
  }
  fn input_len(b: Box<Expr>) -> Option<W256> {
    match buf_length(*b) {
      Expr::Lit(s) => {
        if s > W256(max_idx as u128, 0) {
          panic!("concrete prefix: input buffer size exceeds 500mb")
        } else {
          Some(s)
        }
      }
      _ => None,
    }
  }
  fn has_enough_concrete_size(i: i32, b: Box<Expr>) -> bool {
    if let Some(mr) = input_len(b) {
      return W256(i as u128, 0) >= mr;
    }
    false
  }

  fn go(b: Box<Expr>, i: i32, mut v: Vec<u8>) -> (i32, Vec<u8>) {
    if i >= max_idx() {
      panic!("concrete prefix: prefix size exceeds 500mb");
    } else if has_enough_concrete_size(i, b.clone()) {
      (i, v)
    } else if i as usize >= v.len() {
      v.resize(v.len() * 2, 0);
      go(b, i, v)
    } else {
      match read_byte(Box::new(Expr::Lit(W256(i as u128, 0))), b.clone()) {
        Expr::LitByte(byte) => {
          v[i as usize] = byte;
          go(b, i + 1, v)
        }
        _ => (i, v),
      }
    }
  }

  let v_size = if let Some(w) = input_len(b.clone()) { w.0 } else { 1024 };
  let v = vec![0; v_size as usize];
  let result = go(b.clone(), 0, v);
  result.1
}

pub fn get_addr(e: Box<Expr>) -> Option<Expr> {
  match *e {
    Expr::SStore(_, _, p) => get_addr(p),
    Expr::AbstractStore(a, _) => Some(*a),
    Expr::ConcreteStore(_) => None,
    Expr::GVar(_) => panic!("cannot determine addr of a GVar"),
    _ => panic!("unexpected expressions"),
  }
}

pub fn get_logical_idx(e: Box<Expr>) -> Option<W256> {
  match *e {
    Expr::SStore(_, _, p) => get_logical_idx(p),
    Expr::AbstractStore(_, idx) => idx,
    Expr::ConcreteStore(_) => None,
    Expr::GVar(_) => panic!("cannot determine addr of a GVar"),
    _ => panic!("unexpected expressions"),
  }
}

pub fn contains_node<F>(p: F, b: Box<Expr>) -> bool
where
  F: Fn(&Expr) -> bool,
{
  fold_expr(
    &mut &|a: &Expr| {
      if p(&a) {
        1
      } else {
        0
      }
    },
    0,
    &*b,
  ) > 0
}

// Conversion function from Expr<Buf> to Vec<Expr<u8>>
pub fn to_list(buf: Box<Expr>) -> Option<Vec<Box<Expr>>> {
  match *buf {
    Expr::AbstractBuf(_) => None,
    Expr::ConcreteBuf(bs) => Some(bs.iter().map(|b| Box::new(Expr::LitByte(*b))).collect()),
    buf => match buf_length(buf.clone()) {
      Expr::Lit(l) => {
        if l <= W256(usize::MAX as u128, 0) {
          Some((0..l.0).map(|i| Box::new(read_byte(Box::new(Expr::Lit(W256(i, 0))), Box::new(buf.clone())))).collect())
        } else {
          None
        }
      }
      _ => None,
    },
  }
}

// Define the min_length function
pub fn min_length(buf_env: &BufEnv, buf: Box<Expr>) -> Option<i64> {
  fn go(l: W256, buf: Box<Expr>, buf_env: &BufEnv) -> Option<i64> {
    match *buf {
      Expr::AbstractBuf(_) => {
        if l == W256(0, 0) {
          None
        } else {
          Some(l.0 as i64)
        }
      }
      Expr::ConcreteBuf(b) => Some(std::cmp::max(b.len() as i64, l.0 as i64)),
      Expr::WriteWord(idx_, _, b) => match *idx_.clone() {
        Expr::Lit(idx) => go(l.max(idx + W256(32, 0)), b, buf_env),
        _ => go(l, b, buf_env),
      },
      Expr::WriteByte(idx_, _, b) => match *idx_.clone() {
        Expr::Lit(idx) => go(l.max(idx + W256(1, 0)), b, buf_env),
        _ => go(l, b, buf_env),
      },
      Expr::CopySlice(_, dst_offset_, size_, _, dst) => match (*dst_offset_.clone(), *size_.clone()) {
        (Expr::Lit(dst_offset), Expr::Lit(size)) => go((dst_offset + size).max(l), dst, buf_env),
        _ => go(l, dst, buf_env),
      },
      Expr::GVar(GVar::BufVar(a)) => buf_env.get(&(a as usize)).and_then(|b| go(l, Box::new(b.clone()), buf_env)),
      // Handle other cases if necessary
      _ => panic!("unexpected expr"),
    }

    // go(std::cmp::max(dst_offset + size, l), dst)
  }

  go(W256(0, 0), buf, buf_env)
}

pub fn word_to_addr(e: Box<Expr>) -> Option<Expr> {
  fn go(e: Box<Expr>) -> Option<Expr> {
    match *e {
      Expr::WAddr(a) => Some(*a.clone()),
      Expr::Lit(a) => Some(Expr::LitAddr(a)),
      _ => None,
    }
  }
  go(Box::new(simplify(e)))
}

pub fn drop(n: W256, buf: Box<Expr>) -> Expr {
  slice(Box::new(Expr::Lit(n.clone())), Box::new(sub(Box::new(buf_length(*buf.clone())), Box::new(Expr::Lit(n)))), buf)
}

pub fn slice(offset: Box<Expr>, size: Box<Expr>, src: Box<Expr>) -> Expr {
  copy_slice(offset, Box::new(Expr::Lit(W256(0, 0))), size, src, Box::new(Expr::Mempty))
}

pub fn buf_length(buf: Expr) -> Expr {
  let e = buf_length_env(&HashMap::new(), false, buf.clone());
  e
}

pub fn buf_length_env(env: &HashMap<usize, Expr>, use_env: bool, buf: Expr) -> Expr {
  fn go(l: Expr, buf: Expr, env: &HashMap<usize, Expr>, use_env: bool) -> Expr {
    match buf {
      Expr::ConcreteBuf(b) => emax(Box::new(l), Box::new(Expr::Lit(W256(b.len() as u128, 0)))),
      Expr::AbstractBuf(b) => emax(Box::new(l), Box::new(Expr::BufLength(Box::new(Expr::AbstractBuf(b))))),
      Expr::WriteWord(idx, _, b) => {
        go(emax(Box::new(l), Box::new(add(idx, Box::new(Expr::Lit(W256(32, 0)))))), *b, env, use_env)
      }
      Expr::WriteByte(idx, _, b) => {
        go(emax(Box::new(l), Box::new(add(idx, Box::new(Expr::Lit(W256(1, 0)))))), *b, env, use_env)
      }
      Expr::CopySlice(_, dst_offset, size, _, dst) => {
        go(emax(Box::new(l), Box::new(add(dst_offset, size))), *dst, env, use_env)
      }
      Expr::GVar(GVar::BufVar(a)) => {
        if use_env {
          if let Some(b) = env.get(&(a as usize)) {
            go(l, b.clone(), env, use_env)
          } else {
            panic!("Cannot compute length of open expression")
          }
        } else {
          emax(Box::new(l), Box::new(Expr::BufLength(Box::new(Expr::GVar(GVar::BufVar(a))))))
        }
      }
      Expr::Mempty => Expr::Lit(W256(0, 0)),
      _ => panic!("unsupported expression: {}", buf),
    }
  }

  go(Expr::Lit(W256(0, 0)), buf, &env, use_env)
}

pub fn is_function_sig_check_prop(prop: &Prop) -> bool {
  match prop {
    Prop::PNeg(p1) => match *p1.clone() {
      Prop::PEq(Expr::Eq(e1, e2), Expr::Lit(W256(0, 0))) => match (*e1.clone(), *e2.clone()) {
        (Expr::Lit(w), Expr::SHR(e3, _)) => match *e3.clone() {
          Expr::Lit(W256(0xe0, 0)) => w.to_hex().len() <= 8,
          _ => false,
        },
        _ => false,
      },
      _ => false,
    },
    _ => false,
  }
}
