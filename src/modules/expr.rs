use core::panic;
use std::{clone, cmp::min};

use crate::modules::rlp::{rlp_addr_full, rlp_list, rlp_word_256};
use crate::modules::traversals::{map_expr, map_prop};
use crate::modules::types::{
  keccak, keccak_prime, maybe_lit_addr, maybe_lit_byte, pad_right, until_fixpoint, word256_bytes, Addr, Expr, Prop,
  W256, W64,
};

use super::evm::buf_length;
use super::types::{word256, ByteString};
// ** Constants **

const MAX_LIT: W256 = W256(0xffffffffffffffffffffffffffffffff, 0xffffffffffffffffffffffffffffffff);

// ** Stack Ops ** ---------------------------------------------------------------------------------

pub fn op1<F1, F2>(symbolic: F1, concrete: F2, x: &Expr) -> Expr
where
  F1: Fn(Box<Expr>) -> Expr,
  F2: Fn(W256) -> W256,
{
  match x {
    Expr::Lit(x) => Expr::Lit(concrete(x.clone())),
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
  op2(Expr::Div, |x, y| if y == W256(0, 0) { W256(0, 0) } else { x / y }, &l, &r)
}

pub fn emin(l: Expr, r: Expr) -> Expr {
  norm_args(
    Expr::Min,
    |x, y| {
      if x <= y {
        x
      } else {
        y
      }
    },
    &l,
    &r,
  )
}

pub fn emax(l: Expr, r: Expr) -> Expr {
  norm_args(
    Expr::Min,
    |x, y| {
      if x >= y {
        x
      } else {
        y
      }
    },
    &l,
    &r,
  )
}

pub fn sdiv(l: Expr, r: Expr) -> Expr {
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
    &l,
    &r,
  )
}

pub fn r#mod(l: Expr, r: Expr) -> Expr {
  op2(Expr::Mod, |x, y| if y == W256(0, 0) { W256(0, 0) } else { x % y }, &l, &r)
}

pub fn smod(l: Expr, r: Expr) -> Expr {
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
    &l,
    &r,
  )
}

pub fn addmod(x: Expr, y: Expr, z: Expr) -> Expr {
  op3(
    Expr::AddMod,
    |x, y, z| {
      if z == W256(0, 0) {
        W256(0, 0)
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
      if z == W256(0, 0) {
        W256(0, 0)
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
  // TODO: support W256.pow(W256)
  op2(Expr::Exp, |x, y| W256(0, x.0.pow(y.0 as u32)), &x, &y)
}

pub fn sex(bytes: Expr, x: Expr) -> Expr {
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
    &bytes,
    &x,
  )
}

// Booleans

pub fn lt(x: Expr, y: Expr) -> Expr {
  op2(Expr::LT, |x, y| if x < y { W256(1, 0) } else { W256(0, 0) }, &x, &y)
}

pub fn gt(x: Expr, y: Expr) -> Expr {
  op2(Expr::GT, |x, y| if x > y { W256(1, 0) } else { W256(0, 0) }, &x, &y)
}

pub fn leq(x: Expr, y: Expr) -> Expr {
  op2(Expr::LEq, |x, y| if x <= y { W256(1, 0) } else { W256(0, 0) }, &x, &y)
}

pub fn geq(x: Expr, y: Expr) -> Expr {
  op2(Expr::GEq, |x, y| if x >= y { W256(1, 0) } else { W256(0, 0) }, &x, &y)
}

pub fn slt(x: Expr, y: Expr) -> Expr {
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
        W256(1, 0)
      } else {
        W256(0, 0)
      }
    },
    &x,
    &y,
  )
}

pub fn eq(x: Expr, y: Expr) -> Expr {
  norm_args(Expr::Eq, |x, y| if x == y { W256(1, 0) } else { W256(0, 0) }, &x, &y)
}

pub fn iszero(x: Expr) -> Expr {
  op1(Expr::IsZero, |x| if x == W256(0, 0) { W256(1, 0) } else { W256(0, 0) }, &x)
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
  op2(Expr::SHL, |x, y| if x > W256(256, 0) { W256(0, 0) } else { y << x.0 as u32 }, &x, &y)
}

pub fn shr(x: Expr, y: Expr) -> Expr {
  op2(Expr::SHR, |x, y| if x > W256(256, 0) { W256(0, 0) } else { y >> x.0 as u32 }, &x, &y)
}

pub fn sar(x: Expr, y: Expr) -> Expr {
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
    &x,
    &y,
  )
}

pub fn in_range(sz: u32, e: Expr) -> Prop {
  Prop::PAnd(
    Box::new(Prop::PGEq(e.clone(), Expr::Lit(W256(0, 0)))),
    Box::new(Prop::PLEq(e.clone(), Expr::Lit(W256((2 ^ (sz) - 1) as u128, 0)))),
  )
}

const MAX_WORD32: u32 = u32::MAX;
const MAX_BYTES: W256 = W256(MAX_WORD32 as u128 / 8, 0);

pub fn write_byte(offset: Expr, byte: Expr, src: Expr) -> Expr {
  match (offset, byte, src) {
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

fn is_power_of_two_(n: u128) -> bool {
  n != 0 && (n & (n - 1)) == 0
}

fn count_leading_zeros_(n: u128) -> u32 {
  n.leading_zeros()
}

fn is_byte_aligned_(m: u128) -> bool {
  count_leading_zeros_(m) % 8 == 0
}

fn unsafe_into_usize_(value: u128) -> usize {
  value as usize
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

pub fn index_word(i: Expr, w: Expr) -> Expr {
  match (i, w) {
    (Expr::Lit(idx), Expr::And(box_mask, box_w)) => {
      let full_word_mask = MAX_LIT;
      let mask = match *box_mask {
        Expr::Lit(m) => m,
        _ => panic!("invalid expression"),
      };
      if mask.clone() == full_word_mask {
        index_word(Expr::Lit(idx), *box_w)
      } else {
        let unmasked_bytes = count_leading_zeros(mask.clone()) / 8;
        if idx <= W256(31, 0) && is_power_of_two(mask.clone() + W256(1, 0)) && is_byte_aligned(mask.clone()) {
          if idx >= W256(unmasked_bytes as u128, 0) {
            index_word(Expr::Lit(idx), *box_w)
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
        Expr::LitByte((w >> (unsafe_into_usize(idx) * 8) as u32).0 as u8)
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

pub fn read_byte(idx: Expr, buf: Expr) -> Expr {
  match (idx, buf) {
    (Expr::Lit(x), Expr::ConcreteBuf(b)) => {
      let i = ((x.0 as u64) as u32);
      if x.0 <= i as u128 {
        if (i as usize) < b.len() {
          return Expr::Lit(W256(b[i as usize] as u128, 0));
        }
      }
      Expr::Lit(W256(0, 0))
    }
    (Expr::Lit(x), Expr::WriteByte(idx, val, src)) => {
      if Expr::Lit(x.clone()) == *idx {
        *val
      } else {
        read_byte(Expr::Lit(x.clone()), *src)
      }
    }
    (Expr::Lit(x), Expr::WriteWord(idx, val, src)) => {
      if let Expr::Lit(idx_val) = *idx {
        if x >= idx_val.clone() && x < idx_val.clone() + W256(32, 0) {
          if let Expr::Lit(_) = *val {
            index_word(Expr::Lit(x - idx_val), *val)
          } else {
            Expr::ReadByte(Box::new(Expr::Lit(x)), Box::new(Expr::WriteWord(Box::new(Expr::Lit(idx_val)), val, src)))
          }
        } else {
          read_byte(Expr::Lit(x), *src)
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
          read_byte(Expr::Lit(x + src_offset_val - dst_offset_val), *src)
        } else {
          read_byte(Expr::Lit(x), *dst.clone())
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

pub fn read_bytes(n: usize, idx: Expr, buf: Expr) -> Expr {
  let n = min(32, n);
  let bytes: Vec<Expr> =
    (0..n).map(|i| read_byte(add(idx.clone(), Expr::Lit(W256(0, i as u128))), buf.clone())).collect();
  join_bytes(bytes)
}

fn pad_byte(b: Expr) -> Expr {
  match b {
    Expr::LitByte(b) => Expr::Lit(bytes_to_w256(&[b])),
    _ => join_bytes(vec![b]),
  }
}

fn bytes_to_w256(bytes: &[u8]) -> W256 {
  /*
  if bytes.len() != 32 {
    return None; // Ensure the byte slice is exactly 32 bytes
  }*/

  // Convert the first 16 bytes to the low u128
  let low = u128::from_be_bytes(bytes[0..16].try_into().unwrap());
  // Convert the last 16 bytes to the high u128
  let high = u128::from_be_bytes(bytes[16..32].try_into().unwrap());

  W256(low, high)
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
    Expr::JoinBytes(
      (vec![
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
      ]),
    )
  }
}

fn eq_byte(x: Expr, y: Expr) -> Expr {
  match (x, y) {
    (Expr::LitByte(x), Expr::LitByte(y)) => Expr::Lit(if x == y { W256(1, 0) } else { W256(0, 0) }),
    (x, y) => Expr::EqByte(Box::new(x), Box::new(y)),
  }
}

pub fn read_word(idx: Expr, buf: Expr) -> Expr {
  match (idx.clone(), buf.clone()) {
    (Expr::Lit(idx_val), Expr::WriteWord(idx2, val, buf2)) => {
      if let Expr::Lit(idx2_val) = *idx2 {
        if idx_val == idx2_val {
          return *val;
        } else if idx2_val >= idx_val && idx2_val <= idx_val + W256(32, 0) {
          return read_word_from_bytes(idx.clone(), buf.clone());
        } else {
          return read_word(idx, *buf2);
        }
      }
    }
    (Expr::Lit(idx_val), Expr::CopySlice(src_offset, dst_offset, size, src, dst)) => {
      if let (Expr::Lit(src_offset_val), Expr::Lit(dst_offset_val), Expr::Lit(size_val)) =
        (*src_offset.clone(), *dst_offset.clone(), *size.clone())
      {
        if idx_val >= dst_offset_val.clone()
          && idx_val.clone() + W256(32, 0) <= dst_offset_val.clone() + size_val.clone()
        {
          return read_word(Expr::Lit(idx_val - dst_offset_val + src_offset_val), *src);
        } else if idx_val >= dst_offset_val && idx_val <= dst_offset_val + size_val - W256(32, 0) {
          return read_word(Expr::Lit(idx_val), *dst);
        } else {
          return read_word_from_bytes(Expr::Lit(idx_val), Expr::CopySlice(src_offset, dst_offset, size, src, dst));
        }
      }
    }
    _ => {}
  }
  read_word_from_bytes(idx, buf)
}

pub fn read_word_from_bytes(idx: Expr, buf: Expr) -> Expr {
  if let (Expr::Lit(idx_val), Expr::ConcreteBuf(bs)) = (idx.clone(), buf.clone()) {
    if let i = idx_val {
      let end = i.clone() + W256(32, 0);
      let slice = if (i.0 as usize) < bs.len() {
        if end.0 as usize <= bs.len() {
          &bs[(i.0 as usize)..(end.0 as usize)]
        } else {
          &bs[(i.0 as usize)..]
        }
      } else {
        &[]
      };
      let padded: Vec<u8> = slice.iter().cloned().chain(std::iter::repeat(0)).take(32).collect();
      return Expr::Lit(W256::from_bytes(padded.try_into().unwrap()));
    }
  }
  let bytes: Vec<Expr> = (0..32).map(|i| read_byte(add(idx.clone(), Expr::Lit(W256(i, 0))), buf.clone())).collect();
  if bytes.iter().all(|b| matches!(b, Expr::Lit(_))) {
    let result = bytes.into_iter().map(|b| if let Expr::Lit(byte) = b { byte.0 as u8 } else { 0 }).collect::<Vec<u8>>();
    Expr::Lit(W256::from_bytes(result))
  } else {
    Expr::ReadWord(Box::new(idx), Box::new(buf))
  }
}

pub fn write_word(offset: Expr, value: Expr, buf: Expr) -> Expr {
  let buf_clone = buf.clone();
  match (offset, value, buf) {
    (Expr::Lit(offset), Expr::WAddr(addr), Expr::ConcreteBuf(_))
      if offset < MAX_BYTES && offset.clone() + W256(32, 0) < MAX_BYTES =>
    {
      let val = match *addr {
        Expr::LitAddr(v) => v,
        _ => panic!("unsupported"),
      };
      write_word(Expr::Lit(offset), Expr::Lit(val), buf_clone)
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
      Expr::WriteWord(Box::new(Expr::Lit(idx)), Box::new(val), (buf))
    }

    (Expr::Lit(idx), val, Expr::WriteWord(idx_, val_, buf_)) => {
      if let Expr::Lit(i) = *idx_.clone() {
        if idx >= i + W256(32, 0) {
          return Expr::WriteWord(idx_, val_, Box::new(write_word(Expr::Lit(idx), val, *buf_)));
        }
      }
      Expr::WriteWord(Box::new(Expr::Lit(idx)), Box::new(val), Box::new(Expr::WriteWord(idx_, val_, buf_)))
    }

    (idx, val, buf @ Expr::WriteWord(_, _, _)) => Expr::WriteWord(Box::new(idx), Box::new(val), Box::new(buf)),

    (offset, val, src) => Expr::WriteWord(Box::new(offset), Box::new(val), Box::new(src)),
  }
}

pub fn copy_slice(src_offset: Expr, dst_offset: Expr, size: Expr, src: Expr, dst: Expr) -> Expr {
  match (src_offset.clone(), dst_offset.clone(), size.clone(), src.clone(), dst.clone()) {
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
        copy_slice(src_offset, dst_offset, Expr::Lit(size.clone()), Expr::ConcreteBuf(vec![0; size.0 as usize]), dst)
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
      write_word(dst_offset, read_word(src_offset, src), dst)
    }
    // concrete indices & abstract src (may produce a concrete result if we are copying from a concrete region of src)
    (Expr::Lit(src_offset), Expr::Lit(dst_offset), Expr::Lit(size), src, Expr::ConcreteBuf(dst_buf)) => {
      if (dst_offset < MAX_BYTES
        && size < MAX_BYTES
        && src_offset.clone() + size.clone() - W256(1, 0) > src_offset.clone())
      {
        let hd = pad_right(dst_offset.0 as usize, (&dst_buf[..dst_offset.0 as usize]).to_vec());
        let sl: Vec<Expr> = ((src_offset.0)..(src_offset.0) + (size.0))
          .map(|i| read_byte(Expr::Lit(W256(i as u128, 0)), src.clone()))
          .collect();
        let tl = &dst_buf[dst_offset.0 as usize + size.0 as usize..];

        if sl.iter().all(is_lit_byte) {
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
      Expr::CopySlice(
        Box::new(src_offset.clone()),
        Box::new(dst_offset.clone()),
        Box::new(size.clone()),
        Box::new(src.clone()),
        Box::new(dst.clone()),
      )
    }
  }
}

pub fn is_lit_byte(e: &Expr) -> bool {
  match e {
    Expr::LitByte(_) => true,
    _ => false,
  }
}

// Concretize & simplify Keccak expressions until fixed-point.
pub fn conc_keccak_simp_expr(expr: Expr) -> Expr {
  until_fixpoint(|e| map_expr(|expr: &Expr| conc_keccak_one_pass(expr), e.clone()), expr)
}

// Only concretize Keccak in Props
// Needed because if it also simplified, we may not find some simplification errors, as
// simplification would always be ON
fn conc_keccak_props(props: Vec<Prop>) -> Vec<Prop> {
  until_fixpoint(|ps| ps.into_iter().map(|p| map_prop(&conc_keccak_one_pass, p.clone())).collect(), props)
}

fn is_concretebuf(expr: &Expr) -> bool {
  match expr {
    Expr::ConcreteBuf(_) => true,
    _ => false,
  }
}

fn is_empty_concretebuf(expr: &Expr) -> bool {
  match expr {
    Expr::ConcreteBuf(dst_buf) => dst_buf.is_empty(),
    _ => false,
  }
}

fn is_simplifiable_ww(expr: &Expr) -> bool {
  match expr {
    Expr::WriteWord(a, _, c) if **a == Expr::Lit(W256(0, 0)) && is_concretebuf(c) => true,
    _ => false,
  }
}

fn get_len_of_bs_in_ww(expr: &Expr) -> usize {
  match expr {
    Expr::WriteWord(a, _, c) if **a == Expr::Lit(W256(0, 0)) && is_concretebuf(c) => match *c.clone() {
      Expr::ConcreteBuf(bs) => bs.len(),
      _ => 0,
    },
    _ => 0,
  }
}

// Simplifies in case the input to the Keccak is of specific array/map format and
//            can be simplified into a concrete value
// Turns (Keccak ConcreteBuf) into a Lit
fn conc_keccak_one_pass(expr: &Expr) -> Expr {
  match expr.clone() {
    Expr::Keccak(expr_) if is_concretebuf(&expr_) => match *expr_.clone() {
      Expr::ConcreteBuf(bs) => keccak(*expr_.clone()).unwrap(),
      _ => panic!(""),
    },
    Expr::Keccak(orig) => match orig.as_ref() {
      Expr::CopySlice(
        a, //Expr::Lit(W256(0, 0)),
        b, //Expr::Lit(W256(0, 0)),
        c, // Expr::Lit(W256(64, 0)),
        d, // Expr::WriteWord(Expr::Lit(W256(0, 0)), _, (Expr::ConcreteBuf(bs))),
        e, //Expr::ConcreteBuf(dst_buf),
      ) if **a == Expr::Lit(W256(0, 0))
        && **b == Expr::Lit(W256(0, 0))
        && **c == Expr::Lit(W256(64, 0))
        && is_simplifiable_ww(d)
        && is_empty_concretebuf(e) =>
      {
        match (
          get_len_of_bs_in_ww(d),
          copy_slice(
            Expr::Lit(W256(0, 0)),
            Expr::Lit(W256(0, 0)),
            Expr::Lit(W256(64, 0)),
            simplify(&orig.clone()),
            Expr::ConcreteBuf(vec![]),
          ),
        ) {
          (64, Expr::ConcreteBuf(a)) => keccak(Expr::ConcreteBuf(a)).unwrap(),
          _ => Expr::Keccak(orig),
        }
      }
      _ => Expr::Keccak(orig),
    },
    _ => expr.clone(),
  }
}

// Main simplify function
pub fn simplify(expr: &Expr) -> Expr {
  let simplified = map_expr(go_expr, expr.clone());
  if &simplified == expr {
    simplified
  } else {
    simplify(&map_expr(go_expr, &structure_array_slots(expr)))
  }
}

fn go_expr(expr: &Expr) -> Expr {
  match expr {
    Expr::Failure(a, b, c) => Expr::Failure(simplify_props(a.clone()), b.clone(), c.clone()),
    Expr::Partial(a, b, c) => Expr::Partial(simplify_props(a.clone()), b.clone(), c.clone()),
    Expr::Success(a, b, c, d) => Expr::Success(simplify_props(a.clone()), b.clone(), c.clone(), d.clone()),

    Expr::SLoad(slot, store) => read_storage(&slot.clone(), &store.clone()).unwrap(),
    Expr::SStore(slot, val, store) => write_storage(*slot.clone(), *val.clone(), *store.clone()),

    Expr::ReadWord(idx_, buf_) => match (**idx_, **buf_) {
      (Expr::Lit(_), _) => simplify_reads(expr),
      (idx, buf) => read_word(idx.clone(), buf.clone()),
    },

    Expr::ReadByte(idx_, buf_) => match (**idx_, **buf_) {
      (Expr::Lit(_), _) => simplify_reads(expr),
      (idx, buf) => read_byte(idx.clone(), buf.clone()),
    },

    Expr::BufLength(buf) => buf_length(**buf),

    Expr::WriteWord(a_, b_, c_) => match (**a_, **b_, **c_) {
      (Expr::Lit(idx), val, Expr::ConcreteBuf(b)) if idx < MAX_BYTES => {
        let simplified_buf = pad_and_concat_buffers(*idx, &b);
        write_word((Expr::Lit(idx)), val.clone(), (Expr::ConcreteBuf(simplified_buf)))
      }
      (a, b, c) => write_word(a.clone(), b.clone(), c.clone()),
    },

    Expr::WriteByte(a, b, c) => write_byte(*a.clone(), *b.clone(), *c.clone()),

    Expr::CopySlice(src_off_, dst_off_, size_, src_, dst_) => match (**src_off_, **dst_off_, **size_, **src_, **dst_) {
      (Expr::Lit(W256(0, 0)), Expr::Lit(W256(0, 0)), Expr::Lit(W256(0, 0)), _, dst) => dst.clone(),
      (Expr::Lit(W256(0, 0)), Expr::Lit(W256(0, 0)), Expr::Lit(s), src, Expr::ConcreteBuf(b))
        if b.len() == 0 && buf_length(src) == Expr::Lit(s) =>
      {
        src.clone()
      }
      (src_off, dst_off, size, src, dst) => {
        if let Expr::WriteWord(w_off, value, box Expr::ConcreteBuf(buf)) = **src {
          let n = if let Expr::Lit(n) = src_off { n } else { W256(0, 0) };
          let sz = if let Expr::Lit(sz) = size { sz } else { W256(0, 0) };
          if n + sz >= n && n + sz >= sz && n + sz <= MAX_BYTES {
            let simplified_buf = pad_and_concat_buffers(n + sz, &buf);
            return copy_slice(
              src_off.clone(),
              dst_off.clone(),
              size.clone(),
              (Expr::WriteWord(w_off.clone(), value.clone(), Box::new(Expr::ConcreteBuf(simplified_buf)))),
              dst.clone(),
            );
          }
        }
        copy_slice(src_off.clone(), dst_off.clone(), size.clone(), src.clone(), dst.clone())
      }
    },
    Expr::IndexWord(a, b) => index_word(*a.clone(), *b.clone()),

    Expr::LT(a_, b_) => match (**a_, **b_) {
      (Expr::Lit(a), Expr::Lit(b)) => {
        if a < b {
          Expr::Lit(W256(1, 0))
        } else {
          Expr::Lit(W256(0, 0))
        }
      }
      (a_, Expr::Lit(W256(0, 0))) => Expr::Lit(W256(0, 0)),
      (a, b) => lt(a.clone(), b.clone()),
    },

    Expr::GT(a, b) => gt(*a.clone(), *b.clone()),
    Expr::GEq(a, b) => geq(*a.clone(), *b.clone()),
    Expr::LEq(a, b) => leq(*a.clone(), *b.clone()),
    Expr::SLT(a, b) => slt(*a.clone(), *b.clone()),
    Expr::SGT(a, b) => sgt(*a.clone(), *b.clone()),

    Expr::IsZero(a) => iszero(*a.clone()),

    Expr::Xor(a_, b_) => match (**a_, **b_) {
      (Expr::Lit(a), Expr::Lit(b)) => Expr::Lit(a ^ b),
      _ => xor(*a_.clone(), *b_.clone()),
    },

    Expr::Eq(a_, b_) => match (**a_, **b_) {
      (Expr::Lit(a), Expr::Lit(b)) => Expr::Lit(if a == b { W256(1, 0) } else { W256(0, 0) }),
      (_, Expr::Lit(W256(0, 0))) => iszero(expr.clone()),
      (a, b) => eq(a.clone(), b.clone()),
    },

    Expr::ITE(a_, b_, c_) => match (**a_, **b_, **c_) {
      (Expr::Lit(W256(1, 0)), b, _) => b,
      (Expr::Lit(W256(0, 0)), _, c) => c,
      (a, b, c) => ite(a.clone(), b.clone(), c.clone()),
    },

    Expr::And(a_, b_) => match (**a_, **b_) {
      (Expr::Lit(a), Expr::Lit(b)) => Expr::Lit(a & b),
      (Expr::Lit(W256(0, 0)), _) => Expr::Lit(W256(0, 0)),
      _ => and(*a_.clone(), *b_.clone()),
    },

    Expr::Or(a_, b_) => match (**a_, **b_) {
      (Expr::Lit(a), Expr::Lit(b)) => Expr::Lit(a | b),
      (Expr::Lit(W256(0, 0)), a) => a.clone(),
      _ => or(*a_.clone(), *b_.clone()),
    },

    Expr::Not(a_) => match **a_ {
      (Expr::Lit(a)) => Expr::Lit(if a == W256(0, 0) { W256(1, 0) } else { W256(0, 0) }),
      _ => not(*a_.clone()),
    },

    Expr::Div(a, b) => div(*a.clone(), *b.clone()),
    Expr::SDiv(a, b) => sdiv(*a.clone(), *b.clone()),
    Expr::Mod(a, b) => modulo(*a.clone(), *b.clone()),
    Expr::SMod(a, b) => smod(*a.clone(), *b.clone()),

    Expr::Add(a_, b_) => match (**a_, **b_) {
      (Expr::Lit(W256(0, 0)), a) => a,
      (Expr::Lit(a), Expr::Lit(b)) => Expr::Lit(a + b),
      _ => add(**a_, **b_),
    },

    Expr::Sub(a_, b_) => match (**a_, **b_) {
      (a, Expr::Lit(W256(0, 0))) => a,
      (Expr::Lit(a), Expr::Lit(b)) => Expr::Lit(a - b),
      _ => sub(**a_, **b_),
    },

    Expr::SHL(a_, b_) => match (**a_, b_) {
      (Expr::Lit(a), b) => shl(Expr::Lit(a << 1), **b),
      _ => shl(*a_.clone(), *b_.clone()),
    },

    Expr::SHR(a_, b_) => match (**a_, b_) {
      (Expr::Lit(a), b) => shr(Expr::Lit(a >> 1), **b),
      _ => shr(*a_.clone(), *b_.clone()),
    },

    Expr::Max(a, b) => emax(*a.clone(), *b.clone()),
    Expr::Min(a, b) => emin(*a.clone(), *b.clone()),

    Expr::Mul(a_, b_) => match (**a_, **b_) {
      (a, Expr::Lit(W256(0, 0))) => Expr::Lit(W256(0, 0)),
      (Expr::Lit(W256(0, 0)), a) => Expr::Lit(W256(0, 0)),
      (Expr::Lit(a), Expr::Lit(b)) => Expr::Lit(a * b),
      _ => mul(**a_, **b_),
    },

    Expr::Lit(n) => Expr::Lit(*n),
    Expr::WAddr(a) => Expr::WAddr(a.clone()),
    Expr::LitAddr(a) => Expr::LitAddr(*a),
    _ => expr.clone(),
  }
}

fn simplify_prop(prop: Prop) -> Prop {
  let new_prop = map_prop(go_prop, simp_inner_expr(prop.clone()));

  if new_prop == prop {
    prop
  } else {
    simplify_prop(new_prop)
  }
}

fn go_prop(prop: Prop) -> Prop {
  let v: W256 = W256::from_dec_str("1461501637330902918203684832716283019655932542975").unwrap();
  match prop {
    // LT/LEq comparisons
    Prop::PGT(a, b) => Prop::PLT(b, a),
    Prop::PGEq(a, b) => Prop::PLEq(b, a),

    Prop::PLEq(Expr::Lit(W256(0, 0)), _) => Prop::PBool(true),
    Prop::PLEq(Expr::WAddr(_), Expr::Lit(v)) => Prop::PBool(true),
    Prop::PLEq(_, Expr::Lit(x)) if x == MAX_LIT => Prop::PBool(true),

    Prop::PLEq(Expr::Var(_), Expr::Lit(val)) if val == MAX_LIT => Prop::PBool(true),
    Prop::PLEq(Expr::Lit(l), Expr::Lit(r)) => Prop::PBool(l <= r),
    Prop::PLEq(a, Expr::Max(b, _)) if a == *b => Prop::PBool(true),
    Prop::PLEq(a, Expr::Max(_, b)) if a == *b => Prop::PBool(true),
    Prop::PLEq(Expr::Sub(a, b), c) if *a == c => Prop::PLEq(*b, *a),

    Prop::PLT(a, b) => match (a, b) {
      (Expr::Var(_), Expr::Lit(W256(0, 0))) => Prop::PBool(false),
      (Expr::Lit(l), Expr::Lit(r)) => Prop::PBool(l < r),
      (Expr::Max(a_, b_), Expr::Lit(c)) => match *a_ {
        Expr::Lit(a_v) if (a_v < c) => Prop::PLT(b, Expr::Lit(c)),
        _ => prop,
      },
      (Expr::Lit(W256(0, 0)), Expr::Eq(a_, b_)) => Prop::PEq(*a_, *b_),
      _ => prop,
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
        _ => prop,
      }
    }

    // And/Or
    Prop::PAnd(a, b) => match (*a, *b) {
      (Prop::PBool(l), Prop::PBool(r)) => Prop::PBool(l && r),
      (Prop::PBool(false), _) => Prop::PBool(false),
      (_, Prop::PBool(false)) => Prop::PBool(false),
      (Prop::PBool(true), x) => x,
      (x, Prop::PBool(true)) => x,
      _ => prop,
    },
    Prop::POr(a, b) => match (*a, *b) {
      (Prop::PBool(l), Prop::PBool(r)) => Prop::PBool(l || r),
      (Prop::PBool(true), _) => Prop::PBool(true),
      (_, Prop::PBool(true)) => Prop::PBool(true),
      (Prop::PBool(false), x) => x,
      (x, Prop::PBool(false)) => x,
      _ => prop,
    },

    // Imply
    Prop::PImpl(a, b) => match (*a, *b) {
      (_, Prop::PBool(true)) => Prop::PBool(true),
      (Prop::PBool(true), b) => b,
      (Prop::PBool(false), _) => Prop::PBool(true),
      _ => prop,
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
              _ => prop,
            },
            _ => prop,
          }
        }
        (Expr::Eq(a, b), Expr::Lit(W256(0, 0))) => Prop::PNeg(Box::new(Prop::PEq(*a, *b))),
        (Expr::Eq(a, b), Expr::Lit(W256(1, 0))) => Prop::PEq(*a, *b),
        (Expr::Sub(a, b), Expr::Lit(W256(0, 0))) => Prop::PEq(*a, *b),
        (Expr::LT(a, b), Expr::Lit(W256(0, 0))) => Prop::PLEq(*b, *a),
        (Expr::Lit(l), Expr::Lit(r)) => Prop::PBool(l == r),
      }
    }
    o @ Prop::PEq(ref l, ref r) if l == r => Prop::PBool(true),
    _ => prop,
  }
}

pub fn read_storage(w: &Expr, st: &Expr) -> Option<Expr> {
  todo!()
}

pub fn write_storage(k: Expr, v: Expr, store: Expr) -> Expr {
  match (k.clone(), v.clone(), store.clone()) {
    (Expr::Lit(key), Expr::Lit(val), store) => match (store) {
      Expr::ConcreteStore(s) => {
        let mut s_ = s.clone();
        s_.insert(key, val);
        Expr::ConcreteStore(s_)
      }
      _ => Expr::SStore(Box::new(k), Box::new(v), Box::new(store)),
    },
    (key, val, Expr::SStore(key_, val_, prev)) => {
      if (key == *key_) {
        Expr::SStore(Box::new(key), Box::new(val), prev)
      } else {
        match (key.clone(), *key_.clone()) {
          (Expr::Lit(k), Expr::Lit(k_)) => {
            if (k > k_) {
              Expr::SStore(key_, val_, Box::new(write_storage(key, val, *prev)))
            } else {
              Expr::SStore(Box::new(key), Box::new(val), Box::new(store))
            }
          }
          _ => Expr::SStore(Box::new(key), Box::new(val), Box::new(store)),
        }
      }
    }
    _ => Expr::SStore(Box::new(k), Box::new(v), Box::new(store)),
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
