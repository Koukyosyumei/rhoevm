use crate::modules::types::{Expr, Prop, W256};
use core::panic;
use std::cmp::min;

// ** Constants **

const MAX_LIT: W256 = 0xffffffff;

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
      let msb = (y >> 31) & 1 != 0;
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
    (Expr::Lit(offset), Expr::LitByte(val), Expr::ConcreteBuf(src)) if src.len() == 0 && offset < MAX_BYTES => {
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

pub fn is_power_of_two(n: u64) -> bool {
  n != 0 && (n & (n - 1)) == 0
}

pub fn count_leading_zeros(n: u64) -> u32 {
  n.leading_zeros()
}

pub fn is_byte_aligned(m: u64) -> bool {
  count_leading_zeros(m) % 8 == 0
}

fn unsafe_into_usize(value: u64) -> usize {
  value as usize
}

pub fn index_word(i: Expr, w: Expr) -> Expr {
  match (i, w) {
    (Expr::Lit(idx), Expr::And(box_mask, box_w)) => {
      let full_word_mask = (1u64 << 63u64) - 1;
      let mask = match *box_mask {
        Expr::Lit(m) => m,
        _ => panic!("invalid expression"),
      };
      if mask as u64 == full_word_mask as u64 {
        index_word(Expr::Lit(idx), *box_w)
      } else {
        let unmasked_bytes = (count_leading_zeros(mask as u64) / 8) as u64;
        if idx <= 31 && is_power_of_two(mask as u64 + 1) && is_byte_aligned(mask as u64) {
          if idx as u64 >= unmasked_bytes {
            index_word(Expr::Lit(idx), *box_w)
          } else {
            Expr::LitByte(0)
          }
        } else if idx <= 31 {
          Expr::IndexWord(
            Box::new(Expr::Lit(idx)),
            Box::new(Expr::And(Box::new(Expr::Lit(mask)), Box::new(*box_w))),
          )
        } else {
          Expr::LitByte(0)
        }
      }
    }
    (Expr::Lit(idx), Expr::Lit(w)) => {
      if idx <= 31 {
        Expr::LitByte((w >> (248 - unsafe_into_usize(idx as u64) * 8)) as u8)
      } else {
        Expr::LitByte(0)
      }
    }
    (Expr::Lit(idx), Expr::JoinBytes(bytes)) => {
      if idx <= 31 {
        match idx {
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
      let i = ((x as u64) as u32);
      if x <= i {
        if (i as usize) < b.len() {
          return Expr::Lit(b[i as usize] as u32);
        }
      }
      Expr::Lit(0)
    }
    (i @ Expr::Lit(x), Expr::WriteByte(idx, val, src)) => {
      if i == *idx {
        *val
      } else {
        read_byte(i, *src)
      }
    }
    (i @ Expr::Lit(x), Expr::WriteWord(idx, val, src)) => {
      if let Expr::Lit(idx_val) = *idx {
        if x >= idx_val && x < idx_val + 32 {
          if let Expr::Lit(_) = *val {
            index_word(Expr::Lit(x - idx_val), *val)
          } else {
            Expr::ReadByte(
              Box::new(Expr::Lit(x)),
              Box::new(Expr::WriteWord(Box::new(Expr::Lit(idx_val)), val, src)),
            )
          }
        } else {
          read_byte(i, *src)
        }
      } else {
        Expr::ReadByte(Box::new(Expr::Lit(x)), Box::new(Expr::WriteWord(idx, val, src)))
      }
    }
    (i @ Expr::Lit(x), Expr::CopySlice(src_offset, dst_offset, size, src, ref dst)) => {
      if let (Expr::Lit(src_offset_val), Expr::Lit(dst_offset_val), Expr::Lit(size_val)) =
        (*src_offset.clone(), *dst_offset.clone(), *size.clone())
      {
        if x >= dst_offset_val && x < dst_offset_val + size_val {
          read_byte(Expr::Lit(x + src_offset_val - dst_offset_val), *src)
        } else {
          read_byte(i, *dst.clone())
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
  let bytes: Vec<Expr> = (0..n).map(|i| read_byte(add(idx.clone(), Expr::Lit(i as u32)), buf.clone())).collect();
  join_bytes(bytes)
}

fn pad_byte(b: Expr) -> Expr {
  match b {
    Expr::LitByte(b) => Expr::Lit(bytes_to_w256(&[b]) as u32),
    _ => join_bytes(vec![b]),
  }
}

fn bytes_to_w256(bytes: &[u8]) -> u64 {
  // Assuming W256 is represented as u64 for simplicity; adjust as necessary
  let mut result = 0u64;
  for &byte in bytes.iter().rev() {
    result = (result << 8) | byte as u64;
  }
  result
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
    Expr::Lit(bytes_to_w256(&lit_bytes) as u32)
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
    (Expr::LitByte(x), Expr::LitByte(y)) => Expr::Lit(if x == y { 1 } else { 0 }),
    (x, y) => Expr::EqByte(Box::new(x), Box::new(y)),
  }
}

pub fn read_word(idx: Expr, buf: Expr) -> Expr {
  match (idx.clone(), buf.clone()) {
    (Expr::Lit(idx_val), Expr::WriteWord(idx2, val, buf2)) => {
      if let Expr::Lit(idx2_val) = *idx2 {
        if idx_val == idx2_val {
          return *val;
        } else if idx2_val >= idx_val && idx2_val <= idx_val + 32 {
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
        if idx_val >= dst_offset_val && idx_val + 32 <= dst_offset_val + size_val {
          return read_word(Expr::Lit(idx_val - dst_offset_val + src_offset_val), *src);
        } else if idx_val >= dst_offset_val && idx_val <= dst_offset_val + size_val - 32 {
          return read_word(Expr::Lit(idx_val), *dst);
        } else {
          return read_word_from_bytes(
            Expr::Lit(idx_val),
            Expr::CopySlice(src_offset, dst_offset, size, src, dst),
          );
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
      let end = i + 32;
      let slice = if (i as usize) < bs.len() {
        if end as usize <= bs.len() {
          &bs[(i as usize)..(end as usize)]
        } else {
          &bs[(i as usize)..]
        }
      } else {
        &[]
      };
      let padded: Vec<u8> = slice.iter().cloned().chain(std::iter::repeat(0)).take(32).collect();
      return Expr::Lit(u64::from_le_bytes(padded.try_into().unwrap()) as u32);
    }
  }
  let bytes: Vec<Expr> = (0..32).map(|i| read_byte(add(idx.clone(), Expr::Lit(i as u32)), buf.clone())).collect();
  if bytes.iter().all(|b| matches!(b, Expr::Lit(_))) {
    let result = bytes.into_iter().map(|b| if let Expr::Lit(byte) = b { byte as u8 } else { 0 }).collect::<Vec<u8>>();
    Expr::Lit(u64::from_le_bytes(result.try_into().unwrap()) as u32)
  } else {
    Expr::ReadWord(Box::new(idx), Box::new(buf))
  }
}

pub fn write_word(offset: Expr, value: Expr, buf: Expr) -> Expr {
  let buf_clone = buf.clone();
  match (offset, value, buf) {
    (Expr::Lit(offset), Expr::WAddr(addr), Expr::ConcreteBuf(_)) if offset < MAX_BYTES && offset + 32 < MAX_BYTES => {
      let val = match *addr {
        Expr::LitAddr(v) => v,
        _ => panic!("unsupported"),
      };
      write_word(Expr::Lit(offset), Expr::Lit(val), buf_clone)
    }

    (Expr::Lit(offset), Expr::Lit(val), Expr::ConcreteBuf(ref src))
      if offset < MAX_BYTES && offset + 32 < MAX_BYTES && src.is_empty() =>
    {
      let mut new_buf = vec![0; offset as usize];
      new_buf.extend_from_slice(&word256_bytes(val.into()));
      Expr::ConcreteBuf(new_buf)
    }

    (Expr::Lit(offset), Expr::Lit(val), Expr::ConcreteBuf(mut src))
      if offset < MAX_BYTES && offset + 32 < MAX_BYTES =>
    {
      src.resize(offset as usize, 0);
      src.extend_from_slice(&word256_bytes(val.into()));
      Expr::ConcreteBuf(src)
    }

    (Expr::Lit(idx), val, Expr::WriteWord(idx_, _, buf)) if Expr::Lit(idx) == *idx_ => {
      Expr::WriteWord(Box::new(Expr::Lit(idx)), Box::new(val), (buf))
    }

    (Expr::Lit(idx), val, Expr::WriteWord(idx_, val_, buf_)) => {
      if let Expr::Lit(i) = *idx_ {
        if idx >= i + 32 {
          return Expr::WriteWord(idx_, val_, Box::new(write_word(Expr::Lit(idx), val, *buf_)));
        }
      }
      Expr::WriteWord(
        Box::new(Expr::Lit(idx)),
        Box::new(val),
        Box::new(Expr::WriteWord(idx_, val_, buf_)),
      )
    }

    (idx, val, buf @ Expr::WriteWord(_, _, _)) => Expr::WriteWord(Box::new(idx), Box::new(val), Box::new(buf)),

    (offset, val, src) => Expr::WriteWord(Box::new(offset), Box::new(val), Box::new(src)),
  }
}

pub fn word256_bytes(val: u64) -> Vec<u8> {
  // Convert a 256-bit word (represented as u64 for simplicity) to bytes
  val.to_be_bytes().to_vec() // Adjust as necessary for full 256-bit handling
}

pub fn conc_keccak_props(props: Vec<Prop>) -> Vec<Prop> {
  todo!()
}
