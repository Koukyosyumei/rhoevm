use byteorder::{BigEndian, ReadBytesExt};
use num_bigint::BigInt;
use num_traits::cast::ToPrimitive;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::fmt::{self};
use std::hash::Hash;
use std::io::Cursor;
use std::iter;
use std::ops::{Add, BitAnd, BitOr, BitXor, Div, Mul, Not, Rem, Shl, Shr, Sub};
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use std::sync::Arc;
use std::vec::Vec; // Assuming state crate is used for the State monad
use tiny_keccak::{Hasher, Keccak};

use crate::modules::feeschedule::FeeSchedule;
use crate::modules::op::Op;

pub type Word8 = u8;
pub type Word32 = u32;
pub type Word64 = u64;
pub type W64 = u64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct W256(pub u128, pub u128);
pub type Word256 = W256;
#[derive(Debug, Clone)]
pub struct W512(pub W256, pub W256);

pub type Addr = W256;
pub type Nibble = i32;

pub type ByteString = Vec<u8>;
pub type FunctionSelector = u32;

/*
-- Function Selectors ------------------------------------------------------------------------------


-- | https://docs.soliditylang.org/en/v0.8.19/abi-spec.html#function-selector
newtype FunctionSelector = FunctionSelector { unFunctionSelector :: Word32 }
  deriving (Bits, Num, Eq, Ord, Real, Enum, Integral)
instance Show FunctionSelector where show s = "0x" <> showHex s ""
*/

impl W256 {
  // Method to convert a decimal string to W256
  pub fn from_dec_str(s: &str) -> Result<Self, &'static str> {
    // Parse the decimal string into a BigInt
    let big_int = BigInt::from_str(s).map_err(|_| "Invalid decimal string")?;

    // Split the BigInt into two u128 values
    let (lower, upper) = Self::split_bigint(big_int);

    // Create and return a W256 instance
    Ok(W256(lower, upper))
  }

  // Helper method to split BigInt into two u128 values
  fn split_bigint(value: BigInt) -> (u128, u128) {
    let mask: BigInt = BigInt::from(u128::MAX);
    let lower = (&value & &mask).to_u128().unwrap_or(0);
    let upper = ((&value >> 128 as u64) & mask).to_u128().unwrap_or(0);
    (lower, upper)
  }
}

// Implement Display for W256
impl fmt::Display for W256 {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    // Format as hexadecimal string
    write!(f, "{:032x}{:032x}", self.1, self.0)
  }
}

// Implement the Default trait
impl Default for W256 {
  fn default() -> Self {
    W256(0, 0)
  }
}

// Implement the Hash trait
impl Hash for W256 {
  fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
    self.0.hash(state);
    self.1.hash(state);
  }
}

impl PartialEq for W256 {
  fn eq(&self, other: &Self) -> bool {
    self.0 == other.0 && self.1 == other.1
  }
}

// Implement the FromStr trait
impl FromStr for W256 {
  type Err = String;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let padded = format!("{:0>64}", s); // Pad with leading zeros to ensure length is 64
    if padded.len() != 64 {
      return Err("Input string must be exactly 64 hexadecimal characters long".to_string());
    }
    let high = u128::from_str_radix(&padded[0..32], 16)
      .map_err(|_| "Failed to parse the first 32 characters as u128".to_string())?;
    let low = u128::from_str_radix(&padded[32..64], 16)
      .map_err(|_| "Failed to parse the last 32 characters as u128".to_string())?;
    Ok(W256(low, high))
  }
}

impl W256 {
  // Maximum value for W256 (2^256 - 1)
  pub const fn max_value() -> W256 {
    W256(u128::MAX, u128::MAX)
  }

  pub fn to_hex(&self) -> String {
    let s = format!("{:032x}{:032x}", self.1, self.0);
    let s_trimed = s.trim_start_matches('0').to_string();
    if s_trimed == "" {
      "0".to_string()
    } else {
      s_trimed
    }
  }

  /// Converts the 256-bit number to a decimal string representation.
  pub fn to_decimal(&self) -> String {
    BigInt::from_str_radix(&self.to_hex(), 16).unwrap().to_string()
  }

  pub fn to_int(&self) -> Option<i32> {
    let max_int: W256 = W256(i32::MAX as u128, 0);
    if self <= &max_int {
      let W256(n, _) = *self;
      Some(n as i32)
    } else {
      None
    }
  }

  pub fn from_bytes(bytes: Vec<u8>) -> Self {
    let padded_bytes = pad_left_prime_vec(32, bytes);

    let high = u128::from_be_bytes(padded_bytes[0..16].try_into().unwrap());
    let low = u128::from_be_bytes(padded_bytes[16..32].try_into().unwrap());

    W256(low, high)
  }
}

pub fn to_int(e: &Expr) -> Option<i32> {
  match e {
    Expr::Lit(v) => v.to_int(),
    _ => None,
  }
}

pub fn pad_left_prime_vec(size: usize, bytes: Vec<u8>) -> Vec<u8> {
  let mut padded = vec![0; size];
  let start = size.saturating_sub(bytes.len());
  padded[start..].clone_from_slice(&bytes);
  padded
}

impl Eq for W256 {}

// Implement Display for W512
impl fmt::Display for W512 {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    // Format as concatenated hexadecimal strings of W256 parts
    write!(f, "{}{}", self.0, self.1)
  }
}

// Implement Hash for W512
impl Hash for W512 {
  fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
    self.0.hash(state);
    self.1.hash(state);
  }
}

impl PartialEq for W512 {
  fn eq(&self, other: &Self) -> bool {
    self.0 == other.0 && self.1 == other.1
  }
}

impl Eq for W512 {}

// Implement basic operations for W256
impl Add for W256 {
  type Output = W256;

  fn add(self, other: W256) -> W256 {
    let (low, carry) = self.0.overflowing_add(other.0);
    let (high, _) = self.1.overflowing_add(other.1 + if carry { 1 } else { 0 });
    W256(low, high)
  }
}

impl Sub for W256 {
  type Output = W256;

  fn sub(self, other: W256) -> W256 {
    let (low, borrow) = self.0.overflowing_sub(other.0);
    let (high, _) = self.1.overflowing_sub(other.1 + if borrow { 1 } else { 0 });
    W256(low, high)
  }
}

impl BitAnd for W256 {
  type Output = W256;

  fn bitand(self, other: W256) -> W256 {
    W256(self.0 & other.0, self.1 & other.1)
  }
}

impl Mul for W256 {
  type Output = W256;

  fn mul(self, other: W256) -> W256 {
    let self_low = self.0;
    let self_high = self.1;
    let other_low = other.0;
    let other_high = other.1;

    let low_low = self_low.wrapping_mul(other_low);
    let high_low = self_high.wrapping_mul(other_low);
    let low_high = self_low.wrapping_mul(other_high);
    let high_high = self_high.wrapping_mul(other_high);

    let low = low_low;
    let high = high_low.wrapping_add(low_high).wrapping_add(high_high);

    W256(low, high)
  }
}

impl BitXor for W256 {
  type Output = W256;

  fn bitxor(self, other: W256) -> W256 {
    W256(self.0 ^ other.0, self.1 ^ other.1)
  }
}

impl BitOr for W256 {
  type Output = W256;

  fn bitor(self, other: W256) -> W256 {
    W256(self.0 | other.0, self.1 | other.1)
  }
}

impl Not for W256 {
  type Output = W256;

  fn not(self) -> W256 {
    W256(!self.0, !self.1)
  }
}

impl W256 {
  // Exponentiation by squaring
  pub fn pow(self, mut exponent: u32) -> W256 {
    let mut result = W256(0, 1); // Start with W256 equivalent of 1
    let mut base = self;

    while exponent > 0 {
      // If the exponent is odd, multiply the result by the base
      if exponent % 2 == 1 {
        result = result.mul(base.clone());
      }
      // Square the base
      base = base.clone().mul(base.clone());
      // Divide the exponent by 2
      exponent /= 2;
    }

    result
  }

  pub fn div_rem(self, b: W256) -> (W256, W256) {
    let mut x = self.clone();
    let mut ans = W256(0, 0);
    let mut i = 0;

    if b == W256(0, 0) {
      return (W256(0, 0), W256(0, 0));
    }

    loop {
      if x < (b.clone().shl(i)) {
        if i <= 0 {
          break;
        } else {
          i = i - 1;
          ans = ans + W256::one().shl(i);
          x = x - b.clone().shl(i);
          i = 0;
        }
      } else {
        i = i + 1;
      }
    }

    (ans.clone(), self - ans.clone() * b) // Return the quotient and remainder
  }

  pub fn one() -> W256 {
    W256(1, 0)
  }
}

impl Div for W256 {
  type Output = W256;

  fn div(self, other: W256) -> W256 {
    self.div_rem(other).0
  }
}

impl Rem for W256 {
  type Output = W256;

  fn rem(self, other: W256) -> W256 {
    self.div_rem(other).1
  }
}

impl Shl<u32> for W256 {
  type Output = W256;

  fn shl(self, shift: u32) -> W256 {
    if shift == 0 {
      self
    } else if shift < 128 {
      let low = self.0 << shift;
      let high = (self.1 << shift) | (self.0 >> (128 - shift));
      W256(low, high)
    } else {
      let low = 0;
      let high = self.0 << (shift - 128);
      W256(low, high)
    }
  }
}

impl Shr<u32> for W256 {
  type Output = W256;

  fn shr(self, shift: u32) -> W256 {
    if shift == 0 {
      self
    } else if shift < 128 {
      let high = self.1 >> shift;
      let low = (self.0 >> shift) | (self.1 << (128 - shift));
      W256(low, high)
    } else {
      let high = 0;
      let low = self.1 >> (shift - 128);
      W256(low, high)
    }
  }
}

// Implement basic operations for W512
impl Add for W512 {
  type Output = W512;

  fn add(self, other: W512) -> W512 {
    let W512(left1, right1) = self;
    let W512(left2, right2) = other;
    W512(left1 + left2, right1 + right2)
  }
}

impl Mul for W512 {
  type Output = W512;

  fn mul(self, other: W512) -> W512 {
    // Implement multiplication for W512
    let W512(left1, right1) = self;
    let W512(left2, right2) = other;

    let low1 = left1.clone() * right2.clone();
    let low2 = right1.clone() * left2.clone();
    let high1 = left1 * left2;
    let high2 = right1 * right2;

    W512(high1 + low1 + low2, high2)
  }
}

impl Div for W512 {
  type Output = W512;

  fn div(self, _other: W512) -> W512 {
    // Implement division for W512 (using arbitrary precision arithmetic)
    unimplemented!()
  }
}

impl Rem for W512 {
  type Output = W512;

  fn rem(self, _other: W512) -> W512 {
    // Implement modulus for W512 (using arbitrary precision arithmetic)
    unimplemented!()
  }
}

impl Shr<u32> for W512 {
  type Output = W512;

  fn shr(self, _rhs: u32) -> W512 {
    // Implement right shift for W512
    unimplemented!()
  }
}

impl Shl<u32> for W512 {
  type Output = W512;

  fn shl(self, _rhs: u32) -> W512 {
    // Implement left shift for W512
    unimplemented!()
  }
}

// Implement comparison operations for W256
impl PartialOrd for W256 {
  fn partial_cmp(&self, other: &W256) -> Option<Ordering> {
    match self.0.cmp(&other.0) {
      Ordering::Equal => self.1.partial_cmp(&other.1),
      ordering => Some(ordering),
    }
  }
}

impl W256 {
  pub fn max(self, other: W256) -> W256 {
    if self.1 > other.1 || (self.1 == other.1 && self.0 > other.0) {
      self
    } else {
      other
    }
  }
}

// Symbolic IR -------------------------------------------------------------------------------------

// Variables referring to a global environment
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GVar {
  BufVar(i32),
  StoreVar(i32),
}

pub trait GVarTrait {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "GVar")
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BufVar {
  v: i32,
}
impl GVarTrait for BufVar {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "BufVar {}", self.v)
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StoreVar {
  v: i32,
}
impl GVarTrait for StoreVar {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "StoreVar {}", self.v)
  }
}

impl fmt::Display for GVar {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      GVar::BufVar(n) => write!(f, "BufVar({})", n),
      GVar::StoreVar(n) => write!(f, "StoreVar({})", n),
    }
  }
}

#[derive(Debug, Clone)]
pub enum Expr {
  Mempty,
  // Identifiers
  Lit(W256),
  Var(String),
  GVar(GVar),

  // Bytes
  LitByte(u8),
  IndexWord(Box<Expr>, Box<Expr>),
  EqByte(Box<Expr>, Box<Expr>),
  JoinBytes(Vec<Expr>),

  // Control Flow
  Partial(Vec<Prop>, TraceContext, PartialExec),
  Failure(Vec<Prop>, TraceContext, EvmError),
  Success(Vec<Prop>, TraceContext, Box<Expr>, ExprExprMap),
  ITE(Box<Expr>, Box<Expr>, Box<Expr>),

  // Integers
  Add(Box<Expr>, Box<Expr>),
  Sub(Box<Expr>, Box<Expr>),
  Mul(Box<Expr>, Box<Expr>),
  Div(Box<Expr>, Box<Expr>),
  SDiv(Box<Expr>, Box<Expr>),
  Mod(Box<Expr>, Box<Expr>),
  SMod(Box<Expr>, Box<Expr>),
  AddMod(Box<Expr>, Box<Expr>, Box<Expr>),
  MulMod(Box<Expr>, Box<Expr>, Box<Expr>),
  Exp(Box<Expr>, Box<Expr>),
  SEx(Box<Expr>, Box<Expr>),
  Min(Box<Expr>, Box<Expr>),
  Max(Box<Expr>, Box<Expr>),

  // Booleans
  LT(Box<Expr>, Box<Expr>),
  GT(Box<Expr>, Box<Expr>),
  LEq(Box<Expr>, Box<Expr>),
  GEq(Box<Expr>, Box<Expr>),
  SLT(Box<Expr>, Box<Expr>),
  SGT(Box<Expr>, Box<Expr>),
  Eq(Box<Expr>, Box<Expr>),
  IsZero(Box<Expr>),

  // Bits
  And(Box<Expr>, Box<Expr>),
  Or(Box<Expr>, Box<Expr>),
  Xor(Box<Expr>, Box<Expr>),
  Not(Box<Expr>),
  SHL(Box<Expr>, Box<Expr>),
  SHR(Box<Expr>, Box<Expr>),
  SAR(Box<Expr>, Box<Expr>),

  // Hashes
  Keccak(Box<Expr>),
  SHA256(Box<Expr>),

  // Block context
  Origin,
  BlockHash(Box<Expr>),
  Coinbase,
  Timestamp,
  BlockNumber,
  PrevRandao,
  GasLimit,
  ChainId,
  BaseFee,

  // Tx context
  TxValue,

  // Frame context
  Balance(Box<Expr>),
  Gas(i32),

  // Code
  CodeSize(Box<Expr>),
  CodeHash(Box<Expr>),

  // Logs
  LogEntry(Box<Expr>, Box<Expr>, Vec<Box<Expr>>),

  // Contract
  C { code: ContractCode, storage: Box<Expr>, balance: Box<Expr>, nonce: Option<W64> },

  // Addresses
  SymAddr(String),
  LitAddr(Addr),
  WAddr(Box<Expr>),

  // Storage
  ConcreteStore(W256W256Map),
  AbstractStore(Box<Expr>, Option<W256>),

  SLoad(Box<Expr>, Box<Expr>),
  SStore(Box<Expr>, Box<Expr>, Box<Expr>),

  // Buffers
  ConcreteBuf(Vec<u8>),
  AbstractBuf(String),

  ReadWord(Box<Expr>, Box<Expr>),
  ReadByte(Box<Expr>, Box<Expr>),
  WriteWord(Box<Expr>, Box<Expr>, Box<Expr>),
  WriteByte(Box<Expr>, Box<Expr>, Box<Expr>),
  CopySlice(Box<Expr>, Box<Expr>, Box<Expr>, Box<Expr>, Box<Expr>),

  BufLength(Box<Expr>),
  End,
}

impl fmt::Display for Expr {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Expr::Mempty => write!(f, "Mempty"),
      Expr::Lit(val) => write!(f, "Lit(0x{})", val.to_hex()),
      Expr::Var(name) => write!(f, "Var({})", name),
      Expr::GVar(gvar) => write!(f, "GVar({})", gvar),
      Expr::LitByte(val) => write!(f, "LitByte(0x{:x})", val),
      Expr::IndexWord(expr1, expr2) => write!(f, "IndexWord({}, {})", expr1, expr2),
      Expr::EqByte(expr1, expr2) => write!(f, "EqByte({}, {})", expr1, expr2),
      Expr::JoinBytes(exprs) => write!(f, "JoinBytes({:?})", exprs),
      Expr::Partial(props, ctx, exec) => write!(f, "Partial({:?}, {:?}, {:?})", props, ctx, exec),
      Expr::Failure(props, ctx, err) => write!(f, "Failure({:?}, {:?}, {:?})", props, ctx, err),
      Expr::Success(props, ctx, buf, contracts) => {
        write!(f, "Success({:?}, {:?}, {}, {:?})", props, ctx, buf, contracts)
      }
      Expr::ITE(cond, then_expr, else_expr) => write!(f, "ITE({}, {}, {})", cond, then_expr, else_expr),
      Expr::Add(expr1, expr2) => write!(f, "Add({}, {})", expr1, expr2),
      Expr::Sub(expr1, expr2) => write!(f, "Sub({}, {})", expr1, expr2),
      Expr::Mul(expr1, expr2) => write!(f, "Mul({}, {})", expr1, expr2),
      Expr::Div(expr1, expr2) => write!(f, "Div({}, {})", expr1, expr2),
      Expr::SDiv(expr1, expr2) => write!(f, "SDiv({}, {})", expr1, expr2),
      Expr::Mod(expr1, expr2) => write!(f, "Mod({}, {})", expr1, expr2),
      Expr::SMod(expr1, expr2) => write!(f, "SMod({}, {})", expr1, expr2),
      Expr::AddMod(expr1, expr2, expr3) => write!(f, "AddMod({}, {}, {})", expr1, expr2, expr3),
      Expr::MulMod(expr1, expr2, expr3) => write!(f, "MulMod({}, {}, {})", expr1, expr2, expr3),
      Expr::Exp(expr1, expr2) => write!(f, "Exp({}, {})", expr1, expr2),
      Expr::SEx(expr1, expr2) => write!(f, "SEx({}, {})", expr1, expr2),
      Expr::Min(expr1, expr2) => write!(f, "Min({}, {})", expr1, expr2),
      Expr::Max(expr1, expr2) => write!(f, "Max({}, {})", expr1, expr2),
      Expr::LT(expr1, expr2) => write!(f, "LT({}, {})", expr1, expr2),
      Expr::GT(expr1, expr2) => write!(f, "GT({}, {})", expr1, expr2),
      Expr::LEq(expr1, expr2) => write!(f, "LEq({}, {})", expr1, expr2),
      Expr::GEq(expr1, expr2) => write!(f, "GEq({}, {})", expr1, expr2),
      Expr::SLT(expr1, expr2) => write!(f, "SLT({}, {})", expr1, expr2),
      Expr::SGT(expr1, expr2) => write!(f, "SGT({}, {})", expr1, expr2),
      Expr::Eq(expr1, expr2) => write!(f, "Eq({}, {})", expr1, expr2),
      Expr::IsZero(expr) => write!(f, "IsZero({})", expr),
      Expr::And(expr1, expr2) => write!(f, "And({}, {})", expr1, expr2),
      Expr::Or(expr1, expr2) => write!(f, "Or({}, {})", expr1, expr2),
      Expr::Xor(expr1, expr2) => write!(f, "Xor({}, {})", expr1, expr2),
      Expr::Not(expr) => write!(f, "Not({})", expr),
      Expr::SHL(expr1, expr2) => write!(f, "SHL({}, {})", expr1, expr2),
      Expr::SHR(expr1, expr2) => write!(f, "SHR({}, {})", expr1, expr2),
      Expr::SAR(expr1, expr2) => write!(f, "SAR({}, {})", expr1, expr2),
      Expr::Keccak(expr) => write!(f, "Keccak({})", expr),
      Expr::SHA256(expr) => write!(f, "SHA256({})", expr),
      Expr::Origin => write!(f, "Origin"),
      Expr::BlockHash(expr) => write!(f, "BlockHash({})", expr),
      Expr::Coinbase => write!(f, "Coinbase"),
      Expr::Timestamp => write!(f, "Timestamp"),
      Expr::BlockNumber => write!(f, "BlockNumber"),
      Expr::PrevRandao => write!(f, "PrevRandao"),
      Expr::GasLimit => write!(f, "GasLimit"),
      Expr::ChainId => write!(f, "ChainId"),
      Expr::BaseFee => write!(f, "BaseFee"),
      Expr::TxValue => write!(f, "TxValue"),
      Expr::Balance(expr) => write!(f, "Balance({})", expr),
      Expr::Gas(idx) => write!(f, "Gas({})", idx),
      Expr::CodeSize(expr) => write!(f, "CodeSize({})", expr),
      Expr::CodeHash(expr) => write!(f, "CodeHash({})", expr),
      Expr::LogEntry(addr, buf, topics) => write!(f, "LogEntry({}, {}, {:?})", addr, buf, topics),
      Expr::C { code, storage, balance, nonce } => {
        write!(f, "Contract {{ code: {:?}, storage: {}, balance: {}, nonce: {:?} }}", code, storage, balance, nonce)
      }
      Expr::SymAddr(name) => write!(f, "SymAddr({})", name),
      Expr::LitAddr(addr) => write!(f, "LitAddr({})", addr),
      Expr::WAddr(expr) => write!(f, "WAddr({})", expr),
      Expr::ConcreteStore(store) => write!(f, "ConcreteStore({:?})", store),
      Expr::AbstractStore(addr, key) => write!(f, "AbstractStore({}, {:?})", addr, key),
      Expr::SLoad(key, storage) => write!(f, "SLoad({}, {})", key, storage),
      Expr::SStore(key, value, old_storage) => {
        write!(f, "SStore({}, {}, {})", key, value, old_storage)
      }
      Expr::ConcreteBuf(buf) => write!(f, "ConcreteBuf({:x?})", buf),
      Expr::AbstractBuf(name) => write!(f, "AbstractBuf({})", name),
      Expr::ReadWord(index, src) => write!(f, "ReadWord({}, {})", index, src),
      Expr::ReadByte(index, src) => write!(f, "ReadByte({}, {})", index, src),
      Expr::WriteWord(index, value, buf) => write!(f, "WriteWord({}, {}, {})", index, value, buf),
      Expr::WriteByte(index, value, buf) => write!(f, "WriteByte({}, {}, {})", index, value, buf),
      Expr::CopySlice(src_offset, dst_offset, size, src, dst) => {
        write!(f, "CopySlice({}, {}, {}, {}, {})", src_offset, dst_offset, size, src, dst)
      }
      Expr::BufLength(buf) => write!(f, "BufLength({})", buf),
      Expr::End => write!(f, "end"),
    }
  }
}

pub fn len_buf(e: &Expr) -> usize {
  match e {
    Expr::ConcreteBuf(buf) => buf.len(),
    _ => 0,
  }
}

impl Eq for Expr {}

impl PartialEq for Expr {
  fn eq(&self, other: &Self) -> bool {
    use Expr::*;

    match (self, other) {
      (Mempty, Mempty) => true,
      (Lit(val1), Lit(val2)) => val1 == val2,
      (Var(name1), Var(name2)) => name1 == name2,
      (GVar(gvar1), GVar(gvar2)) => gvar1 == gvar2,
      (LitByte(byte1), LitByte(byte2)) => byte1 == byte2,
      (IndexWord(expr1a, expr1b), IndexWord(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (EqByte(expr1a, expr1b), EqByte(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (JoinBytes(vec1), JoinBytes(vec2)) => vec1 == vec2,
      (Partial(props1, tc1, exec1), Partial(props2, tc2, exec2)) => props1 == props2 && tc1 == tc2 && exec1 == exec2,
      (Failure(props1, tc1, err1), Failure(props2, tc2, err2)) => props1 == props2 && tc1 == tc2 && err1 == err2,
      (Success(props1, tc1, expr1, map1), Success(props2, tc2, expr2, map2)) => {
        props1 == props2 && tc1 == tc2 && expr1 == expr2 && map1 == map2
      }
      (ITE(cond1, then1, else1), ITE(cond2, then2, else2)) => cond1 == cond2 && then1 == then2 && else1 == else2,
      (Add(expr1a, expr1b), Add(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (Sub(expr1a, expr1b), Sub(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (Mul(expr1a, expr1b), Mul(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (Div(expr1a, expr1b), Div(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (SDiv(expr1a, expr1b), SDiv(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (Mod(expr1a, expr1b), Mod(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (SMod(expr1a, expr1b), SMod(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (AddMod(expr1a, expr1b, expr1c), AddMod(expr2a, expr2b, expr2c)) => {
        expr1a == expr2a && expr1b == expr2b && expr1c == expr2c
      }
      (MulMod(expr1a, expr1b, expr1c), MulMod(expr2a, expr2b, expr2c)) => {
        expr1a == expr2a && expr1b == expr2b && expr1c == expr2c
      }
      (Exp(expr1a, expr1b), Exp(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (SEx(expr1a, expr1b), SEx(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (Min(expr1a, expr1b), Min(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (Max(expr1a, expr1b), Max(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (LT(expr1a, expr1b), LT(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (GT(expr1a, expr1b), GT(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (LEq(expr1a, expr1b), LEq(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (GEq(expr1a, expr1b), GEq(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (SLT(expr1a, expr1b), SLT(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (SGT(expr1a, expr1b), SGT(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (Eq(expr1a, expr1b), Eq(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (IsZero(expr1), IsZero(expr2)) => expr1 == expr2,
      (And(expr1a, expr1b), And(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (Or(expr1a, expr1b), Or(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (Xor(expr1a, expr1b), Xor(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (Not(expr1), Not(expr2)) => expr1 == expr2,
      (SHL(expr1a, expr1b), SHL(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (SHR(expr1a, expr1b), SHR(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (SAR(expr1a, expr1b), SAR(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (Keccak(expr1), Keccak(expr2)) => expr1 == expr2,
      (SHA256(expr1), SHA256(expr2)) => expr1 == expr2,
      (Origin, Origin) => true,
      (BlockHash(expr1), BlockHash(expr2)) => expr1 == expr2,
      (Coinbase, Coinbase) => true,
      (Timestamp, Timestamp) => true,
      (BlockNumber, BlockNumber) => true,
      (PrevRandao, PrevRandao) => true,
      (GasLimit, GasLimit) => true,
      (ChainId, ChainId) => true,
      (BaseFee, BaseFee) => true,
      (TxValue, TxValue) => true,
      (Balance(expr1), Balance(expr2)) => expr1 == expr2,
      (Gas(val1), Gas(val2)) => val1 == val2,
      (CodeSize(expr1), CodeSize(expr2)) => expr1 == expr2,
      (CodeHash(expr1), CodeHash(expr2)) => expr1 == expr2,
      (LogEntry(expr1a, expr1b, vec1), LogEntry(expr2a, expr2b, vec2)) => {
        expr1a == expr2a && expr1b == expr2b && vec1 == vec2
      }
      (
        C { code: code1, storage: storage1, balance: balance1, nonce: nonce1 },
        C { code: code2, storage: storage2, balance: balance2, nonce: nonce2 },
      ) => code1 == code2 && storage1 == storage2 && balance1 == balance2 && nonce1 == nonce2,
      (SymAddr(name1), SymAddr(name2)) => name1 == name2,
      (LitAddr(addr1), LitAddr(addr2)) => addr1 == addr2,
      (WAddr(expr1), WAddr(expr2)) => expr1 == expr2,
      (ConcreteStore(map1), ConcreteStore(map2)) => map1 == map2,
      (AbstractStore(expr1, opt1), AbstractStore(expr2, opt2)) => expr1 == expr2 && opt1 == opt2,
      (SLoad(expr1a, expr1b), SLoad(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (SStore(expr1a, expr1b, expr1c), SStore(expr2a, expr2b, expr2c)) => {
        expr1a == expr2a && expr1b == expr2b && expr1c == expr2c
      }
      (ConcreteBuf(buf1), ConcreteBuf(buf2)) => buf1 == buf2,
      (AbstractBuf(str1), AbstractBuf(str2)) => str1 == str2,
      (ReadWord(expr1a, expr1b), ReadWord(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (ReadByte(expr1a, expr1b), ReadByte(expr2a, expr2b)) => expr1a == expr2a && expr1b == expr2b,
      (WriteWord(expr1a, expr1b, expr1c), WriteWord(expr2a, expr2b, expr2c)) => {
        expr1a == expr2a && expr1b == expr2b && expr1c == expr2c
      }
      (WriteByte(expr1a, expr1b, expr1c), WriteByte(expr2a, expr2b, expr2c)) => {
        expr1a == expr2a && expr1b == expr2b && expr1c == expr2c
      }
      (CopySlice(expr1a, expr1b, expr1c, expr1d, expr1e), CopySlice(expr2a, expr2b, expr2c, expr2d, expr2e)) => {
        expr1a == expr2a && expr1b == expr2b && expr1c == expr2c && expr1d == expr2d && expr1e == expr2e
      }
      (BufLength(expr1), BufLength(expr2)) => expr1 == expr2,
      _ => false,
    }
  }
}

impl Hash for Expr {
  fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
    use Expr::*;

    match self {
      Mempty => {
        "Mempty".hash(state);
      }
      Lit(val) => {
        "Lit".hash(state);
        val.hash(state);
      }
      Var(name) => {
        "Var".hash(state);
        name.hash(state);
      }
      GVar(gvar) => {
        "GVar".hash(state);
        gvar.hash(state);
      }
      LitByte(byte) => {
        "LitByte".hash(state);
        byte.hash(state);
      }
      IndexWord(expr1, expr2) => {
        "IndexWord".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      EqByte(expr1, expr2) => {
        "EqByte".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      JoinBytes(vec) => {
        "JoinBytes".hash(state);
        vec.hash(state);
      }
      Partial(props, tc, exec) => {
        "Partial".hash(state);
        props.hash(state);
        tc.hash(state);
        exec.hash(state);
      }
      Failure(props, tc, err) => {
        "Failure".hash(state);
        props.hash(state);
        tc.hash(state);
        err.hash(state);
      }
      Success(props, tc, expr, map) => {
        "Success".hash(state);
        props.hash(state);
        tc.hash(state);
        expr.hash(state);
        map.hash(state);
      }
      ITE(cond, then, else_) => {
        "ITE".hash(state);
        cond.hash(state);
        then.hash(state);
        else_.hash(state);
      }
      Add(expr1, expr2) => {
        "Add".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      Sub(expr1, expr2) => {
        "Sub".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      Mul(expr1, expr2) => {
        "Mul".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      Div(expr1, expr2) => {
        "Div".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      SDiv(expr1, expr2) => {
        "SDiv".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      Mod(expr1, expr2) => {
        "Mod".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      SMod(expr1, expr2) => {
        "SMod".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      AddMod(expr1, expr2, expr3) => {
        "AddMod".hash(state);
        expr1.hash(state);
        expr2.hash(state);
        expr3.hash(state);
      }
      MulMod(expr1, expr2, expr3) => {
        "MulMod".hash(state);
        expr1.hash(state);
        expr2.hash(state);
        expr3.hash(state);
      }
      Exp(expr1, expr2) => {
        "Exp".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      SEx(expr1, expr2) => {
        "SEx".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      Min(expr1, expr2) => {
        "Min".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      Max(expr1, expr2) => {
        "Max".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      LT(expr1, expr2) => {
        "LT".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      GT(expr1, expr2) => {
        "GT".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      LEq(expr1, expr2) => {
        "LEq".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      GEq(expr1, expr2) => {
        "GEq".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      SLT(expr1, expr2) => {
        "SLT".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      SGT(expr1, expr2) => {
        "SGT".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      Eq(expr1, expr2) => {
        "Eq".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      IsZero(expr) => {
        "IsZero".hash(state);
        expr.hash(state);
      }
      And(expr1, expr2) => {
        "And".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      Or(expr1, expr2) => {
        "Or".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      Xor(expr1, expr2) => {
        "Xor".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      Not(expr) => {
        "Not".hash(state);
        expr.hash(state);
      }
      SHL(expr1, expr2) => {
        "SHL".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      SHR(expr1, expr2) => {
        "SHR".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      SAR(expr1, expr2) => {
        "SAR".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      Keccak(expr) => {
        "Keccak".hash(state);
        expr.hash(state);
      }
      SHA256(expr) => {
        "SHA256".hash(state);
        expr.hash(state);
      }
      Origin => {
        "Origin".hash(state);
      }
      BlockHash(expr) => {
        "BlockHash".hash(state);
        expr.hash(state);
      }
      Coinbase => {
        "Coinbase".hash(state);
      }
      Timestamp => {
        "Timestamp".hash(state);
      }
      BlockNumber => {
        "BlockNumber".hash(state);
      }
      PrevRandao => {
        "PrevRandao".hash(state);
      }
      GasLimit => {
        "GasLimit".hash(state);
      }
      ChainId => {
        "ChainId".hash(state);
      }
      BaseFee => {
        "BaseFee".hash(state);
      }
      TxValue => {
        "TxValue".hash(state);
      }
      Balance(expr) => {
        "Balance".hash(state);
        expr.hash(state);
      }
      Gas(val) => {
        "Gas".hash(state);
        val.hash(state);
      }
      CodeSize(expr) => {
        "CodeSize".hash(state);
        expr.hash(state);
      }
      CodeHash(expr) => {
        "CodeHash".hash(state);
        expr.hash(state);
      }
      LogEntry(expr1, expr2, vec) => {
        "LogEntry".hash(state);
        expr1.hash(state);
        expr2.hash(state);
        vec.hash(state);
      }
      C { code, storage, balance, nonce } => {
        "Contract".hash(state);
        code.hash(state);
        storage.hash(state);
        balance.hash(state);
        nonce.hash(state);
      }
      SymAddr(name) => {
        "SymAddr".hash(state);
        name.hash(state);
      }
      LitAddr(addr) => {
        "LitAddr".hash(state);
        addr.hash(state);
      }
      WAddr(expr) => {
        "WAddr".hash(state);
        expr.hash(state);
      }
      ConcreteStore(map) => {
        "ConcreteStore".hash(state);
        map.hash(state);
      }
      AbstractStore(expr, opt) => {
        "AbstractStore".hash(state);
        expr.hash(state);
        opt.hash(state);
      }
      SLoad(expr1, expr2) => {
        "SLoad".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      SStore(expr1, expr2, expr3) => {
        "SStore".hash(state);
        expr1.hash(state);
        expr2.hash(state);
        expr3.hash(state);
      }
      ConcreteBuf(buf) => {
        "ConcreteBuf".hash(state);
        buf.hash(state);
      }
      AbstractBuf(str) => {
        "AbstractBuf".hash(state);
        str.hash(state);
      }
      ReadWord(expr1, expr2) => {
        "ReadWord".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      ReadByte(expr1, expr2) => {
        "ReadByte".hash(state);
        expr1.hash(state);
        expr2.hash(state);
      }
      WriteWord(expr1, expr2, expr3) => {
        "WriteWord".hash(state);
        expr1.hash(state);
        expr2.hash(state);
        expr3.hash(state);
      }
      WriteByte(expr1, expr2, expr3) => {
        "WriteByte".hash(state);
        expr1.hash(state);
        expr2.hash(state);
        expr3.hash(state);
      }
      CopySlice(expr1, expr2, expr3, expr4, expr5) => {
        "CopySlice".hash(state);
        expr1.hash(state);
        expr2.hash(state);
        expr3.hash(state);
        expr4.hash(state);
        expr5.hash(state);
      }
      BufLength(expr) => {
        "BufLength".hash(state);
        expr.hash(state);
      }
      End => {
        "@end".hash(state);
      }
    }
  }
}

// Propositions -----------------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum Prop {
  PEq(Expr, Expr),
  PLT(Expr, Expr),
  PGT(Expr, Expr),
  PGEq(Expr, Expr),
  PLEq(Expr, Expr),
  PNeg(Box<Prop>),
  PAnd(Box<Prop>, Box<Prop>),
  POr(Box<Prop>, Box<Prop>),
  PImpl(Box<Prop>, Box<Prop>),
  PBool(bool),
}

// Errors -----------------------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Hash)]
pub enum EvmError {
  BalanceTooLow(Box<Expr>, Box<Expr>),
  UnrecognizedOpcode(u8),
  SelfDestruction,
  StackUnderrun,
  BadJumpDestination,
  Revert(Box<Expr>),
  OutOfGas(u64, u64),
  StackLimitExceeded,
  IllegalOverflow,
  StateChangeWhileStatic,
  InvalidMemoryAccess,
  CallDepthLimitReached,
  MaxCodeSizeExceeded(u32, u32),
  MaxInitCodeSizeExceeded(u32, Box<Expr>),
  InvalidFormat,
  PrecompileFailure,
  ReturnDataOutOfBounds,
  NonceOverflow,
  BadCheatCode(u32),
  NonexistentFork(i32),
}

impl fmt::Display for EvmError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      EvmError::BalanceTooLow(a, b) => write!(f, "Balance too low: {} < {}", a, b),
      EvmError::UnrecognizedOpcode(op) => write!(f, "Unrecognized opcode: {}", op),
      EvmError::SelfDestruction => write!(f, "Self destruction"),
      EvmError::StackUnderrun => write!(f, "Stack underrun"),
      EvmError::BadJumpDestination => write!(f, "Bad jump destination"),
      EvmError::Revert(buf) => write!(f, "Revert: {:?}", buf),
      EvmError::OutOfGas(used, limit) => write!(f, "Out of gas: {} / {}", used, limit),
      EvmError::StackLimitExceeded => write!(f, "Stack limit exceeded"),
      EvmError::IllegalOverflow => write!(f, "Illegal overflow"),
      EvmError::StateChangeWhileStatic => write!(f, "State change while static"),
      EvmError::InvalidMemoryAccess => write!(f, "Invalid memory access"),
      EvmError::CallDepthLimitReached => write!(f, "Call depth limit reached"),
      EvmError::MaxCodeSizeExceeded(current, max) => {
        write!(f, "Max code size exceeded: {} / {}", current, max)
      }
      EvmError::MaxInitCodeSizeExceeded(current, max) => {
        write!(f, "Max init code size exceeded: {} / {}", current, max)
      }
      EvmError::InvalidFormat => write!(f, "Invalid format"),
      EvmError::PrecompileFailure => write!(f, "Precompile failure"),
      EvmError::ReturnDataOutOfBounds => write!(f, "Return data out of bounds"),
      EvmError::NonceOverflow => write!(f, "Nonce overflow"),
      EvmError::BadCheatCode(selector) => write!(f, "Bad cheat code: {}", selector),
      EvmError::NonexistentFork(fork) => write!(f, "Nonexistent fork: {}", fork),
    }
  }
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub enum TraceData {
  EventTrace(Expr, Expr, Vec<Expr>),
  FrameTrace(FrameContext),
  ErrorTrace(EvmError),
  EntryTrace(String),
  ReturnTrace(Expr, FrameContext),
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub struct Contract {
  pub code: ContractCode,
  pub storage: Expr,
  pub orig_storage: Expr,
  pub balance: Expr,
  pub nonce: Option<W64>,
  pub codehash: Expr,
  pub op_idx_map: Vec<i32>,
  pub external: bool,
  pub code_ops: Vec<(i32, Op)>,
}

pub fn update_balance(c: Contract, new_balance: Expr) -> Contract {
  Contract {
    code: c.code,
    storage: c.storage,
    orig_storage: c.orig_storage,
    balance: new_balance,
    nonce: c.nonce,
    codehash: c.codehash,
    op_idx_map: c.op_idx_map,
    external: c.external,
    code_ops: c.code_ops,
  }
}

impl Contract {
  pub fn bytecode(&self) -> Option<Expr> {
    match &self.code {
      ContractCode::InitCode(_, _) => Some(Expr::Mempty), // Equivalent to Just mempty
      ContractCode::RuntimeCode(RuntimeCodeStruct::ConcreteRuntimeCode(bs)) => Some(Expr::ConcreteBuf(*bs.clone())),
      ContractCode::RuntimeCode(RuntimeCodeStruct::SymbolicRuntimeCode(ops)) => Some(from_list(ops.to_vec())),
      ContractCode::UnKnownCode(_) => None,
    }
  }
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub enum ContractCode {
  UnKnownCode(Box<Expr>),
  InitCode(Box<Vec<u8>>, Box<Expr>),
  RuntimeCode(RuntimeCodeStruct),
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub enum RuntimeCodeStruct {
  ConcreteRuntimeCode(Box<Vec<u8>>),
  SymbolicRuntimeCode(Vec<Box<Expr>>),
}

// Define the Trace struct
#[derive(Debug, Clone, PartialEq, Hash)]
pub struct Trace {
  pub op_ix: i32,           // Operation index
  pub contract: Contract,   // Contract associated with the trace
  pub tracedata: TraceData, // Data associated with the trace
}

// Define TraceContext struct
#[derive(Debug, Clone, PartialEq, Hash)]
pub struct TraceContext {
  pub traces: Vec<Trace>,         // Assuming Trace is a suitable type like struct Trace;
  pub contracts: ExprContractMap, // Using HashMap for contracts
  pub labels: AddrStringMap,      // Using HashMap for labels
}

// Implement Monoid trait for TraceContext
impl Default for TraceContext {
  fn default() -> Self {
    TraceContext { traces: Vec::new(), contracts: ExprContractMap::new(), labels: AddrStringMap::new() }
  }
}

#[derive(Debug, Clone)]
pub enum Gas {
  Symbolic,
  Concerete(Word64),
}

pub type MutableMemory = Vec<u8>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Memory {
  ConcreteMemory(MutableMemory),
  SymbolicMemory(Expr),
}

impl Memory {
  // Method to get a mutable reference to ConcreteMemory
  pub fn as_mut_concrete_memory(&mut self) -> Option<&mut Vec<u8>> {
    match self {
      Memory::ConcreteMemory(mem) => Some(mem),
      _ => None,
    }
  }
}

// The "registers" of the VM along with memory and data stack
#[derive(Clone)]
pub struct FrameState {
  pub contract: Box<Expr>,
  pub code_contract: Box<Expr>,
  pub code: ContractCode,
  pub pc: usize,
  pub base_pc: usize,
  pub stack: Vec<Box<Expr>>,
  pub memory: Memory,
  pub memory_size: u64,
  pub calldata: Box<Expr>,
  pub callvalue: Box<Expr>,
  pub caller: Box<Expr>,
  pub gas: Gas,
  pub returndata: Box<Expr>,
  pub static_flag: bool,
  pub prev_model: Option<String>,
}

// Define the tree structure
#[derive(Debug, Clone)]
pub struct Tree<T> {
  pub value: T,
  pub children: Vec<Tree<T>>,
}

// Define a cursor or position in the tree
#[derive(Debug, Clone)]
pub struct TreePos<T> {
  pub current: Tree<T>,
  pub path: Vec<usize>, // Path from root to current node
}

#[derive(Clone)]
pub struct VM {
  pub result: Option<VMResult>,
  pub state: FrameState,
  pub frames: Vec<Frame>,
  pub env: Env,
  pub block: Block,
  pub tx: TxState,
  pub logs: Vec<Expr>,
  pub traces: Vec<Trace>,
  pub cache: Cache,
  pub burned: Gas,
  pub constraints: Vec<Prop>,
  pub constraints_raw_expr: Vec<Box<Expr>>,
  pub config: RuntimeConfig,
  pub iterations: HashMap<CodeLocation, (i64, Vec<Box<Expr>>)>,
  pub forks: Vec<ForkState>,
  pub current_fork: i32,
  pub labels: HashMap<Addr, String>,
  // log
  pub decoded_opcodes: Vec<String>,
}

pub type CodeLocation = (Expr, i64);

#[derive(Clone)]
pub struct Cache {
  pub fetched: HashMap<Addr, Contract>,
  pub path: HashMap<(CodeLocation, i64), bool>,
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub enum FrameContext {
  CreationContext {
    address: Expr,
    codehash: Expr,
    createversion: ExprContractMap,
    substate: SubState,
  },
  CallContext {
    target: Expr,
    context: Expr,
    offset: Expr,
    size: Expr,
    codehash: Expr,
    abi: Option<W256>,
    calldata: Expr,
    callreversion: ExprContractMap,
    substate: SubState,
  },
}

#[derive(Clone)]
pub struct Frame {
  pub context: FrameContext,
  pub state: FrameState,
}

#[derive(Debug, Clone)]
pub enum BaseState {
  EmptyBase,
  AbstractBase,
}

#[derive(Clone)]
pub struct RuntimeConfig {
  pub allow_ffi: bool,
  pub override_caller: Option<Expr>,
  pub reset_caller: bool,
  pub base_state: BaseState,
}

#[derive(Debug, Clone)]
pub enum VMResult {
  Unfinished(PartialExec),
  VMFailure(EvmError),
  VMSuccess(Expr),
  HandleEffect,
}

// Type alias for the EVM monad
pub type EVM<A> = (VM, A);

// Define the Query enum
pub enum Query {
  PleaseFetchContract(Addr, BaseState, Box<dyn Fn(Contract) -> ()>),
  PleaseFetchSlot(Addr, W256, Box<dyn Fn(W256) -> ()>),
  PleaseAskSMT(Expr, Vec<Prop>, Box<dyn Fn(BranchCondition) -> ()>),
  PleaseDoFFI(Vec<String>, Box<dyn Fn(ByteString) -> ()>),
}

// Define the Choose enum
pub enum Choose {
  PleaseChoosePath(Expr, Arc<dyn Fn(bool) -> EVM<()>>),
}

// Define the Effect enum
pub enum Effect {
  Query(Query),
  Choose(Choose),
}

// Define the BranchCondition enum
pub enum BranchCondition {
  Case(bool),
  Unknown,
}

// Implement Display for Query
impl fmt::Display for Query {
  fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
    todo!()
    /*
    match self {
      Query::PleaseFetchContract(addr, base, _) => write!(f, "<EVM.Query: fetch contract {} {}>", addr, base),
      Query::PleaseFetchSlot(addr, slot, _) => write!(f, "<EVM.Query: fetch slot {} for {}>", slot, addr),
      Query::PleaseAskSMT(condition, constraints, _) => todo!(),
      Query::PleaseDoFFI(cmd, _) => write!(f, "<EVM.Query: do ffi: {}>", cmd.join(", ")),
      /*write!(
        f,
        "<EVM.Query: ask SMT about {} in context {}>",
        condition,
        constraints.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(", ")
      ), */
    }
    */
  }
}

// Implement Display for Choose
impl fmt::Display for Choose {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Choose::PleaseChoosePath(_, _) => write!(f, "<EVM.Choice: waiting for user to select path (0,1)>"),
    }
  }
}

// Implement Display for Effect
impl fmt::Display for Effect {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Effect::Query(query) => write!(f, "{}", query),
      Effect::Choose(choice) => write!(f, "{}", choice),
    }
  }
}

// Implement Display for BranchCondition
impl fmt::Display for BranchCondition {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      BranchCondition::Case(b) => write!(f, "Case({})", b),
      BranchCondition::Unknown => write!(f, "Unknown"),
    }
  }
}

// Various environmental data
#[derive(Clone)]
pub struct Env {
  pub contracts: ExprContractMap,
  pub chain_id: W256,
  pub fresh_address: i32,
  pub fresh_gas_vals: i32,
}

// DData about the block
#[derive(Clone)]
pub struct Block {
  pub coinbase: Expr,
  pub time_stamp: Expr,
  pub number: W256,
  pub prev_randao: W256,
  pub gaslimit: Word64,
  pub base_fee: W256,
  pub max_code_size: W256,
  pub schedule: FeeSchedule,
}

#[derive(Clone)]
pub struct TxState {
  pub gasprice: W256,
  pub gaslimit: Word64,
  pub priority_fee: W256,
  pub origin: Expr,
  pub to_addr: Expr,
  pub value: Expr,
  pub substate: SubState,
  pub is_create: bool,
  pub tx_reversion: ExprContractMap,
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub struct SubState {
  pub selfdestructs: Vec<Box<Expr>>,
  pub touched_accounts: Vec<Box<Expr>>,
  pub accessed_addresses: ExprSet,
  pub accessed_storage_keys: ExprW256Set,
  pub refunds: Vec<(Expr, Word64)>,
}

#[derive(Debug, Clone)]
pub struct VMOpts {
  pub contract: Contract,
  pub other_contracts: Vec<(Expr, Contract)>,
  pub calldata: (Expr, Vec<Prop>),
  pub base_state: BaseState,
  pub value: Expr,
  pub priority_fee: W256,
  pub address: Expr,
  pub caller: Expr,
  pub origin: Expr,
  pub gas: Gas,
  pub gaslimit: Word64,
  pub number: W256,
  pub time_stamp: Expr,
  pub coinbase: Expr,
  pub prev_randao: W256,
  pub max_code_size: W256,
  pub block_gaslimit: Word64,
  pub gasprice: W256,
  pub base_fee: W256,
  pub schedule: FeeSchedule,
  pub chain_id: W256,
  pub create: bool,
  pub tx_access_list: HashMap<Expr, Vec<W256>>,
  pub allow_ffi: bool,
}

#[derive(Clone)]
pub struct ForkState {
  pub env: Env,
  pub block: Block,
  pub cache: Cache,
  pub urlaor_alias: String,
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub enum PartialExec {
  UnexpectedSymbolicArg { pc: usize, msg: String, args: Vec<Expr> },
  MaxIterationsReached { pc: usize, addr: Box<Expr> },
  JumpIntoSymbolicCode { pc: usize, jump_dst: usize },
}

// Example function translating fromList logic from Haskell
pub fn from_list(bs: Vec<Box<Expr>>) -> Expr {
  if bs.iter().all(|expr| matches!(**expr, Expr::LitByte(_))) {
    let packed_bytes: Vec<u8> = bs
      .iter()
      .filter_map(|expr| match *expr.clone() {
        Expr::LitByte(b) => Some(b),
        _ => None,
      })
      .collect();
    Expr::ConcreteBuf(packed_bytes)
  } else {
    let mut concrete_bytes = Vec::with_capacity(bs.len());
    for (_idx, expr) in bs.iter().enumerate() {
      match **expr {
        Expr::LitByte(b) => concrete_bytes.push(b),
        _ => concrete_bytes.push(0),
      }
    }
    let mut buf_expr = Expr::ConcreteBuf(concrete_bytes);

    for (idx, expr) in bs.into_iter().enumerate() {
      match *expr {
        Expr::LitByte(_) => continue,
        _ => buf_expr = Expr::WriteByte(Box::new(Expr::Lit(W256(0, idx as u128))), expr, Box::new(buf_expr)),
      }
    }
    buf_expr
  }
}

/*
type AddableVec<T> = Vec<T>;

impl<T> Add for AddableVec<T>
where
  T: Clone, // T must implement Clone
{
  type Output = AddableVec<T>; // The output type is also Vec<T>

  fn add(self, other: AddableVec<T>) -> AddableVec<T> {
    // Create a new vector with capacity to hold both input vectors
    let mut result = AddableVec::with_capacity(self.len() + other.len());

    // Extend the result vector with elements from the first vector
    result.extend(self);

    // Extend the result vector with elements from the second vector
    result.extend(other);

    result // Return the concatenated vector
  }
}
*/

// Implement the Default trait for AddableVec
impl Default for Expr {
  fn default() -> Expr {
    Expr::Mempty // Return an empty vector
  }
}

#[derive(Clone, PartialEq, Hash)]
pub struct AddableVec<T>(Vec<T>);

impl<T> AddableVec<T> {
  // Implement a from_vec method to create AddableVec from Vec<T>
  pub fn from_vec(vec: Vec<T>) -> AddableVec<T> {
    AddableVec(vec)
  }

  // Optionally, you can also implement other utility methods like to_vec
  pub fn to_vec(self) -> Vec<T> {
    self.0
  }
}

// Implement the Default trait for AddableVec
impl<T> Default for AddableVec<T> {
  fn default() -> AddableVec<T> {
    AddableVec(Vec::new()) // Return an empty vector
  }
}

impl<T> Add for AddableVec<T>
where
  T: Clone,
{
  type Output = AddableVec<T>;

  fn add(self, other: AddableVec<T>) -> AddableVec<T> {
    let mut result = Vec::with_capacity(self.0.len() + other.0.len());
    result.extend(self.0);
    result.extend(other.0);
    AddableVec(result)
  }
}

// Implement Debug trait for easy printing
impl<T: std::fmt::Debug> std::fmt::Debug for AddableVec<T> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_tuple("AddableVec").field(&self.0).finish()
  }
}

macro_rules! impl_hashset_traits {
  ($name:ident, $inner:ty) => {
    #[derive(Debug, Clone)]
    pub struct $name(HashSet<$inner>);

    impl<const N: usize> From<[$inner; N]> for $name {
      fn from(arr: [$inner; N]) -> Self {
        $name(arr.into_iter().collect())
      }
    }

    impl FromIterator<$inner> for $name {
      fn from_iter<I: IntoIterator<Item = $inner>>(iter: I) -> Self {
        $name(iter.into_iter().collect())
      }
    }

    impl PartialEq for $name {
      fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
      }
    }

    impl Eq for $name {}

    impl Hash for $name {
      fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let vec: Vec<_> = self.0.iter().collect();
        // vec.sort();
        for elem in vec {
          elem.hash(state);
        }
      }
    }

    impl Deref for $name {
      type Target = HashSet<$inner>;

      fn deref(&self) -> &Self::Target {
        &self.0
      }
    }

    impl DerefMut for $name {
      fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
      }
    }
  };
}

macro_rules! impl_hashmap_traits {
  ($name:ident, $key:ty, $value:ty) => {
    #[derive(Debug, Clone)]
    pub struct $name(HashMap<$key, $value>);

    impl $name {
      pub fn new() -> Self {
        $name(HashMap::new())
      }

      pub fn from(vec: Vec<($key, $value)>) -> Self {
        $name(vec.into_iter().collect())
      }

      pub fn insert(&mut self, key: $key, value: $value) {
        self.0.insert(key, value);
      }

      pub fn get(&self, key: &$key) -> Option<&$value> {
        self.0.get(key)
      }

      pub fn get_mut(&mut self, key: &$key) -> Option<&mut $value> {
        self.0.get_mut(key)
      }

      pub fn entry(&mut self, key: $key) -> std::collections::hash_map::Entry<$key, $value> {
        self.0.entry(key)
      }

      pub fn values(&mut self) -> std::collections::hash_map::Values<'_, $key, $value> {
        self.0.values()
      }

      pub fn keys(&mut self) -> std::collections::hash_map::Keys<'_, $key, $value> {
        self.0.keys()
      }

      pub fn iter(&mut self) -> std::collections::hash_map::Iter<'_, $key, $value> {
        self.0.iter()
      }
    }

    impl FromIterator<($key, $value)> for $name {
      fn from_iter<I: IntoIterator<Item = ($key, $value)>>(iter: I) -> Self {
        $name(iter.into_iter().collect())
      }
    }

    impl PartialEq for $name {
      fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
      }
    }

    impl Eq for $name {}

    impl Hash for $name {
      fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let vec: Vec<_> = self.0.iter().collect();
        // vec.sort_by(|a, b| a.0.cmp(b.0)); // Sort by keys
        for (key, value) in vec {
          key.hash(state);
          value.hash(state);
        }
      }
    }
  };
}

impl_hashset_traits!(ExprSet, Expr);
impl_hashset_traits!(ExprW256Set, (Expr, W256));
impl_hashmap_traits!(ExprContractMap, Expr, Contract);
impl_hashmap_traits!(AddrStringMap, Addr, String);
impl_hashmap_traits!(ExprExprMap, Expr, Expr);
impl_hashmap_traits!(W256W256Map, W256, W256);

pub fn unbox<T>(value: Box<T>) -> T {
  *value
}

pub fn pad_left(n: usize, xs: Vec<u8>) -> Vec<u8> {
  if xs.len() >= n {
    return xs; // No padding needed if already of sufficient length
  }
  let padding_length = n - xs.len();
  let padding = iter::repeat(0u8).take(padding_length);
  padding.chain(xs.into_iter()).collect()
}

pub fn pad_left_prime(n: usize, xs: Vec<Box<Expr>>) -> Vec<Box<Expr>> {
  if xs.len() >= n {
    return xs; // No padding needed if already of sufficient length
  }
  let padding_length = n - xs.len();
  let padding = iter::repeat(Box::new(Expr::LitByte(0))).take(padding_length);
  padding.chain(xs.into_iter()).collect()
}

pub fn pad_right(n: usize, mut xs: Vec<u8>) -> Vec<u8> {
  if xs.len() >= n {
    return xs; // No padding needed if already of sufficient length
  }
  let padding_length = n - xs.len();
  xs.extend(iter::repeat(0u8).take(padding_length));
  xs
}

pub fn maybe_lit_word(word: Expr) -> Option<W256> {
  match word {
    Expr::Lit(w) => Some(w),
    Expr::WAddr(addr) => match *addr {
      Expr::LitAddr(w) => Some(w),
      _ => None,
    },
    _ => None,
  }
}

pub fn maybe_lit_byte(byte: Expr) -> Option<Word8> {
  if let Expr::LitByte(b) = byte {
    Some(b.clone())
  } else {
    None
  }
}

pub fn maybe_lit_addr(addr: Expr) -> Option<Addr> {
  if let Expr::LitAddr(s) = addr {
    Some(s.clone())
  } else {
    None
  }
}

pub fn until_fixpoint<F, T>(f: F, mut x: T) -> T
where
  F: Fn(&T) -> T,
  T: PartialEq + Clone,
{
  loop {
    let x_new = f(&x);
    if x == x_new {
      return x;
    }
    x = x_new;
  }
}

pub fn word256(xs: &ByteString) -> W256 {
  // If the length of xs is 1, optimize for one-byte pushes
  if xs.len() == 1 {
    let value = xs[0] as u128;
    return W256(0, value);
  }

  // Otherwise, pad the input and deserialize
  let padded_xs = pad_left(32, xs.to_vec());
  let mut cursor = Cursor::new(padded_xs);

  let a = cursor.read_u64::<BigEndian>().unwrap() as u128;
  let b = cursor.read_u64::<BigEndian>().unwrap() as u128;
  let c = cursor.read_u64::<BigEndian>().unwrap() as u128;
  let d = cursor.read_u64::<BigEndian>().unwrap() as u128;

  W256((a << 64) | b, (c << 64) | d)
}

pub fn word256_bytes(w256: W256) -> Vec<u8> {
  /*
  let W256(a, b) = w256;
  let mut buffer = Vec::with_capacity(32);

  // Encode each 128-bit portion
  buffer.write_u128(a);
  buffer.write_u128(b);

  buffer*/
  let W256(low, high) = w256;
  let mut buffer = Vec::with_capacity(32);
  buffer.extend_from_slice(&high.to_be_bytes());
  buffer.extend_from_slice(&low.to_be_bytes());
  buffer
}

pub fn keccak_bytes(input: &ByteString) -> ByteString {
  let mut keccak = Keccak::v256();
  keccak.update(input);
  let mut result = vec![0u8; 32]; // Keccak-256 produces a 256-bit (32-byte) hash
  keccak.finalize(&mut result);
  result
}

pub fn keccak(buf: Expr) -> Result<Expr, &'static str> {
  match buf {
    Expr::ConcreteBuf(bs) => {
      let hash_result = keccak_bytes(&bs);
      let byte_array: [u8; 4] = hash_result[..4].try_into().map_err(|_| "Conversion failed")?;
      // Convert the byte array to a u32 (assuming the bytes are in little-endian order)
      Ok(Expr::Lit(W256(u32::from_le_bytes(byte_array) as u128, 0)))
    }
    _ => Ok(Expr::Keccak(Box::new(buf))), // Assuming Expr has a variant for Keccak
  }
}

pub fn keccak_prime(input: &ByteString) -> W256 {
  let hash_result = keccak_bytes(input);
  word256(&hash_result[..32].to_vec())
}

pub fn word32(xs: &[u8]) -> u32 {
  xs.iter().rev().enumerate().fold(0, |acc, (n, &x)| acc | (u32::from(x) << (n)))
}

pub fn abi_keccak(input: &[u8]) -> FunctionSelector {
  let hash_result = keccak_bytes(&input.to_vec());
  let selector_bytes = &hash_result[..4];
  let selector = word32(selector_bytes);
  selector
}
