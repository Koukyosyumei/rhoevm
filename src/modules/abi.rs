use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fmt::Display;

use crate::modules::types::Addr;

#[derive(Debug, Clone)]
pub struct Sig {
  method_signature: String,
  inputs: Vec<String>,
}

impl Sig {
  pub fn new(method_signature: &str, inputs: &[String]) -> Self {
    Self {
      method_signature: method_signature.to_string(),
      inputs: inputs.to_vec(),
    }
  }
}

// Define AbiValue enum
#[derive(Debug, Clone)]
enum AbiValue {
  AbiUInt(i32, u32),
  AbiInt(i32, i32),
  AbiAddress(Addr),
  AbiBool(bool),
  AbiBytes(i32, Vec<u8>),
  AbiBytesDynamic(Vec<u8>),
  AbiString(Vec<u8>),
  AbiArrayDynamic(AbiType, Vec<AbiValue>),
  AbiArray(i32, AbiType, Vec<AbiValue>),
  AbiTuple(Vec<AbiValue>),
  AbiFunction(Vec<u8>),
}

// Implement Display for AbiValue
impl Display for AbiValue {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      AbiValue::AbiUInt(_, n) => write!(f, "{}", n),
      AbiValue::AbiInt(_, n) => write!(f, "{}", n),
      AbiValue::AbiAddress(n) => write!(f, "{}", n),
      AbiValue::AbiBool(b) => write!(f, "{}", if *b { "true" } else { "false" }),
      AbiValue::AbiBytes(_, b) => write!(f, "{:?}", b),
      AbiValue::AbiBytesDynamic(b) => write!(f, "{:?}", b),
      AbiValue::AbiString(s) => write!(f, "{}", String::from_utf8_lossy(s)),
      AbiValue::AbiArrayDynamic(_, v) | AbiValue::AbiArray(_, _, v) => {
        let items: Vec<String> = v.iter().map(|item| item.to_string()).collect();
        write!(f, "[{}]", items.join(", "))
      }
      AbiValue::AbiTuple(v) => {
        let items: Vec<String> = v.iter().map(|item| item.to_string()).collect();
        write!(f, "({})", items.join(", "))
      }
      AbiValue::AbiFunction(b) => write!(f, "{:?}", b),
    }
  }
}

// Define AbiType enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AbiType {
  AbiUIntType(i32),
  AbiIntType(i32),
  AbiAddressType,
  AbiBoolType,
  AbiBytesType(i32),
  AbiBytesDynamicType,
  AbiStringType,
  AbiArrayDynamicType(Box<AbiType>),
  AbiArrayType(i32, Box<AbiType>),
  AbiTupleType(Vec<AbiType>),
  AbiFunctionType,
}

// Implement Display for AbiType
impl Display for AbiType {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      AbiType::AbiUIntType(n) => write!(f, "uint{}", n),
      AbiType::AbiIntType(n) => write!(f, "int{}", n),
      AbiType::AbiAddressType => write!(f, "address"),
      AbiType::AbiBoolType => write!(f, "bool"),
      AbiType::AbiBytesType(n) => write!(f, "bytes{}", n),
      AbiType::AbiBytesDynamicType => write!(f, "bytes"),
      AbiType::AbiStringType => write!(f, "string"),
      AbiType::AbiArrayDynamicType(t) => write!(f, "{}[]", t),
      AbiType::AbiArrayType(n, t) => write!(f, "{}[{}]", t, n),
      AbiType::AbiTupleType(ts) => {
        let items: Vec<String> = ts.iter().map(|t| t.to_string()).collect();
        write!(f, "({})", items.join(", "))
      }
      AbiType::AbiFunctionType => write!(f, "function"),
    }
  }
}

// Define AbiKind enum
#[derive(Debug, Clone, PartialEq)]
enum AbiKind {
  Dynamic,
  Static,
}

// Define functions to determine AbiKind and AbiValueType
fn abi_kind(t: &AbiType) -> AbiKind {
  match t {
    AbiType::AbiBytesDynamicType => AbiKind::Dynamic,
    AbiType::AbiStringType => AbiKind::Dynamic,
    AbiType::AbiArrayDynamicType(_) => AbiKind::Dynamic,
    AbiType::AbiArrayType(_, t) => abi_kind(t),
    AbiType::AbiTupleType(ts) => {
      if ts.iter().any(|t| abi_kind(t) == AbiKind::Dynamic) {
        AbiKind::Dynamic
      } else {
        AbiKind::Static
      }
    }
    _ => AbiKind::Static,
  }
}

fn abi_value_type(v: &AbiValue) -> AbiType {
  match v {
    AbiValue::AbiUInt(_, _) => AbiType::AbiUIntType(0),
    AbiValue::AbiInt(_, _) => AbiType::AbiIntType(0),
    AbiValue::AbiAddress(_) => AbiType::AbiAddressType,
    AbiValue::AbiBool(_) => AbiType::AbiBoolType,
    AbiValue::AbiBytes(_, _) => AbiType::AbiBytesType(0),
    AbiValue::AbiBytesDynamic(_) => AbiType::AbiBytesDynamicType,
    AbiValue::AbiString(_) => AbiType::AbiStringType,
    AbiValue::AbiArrayDynamic(t, _) => AbiType::AbiArrayDynamicType(Box::new(t.clone())),
    AbiValue::AbiArray(n, t, _) => AbiType::AbiArrayType(*n, Box::new(t.clone())),
    AbiValue::AbiTuple(v) => AbiType::AbiTupleType(v.iter().map(abi_value_type).collect()),
    AbiValue::AbiFunction(_) => AbiType::AbiFunctionType,
  }
}
