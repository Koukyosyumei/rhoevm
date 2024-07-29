use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fmt::Display;
use tiny_keccak::{Hasher, Keccak};

use crate::modules::types::{abi_keccak, pad_right, Addr, ByteString};

#[derive(Debug, Clone)]
pub struct Sig {
  pub method_signature: String,
  pub inputs: Vec<AbiType>,
}

impl Sig {
  pub fn new(method_signature: &str, inputs: &[AbiType]) -> Self {
    Self { method_signature: method_signature.to_string(), inputs: inputs.to_vec() }
  }
}

// Define AbiValue enum
#[derive(Debug, Clone)]
pub enum AbiValue {
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
pub enum AbiKind {
  Dynamic,
  Static,
}

// Define functions to determine AbiKind and AbiValueType
pub fn abi_kind(t: &AbiType) -> AbiKind {
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

pub fn abi_value_type(v: &AbiValue) -> AbiType {
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

// Deserialize the ABI JSON structure
#[derive(Deserialize, Debug)]
pub struct AbiEntry {
  #[serde(rename = "type")]
  pub abi_type: String,
  pub name: Option<String>,
  pub inputs: Option<Vec<AbiInputOutput>>,
  pub outputs: Option<Vec<AbiInputOutput>>,
}

#[derive(Deserialize, Debug)]
pub struct AbiInputOutput {
  #[serde(rename = "type")]
  pub abi_type: String,
  pub name: Option<String>,
}

impl AbiType {
  // Function to convert a Solidity type to AbiType
  pub fn from_solidity_type(sol_type: &str) -> Self {
    if let Some(size) = sol_type.strip_prefix("uint").and_then(|s| s.parse::<i32>().ok()) {
      AbiType::AbiUIntType(size)
    } else if let Some(size) = sol_type.strip_prefix("int").and_then(|s| s.parse::<i32>().ok()) {
      AbiType::AbiIntType(size)
    } else if sol_type == "address" {
      AbiType::AbiAddressType
    } else if sol_type == "bool" {
      AbiType::AbiBoolType
    } else if let Some(size) = sol_type.strip_prefix("bytes").and_then(|s| s.parse::<i32>().ok()) {
      AbiType::AbiBytesType(size)
    } else if sol_type == "bytes" {
      AbiType::AbiBytesDynamicType
    } else if sol_type == "string" {
      AbiType::AbiStringType
    } else if let Some(inner_type) = sol_type.strip_prefix("[]") {
      AbiType::AbiArrayDynamicType(Box::new(AbiType::from_solidity_type(inner_type)))
    } else if let Some((size_str, inner_type)) = sol_type.split_once('[') {
      if let Some(size) = size_str.parse::<i32>().ok() {
        let inner_type = inner_type.strip_suffix(']').unwrap_or(inner_type);
        AbiType::AbiArrayType(size, Box::new(AbiType::from_solidity_type(inner_type)))
      } else {
        AbiType::AbiBytesDynamicType // fallback
      }
    } else if sol_type == "function" {
      AbiType::AbiFunctionType
    } else if sol_type.starts_with("tuple") {
      let mut types = Vec::new();
      if let Some(inner_types) =
        sol_type.strip_prefix("tuple").and_then(|s| s.strip_prefix("(").and_then(|s| s.strip_suffix(")")))
      {
        for type_str in inner_types.split(",") {
          types.push(AbiType::from_solidity_type(type_str));
        }
      }
      AbiType::AbiTupleType(types)
    } else {
      panic!("Unknown Solidity type: {}", sol_type)
    }
  }
}

pub fn parse_abi_file(abi_json: &str) -> HashMap<String, Vec<AbiType>> {
  // Parse the ABI JSON
  let abi_entries: Vec<AbiEntry> = serde_json::from_str(abi_json).expect("Failed to parse ABI JSON");

  // Create a map from function/event names to their types
  let mut abi_map: HashMap<String, Vec<AbiType>> = HashMap::new();

  for entry in abi_entries {
    if let Some(name) = entry.name {
      let mut types = Vec::new();

      if let Some(inputs) = entry.inputs {
        for input in inputs {
          let abi_type = AbiType::from_solidity_type(&input.abi_type);
          types.push(abi_type);
        }
      }

      abi_map.insert(name, types);
    }
  }

  abi_map
}

// Implement parsing for each ABI type
fn parse_abi_value(abi_type: &AbiType, input: &Vec<u8>) -> AbiValue {
  todo!()
}

pub fn make_abi_value(typ: &AbiType, str: &String) -> AbiValue {
  let padded_str = match typ {
    AbiType::AbiBytesType(n) => pad_right(2 * (*n as usize) + 2, str.as_bytes().to_vec()),
    _ => str.as_bytes().to_vec(),
  };

  parse_abi_value(typ, &padded_str)
}

pub fn selector(s: &String) -> ByteString {
  let mut hasher = Keccak::v256();
  hasher.update(s.as_bytes());
  let mut output = [0u8; 32];
  hasher.finalize(&mut output);
  (output[..4]).to_vec()
}
