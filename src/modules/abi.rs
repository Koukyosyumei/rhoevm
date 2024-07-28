use byteorder::BigEndian;
use num_traits::ToBytes;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::fmt;
use std::fmt::Display;

use crate::modules::types::{abi_keccak, pad_right, word32, Addr, ByteString};

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

/*
parseAbiValue :: AbiType -> ReadP AbiValue
parseAbiValue (AbiUIntType n) = do W256 w <- readS_to_P reads
                                   pure $ AbiUInt n w
parseAbiValue (AbiIntType n) = do W256 w <- readS_to_P reads
                                  pure $ AbiInt n (unsafeInto w)
parseAbiValue AbiAddressType = AbiAddress <$> readS_to_P reads
parseAbiValue AbiBoolType = (do W256 w <- readS_to_P reads
                                pure $ AbiBool (w /= 0))
                            <|> (do Boolz b <- readS_to_P reads
                                    pure $ AbiBool b)
parseAbiValue (AbiBytesType n) = AbiBytes n <$> do ByteStringS bytes <- bytesP
                                                   pure bytes
parseAbiValue AbiBytesDynamicType = AbiBytesDynamic <$> do ByteStringS bytes <- bytesP
                                                           pure bytes
parseAbiValue AbiStringType = AbiString <$> do Char8.pack <$> readS_to_P reads
parseAbiValue (AbiArrayDynamicType typ) =
  AbiArrayDynamic typ <$> do a <- listP (parseAbiValue typ)
                             pure $ Vector.fromList a
parseAbiValue (AbiArrayType n typ) =
  AbiArray n typ <$> do a <- listP (parseAbiValue typ)
                        pure $ Vector.fromList a
parseAbiValue (AbiTupleType _) = internalError "tuple types not supported"
parseAbiValue AbiFunctionType = AbiFunction <$> do ByteStringS
*/

// Implement parsing for each ABI type
fn parse_abi_value(abi_type: &AbiType, input: &Vec<u8>) -> AbiValue {
  todo!()
  /*
  match abi_type {
    AbiType::AbiUIntType(n) => AbiValue::AbiUInt(*n, word32(input)),

    AbiType::AbiIntType(n) => AbiValue::AbiInt(*n, word32(input) as i32),

    AbiType::AbiAddressType => AbiValue::AbiAddress(hex::encode(input)),

    AbiType::AbiBoolType => alt((
      map(be_u256, |w| AbiValue::AbiBool(w != BigUint::from(0u8))),
      map(take(1usize), |b: &[u8]| AbiValue::AbiBool(b[0] != 0)),
    ))(input),

    AbiType::AbiBytesType(n) => map(take(n), |bytes: &[u8]| AbiValue::AbiBytes(n, bytes.to_vec()))(input),

    AbiType::AbiBytesDynamicType => {
      length_data(be_u256)(input).map(|(remaining, bytes)| (remaining, AbiValue::AbiBytesDynamic(bytes.to_vec())))
    }

    AbiType::AbiStringType => map(digit1, |s: &str| AbiValue::AbiString(s.to_string()))(input),

    AbiType::AbiArrayDynamicType(boxed_type) => length_data(be_u256)(input).and_then(|(remaining, data)| {
      let mut items = Vec::new();
      let mut slice = data;

      while !slice.is_empty() {
        let (rest, item) = parse_abi_value(*boxed_type.clone(), slice)?;
        slice = rest;
        items.push(item);
      }

      Ok((remaining, AbiValue::AbiArrayDynamic(boxed_type, items)))
    }),

    AbiType::AbiArrayType(n, boxed_type) => {
      let mut items = Vec::new();
      let mut slice = input;

      for _ in 0..n {
        let (rest, item) = parse_abi_value(*boxed_type.clone(), slice)?;
        slice = rest;
        items.push(item);
      }

      Ok((slice, AbiValue::AbiArray(n, boxed_type, items)))
    }

    AbiType::AbiTupleType(_) => {
      // Tuples are currently not supported
      Err(nom::Err::Error((input, nom::error::ErrorKind::Tag)))
    }

    AbiType::AbiFunctionType => map(take(4usize), |bytes: &[u8]| AbiValue::AbiFunction(bytes.to_vec()))(input),
  }*/
}

pub fn make_abi_value(typ: &AbiType, str: &String) -> AbiValue {
  let padded_str = match typ {
    AbiType::AbiBytesType(n) => pad_right(2 * (*n as usize) + 2, str.as_bytes().to_vec()),
    _ => str.as_bytes().to_vec(),
  };

  parse_abi_value(typ, &padded_str)
}

pub fn selector(s: &String) -> ByteString {
  let utf8_encoded = s.as_bytes();
  let hashed_s = abi_keccak(utf8_encoded);
  hashed_s.to_le_bytes().to_vec()
}

/*
makeAbiValue :: AbiType -> String -> AbiValue
makeAbiValue typ str = case readP_to_S (parseAbiValue typ) (padStr str) of
  [(val,"")] -> val
  _ -> internalError $ "could not parse abi argument: " ++ str ++ " : " ++ show typ
  where
    padStr = case typ of
      (AbiBytesType n) -> padRight' (2 * n + 2) -- +2 is for the 0x prefix
      _ -> id

selector :: Text -> BS.ByteString
selector s = BSLazy.toStrict . runPut $
  putWord32be (abiKeccak (encodeUtf8 s)).unFunctionSelector
*/

/*
fn selector(s: &str) -> Vec<u8> {
    // Step 1: UTF-8 encode the input string
    let utf8_encoded = s.as_bytes();

    // Step 2: Compute the Keccak256 hash
    let mut hasher = Keccak256::new();
    hasher.update(utf8_encoded);
    let hash_result = hasher.finalize();

    // Step 3: Retrieve the function selector (first 4 bytes)
    let mut selector_bytes = [0u8; 4];
    selector_bytes.copy_from_slice(&hash_result[..4]);

    // Step 4: Convert the function selector to a 32-bit word in big-endian format
    let mut cursor = Cursor::new(Vec::new());
    cursor.write_u32::<BigEndian>(u32::from_be_bytes(selector_bytes)).unwrap();

    // Return the serialized bytes
    cursor.into_inner()
}
*/
