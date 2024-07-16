use hex::decode;
use serde::{Deserialize, Serialize};
use serde_json::{from_str, json, Value};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::process::Command;
use std::str;

use crate::modules::abi::AbiType;
use crate::modules::evm::{abi_keccak, hashcode, keccak, keccak_prime};
use crate::modules::types::{
  Addr, BaseState, Contract, ContractCode, Expr, Gas, Prop, RuntimeCodeStruct, VMOpts, VM, W256,
};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StorageItem {
  slot_type: SlotType,
  offset: i32,
  slot: i32,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
enum SlotType {
  #[serde(rename = "StorageMapping")]
  StorageMapping(Vec<AbiType>, AbiType),

  #[serde(rename = "StorageValue")]
  StorageValue(AbiType),
  // Uncomment if needed
  // #[serde(rename = "StorageArray")]
  // StorageArray(AbiType),
}

impl Default for SlotType {
  fn default() -> Self {
    SlotType::StorageValue(AbiType::default())
  }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SolcContract {
  runtime_codehash: W256,
  creation_codehash: W256,
  runtime_code: Vec<u8>,
  creation_code: Vec<u8>,
  contract_name: String,
  constructor_inputs: Vec<(String, AbiType)>,
  abi_map: HashMap<String, Method>,
  event_map: HashMap<W256, Event>,
  error_map: HashMap<W256, SolError>,
  immutable_references: HashMap<W256, Vec<Reference>>,
  storage_layout: Option<HashMap<String, StorageItem>>,
  runtime_srcmap: Vec<SrcMap>,
  creation_srcmap: Vec<SrcMap>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Method {
  output: Vec<(String, AbiType)>,
  inputs: Vec<(String, AbiType)>,
  name: String,
  method_signature: String,
  mutability: Mutability,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Mutability {
  Pure,
  View,
  NonPayable,
  Payable,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Contracts(HashMap<String, SolcContract>);

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Asts(HashMap<String, Value>);

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
struct SrcFile {
  id: i32,
  filepath: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Sources(HashMap<SrcFile, Option<Vec<u8>>>);

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct BuildOutput {
  contracts: Contracts,
  sources: SourceCache,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
enum ProjectType {
  DappTools,
  CombinedJSON,
  Foundry,
  FoundryStdLib,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SourceCache {
  files: HashMap<i32, (String, Vec<u8>)>,
  lines: HashMap<i32, Vec<Vec<u8>>>,
  asts: HashMap<String, Value>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Reference {
  start: i32,
  length: i32,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
enum JumpType {
  JumpInto,
  JumpFrom,
  JumpRegular,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SrcMap {
  offset: i32,
  length: i32,
  file: i32,
  jump: JumpType,
  modifier_depth: i32,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Event; // Placeholder for Event, replace with actual type

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SolError; // Placeholder for SolError, replace with actual type

impl Default for AbiType {
  fn default() -> Self {
    AbiType::AbiUIntType(0)
  }
}

struct StorageLayout {
  // Define your storage layout fields
}

struct ImmutableReferences {
  // Define your immutable references fields
}

fn line_subrange(xs: &Vec<Vec<u8>>, (s1, n1): (usize, usize), i: usize) -> Option<(usize, usize)> {
  let ks: Vec<usize> = xs.iter().map(|x| 1 + x.len()).collect();
  let s2 = ks.iter().take(i).sum::<usize>();
  let n2 = ks.get(i).cloned().unwrap_or(0);

  if s1 + n1 < s2 || s1 > s2 + n2 {
    None
  } else {
    Some((s1 - s2, std::cmp::min(s2 + n2 - s1, n1)))
  }
}

fn read_solc(pt: ProjectType, root: &str, fp: &str) -> Result<BuildOutput, String> {
  let file_contents = fs::read_to_string(fp).map_err(|e| format!("Failed to read file: {}", e))?;
  let contract_name = fp.rsplit('/').next().unwrap_or("").to_string();

  match read_json(pt, &contract_name, &file_contents) {
    None => Err(format!("Unable to parse {} project JSON: {}", pt, fp)),
    Some((contracts, asts, sources)) => {
      let source_cache = make_source_cache(root, &sources, &asts);
      Ok(BuildOutput::Success(contracts, source_cache))
    }
  }
}

fn yul(contract_name: &str, src: &str) -> Option<Vec<u8>> {
  let json: Value = from_str(&solc(Language::Yul, src).unwrap()).unwrap();
  let f = json["contracts"]["hevm.sol"][contract_name];
  let bytecode = f["evm"]["bytecode"]["object"].as_str()?.as_bytes().to_vec();
  Some(to_code(contract_name, &bytecode))
}

fn yul_runtime(contract_name: &str, src: &str) -> Option<Vec<u8>> {
  let json: Value = from_str(&solc(Language::Yul, src).unwrap()).unwrap();
  let f = json["contracts"]["hevm.sol"][contract_name];
  let bytecode = f["evm"]["deployedBytecode"]["object"].as_str()?.as_bytes().to_vec();
  Some(to_code(contract_name, &bytecode))
}

fn solidity(contract: &str, src: &str) -> Option<Vec<u8>> {
  let json = solc(Language::Solidity, src).unwrap();
  let (contracts, _, _) = read_std_json(&json)?;
  contracts.get(&format!("hevm.sol:{}", contract)).map(|contract| contract.creation_code.clone())
}

fn solc_runtime(contract: &str, src: &str) -> Option<Vec<u8>> {
  let json = solc(Language::Solidity, src).unwrap();
  let (contracts, _, _) = read_std_json(&json)?;
  contracts.get(&format!("hevm.sol:{}", contract)).map(|contract| contract.runtime_code.clone())
}

fn function_abi(f: &str) -> Result<Method, String> {
  let json = solc(
    Language::Solidity,
    &format!("contract ABI {{ function {} public {{}}}}", f),
  )?;
  let (contracts, _, _) = read_std_json(&json)?;
  contracts
    .get("hevm.sol:ABI")
    .and_then(|contract| contract.abi_map.get(f).cloned())
    .ok_or_else(|| "Unexpected abi format".to_string())
}

fn force<T>(s: &str, maybe_a: Option<T>) -> T {
  maybe_a.unwrap_or_else(|| panic!("{}", s))
}

fn read_json(pt: ProjectType, contract_name: &str, json: &str) -> Option<(Contracts, Asts, Sources)> {
  match pt {
    ProjectType::DappTools => read_std_json(json),
    ProjectType::CombinedJSON => read_combined_json(json),
    _ => read_foundry_json(contract_name, json),
  }
}

fn read_foundry_json(contract_name: &str, json: &str) -> Option<(Contracts, Asts, Sources)> {
  let json: Value = serde_json::from_str(json).ok()?;
  let runtime = json["deployedBytecode"].to_owned();
  let runtime_code = to_code(contract_name, &runtime["object"].as_str()?.as_bytes().to_vec());
  let runtime_src_map = make_src_maps(runtime["sourceMap"].as_str()?);

  let creation = json["bytecode"].to_owned();
  let creation_code = to_code(contract_name, &creation["object"].as_str()?.as_bytes().to_vec());
  let creation_src_map = make_src_maps(creation["sourceMap"].as_str()?);

  let ast = json["ast"].to_owned();
  let path = ast["absolutePath"].as_str()?.to_string();

  let abi = json["abi"].as_array()?.to_vec();
  let id = json["id"].as_u64()? as u32;

  let contract = SolcContract {
    runtime_code,
    creation_code,
    runtime_codehash: keccak(strip_bytecode_metadata(&runtime_code)),
    creation_codehash: keccak(strip_bytecode_metadata(&creation_code)),
    runtime_srcmap: runtime_src_map,
    creation_srcmap: creation_src_map,
    contract_name: format!("{}:{}", path, contract_name),
    constructor_inputs: mk_constructor(&abi),
    abi_map: mk_abi_map(&abi),
    event_map: mk_event_map(&abi),
    error_map: mk_error_map(&abi),
    storage_layout: mk_storage_layout(ast["storageLayout"].as_str()?),
    immutable_references: None, // TODO: foundry doesn't expose this?
  };

  let contracts = Contracts(vec![(format!("{}:{}", path, contract_name), contract)].into_iter().collect());
  let asts = Asts(vec![(path, ast)].into_iter().collect());
  let sources = Sources(vec![(SrcFile { id: id, filepath: path }, None)].into_iter().collect());

  Some((contracts, asts, sources))
}

fn read_std_json(json: &str) -> Option<(Contracts, Asts, Sources)> {
  let json: Value = serde_json::from_str(json).ok()?;
  let contracts = json["contracts"].as_object()?;
  let sources = json["sources"].as_object()?;

  let asts = sources.iter().map(|(src, _)| (src.clone(), json["ast"][src].to_owned())).collect();

  let contract_map = contracts
    .iter()
    .flat_map(|(s, x)| {
      let evm_stuff = x["evm"].to_owned();
      let sc = format!("{}:{}", s, x.keys().next().unwrap());
      let runtime_code = to_code(
        &sc,
        &evm_stuff["deployedBytecode"]["object"].as_str()?.as_bytes().to_vec(),
      );
      let creation_code = to_code(&sc, &evm_stuff["bytecode"]["object"].as_str()?.as_bytes().to_vec());
      let src_contents = x["metadata"]["sources"].as_object().map(|srcs| {
        srcs.iter().map(|(src, content)| (src.clone(), content["content"].as_str()?.to_string())).collect()
      });
      let abis = x["abi"].as_array()?.to_vec();

      Some((
        sc.clone(),
        (
          SolcContract {
            runtime_code: Some(runtime_code.clone()),
            creation_code: Some(creation_code.clone()),
            runtime_codehash: Some(keccak(&strip_bytecode_metadata(&runtime_code))),
            creation_codehash: Some(keccak(&strip_bytecode_metadata(&creation_code))),
            runtime_srcmap: make_src_maps(evm_stuff["sourceMap"].as_str()?),
            creation_srcmap: make_src_maps(evm_stuff["sourceMap"].as_str()?),
            contract_name: sc,
            constructor_inputs: mk_constructor(&abis),
            abi_map: mk_abi_map(&abis),
            event_map: mk_event_map(&abis),
            error_map: mk_error_map(&abis),
            storage_layout: mk_storage_layout(x["storageLayout"].as_str()?),
            immutable_references: None,
          },
          src_contents,
        ),
      ))
    })
    .collect();

  Some((
    Contracts(contract_map),
    Asts(asts),
    Sources(vec![].into_iter().collect()),
  ))
}

fn read_combined_json(json: &str) -> Option<(Contracts, Asts, Sources)> {
  let json: Value = serde_json::from_str(json).ok()?;
  let contracts = json["contracts"].as_object()?;
  let sources = json["sourceList"].as_array()?.iter().filter_map(|s| s.as_str()).collect();
  let asts = sources.iter().map(|src| (src.to_string(), json["sources"][src].to_owned())).collect();

  let contract_map = contracts
    .iter()
    .map(|(s, x)| {
      let runtime_code = to_code(s, &x["bin-runtime"].as_str()?.as_bytes().to_vec());
      let creation_code = to_code(s, &x["bin"].as_str()?.as_bytes().to_vec());
      let abis = x["abi"].as_array()?.to_vec();

      (
        s.clone(),
        SolcContract {
          runtime_code: Some(runtime_code.clone()),
          creation_code: Some(creation_code.clone()),
          runtime_codehash: Some(keccak(&strip_bytecode_metadata(&runtime_code))),
          creation_codehash: Some(keccak(&strip_bytecode_metadata(&creation_code))),
          runtime_srcmap: make_src_maps(x["srcmap-runtime"].as_str()?),
          creation_srcmap: make_src_maps(x["srcmap"].as_str()?),
          contract_name: s.clone(),
          constructor_inputs: mk_constructor(&abis),
          abi_map: mk_abi_map(&abis),
          event_map: mk_event_map(&abis),
          error_map: mk_error_map(&abis),
          storage_layout: mk_storage_layout(x["storage-layout"].as_str()?),
          immutable_references: None,
        },
      )
    })
    .collect();

  Some((
    Contracts(contract_map),
    Asts(asts),
    Sources(vec![].into_iter().collect()),
  ))
}

enum Language {
  Solidity,
  Yul,
}

fn solc(lang: Language, src: &str) -> io::Result<String> {
  let stdjson = stdjson(lang, src)?;
  let output = Command::new("solc").arg("--standard-json").arg(&stdjson).output()?;

  let stdout = String::from_utf8(output.stdout)?;
  Ok(stdout)
}

fn stdjson(lang: Language, src: &str) -> io::Result<String> {
  let json_obj = match lang {
    Language::Solidity => {
      json!({
          "language": "Solidity",
          "sources": {
              "contract.sol": {
                  "content": src
              }
          },
          "settings": {
              "outputSelection": {
                  "*": {
                      "*": ["*"]
                  }
              }
          }
      })
    }
    Language::Yul => {
      json!({
          "language": "Yul",
          "sources": {
              "contract.yul": {
                  "content": src
              }
          },
          "settings": {
              "outputSelection": {
                  "*": {
                      "*": ["*"]
                  }
              }
          }
      })
    }
  };

  Ok(json_obj.to_string())
}

#[derive(Debug)]
struct ToCodeError {
  message: String,
}

impl fmt::Display for ToCodeError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.message)
  }
}

impl Error for ToCodeError {}

fn to_code(contract_name: &str, t: &str) -> Result<Vec<u8>, ToCodeError> {
  match decode(t) {
    Ok(d) => Ok(d),
    Err(_) => {
      if contains_linker_hole(t) {
        Err(ToCodeError {
          message: format!(
            "Error toCode: unlinked libraries detected in bytecode, in {}",
            contract_name
          ),
        })
      } else {
        Err(ToCodeError {
          message: format!("Error toCode: decoding error, in {}", contract_name),
        })
      }
    }
  }
}

fn contains_linker_hole(t: &str) -> bool {
  // Implement your logic to check for linker holes here
  // For demonstration purposes, always return false
  false
}

fn make_src_maps(source_map: &str) -> Option<HashMap<String, String>> {
  // Implementation of your make_src_maps function
  unimplemented!();
}

fn strip_bytecode_metadata(bytecode: &[u8]) -> &[u8] {
  // Implementation of your strip_bytecode_metadata function
  unimplemented!();
}

fn mk_constructor(abis: &[Value]) -> Option<Vec<Method>> {
  // Implementation of your mk_constructor function
  unimplemented!();
}

fn mk_abi_map(abis: &[Value]) -> Option<HashMap<String, Method>> {
  // Implementation of your mk_abi_map function
  unimplemented!();
}

fn mk_event_map(abis: &[Value]) -> Option<HashMap<String, Method>> {
  // Implementation of your mk_event_map function
  unimplemented!();
}

fn mk_error_map(abis: &[Value]) -> Option<HashMap<String, Method>> {
  // Implementation of your mk_error_map function
  unimplemented!();
}

fn mk_storage_layout(storage_layout: &str) -> Option<StorageLayout> {
  // Implementation of your mk_storage_layout function
  unimplemented!();
}
