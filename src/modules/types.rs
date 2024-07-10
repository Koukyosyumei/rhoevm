use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::fmt::{self, write};
use std::hash::{Hash, Hasher};
use std::path::Display;
use std::vec::Vec;

#[path = "./etypes.rs"]
pub mod etypes;
pub use etypes::{Buf, Byte, EAddr, EContract, ETypeTrait, EWord, End, Log, Storage};

pub type Addr = u32;
pub type W64 = u8;
pub type W256 = u32;
pub type Int256 = i32;
pub type Nibble = i32;
pub type Word8 = u8;
pub type Word32 = u32;
pub type Word64 = u64;
pub type Word256 = u32;
pub type ByteString = Vec<u8>;
pub type FunctionSelector = u32;
pub type Word160 = u32;
pub type Word512 = u32;

fn truncate_to_addr(w: W256) -> Addr {
  w as Addr
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
  Success(Vec<Prop>, TraceContext, Box<Expr>, HashMap<Expr, Expr>),
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
  Gas(i32, Box<Expr>),

  // Code
  CodeSize(Box<Expr>),
  CodeHash(Box<Expr>),

  // Logs
  LogEntry(Box<Expr>, Box<Expr>, Vec<Expr>),

  // Contract
  Contract {
    code: ContractCode,
    storage: Box<Expr>,
    balance: Box<Expr>,
    nonce: Option<W64>,
  },

  // Addresses
  SymAddr(String),
  LitAddr(Addr),
  WAddr(Box<Expr>),

  // Storage
  ConcreteStore(HashMap<W256, W256>),
  AbstractStore(Box<Expr>, Option<W256>),

  SLoad(Box<Expr>, Box<Expr>),
  SStore(Box<Expr>, Box<Expr>, Box<Expr>, Box<Expr>),

  // Buffers
  ConcreteBuf(Vec<u8>),
  AbstractBuf(String),

  ReadWord(Box<Expr>, Box<Expr>),
  ReadByte(Box<Expr>, Box<Expr>),
  WriteWord(Box<Expr>, Box<Expr>, Box<Expr>),
  WriteByte(Box<Expr>, Box<Expr>, Box<Expr>),
  CopySlice(Box<Expr>, Box<Expr>, Box<Expr>, Box<Expr>, Box<Expr>),

  BufLength(Box<Expr>),
}

impl fmt::Display for Expr {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Expr::Mempty => write!(f, "Mempty"),
      Expr::Lit(val) => write!(f, "Lit({})", val),
      Expr::Var(name) => write!(f, "Var({})", name),
      Expr::GVar(gvar) => write!(f, "GVar({})", gvar),
      Expr::LitByte(val) => write!(f, "LitByte({})", val),
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
      Expr::Gas(idx, expr) => write!(f, "Gas({}, {})", idx, expr),
      Expr::CodeSize(expr) => write!(f, "CodeSize({})", expr),
      Expr::CodeHash(expr) => write!(f, "CodeHash({})", expr),
      Expr::LogEntry(addr, buf, topics) => write!(f, "LogEntry({}, {}, {:?})", addr, buf, topics),
      Expr::Contract {
        code,
        storage,
        balance,
        nonce,
      } => write!(
        f,
        "Contract {{ code: {:?}, storage: {}, balance: {}, nonce: {:?} }}",
        code, storage, balance, nonce
      ),
      Expr::SymAddr(name) => write!(f, "SymAddr({})", name),
      Expr::LitAddr(addr) => write!(f, "LitAddr({})", addr),
      Expr::WAddr(expr) => write!(f, "WAddr({})", expr),
      Expr::ConcreteStore(store) => write!(f, "ConcreteStore({:?})", store),
      Expr::AbstractStore(addr, key) => write!(f, "AbstractStore({}, {:?})", addr, key),
      Expr::SLoad(key, storage) => write!(f, "SLoad({}, {})", key, storage),
      Expr::SStore(key, value, old_storage, new_storage) => {
        write!(f, "SStore({}, {}, {}, {})", key, value, old_storage, new_storage)
      }
      Expr::ConcreteBuf(buf) => write!(f, "ConcreteBuf({:?})", buf),
      Expr::AbstractBuf(name) => write!(f, "AbstractBuf({})", name),
      Expr::ReadWord(index, src) => write!(f, "ReadWord({}, {})", index, src),
      Expr::ReadByte(index, src) => write!(f, "ReadByte({}, {})", index, src),
      Expr::WriteWord(dst, value, prev) => write!(f, "WriteWord({}, {}, {})", dst, value, prev),
      Expr::WriteByte(dst, value, prev) => write!(f, "WriteByte({}, {}, {})", dst, value, prev),
      Expr::CopySlice(src_offset, dst_offset, size, src, dst) => write!(
        f,
        "CopySlice({}, {}, {}, {}, {})",
        src_offset, dst_offset, size, src, dst
      ),
      Expr::BufLength(buf) => write!(f, "BufLength({})", buf),
    }
  }
}

// Propositions -----------------------------------------------------------------------------------
#[derive(Clone)]
enum Prop {
  PEq(Expr),
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
pub enum EvmError {
  BalanceTooLow(Box<Expr>, Box<Expr>),
  UnrecognizedOpcode(u8),
  SelfDestruction,
  StackUnderrun,
  BadJumpDestination,
  Revert(Box<Buf>),
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

pub enum TraceData {
  EventTrace(Expr, Expr, Vec<Expr>),
  FrameTrace(FrameContext),
  ErrorTrace(EvmError),
  EntryTrace(String),
  ReturnTrace(Expr, FrameContext),
}

#[derive(Clone)]
pub struct Contract {
  pub code: ContractCode,
  pub storage: Expr,
  pub orig_storage: Expr,
  pub balance: Expr,
  pub nonce: Option<W64>,
  pub codehash: Expr,
  pub op_idx_map: Vec<i32>,
  pub external: bool,
}

#[derive(Clone)]
pub enum ContractCode {
  UnKnownCode(Box<Expr>),
  InitCode(Vec<u8>, Box<Expr>),
  RuntimeCode(RuntimeCodeStruct),
}

#[derive(Clone)]
pub enum RuntimeCodeStruct {
  ConcreteRuntimeCode(Vec<u8>),
  SymbolicRuntimeCode(Vec<Expr>),
}

// Define the Trace struct
pub struct Trace {
  op_ix: i32,           // Operation index
  contract: Contract,   // Contract associated with the trace
  tracedata: TraceData, // Data associated with the trace
}

// Define TraceContext struct
struct TraceContext {
  traces: Vec<Trace>,                 // Assuming Trace is a suitable type like struct Trace;
  contracts: HashMap<Expr, Contract>, // Using HashMap for contracts
  labels: HashMap<Addr, String>,      // Using HashMap for labels
}

// Implement Monoid trait for TraceContext
impl Default for TraceContext {
  fn default() -> Self {
    TraceContext {
      traces: Vec::new(),
      contracts: HashMap::new(),
      labels: HashMap::new(),
    }
  }
}

pub enum Gas {
  Symbolic,
  Concerete(Word64),
}

type MutableMemory = Vec<u8>;
pub enum Memory {
  ConcreteMemory(MutableMemory),
  SymbolicMemory(Expr),
}

// The "registers" of the VM along with memory and data stack
pub struct FrameState {
  pub contract: Expr,
  pub code_contract: Expr,
  pub code: ContractCode,
  pub pc: i32,
  pub stack: Vec<Expr>,
  pub memory: Memory,
  pub memory_size: u64,
  pub calldata: Expr,
  pub callvalue: Expr,
  pub caller: Expr,
  pub gas: Gas,
  pub returndata: Expr,
  pub static_flag: bool,
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

pub struct VM {
  pub result: Option<VMResult>,
  pub state: FrameState,
  pub frames: Vec<Frame>,
  pub env: Env,
  pub block: Block,
  pub tx: TxState,
  pub logs: Vec<Expr>,
  // pub traces: TreePos<Trace>,
  pub cache: Cache,
  pub burned: Gas,
  pub constraints: Vec<Prop>,
  pub config: RuntimeConfig,
  pub iterations: HashMap<i64, Vec<Expr>>,
  pub forks: Vec<ForkState>,
  pub current_fork: i32,
  pub labels: HashMap<Addr, String>,
}

type CodeLocation = (Expr, i64);

pub struct Cache {
  pub fetched: HashMap<Addr, Contract>,
  pub path: HashMap<(CodeLocation, i64), bool>,
}

pub enum FrameContext {
  CreationContext {
    address: Expr,
    codehash: Expr,
    createversion: HashMap<Expr, Contract>,
    substate: SubState,
  },
  CallCOntext {
    target: Expr,
    context: Expr,
    offset: Expr,
  },
}

pub struct Frame {
  context: FrameContext,
  state: FrameState,
}

#[derive(Clone)]
pub enum BaseState {
  EmptyBase,
  AbstractBase,
}

pub struct RuntimeConfig {
  pub allow_ffi: bool,
  pub override_caller: Option<Expr>,
  pub reset_caller: bool,
  pub base_state: BaseState,
}

pub enum VMResult {
  Unfinished,
  VMFailure(EvmError),
  VMSuccess(Expr),
  HandleEffect,
}

// Various environmental data
#[derive(Clone)]
pub struct Env {
  pub contracts: HashMap<Expr, Contract>,
  pub chain_id: W256,
  pub fresh_address: i32,
  pub fresh_gas_vals: i32,
}

// DData about the block
#[derive(Clone)]
pub struct Block {
  pub coinbase: Expr,
  pub timestamp: Expr,
  pub number: W256,
  pub prev_randao: W256,
  pub gaslimit: Word64,
  pub base_fee: W256,
  pub max_code_size: W256,
  pub schedule: FeeSchedule<Word64>,
}

#[derive(Debug, Clone)]
pub struct FeeSchedule<T> {
  pub g_zero: T,
  pub g_base: T,
  pub g_verylow: T,
  pub g_low: T,
  pub g_mid: T,
  pub g_high: T,
  g_extcode: T,
  g_balance: T,
  g_sload: T,
  g_jumpdest: T,
  g_sset: T,
  g_sreset: T,
  r_sclear: T,
  g_selfdestruct: T,
  g_selfdestruct_newaccount: T,
  r_selfdestruct: T,
  g_create: T,
  g_codedeposit: T,
  g_call: T,
  g_callvalue: T,
  g_callstipend: T,
  g_newaccount: T,
  g_exp: T,
  g_expbyte: T,
  g_memory: T,
  g_txcreate: T,
  g_txdatazero: T,
  g_txdatanonzero: T,
  g_transaction: T,
  g_log: T,
  g_logdata: T,
  g_logtopic: T,
  g_sha3: T,
  g_sha3word: T,
  g_initcodeword: T,
  g_copy: T,
  g_blockhash: T,
  g_extcodehash: T,
  g_quaddivisor: T,
  g_ecadd: T,
  g_ecmul: T,
  g_pairing_point: T,
  g_pairing_base: T,
  g_fround: T,
  r_block: T,
  g_cold_sload: T,
  g_cold_account_access: T,
  g_warm_storage_read: T,
  g_access_list_address: T,
  g_access_list_storage_key: T,
}

pub struct TxState {
  pub gasprice: W256,
  pub gaslimit: Word64,
  pub priority_fee: W256,
  pub origin: Expr,
  pub to_addr: Expr,
  pub value: Expr,
  pub substate: SubState,
  pub is_create: bool,
  pub tx_reversion: HashMap<Expr, Contract>,
}

pub struct SubState {
  pub selfdestructs: Vec<Expr>,
  pub touched_accounts: Vec<Expr>,
  pub accessed_addresses: HashSet<Expr>,
  pub accessed_storage_keys: HashSet<(Expr, W256)>,
  pub refunds: Vec<(Expr, Word64)>,
}

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
  pub timestamp: Expr,
  pub coinbase: Expr,
  pub prev_randao: W256,
  pub max_code_size: W256,
  pub block_gaslimit: Word64,
  pub gasprice: W256,
  pub base_fee: W256,
  pub schedule: FeeSchedule<Word64>,
  pub chain_id: W256,
  pub create: bool,
  pub tx_access_list: HashMap<Expr, Vec<W256>>,
  pub allow_ffi: bool,
}

pub struct ForkState {
  pub env: Env,
  pub block: Block,
  pub cache: Cache,
  pub urlaor_alias: String,
}

pub enum PartialExec {
  UnexpectedSymbolicArg,
  MaxIterationsReached,
  JumpIntoSymbolicCode,
}

/*

data PartialExec
  = UnexpectedSymbolicArg { pc :: Int, msg  :: String, args  :: [SomeExpr] }
  | MaxIterationsReached  { pc :: Int, addr :: Expr EAddr }
  | JumpIntoSymbolicCode  { pc :: Int, jumpDst :: Int }
  deriving (Show, Eq, Ord)
*/
