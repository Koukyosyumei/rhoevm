use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::Debug;
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

trait ExprTraitClone<T> {
  fn clone_box(&self) -> Box<dyn ExprTrait<T>>;
}

pub trait ExprTrait<T: ETypeTrait>: ExprTraitClone<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Expr")
  }
}

impl<T: ETypeTrait, U> ExprTraitClone<T> for U
where
  U: 'static + ExprTrait<T> + Clone,
{
  fn clone_box(&self) -> Box<dyn ExprTrait<T>> {
    Box::new(self.clone())
  }
}

impl<T> Clone for Box<dyn ExprTrait<T>> {
  fn clone(&self) -> Box<dyn ExprTrait<T>> {
    self.clone_box()
  }
}

impl Debug for dyn ExprTrait<EWord> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ExprTrait<EWord>")
  }
}
impl fmt::Display for dyn ExprTrait<EWord> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ExprTrait<EWord>")
  }
}
impl PartialEq for dyn ExprTrait<EWord> {
  fn eq(&self, other: &Self) -> bool {
    return true;
  }
}
impl PartialEq for dyn ExprTrait<EAddr> {
  fn eq(&self, other: &Self) -> bool {
    return true;
  }
}
impl Eq for dyn ExprTrait<EWord> {}
impl Eq for dyn ExprTrait<EAddr> {}
impl Hash for dyn ExprTrait<EWord> {
  fn hash<H: Hasher>(&self, state: &mut H) {}
}
impl Hash for dyn ExprTrait<EAddr> {
  fn hash<H: Hasher>(&self, state: &mut H) {}
}

impl ExprTraitClone<EWord> for Box<dyn ExprTrait<EWord>> {
  fn clone_box(&self) -> Box<dyn ExprTrait<EWord>> {
    self.clone()
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExprLit {
  pub value: W256,
}
impl ExprTrait<EWord> for ExprLit {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Lit {}", self.value)
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExprVar {
  pub name: String,
}
impl ExprTrait<EWord> for ExprVar {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Var {}", self.name)
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExprLitAddr {
  pub addr: Addr,
}
impl ExprTrait<EAddr> for ExprLitAddr {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "LitAddr {}", self.addr)
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExprMempty;
impl ExprTrait<Buf> for ExprMempty {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Mempty")
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExprConcreteBuf {
  pub buf: Vec<u8>,
}
impl ExprTrait<Buf> for ExprConcreteBuf {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ConcreteBuf")
  }
}

///
#[derive(Debug, Clone)]
pub struct ExprBinOp {
  pub op: String,
  pub left: Box<dyn ExprTrait<EWord>>,
  pub right: Box<dyn ExprTrait<EWord>>,
}
impl ExprTrait<EWord> for ExprBinOp {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "BinOp ({}) {} ({})", self.left, self.op, self.right)
  }
}

// Propositions -----------------------------------------------------------------------------------
#[derive(Clone)]
enum Prop {
  PEq(Box<dyn ExprTrait<EWord>>),
  PLT(Box<dyn ExprTrait<EWord>>, Box<dyn ExprTrait<EWord>>),
  PGT(Box<dyn ExprTrait<EWord>>, Box<dyn ExprTrait<EWord>>),
  PGEq(Box<dyn ExprTrait<EWord>>, Box<dyn ExprTrait<EWord>>),
  PLEq(Box<dyn ExprTrait<EWord>>, Box<dyn ExprTrait<EWord>>),
  PNeg(Box<Prop>),
  PAnd(Box<Prop>, Box<Prop>),
  POr(Box<Prop>, Box<Prop>),
  PImpl(Box<Prop>, Box<Prop>),
  PBool(bool),
}

// Errors -----------------------------------------------------------------------------------------
enum EvmError {
  BalanceTooLow(Box<dyn ExprTrait<EWord>>, Box<dyn ExprTrait<EWord>>),
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
  MaxInitCodeSizeExceeded(u32, Box<dyn ExprTrait<EWord>>),
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
  EventTrace(
    Box<dyn ExprTrait<EWord>>,
    Box<dyn ExprTrait<Buf>>,
    Vec<Box<dyn ExprTrait<EWord>>>,
  ),
  FrameTrace(FrameContext),
  ErrorTrace(EvmError),
  EntryTrace(String),
  ReturnTrace(Box<dyn ExprTrait<Buf>>, FrameContext),
}

#[derive(Clone)]
pub struct Contract {
  pub code: ContractCode,
  pub storage: Box<dyn ExprTrait<Storage>>,
  pub orig_storage: Box<dyn ExprTrait<Storage>>,
  pub balance: Box<dyn ExprTrait<EWord>>,
  pub nonce: Option<W64>,
  pub codehash: Box<dyn ExprTrait<EWord>>,
  pub op_idx_map: Vec<i32>,
  pub external: bool,
}

#[derive(Clone)]
pub enum ContractCode {
  UnKnownCode(Box<dyn ExprTrait<EAddr>>),
  InitCode(Vec<u8>, Box<dyn ExprTrait<Buf>>),
  RuntimeCode(RuntimeCodeStruct),
}

#[derive(Clone)]
pub enum RuntimeCodeStruct {
  ConcreteRuntimeCode(Vec<u8>),
  SymbolicRuntimeCode(Vec<Box<dyn ExprTrait<Byte>>>),
}

// Define the Trace struct
pub struct Trace {
  op_ix: i32,           // Operation index
  contract: Contract,   // Contract associated with the trace
  tracedata: TraceData, // Data associated with the trace
}

// Define TraceContext struct
struct TraceContext {
  traces: Vec<Trace>, // Assuming Trace is a suitable type like struct Trace;
  contracts: HashMap<Box<dyn ExprTrait<EWord>>, Contract>, // Using HashMap for contracts
  labels: HashMap<Addr, String>, // Using HashMap for labels
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
  SymbolicMemory(Box<dyn ExprTrait<Buf>>),
}

// The "registers" of the VM along with memory and data stack
pub struct FrameState {
  pub contract: Box<dyn ExprTrait<EAddr>>,
  pub code_contract: Box<dyn ExprTrait<EAddr>>,
  pub code: ContractCode,
  pub pc: i32,
  pub stack: Vec<Box<dyn ExprTrait<EWord>>>,
  pub memory: Memory,
  pub memory_size: u64,
  pub calldata: Box<dyn ExprTrait<Buf>>,
  pub callvalue: Box<dyn ExprTrait<EWord>>,
  pub caller: Box<dyn ExprTrait<EAddr>>,
  pub gas: Gas,
  pub returndata: Box<dyn ExprTrait<Buf>>,
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
  pub logs: Vec<Box<dyn ExprTrait<Log>>>,
  // pub traces: TreePos<Trace>,
  pub cache: Cache,
  pub burned: Gas,
  pub constraints: Vec<Prop>,
  pub config: RuntimeConfig,
  pub iterations: HashMap<i64, Vec<Box<dyn ExprTrait<EWord>>>>,
  pub forks: Vec<ForkState>,
  pub current_fork: i32,
  pub labels: HashMap<Addr, String>,
}

type CodeLocation = (Box<dyn ExprTrait<EAddr>>, i64);

pub struct Cache {
  pub fetched: HashMap<Addr, Contract>,
  pub path: HashMap<(CodeLocation, i64), bool>,
}

pub enum FrameContext {
  CreationContext {
    address: Box<dyn ExprTrait<EAddr>>,
    codehash: Box<dyn ExprTrait<EWord>>,
    createversion: HashMap<Box<dyn ExprTrait<EAddr>>, Contract>,
    substate: SubState,
  },
  CallCOntext {
    target: Box<dyn ExprTrait<EAddr>>,
    context: Box<dyn ExprTrait<EAddr>>,
    offset: Box<dyn ExprTrait<EWord>>,
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
  pub override_caller: Option<Box<dyn ExprTrait<EAddr>>>,
  pub reset_caller: bool,
  pub base_state: BaseState,
}

pub enum VMResult {
  Unfinished,
  VMFailure(EvmError),
  VMSuccess(Box<dyn ExprTrait<Buf>>),
  HandleEffect,
}

// Various environmental data
pub struct Env {
  pub contracts: HashMap<Box<dyn ExprTrait<EAddr>>, Contract>,
  pub chain_id: W256,
  pub fresh_address: i32,
  pub fresh_gas_vals: i32,
}

// DData about the block
pub struct Block {
  pub coinbase: Box<dyn ExprTrait<EAddr>>,
  pub timestamp: Box<dyn ExprTrait<EWord>>,
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
  pub origin: Box<dyn ExprTrait<EAddr>>,
  pub to_addr: Box<dyn ExprTrait<EAddr>>,
  pub value: Box<dyn ExprTrait<EWord>>,
  pub substate: SubState,
  pub is_create: bool,
  pub tx_reversion: HashMap<Box<dyn ExprTrait<EAddr>>, Contract>,
}

pub struct SubState {
  pub selfdestructs: Vec<Box<dyn ExprTrait<EAddr>>>,
  pub touched_accounts: Vec<Box<dyn ExprTrait<EAddr>>>,
  pub accessed_addresses: HashSet<Box<dyn ExprTrait<EAddr>>>,
  pub accessed_storage_keys: HashSet<(Box<dyn ExprTrait<EAddr>>, Word64)>,
  pub refunds: Vec<(Box<dyn ExprTrait<EAddr>>, Word64)>,
}

pub struct VMOpts {
  pub contract: Contract,
  pub other_contracts: Vec<(Box<dyn ExprTrait<EAddr>>, Contract)>,
  pub calldata: (Box<dyn ExprTrait<Buf>>, Vec<Prop>),
  pub base_state: BaseState,
  pub value: Box<dyn ExprTrait<EWord>>,
  pub priority_fee: W256,
  pub address: Box<dyn ExprTrait<EAddr>>,
  pub caller: Box<dyn ExprTrait<EAddr>>,
  pub origin: Box<dyn ExprTrait<EAddr>>,
  pub gas: Gas,
  pub gaslimit: Word64,
  pub number: W256,
  pub timestamp: Box<dyn ExprTrait<EWord>>,
  pub coinbase: Box<dyn ExprTrait<EAddr>>,
  pub prev_randao: W256,
  pub max_code_size: W256,
  pub block_gaslimit: Word64,
  pub gasprice: W256,
  pub base_fee: W256,
  pub schedule: FeeSchedule<Word64>,
  pub chain_id: W256,
  pub create: bool,
  pub tx_access_list: HashMap<Box<dyn ExprTrait<EAddr>>, Vec<W256>>,
  pub allow_ffi: bool,
}

pub struct ForkState {
  pub env: Env,
  pub block: Block,
  pub cache: Cache,
  pub urlaor_alias: String,
}

/*
data ForkState = ForkState
  { env :: Env
  , block :: Block
  , cache :: Cache
  , urlOrAlias :: String
  }
  deriving (Show, Generic)

-- | The "accrued substate" across a transaction
data SubState = SubState
  { selfdestructs       :: [Expr EAddr]
  , touchedAccounts     :: [Expr EAddr]
  , accessedAddresses   :: Set (Expr EAddr)
  , accessedStorageKeys :: Set (Expr EAddr, W256)
  , refunds             :: [(Expr EAddr, Word64)]
  -- in principle we should include logs here, but do not for now
  }
  deriving (Eq, Ord, Show)

-- | The state that spans a whole transaction
data TxState = TxState
  { gasprice    :: W256
  , gaslimit    :: Word64
  , priorityFee :: W256
  , origin      :: Expr EAddr
  , toAddr      :: Expr EAddr
  , value       :: Expr EWord
  , substate    :: SubState
  , isCreate    :: Bool
  , txReversion :: Map (Expr EAddr) Contract
  }
  deriving (Show)

data Env = Env
  { contracts      :: Map (Expr EAddr) Contract
  , chainId        :: W256
  , freshAddresses :: Int
  , freshGasVals :: Int
  }
  deriving (Show, Generic)

data FrameContext
  = CreationContext
    { address         :: Expr EAddr
    , codehash        :: Expr EWord
    , createreversion :: Map (Expr EAddr) Contract
    , substate        :: SubState
    }
  | CallContext
    { target        :: Expr EAddr
    , context       :: Expr EAddr
    , offset        :: Expr EWord
    , size          :: Expr EWord
    , codehash      :: Expr EWord
    , abi           :: Maybe W256
    , calldata      :: Expr Buf
    , callreversion :: Map (Expr EAddr) Contract
    , subState      :: SubState
    }
  deriving (Eq, Ord, Show, Generic)

data Frame (t :: VMType) s = Frame
  { context :: FrameContext
  , state   :: FrameState t s
  }

deriving instance Show (Frame Symbolic s)
deriving instance Show (Frame Concrete s)

-- | The possible result states of a VM
data VMResult (t :: VMType) s where
  Unfinished :: PartialExec -> VMResult Symbolic s -- ^ Execution could not continue further
  VMFailure :: EvmError -> VMResult t s            -- ^ An operation failed
  VMSuccess :: (Expr Buf) -> VMResult t s          -- ^ Reached STOP, RETURN, or end-of-code
  HandleEffect :: (Effect t s) -> VMResult t s     -- ^ An effect must be handled for execution to continue

deriving instance Show (VMResult t s)

-- | The state of a stepwise EVM execution
data VM (t :: VMType) s = VM
  { result         :: Maybe (VMResult t s)
  , state          :: FrameState t s
  , frames         :: [Frame t s]
  , env            :: Env
  , block          :: Block
  , tx             :: TxState
  , logs           :: [Expr Log]
  , traces         :: Zipper.TreePos Zipper.Empty Trace
  , cache          :: Cache
  , burned         :: !(Gas t)
  , iterations     :: Map CodeLocation (Int, [Expr EWord])
  -- ^ how many times we've visited a loc, and what the contents of the stack were when we were there last
  , constraints    :: [Prop]
  , config         :: RuntimeConfig
  , forks          :: Seq ForkState
  , currentFork    :: Int
  , labels         :: Map Addr Text
  }
  deriving (Generic)
*/
