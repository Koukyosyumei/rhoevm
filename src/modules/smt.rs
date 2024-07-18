use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::str::FromStr;
use std::{fmt, vec};

use futures::sink::Buffer;
use futures::Future;

use crate::modules::cse::{eliminate_props, BufEnv, StoreEnv};
use crate::modules::effects::Config;
use crate::modules::evm::buf_length;
use crate::modules::expr::{add, conc_keccak_props, in_range, sub, write_byte};
use crate::modules::keccak::{keccak_assumptions, keccak_compute};
use crate::modules::traversals::{map_prop_m, TraversableTerm};
use crate::modules::types::{Addr, Block, Expr, Frame, FrameContext, GVar, Prop, W256W256Map, W256};

use super::etypes::Buf;

// Type aliases for convenience
type Text = String;
type Builder = String; // Placeholder for Builder

// BuilderState struct
#[derive(Debug, Default)]
struct BuilderState {
  calldata: Vec<Text>,
  addrs: Vec<Text>,
  buffers: HashMap<Text, Expr>,
  store_reads: HashMap<(Expr, Option<W256>), HashSet<Expr>>,
  block_context: Vec<Text>,
  tx_context: Vec<Text>,
}

// Implementing Semigroup and Monoid traits for BuilderState
impl std::ops::Add for BuilderState {
  type Output = Self;

  fn add(self, rhs: Self) -> Self::Output {
    BuilderState {
      calldata: self.calldata.into_iter().chain(rhs.calldata.into_iter()).collect(),
      addrs: self.addrs.into_iter().chain(rhs.addrs.into_iter()).collect(),
      buffers: self.buffers.into_iter().chain(rhs.buffers.into_iter()).collect(),
      store_reads: self.store_reads.into_iter().chain(rhs.store_reads.into_iter()).collect(),
      block_context: self.block_context.into_iter().chain(rhs.block_context.into_iter()).collect(),
      tx_context: self.tx_context.into_iter().chain(rhs.tx_context.into_iter()).collect(),
    }
  }
}

impl std::ops::AddAssign for BuilderState {
  fn add_assign(&mut self, rhs: Self) {
    self.calldata.extend(rhs.calldata);
    self.addrs.extend(rhs.addrs);
    self.buffers.extend(rhs.buffers);
    self.store_reads.extend(rhs.store_reads);
    self.block_context.extend(rhs.block_context);
    self.tx_context.extend(rhs.tx_context);
  }
}

// Implementing Eq and Show traits for BuilderState
impl PartialEq for BuilderState {
  fn eq(&self, other: &Self) -> bool {
    self.calldata == other.calldata
      && self.addrs == other.addrs
      && self.buffers == other.buffers
      && self.store_reads == other.store_reads
      && self.block_context == other.block_context
      && self.tx_context == other.tx_context
  }
}

impl Eq for BuilderState {}

impl fmt::Display for BuilderState {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
            f,
            "BuilderState {{ calldata: {:?}, addrs: {:?}, buffers: {:?}, store_reads: {:?}, block_context: {:?}, tx_context: {:?} }}",
            self.calldata, self.addrs, self.buffers, self.store_reads, self.block_context, self.tx_context
        )
  }
}

// BufModel enum
#[derive(Debug, PartialEq, Eq)]
enum BufModel {
  Comp(CompressedBuf),
  Flat(Vec<u8>),
}

// CompressedBuf enum
#[derive(Debug, PartialEq, Eq)]
enum CompressedBuf {
  Base {
    byte: u8,
    length: W256,
  },
  Write {
    byte: u8,
    idx: W256,
    next: Box<CompressedBuf>,
  },
}

// SMTCex struct
#[derive(Debug, PartialEq, Eq)]
struct SMTCex {
  vars: HashMap<Expr, W256>,
  addrs: HashMap<Expr, Addr>,
  buffers: HashMap<Expr, BufModel>,
  store: HashMap<Expr, HashMap<W256, W256>>,
  block_context: HashMap<Expr, W256>,
  tx_context: HashMap<Expr, W256>,
}

// RefinementEqs struct
#[derive(Debug, PartialEq, Eq, Clone)]
struct RefinementEqs(Vec<Builder>, Vec<Prop>);

impl RefinementEqs {
  fn new() -> RefinementEqs {
    RefinementEqs(vec![], vec![])
  }
}

// Implementing Semigroup and Monoid traits for RefinementEqs
impl std::ops::Add for RefinementEqs {
  type Output = Self;

  fn add(self, rhs: Self) -> Self::Output {
    RefinementEqs(
      self.0.into_iter().chain(rhs.0.into_iter()).collect(),
      self.1.into_iter().chain(rhs.1.into_iter()).collect(),
    )
  }
}

impl std::ops::AddAssign for RefinementEqs {
  fn add_assign(&mut self, rhs: Self) {
    self.0.extend(rhs.0);
    self.1.extend(rhs.1);
  }
}

// SMT2 struct
#[derive(Debug, PartialEq, Eq, Clone)]
struct SMT2(Vec<Builder>, RefinementEqs, CexVars, Vec<Prop>);

// Implementing Semigroup and Monoid traits for SMT2
impl std::ops::Add for SMT2 {
  type Output = Self;

  fn add(self, rhs: Self) -> Self::Output {
    SMT2(
      self.0.into_iter().chain(rhs.0.into_iter()).collect(),
      self.1 + rhs.1,
      self.2 + rhs.2,
      self.3.into_iter().chain(rhs.3.into_iter()).collect(),
    )
  }
}

impl std::ops::AddAssign for SMT2 {
  fn add_assign(&mut self, rhs: Self) {
    self.0.extend(rhs.0);
    self.1 += rhs.1;
    self.2 += rhs.2;
    self.3.extend(rhs.3);
  }
}

// CexVars struct
#[derive(Debug, PartialEq, Eq, Clone)]
struct CexVars {
  calldata: Vec<Text>,
  addrs: Vec<Text>,
  buffers: HashMap<Text, Expr>,
  store_reads: HashMap<(Expr, Option<W256>), HashSet<Expr>>,
  block_context: Vec<Text>,
  tx_context: Vec<Text>,
}

impl CexVars {
  pub fn new() -> Self {
    CexVars {
      calldata: vec![],
      addrs: vec![],
      buffers: HashMap::new(),
      store_reads: HashMap::new(),
      block_context: vec![],
      tx_context: vec![],
    }
  }
}

// Implementing Semigroup and Monoid traits for CexVars
impl std::ops::Add for CexVars {
  type Output = Self;

  fn add(self, rhs: Self) -> Self::Output {
    CexVars {
      calldata: self.calldata.into_iter().chain(rhs.calldata.into_iter()).collect(),
      addrs: self.addrs.into_iter().chain(rhs.addrs.into_iter()).collect(),
      buffers: self.buffers.into_iter().chain(rhs.buffers.into_iter()).collect(),
      store_reads: self.store_reads.into_iter().chain(rhs.store_reads.into_iter()).collect(),
      block_context: self.block_context.into_iter().chain(rhs.block_context.into_iter()).collect(),
      tx_context: self.tx_context.into_iter().chain(rhs.tx_context.into_iter()).collect(),
    }
  }
}

impl std::ops::AddAssign for CexVars {
  fn add_assign(&mut self, rhs: Self) {
    self.calldata.extend(rhs.calldata);
    self.addrs.extend(rhs.addrs);
    self.buffers.extend(rhs.buffers);
    self.store_reads.extend(rhs.store_reads);
    self.block_context.extend(rhs.block_context);
    self.tx_context.extend(rhs.tx_context);
  }
}

impl fmt::Display for CexVars {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
            f,
            "CexVars {{ calldata: {:?}, addrs: {:?}, buffers: {:?}, store_reads: {:?}, block_context: {:?}, tx_context: {:?} }}",
            self.calldata, self.addrs, self.buffers, self.store_reads, self.block_context, self.tx_context
        )
  }
}

// Function to flatten buffers in SMTCex
fn flatten_bufs(cex: SMTCex) -> Option<SMTCex> {
  let bs = cex
    .buffers
    .into_iter()
    .map(|(k, v)| {
      if let Some(b) = collapse(v) {
        (k, b)
      } else {
        (k, BufModel::Flat(vec![]))
      }
    })
    .collect();

  Some(SMTCex {
    vars: cex.vars,
    addrs: cex.addrs,
    buffers: bs,
    store: cex.store,
    block_context: cex.block_context,
    tx_context: cex.tx_context,
  })
}

fn unbox<T>(value: Box<T>) -> T {
  *value
}

fn to_buf(model: BufModel) -> Option<Expr> {
  match model {
    BufModel::Comp(CompressedBuf::Base { byte, length }) if length <= 120_000_000 => {
      let bytes = vec![byte; length as usize];
      Some(Expr::ConcreteBuf(bytes))
    }
    BufModel::Comp(CompressedBuf::Write { byte, idx, next }) => {
      let next = to_buf(BufModel::Comp(unbox(next)));
      if let Some(n) = next {
        Some(write_byte(Expr::Lit(idx), Expr::LitByte(byte), n))
      } else {
        None
      }
    }
    BufModel::Flat(bytes) => Some(Expr::ConcreteBuf(bytes)),
    _ => None,
  }
}

// Function to collapse a BufModel
fn collapse(model: BufModel) -> Option<BufModel> {
  match to_buf(model) {
    Some(Expr::ConcreteBuf(b)) => Some(BufModel::Flat(b)),
    _ => None,
  }
}

struct AbstState {
  words: HashMap<Expr, i32>,
  count: i32,
}

fn get_var(cex: &SMTCex, name: &str) -> u32 {
  cex.vars.get(&Expr::Var(name.to_string())).unwrap().clone()
}

fn declare_intermediates(bufs: &BufEnv, stores: &StoreEnv) -> SMT2 {
  let enc_ss = stores.iter().map(|(k, v)| encode_store(*k, v)).collect::<Vec<_>>();
  let enc_bs = bufs.iter().map(|(k, v)| encode_buf(*k, v)).collect::<Vec<_>>();
  let mut sorted = enc_ss;
  sorted.extend(enc_bs);
  sorted.sort_by(|SMT2(l, _, _, _), SMT2(r, _, _, _)| l.cmp(r));

  let decls = sorted; //.iter().map(|SMT2(_, decl, _, _)| decl.clone()).collect::<Vec<_>>();
  let mut smt2 = SMT2(
    vec![(&"; intermediate buffers & stores").to_string()],
    RefinementEqs::new(),
    CexVars::new(),
    vec![],
  );
  for decl in decls.iter().rev() {
    smt2 = smt2 + decl.clone();
  }
  smt2
}

fn declare_addrs(names: Vec<Builder>) -> SMT2 {
  todo!()
}

fn declare_vars(names: Vec<Builder>) -> SMT2 {
  todo!()
}

fn declare_bufs(props: Vec<Prop>, buf_env: BufEnv, store_env: StoreEnv) -> SMT2 {
  todo!()
}

fn encode_store(n: usize, expr: &Expr) -> SMT2 {
  let expr_to_smt = expr_to_smt(expr.clone());
  let txt = format!("(define-fun store{} () Storage {})", n, expr_to_smt);
  SMT2(vec![txt], RefinementEqs(vec![], vec![]), CexVars::new(), vec![])
}

fn encode_buf(n: usize, expr: &Expr) -> SMT2 {
  let expr_to_smt = expr_to_smt(expr.clone());
  let txt = format!("(define-fun buf{} () Buf {})", n, expr_to_smt);
  SMT2(vec![txt], RefinementEqs(vec![], vec![]), CexVars::new(), vec![])
}

fn abstract_away_props(conf: &Config, ps: Vec<Prop>) -> (Vec<Prop>, AbstState) {
  let mut state = AbstState {
    words: HashMap::new(),
    count: 0,
  };
  let abstracted = ps.iter().map(|prop| abstract_away(conf, prop, &mut state)).collect::<Vec<_>>();
  (abstracted, state)
}

fn go(a: &Expr) -> AbstState {
  todo!()
  /*go :: Expr a -> State AbstState (Expr a) */
}

fn abstract_away(conf: &Config, prop: &Prop, state: &mut AbstState) -> Prop {
  todo!()
}

fn abstr_expr(e: &Expr, state: &mut AbstState) -> Expr {
  let v = match state.words.get(e) {
    Some(&v) => v,
    None => {
      let next = state.count;
      state.words.insert(e.clone(), next);
      state.count += 1;
      next
    }
  };
  let name = format!("abst_{}", v);
  Expr::Var(name.into())
}

fn decompose(props: Vec<Prop>, conf: &Config) -> Vec<Prop> {
  if conf.decompose_storage && safe_exprs(&props.clone()) && safe_props(&props.clone()) {
    if let Some(v) = props.into_iter().map(|prop| decompose_storage_prop(prop)).collect::<Option<Vec<Prop>>>() {
      v
    } else {
      vec![]
    }
  } else {
    props
  }
}

// Placeholder functions for the omitted details
fn decompose_storage_prop(prop: Prop) -> Option<Prop> {
  // Implementation for decomposing a single Prop
  Some(prop)
}

fn safe_to_decompose(prop: &Prop) -> Option<()> {
  // Implementation for checking if a Prop is safe to decompose
  Some(())
}

fn safe_to_decompose_prop(prop: &Prop) -> bool {
  // Implementation for checking if a Prop is safe to decompose at the property level
  true
}

fn safe_exprs(props: &[Prop]) -> bool {
  props.iter().all(|prop| safe_to_decompose(prop).is_some())
}

fn safe_props(props: &[Prop]) -> bool {
  props.iter().all(|prop| safe_to_decompose_prop(prop))
}

fn to_prop(e: Expr, num: i32) -> Prop {
  Prop::PEq(e, Expr::Var(format!("abst_{}", num)))
}

fn abstract_vars(abst: &AbstState) -> Vec<Builder> {
  abst.words.clone().into_iter().map(|(_, v)| (format!("abst_{}", v))).collect()
}

fn concatenate_props(a: &[Prop], b: &[Prop], c: &[Prop]) -> Vec<Prop> {
  a.iter().cloned().chain(b.iter().cloned()).chain(c.iter().cloned()).collect()
}

// Function implementations
fn referenced_abstract_stores<T: TraversableTerm>(term: &T) -> HashSet<Builder> {
  term.fold_term(
    |x| match x {
      Expr::AbstractStore(s, idx) => {
        let mut set = HashSet::new();
        set.insert(store_name(unbox(s.clone()), *idx));
        set
      }
      _ => HashSet::new(),
    },
    HashSet::new(),
  )
}

fn referenced_waddrs<T: TraversableTerm>(term: &T) -> HashSet<Builder> {
  term.fold_term(
    |x| match x {
      Expr::WAddr(a) => {
        let mut set = HashSet::new();
        set.insert(format_e_addr(unbox(a.clone())));
        set
      }
      _ => HashSet::new(),
    },
    HashSet::new(),
  )
}

fn referenced_bufs<T: TraversableTerm>(expr: &T) -> Vec<Builder> {
  //let mut buf_set = HashSet::new();
  let bufs = expr.fold_term(
    |x| match x {
      Expr::AbstractBuf(s) => {
        //buf_set.insert(s);
        vec![s.clone()]
      }
      _ => vec![],
    },
    vec![],
  );

  bufs.iter().map(|s| (*s).clone()).collect()
}

fn referenced_vars<T: TraversableTerm>(expr: &T) -> Vec<Builder> {
  //let mut var_set = HashSet::new();
  let vars = expr.fold_term(
    |x| match x {
      Expr::Var(s) => {
        // var_set.insert(s);
        vec![s.clone()]
      }
      _ => vec![],
    },
    vec![],
  );

  vars.iter().map(|s| (*s).clone()).collect()
}

fn referenced_frame_context<T: TraversableTerm>(expr: &T) -> Vec<(Builder, Vec<Prop>)> {
  // let mut context_set = HashSet::new();
  let context = expr.fold_term(
    |x| match x {
      Expr::TxValue => {
        // context_set.insert((("txvalue"), vec![]));
        vec![(("txvalue"), vec![])]
      }
      Expr::Balance(a) => {
        /*[(fromString "balance_" <> formatEAddr a, [PLT v (Lit $ 2 ^ (96 :: Int))])] */
        //context_set.insert((
        //  (&format!("balance_{}", format_e_addr(**a))),
        // vec![Prop::PLT(v.clone(), Expr::Lit(2 ^ 96))],
        //));
        vec![(
          (&format!("balance_{}", format_e_addr(unbox(a)))),
          vec![Prop::PLT(x.clone(), Expr::Lit(2 ^ 96))],
        )]
      }
      Expr::Gas { .. } => {
        panic!("TODO: GAS");
      }
      _ => vec![],
    },
    vec![],
  );

  context.into_iter().map(|(b, p)| (b.to_string(), p)).collect()
}

fn referenced_block_context<T: TraversableTerm>(expr: &T) -> Vec<(Builder, Vec<Prop>)> {
  //let mut context_set = HashSet::new();
  let context = expr.fold_term(
    |x| match x {
      Expr::Origin => {
        //context_set.insert((("origin"), vec![in_range(160, Origin.clone())]));
        vec![(("origin"), vec![in_range(160, Expr::Origin)])]
      }
      Expr::Coinbase => {
        //context_set.insert((("coinbase"), vec![in_range(160, Coinbase.clone())]));
        vec![(("coinbase"), vec![in_range(160, Expr::Coinbase)])]
      }
      Expr::Timestamp => {
        //context_set.insert((("timestamp"), vec![]));
        vec![(("timestamp"), vec![])]
      }
      Expr::BlockNumber => {
        //context_set.insert((("blocknumber"), vec![]));
        vec![(("blocknumber"), vec![])]
      }
      Expr::PrevRandao => {
        //context_set.insert((("prevrandao"), vec![]));
        vec![(("prevrandao"), vec![])]
      }
      Expr::GasLimit => {
        //context_set.insert((("gaslimit"), vec![]));
        vec![(("gaslimit"), vec![])]
      }
      Expr::ChainId => {
        //context_set.insert((("chainid"), vec![]));
        vec![(("chainid"), vec![])]
      }
      Expr::BaseFee => {
        //context_set.insert((("basefee"), vec![]));
        vec![(("basefee"), vec![])]
      }
      _ => vec![],
    },
    vec![],
  );

  context.into_iter().map(|(b, p)| (b.to_string(), p)).collect()
}

fn gather_all_vars(
  to_declare_ps_elim: &[Prop],
  buf_vals: &Vec<Expr>,
  store_vals: &Vec<Expr>,
  abst: &AbstState,
) -> Vec<Builder> {
  to_declare_ps_elim
    .iter()
    .flat_map(|p| referenced_vars(p))
    .chain(buf_vals.iter().flat_map(|v| referenced_vars(v)))
    .chain(store_vals.iter().flat_map(|v| referenced_vars(v)))
    .chain(abstract_vars(abst).into_iter())
    .collect()
}

fn gather_frame_context(
  to_declare_ps_elim: &[Prop],
  buf_vals: &Vec<Expr>,
  store_vals: &Vec<Expr>,
) -> Vec<(Builder, Vec<Prop>)> {
  to_declare_ps_elim
    .iter()
    .flat_map(|p| referenced_frame_context(p))
    .chain(buf_vals.iter().flat_map(|v| referenced_frame_context(v)))
    .chain(store_vals.iter().flat_map(|v| referenced_frame_context(v)))
    .collect()
}

fn gather_block_context(
  to_declare_ps_elim: &[Prop],
  buf_vals: &Vec<Expr>,
  store_vals: &Vec<Expr>,
) -> Vec<(String, Vec<Prop>)> {
  to_declare_ps_elim
    .iter()
    .flat_map(|p| referenced_block_context(p))
    .chain(buf_vals.iter().flat_map(|v| referenced_block_context(v)))
    .chain(store_vals.iter().flat_map(|v| referenced_block_context(v)))
    .collect()
}

fn create_keccak_assertions(kecc_assump: &[Prop], kecc_comp: &[Prop]) -> Vec<SMT2> {
  let mut assertions = Vec::new();
  assertions.push(smt2_line("; keccak assumptions".to_owned()));
  assertions.push(SMT2(
    kecc_assump.iter().map(|p| format!("(assert {})", prop_to_smt(p.clone()))).collect(),
    RefinementEqs::new(),
    CexVars::new(),
    vec![],
  ));
  assertions.push(smt2_line("; keccak computations".to_owned()));
  assertions.push(SMT2(
    kecc_comp.iter().map(|p| format!("(assert {})", prop_to_smt(p.clone()))).collect(),
    RefinementEqs::new(),
    CexVars::new(),
    vec![],
  ));
  assertions
}

/*
-- | Asserts that buffer reads beyond the size of the buffer are equal
-- to zero. Looks for buffer reads in the a list of given predicates
-- and the buffer and storage environments.
assertReads :: [Prop] -> BufEnv -> StoreEnv -> [Prop]
assertReads props benv senv = concatMap assertRead allReads
  where
    assertRead :: (Expr EWord, Expr EWord, Expr Buf) -> [Prop]
    assertRead (idx, Lit 32, buf) = [PImpl (PGEq idx (bufLength buf)) (PEq (ReadWord idx buf) (Lit 0))]
    assertRead (idx, Lit sz, buf) =
      fmap
        -- TODO: unsafeInto instead fromIntegral here makes symbolic tests fail
        (PImpl (PGEq idx (bufLength buf)) . PEq (ReadByte idx buf) . LitByte . fromIntegral)
        [(0::Int)..unsafeInto sz-1]
    assertRead (_, _, _) = internalError "Cannot generate assertions for accesses of symbolic size"

    allReads = filter keepRead $ nubOrd $ findBufferAccess props <> findBufferAccess (Map.elems benv) <> findBufferAccess (Map.elems senv)

    -- discard constraints if we can statically determine that read is less than the buffer length
    keepRead (Lit idx, Lit size, buf) =
      case minLength benv buf of
        Just l | into (idx + size) <= l -> False
        _ -> True
    keepRead _ = True
*/

fn assert_reads(prop: &[Prop], benv: &BufEnv, senv: &StoreEnv) -> Vec<Prop> {
  todo!()
}

fn create_read_assumptions(ps_elim: &[Prop], bufs: &BufEnv, stores: &StoreEnv) -> Vec<SMT2> {
  let assumptions = assert_reads(ps_elim, bufs, stores);
  let mut result = Vec::new();
  result.push(smt2_line("; read assumptions".to_string()));
  result.push(SMT2(
    assumptions.iter().map(|p| format!("(assert {})", prop_to_smt(p.clone()))).collect(),
    RefinementEqs::new(),
    CexVars::new(),
    vec![],
  ));
  result
}

fn assert_props(config: &Config, ps_pre_conc: Vec<Prop>) -> SMT2 {
  let ps = conc_keccak_props(ps_pre_conc);
  let (ps_elim, bufs, stores) = eliminate_props(ps);

  let (ps_elim_abst, abst) = if config.abst_refine_arith || config.abst_refine_mem {
    abstract_away_props(config, ps_elim.clone())
  } else {
    (
      ps_elim.clone(),
      AbstState {
        words: HashMap::new(),
        count: 0,
      },
    )
  };

  let buf_vals = bufs.values().cloned().collect::<Vec<_>>();
  let store_vals = stores.values().cloned().collect::<Vec<_>>();

  let kecc_assump = keccak_assumptions(&ps_pre_conc, &buf_vals, &store_vals);
  let kecc_comp = keccak_compute(&ps_pre_conc, &buf_vals, &store_vals);
  let keccak_assertions = create_keccak_assertions(&kecc_assump, &kecc_comp);

  let abst_props = abst_expr_to_int(&abst).into_iter().map(|(e, num)| to_prop(e, num)).collect::<Vec<Prop>>();

  let to_declare_ps = concatenate_props(&ps, &kecc_assump, &kecc_comp);
  let to_declare_ps_elim = concatenate_props(&ps_elim, &kecc_assump, &kecc_comp);

  /*allVars = fmap referencedVars toDeclarePsElim <> fmap referencedVars bufVals <> fmap referencedVars storeVals <> [abstrVars abst] */

  let all_vars = gather_all_vars(&to_declare_ps_elim, &buf_vals, &store_vals, &abst);
  let frame_ctx = gather_frame_context(&to_declare_ps_elim, &buf_vals, &store_vals);
  let block_ctx = gather_block_context(&to_declare_ps_elim, &buf_vals, &store_vals);

  let storage_reads = find_storage_reads(&to_declare_ps);
  let abstract_stores = find_abstract_stores(&to_declare_ps);
  let addresses = find_addresses(&to_declare_ps);

  let read_assumes = create_read_assumptions(&ps_elim, &bufs, &stores);

  let intermediates = declare_intermediates(&bufs, &stores);

  /*
      ps = Expr.concKeccakProps psPreConc
      (psElim, bufs, stores) = eliminateProps ps
  */

  let simplified_ps = decompose(simplify_props(ps), config);
  let decls = declare_intermediates(&bufs, &stores);
  let encs = ps.iter().map(|p| prop_to_smt(p.clone())).collect::<Vec<_>>();
  let abst_smt = abst_props.iter().map(|p| prop_to_smt(p)).collect::<Vec<_>>();
  let smt2 = SMT2(vec![], RefinementEqs::new(), CexVars::new(), vec![])
    + (smt2_line("; intermediate buffers & stores".to_owned()))
    + (decls)
    + (smt2_line("".to_owned()))
    + (declare_addrs(addresses))
    + (smt2_line("".to_owned()))
    + (declare_bufs(to_declare_ps_elim, bufs, stores))
    + (smt2_line("".to_owned()))
    + (declare_vars(
      (all_vars.iter().fold(Vec::new(), |mut acc, x| {
        acc.extend(x.clone());
        acc
      })),
    ))
    + (smt2_line("".to_owned()))
    + (declare_frame_context(
      (frame_ctx.iter().fold(Vec::new(), |mut acc, x| {
        acc.extend(x.clone());
        acc
      })),
    ))
    + (smt2_line("".to_owned()))
    + (declare_block_context(
      (block_ctx.iter().fold(Vec::new(), |mut acc, x| {
        acc.extend(x.clone());
        acc
      })),
    ))
    + (smt2_line("".to_owned()))
    + (intermediates)
    + (smt2_line("".to_owned()))
    + (keccak_assertions)
    + (read_assumes)
    + (smt2_line("".to_owned()));

  encs.iter().for_each(|p| {
    smt2
      + (SMT2(
        vec![(format!("(assert {})", p))],
        RefinementEqs::new(),
        CexVars::new(),
        vec![],
      ));
  });
  SMT2(vec![], RefinementEqs::new(), CexVars::new(), vec![])
    + (smt2_line("; keccak assumptions".to_owned()))
    + (SMT2(
      kecc_assump.iter().map(|p| (&format!("(assert {})", prop_to_smt(p)))).collect::<Vec<_>>(),
      RefinementEqs::new(),
      CexVars::new(),
      vec![],
    ))
    + (smt2_line("; keccak computations".to_owned()))
    + (SMT2(
      kecc_comp.iter().map(|p| (&format!("(assert {})", prop_to_smt(p)))).collect::<Vec<_>>(),
      RefinementEqs::new(),
      CexVars::new(),
      vec![],
    ))
    + (smt2_line("".to_owned()))
    + (SMT2(vec![], RefinementEqs::new(), storage_reads, vec![]))
    + (SMT2(vec![], RefinementEqs::new(), CexVars::new(), ps_pre_conc))
}

fn expr_to_smt(expr: Expr) -> String {
  match expr {
    Expr::Lit(w) => format!("(_ bv{} 256)", w),
    Expr::Var(s) => s,
    Expr::GVar(GVar::BufVar(n)) => format!("buf{}", n),
    Expr::GVar(GVar::StoreVar(n)) => format!("store{}", n),
    Expr::JoinBytes(v) => concat_bytes(&v),
    Expr::Add(a, b) => op2("bvadd", unbox(a), unbox(b)),
    Expr::Sub(a, b) => op2("bvsub", unbox(a), unbox(b)),
    Expr::Mul(a, b) => op2("bvmul", unbox(a), unbox(b)),
    Expr::Exp(a, b) => match *b {
      Expr::Lit(b_lit) => expand_exp(*a, b_lit),
      _ => panic!("cannot encode symbolic exponentiation into SMT"),
    },
    Expr::Min(a, b) => {
      let aenc = expr_to_smt(*a);
      let benc = expr_to_smt(*b);
      format!("(ite (bvule {} {}) {} {})", aenc, benc, aenc, benc)
    }
    Expr::Max(a, b) => {
      let aenc = expr_to_smt(*a);
      let benc = expr_to_smt(*b);
      format!("(max {} {})", aenc, benc)
    }
    Expr::LT(a, b) => {
      let cond = op2("bvult", *a, *b);
      format!("(ite {} {} {})", cond, one(), zero())
    }
    Expr::SLT(a, b) => {
      let cond = op2("bvslt", *a, *b);
      format!("(ite {} {} {})", cond, one(), zero())
    }
    Expr::SGT(a, b) => {
      let cond = op2("bvsgt", *a, *b);
      format!("(ite {} {} {})", cond, one(), zero())
    }
    Expr::GT(a, b) => {
      let cond = op2("bvugt", *a, *b);
      format!("(ite {} {} {})", cond, one(), zero())
    }
    Expr::LEq(a, b) => {
      let cond = op2("bvule", *a, *b);
      format!("(ite {} {} {})", cond, one(), zero())
    }
    Expr::GEq(a, b) => {
      let cond = op2("bvuge", *a, *b);
      format!("(ite {} {} {})", cond, one(), zero())
    }
    Expr::Eq(a, b) => {
      let cond = op2("=", *a, *b);
      format!("(ite {} {} {})", cond, one(), zero())
    }
    Expr::IsZero(a) => {
      let cond = op2("=", *a, Expr::Lit(0));
      format!("(ite {} {} {})", cond, one(), zero())
    }
    Expr::And(a, b) => op2("bvand", *a, *b),
    Expr::Or(a, b) => op2("bvor", *a, *b),
    Expr::Xor(a, b) => op2("bvxor", *a, *b),
    Expr::Not(a) => op1("bvnot", *a),
    Expr::SHL(a, b) => op2("bvshl", *b, *a),
    Expr::SHR(a, b) => op2("bvlshr", *b, *a),
    Expr::SAR(a, b) => op2("bvashr", *b, *a),
    Expr::SEx(a, b) => op2("signext", *a, *b),
    Expr::Div(a, b) => op2_check_zero("bvudiv", *a, *b),
    Expr::SDiv(a, b) => op2_check_zero("bvsdiv", *a, *b),
    Expr::Mod(a, b) => op2_check_zero("bvurem", *a, *b),
    Expr::SMod(a, b) => op2_check_zero("bvsrem", *a, *b),
    Expr::MulMod(a, b, c) => {
      let aexp = expr_to_smt(*a);
      let bexp = expr_to_smt(*b);
      let cexp = expr_to_smt(*c);
      let alift = format!("(concat (_ bv0 256) {})", aexp);
      let blift = format!("(concat (_ bv0 256) {})", bexp);
      let clift = format!("(concat (_ bv0 256) {})", cexp);
      format!(
        "((_ extract 255 0) (ite (= {} (_ bv0 256)) (_ bv0 512) (bvurem (bvmul {} {}) {})))",
        cexp, alift, blift, clift
      )
    }
    Expr::AddMod(a, b, c) => {
      let aexp = expr_to_smt(*a);
      let bexp = expr_to_smt(*b);
      let cexp = expr_to_smt(*c);
      let alift = format!("(concat (_ bv0 256) {})", aexp);
      let blift = format!("(concat (_ bv0 256) {})", bexp);
      let clift = format!("(concat (_ bv0 256) {})", cexp);
      format!(
        "((_ extract 255 0) (ite (= {} (_ bv0 256)) (_ bv0 512) (bvurem (bvadd {} {}) {})))",
        cexp, alift, blift, clift
      )
    }
    Expr::EqByte(a, b) => {
      let cond = op2("=", *a, *b);
      format!("(ite {} {} {})", cond, one(), zero())
    }
    Expr::Keccak(a) => {
      let enc = expr_to_smt(*a);
      format!("(keccak {})", enc)
    }
    Expr::SHA256(a) => {
      let enc = expr_to_smt(*a);
      format!("(sha256 {})", enc)
    }
    Expr::TxValue => "txvalue".to_string(),
    Expr::Balance(a) => format!("balance_{}", format_e_addr(*a)),
    Expr::Origin => "origin".to_string(),
    Expr::BlockHash(a) => {
      let enc = expr_to_smt(*a);
      format!("(blockhash {})", enc)
    }
    Expr::CodeSize(a) => {
      let enc = expr_to_smt(*a);
      format!("(codesize {})", enc)
    }
    Expr::Coinbase => "coinbase".to_string(),
    Expr::Timestamp => "timestamp".to_string(),
    Expr::BlockNumber => "blocknumber".to_string(),
    Expr::PrevRandao => "prevrandao".to_string(),
    Expr::GasLimit => "gaslimit".to_string(),
    Expr::ChainId => "chainid".to_string(),
    Expr::BaseFee => "basefee".to_string(),
    Expr::SymAddr(a) => format_e_addr(expr),
    Expr::WAddr(a) => format!("(concat (_ bv0 96) {})", expr_to_smt(*a)),
    Expr::LitByte(b) => format!("(_ bv{} 8)", b),
    Expr::IndexWord(idx, w) => match *idx {
      Expr::Lit(n) => {
        if n >= 0 && n < 32 {
          let enc = expr_to_smt(*w);
          format!("(indexWord{})", n)
        } else {
          expr_to_smt(Expr::LitByte(0))
        }
      }
      _ => op2("indexWord", *idx, *w),
    },
    Expr::ReadByte(idx, src) => op2("select", *src, *idx),
    Expr::ConcreteBuf("") => "((as const Buf) #b00000000)".to_string(),
    Expr::ConcreteBuf(bs) => write_bytes(&bs, Expr::Mempty),
    Expr::AbstractBuf(s) => s,
    Expr::ReadWord(idx, prev) => op2("readWord", *idx, *prev),

    Expr::BufLength(b) => match *b {
      Expr::AbstractBuf(ab) => format!("{}_length", ab),
      Expr::GVar(GVar::BufVar(n)) => format!("buf{}_length", n),
      _ => expr_to_smt(buf_length(*b)),
    },
    Expr::WriteByte(idx, val, prev) => {
      let enc_idx = expr_to_smt(*idx);
      let enc_val = expr_to_smt(*val);
      let enc_prev = expr_to_smt(*prev);
      format!("(store {} {} {})", enc_prev, enc_idx, enc_val)
    }
    Expr::WriteWord(idx, val, prev) => {
      let enc_idx = expr_to_smt(*idx);
      let enc_val = expr_to_smt(*val);
      let enc_prev = expr_to_smt(*prev);
      format!("(writeWord {} {} {})", enc_idx, enc_val, enc_prev)
    }
    Expr::CopySlice(src_idx, dst_idx, size, src, dst) => {
      copy_slice(*src_idx, *dst_idx, *size, expr_to_smt(*src), expr_to_smt(*dst))
    }
    Expr::ConcreteStore(s) => encode_concrete_store(&mut &s),
    Expr::AbstractStore(a, idx) => store_name(*a, idx),
    Expr::SStore(idx, val, prev) => {
      let enc_idx = expr_to_smt(*idx);
      let enc_val = expr_to_smt(*val);
      let enc_prev = expr_to_smt(*prev);
      format!("(store {} {} {})", enc_prev, enc_idx, enc_val)
    }
    Expr::SLoad(idx, store) => op2("select", *store, *idx),
    _ => panic!("{}", &format!("TODO: implement: {:?}", expr)),
  }
}

fn op1(op: &str, a: Expr) -> String {
  let enc = expr_to_smt(a);
  format!("({} {})", op, enc)
}

fn op2(op: &str, a: Expr, b: Expr) -> String {
  let aenc = expr_to_smt(a);
  let benc = expr_to_smt(b);
  format!("({} {} {})", op, aenc, benc)
}

fn op2_check_zero(op: &str, a: Expr, b: Expr) -> String {
  let aenc = expr_to_smt(a);
  let benc = expr_to_smt(b);
  format!("(ite (= {} (_ bv0 256)) (_ bv0 256) ({} {} {}))", benc, op, aenc, benc)
}

fn concat_bytes(bytes: &[Expr]) -> String {
  bytes.iter().map(|b| expr_to_smt(b.clone())).collect::<Vec<String>>().join(" ")
}

fn zero() -> String {
  "(_ bv0 256)".to_string()
}

fn one() -> String {
  "(_ bv1 256)".to_string()
}

fn prop_to_smt(prop: Prop) -> String {
  match prop {
    Prop::PEq(a, b) => op2("=", a, b),
    Prop::PLT(a, b) => op2("bvult", a, b),
    Prop::PGT(a, b) => op2("bvugt", a, b),
    Prop::PLEq(a, b) => op2("bvule", a, b),
    Prop::PGEq(a, b) => op2("bvuge", a, b),
    Prop::PNeg(a) => {
      let enc = prop_to_smt(*a);
      format!("(not {})", enc)
    }
    Prop::PAnd(a, b) => {
      let aenc = prop_to_smt(*a);
      let benc = prop_to_smt(*b);
      format!("(and {} {})", aenc, benc)
    }
    Prop::POr(a, b) => {
      let aenc = prop_to_smt(*a);
      let benc = prop_to_smt(*b);
      format!("(or {} {})", aenc, benc)
    }
    Prop::PImpl(a, b) => {
      let aenc = prop_to_smt(*a);
      let benc = prop_to_smt(*b);
      format!("(=> {} {})", aenc, benc)
    }
    Prop::PBool(b) => {
      if b {
        "true".to_string()
      } else {
        "false".to_string()
      }
    }
  }
}

// ** Helpers ** ---------------------------------------------------------------------------------

// Stores a region of src into dst
fn copy_slice(src_offset: Expr, dst_offset: Expr, size0: Expr, src: Builder, dst: Builder) -> Builder {
  if let Expr::Lit(_) = size0 {
    let src_repr = format!("(let ((src {})) {})", src, internal(size0, src_offset, dst_offset, dst));
    src_repr
  } else {
    panic!("TODO: implement copy_slice with a symbolically sized region");
  }
}

fn internal(size: Expr, src_offset: Expr, dst_offset: Expr, dst: Builder) -> Builder {
  match size {
    Expr::Lit(0) => dst,
    _ => {
      let size_prime = sub(size, Expr::Lit(1));
      let enc_dst_off = expr_to_smt(add(dst_offset.clone(), size_prime.clone()));
      let enc_src_off = expr_to_smt(add(src_offset.clone(), size_prime.clone()));
      let child = internal(size_prime, src_offset.clone(), dst_offset.clone(), dst);
      format!("(store {} {} (select src {}))", child, enc_dst_off, enc_src_off)
    }
  }
}

// Unrolls an exponentiation into a series of multiplications
fn expand_exp(base: Expr, expnt: W256) -> Builder {
  if expnt == 1 {
    expr_to_smt(base)
  } else {
    let b = expr_to_smt(base.clone());
    let n = expand_exp(base, expnt - 1);
    format!("(bvmul {} {})", b, n)
  }
}

// Concatenates a list of bytes into a larger bitvector
fn write_bytes(bytes: &[u8], buf: Expr) -> Builder {
  let skip_zeros = buf == Expr::Mempty;
  let mut idx = 0;
  let mut inner = expr_to_smt(buf);
  for &byte in bytes {
    if skip_zeros && byte == 0 {
      idx += 1;
    } else {
      let byte_smt = expr_to_smt(Expr::LitByte(byte));
      let idx_smt = expr_to_smt(Expr::Lit(idx));
      inner = format!("(store {} {} {})", inner, idx_smt, byte_smt);
      idx += 1;
    }
  }
  inner
}

fn encode_concrete_store(s: &mut W256W256Map) -> Builder {
  s.iter().fold(
    "((as const Storage) #x0000000000000000000000000000000000000000000000000000000000000000)".to_string(),
    |prev, (key, val)| {
      let enc_key = expr_to_smt(Expr::Lit(*key));
      let enc_val = expr_to_smt(Expr::Lit(*val));
      format!("(store {} {} {})", prev, enc_key, enc_val)
    },
  )
}

fn store_name(a: Expr, idx: Option<W256>) -> Builder {
  match idx {
    Some(idx) => format!("baseStore_{}_{}", format_e_addr(a), idx),
    None => format!("baseStore_{}", format_e_addr(a)),
  }
}

fn format_e_addr(addr: Expr) -> Builder {
  match addr {
    Expr::LitAddr(a) => format!("litaddr_{}", a),
    Expr::SymAddr(a) => format!("symaddr_{}", a),
    Expr::GVar(_) => panic!("Unexpected GVar"),
    _ => panic!("unexpected expr"),
  }
}

// ** Cex parsing ** --------------------------------------------------------------------------------

enum SpecConstant {
  Hexadecimal(u8),
  Binary(u8),
}

fn parse_addr(sc: SpecConstant) -> Addr {
  parse_sc(sc)
}

fn parse_w256(sc: SpecConstant) -> W256 {
  parse_sc(sc)
}

fn parse_integer(sc: SpecConstant) -> i64 {
  parse_sc(sc)
}

fn parse_w8(sc: SpecConstant) -> u8 {
  parse_sc(sc)
}

fn parse_sc<T: FromStr + Default>(sc: SpecConstant) -> T {
  todo!()
  /*
  match sc {
    SpecConstant::Hexadecimal(a) => i64::from_str_radix(&a[2..], 16).unwrap_or_default(),
    SpecConstant::Binary(a) => i64::from_str_radix(&a[2..], 2).unwrap_or_default(),
    _ => panic!("cannot parse: {:?}", sc),
  }
  */
}

fn parse_err<T>(res: T) -> ! {
  todo!()
  // panic!("cannot parse solver response: {:?}", res)
}

fn parse_var(name: &str) -> Expr {
  Expr::Var(name.to_string())
}

fn parse_e_addr(name: &str) -> Expr {
  if let Some(a) = name.strip_prefix("litaddr_") {
    Expr::LitAddr(a.parse().unwrap())
  } else if let Some(a) = name.strip_prefix("symaddr_") {
    Expr::SymAddr(a.to_string())
  } else {
    panic!("cannot parse: {:?}", name)
  }
}

fn parse_block_ctx(t: &str) -> Expr {
  match t {
    "origin" => Expr::Origin,
    "coinbase" => Expr::Coinbase,
    "timestamp" => Expr::Timestamp,
    "blocknumber" => Expr::BlockNumber,
    "prevrandao" => Expr::PrevRandao,
    "gaslimit" => Expr::GasLimit,
    "chainid" => Expr::ChainId,
    "basefee" => Expr::BaseFee,
    _ => panic!("cannot parse {} into an Expr", t),
  }
}

fn parse_tx_ctx(name: &str) -> Expr {
  if name == "txvalue" {
    Expr::TxValue
  } else if let Some(a) = name.strip_prefix("balance_") {
    Expr::Balance(Box::new(parse_e_addr(&Box::new(a))))
  } else {
    panic!("cannot parse {} into an Expr", name)
  }
}

fn get_addrs(
  parse_name: impl Fn(&str) -> Expr,
  get_val: impl Fn(&str) -> String,
  names: &[&str],
) -> HashMap<Expr, Addr> {
  todo!()
  /*
  let mut map = HashMap::new();
  for &name in names {
    let raw = get_val(name);
    let val = parse_addr(parse_comment_free_file_msg(&raw));
    map.insert(parse_name(name), val);
  }
  map
  */
}

fn get_vars(
  parse_name: impl Fn(&str) -> Expr,
  get_val: impl Fn(&str) -> String,
  names: &[&str],
) -> HashMap<Expr, W256> {
  todo!()
  /*
  let mut map = HashMap::new();
  for &name in names {
    let raw = get_val(name);
    let val = parse_w256(parse_comment_free_file_msg(&raw));
    map.insert(parse_name(name), val);
  }
  map
  */
}

/*
fn get_one<T>(
  parse_val: impl Fn(SpecConstant) -> T,
  get_val: impl Fn(&str) -> String,
  mut acc: HashMap<String, T>,
  name: &str,
) -> HashMap<String, T> {
  let raw = get_val(name);
  let parsed = match parse_comment_free_file_msg(&raw) {
    Ok(String(val_parsed)) if val_parsed.len() == 1 => val_parsed[0].clone(),
    res => parse_err(res),
  };
  let val = match parsed {
    (TermQualIdentifier::Unqualified(IdSymbol(symbol)), TermSpecConstant(sc)) if symbol == name => parse_val(sc),
    _ => panic!("solver did not return model for requested value"),
  };
  acc.insert(name.to_string(), val);
  acc
}

// Queries the solver for models for each of the expressions representing the max read index for a given buffer
fn query_max_reads(get_val: impl Fn(&str) -> String, max_reads: &HashMap<String, Expr>) -> HashMap<String, W256> {
  let mut map = HashMap::new();
  for (key, val) in max_reads {
    let result = query_value(&get_val, val);
    map.insert(key.clone(), result);
  }
  map
}

// Gets the initial model for each buffer, these will often be much too large for our purposes
fn get_bufs(get_val: impl Fn(&str) -> String, bufs: &[&str]) -> HashMap<Expr, BufModel> {
  let mut map = HashMap::new();
  for &name in bufs {
    let len = get_length(&get_val, name);
    let raw = get_val(name);
    let buf = parse_buf(len, parse_comment_free_file_msg(&raw));
    map.insert(Expr::AbstractBuf(name.to_string()), buf);
  }
  map
}

fn get_length(get_val: impl Fn(&str) -> String, name: &str) -> W256 {
  let raw = get_val(&format!("len_{}", name));
  parse_w256(parse_comment_free_file_msg(&raw))
}

fn parse_comment_free_file_msg(raw: &str) -> SpecConstant {
  /*
  let parsed = parse_z3_response(raw).map_err(|e| eprintln!("{}", e))?;
  Ok(String(parsed))
  */
  todo!()
}

fn parse_buf(len: W256, res: SpecConstant) -> BufModel {
  match res {
    Ok(String(model)) => {
      let buf = model
        .iter()
        .map(|term| match term {
          (TermQualIdentifier::Unqualified(IdSymbol(ref sym)), TermSpecConstant(val)) if sym.starts_with("buf") => {
            let idx = sym[3..].parse().expect("cannot parse buf index");
            let val = parse_w8(*val);
            (idx, val)
          }
          _ => panic!("unexpected term while parsing buf: {:?}", term),
        })
        .collect();
      BufModel { len, buf }
    }
    Err(_) => panic!("cannot parse buf model"),
  }
}
*/

fn smt2_line(txt: Builder) -> SMT2 {
  SMT2(vec![txt], RefinementEqs(vec![], vec![]), CexVars::new(), vec![])
}
