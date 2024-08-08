use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::{fmt, vec};
// use std::str::FromStr;

use crate::modules::cse::{eliminate_props, BufEnv, StoreEnv};
use crate::modules::effects::Config;
use crate::modules::expr::{
  add, buf_length, buf_length_env, conc_keccak_props, contains_node, emax, get_addr, get_logical_idx, in_range,
  min_length, simplify_props, sub, write_byte,
};
use crate::modules::format::format_prop;
use crate::modules::keccak::{keccak_assumptions, keccak_compute};
use crate::modules::traversals::{fold_prop, TraversableTerm};
use crate::modules::types::{AddableVec, Addr, Expr, GVar, Prop, W256W256Map, W256};

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
pub enum BufModel {
  Comp(CompressedBuf),
  Flat(Vec<u8>),
}

// CompressedBuf enum
#[derive(Debug, PartialEq, Eq)]
pub enum CompressedBuf {
  Base { byte: u8, length: W256 },
  Write { byte: u8, idx: W256, next: Box<CompressedBuf> },
}

// SMTCex struct
#[derive(Debug, PartialEq, Eq)]
pub struct SMTCex {
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
pub struct SMT2(Vec<Builder>, RefinementEqs, CexVars, Vec<Prop>);

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

pub fn format_smt2(smt2: &SMT2) -> String {
  let mut result =
    format!(";{}", smt2.3.iter().map(|p| format_prop(p)).collect::<Vec<String>>().join("\n")).replace("\n", "\n;");
  result += "\n\n";
  for s in smt2.0.clone() {
    result += &(s.to_string() + &("\n".to_string()));
  }
  result
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
pub fn flatten_bufs(cex: SMTCex) -> Option<SMTCex> {
  let bs = cex
    .buffers
    .into_iter()
    .map(|(k, v)| if let Some(b) = collapse(v) { (k, b) } else { (k, BufModel::Flat(vec![])) })
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

pub fn to_buf(model: BufModel) -> Option<Expr> {
  match model {
    BufModel::Comp(CompressedBuf::Base { byte, length }) if length <= W256(120_000_000, 0) => {
      let bytes = vec![byte; length.0 as usize];
      Some(Expr::ConcreteBuf(bytes))
    }
    BufModel::Comp(CompressedBuf::Write { byte, idx, next }) => {
      let next = to_buf(BufModel::Comp(*next));
      if let Some(n) = next {
        Some(write_byte(Box::new(Expr::Lit(idx)), Box::new(Expr::LitByte(byte)), Box::new(n)))
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

pub struct AbstState {
  pub words: HashMap<Expr, i32>,
  pub count: i32,
}

pub fn get_var(cex: &SMTCex, name: &str) -> W256 {
  cex.vars.get(&Expr::Var(name.to_string())).unwrap().clone()
}

fn encode_store(n: usize, expr: &Expr) -> SMT2 {
  let expr_to_smt = expr_to_smt(expr.clone());
  let txt = format!("(define-fun store{} () Storage {})", n, expr_to_smt);
  SMT2(vec![txt], RefinementEqs(vec![], vec![]), CexVars::new(), vec![])
}

fn encode_buf(n: usize, expr: &Expr, bufs: &BufEnv) -> SMT2 {
  let buf_smt = expr_to_smt(expr.clone());
  let def_buf = format!("(define-fun buf{} () Buf {})", n, buf_smt);
  let len_smt = expr_to_smt(buf_length_env(bufs, true, expr.clone()));
  let def_len = format!("(define-fun buf{}_length () (_ BitVec 256) {})", n, len_smt);
  SMT2(vec![def_buf, def_len], RefinementEqs(vec![], vec![]), CexVars::new(), vec![])
}

fn declare_intermediates(bufs: &BufEnv, stores: &StoreEnv) -> SMT2 {
  let enc_ss = stores.iter().map(|(k, v)| encode_store(*k, v)).collect::<Vec<_>>();
  let enc_bs = bufs.iter().map(|(k, v)| encode_buf(*k, v, bufs)).collect::<Vec<_>>();
  let mut sorted = enc_ss;
  sorted.extend(enc_bs);
  sorted.sort_by(|SMT2(l, _, _, _), SMT2(r, _, _, _)| r.cmp(l));

  let decls = sorted; //.iter().map(|SMT2(_, decl, _, _)| decl.clone()).collect::<Vec<_>>();
  let mut smt2 =
    SMT2(vec![(&"; intermediate buffers & stores").to_string()], RefinementEqs::new(), CexVars::new(), vec![]);
  for decl in decls.iter().rev() {
    smt2 = smt2 + decl.clone();
  }
  smt2
}

fn declare_addrs(names: Vec<Builder>) -> SMT2 {
  let mut result = vec!["; symbolic addresseses".to_string()];
  for n in &names {
    result.push(format!("(declare-fun {} () Addr)", n).to_string());
  }

  SMT2(result, RefinementEqs(vec![], vec![]), CexVars { addrs: names, ..CexVars::new() }, vec![])
}

fn declare_vars(names: Vec<Builder>) -> SMT2 {
  let declarations: HashSet<String> =
    names.iter().map(|name| format!("(declare-fun {} () (_ BitVec 256))", name)).collect();
  let cexvars = CexVars { calldata: names.to_vec(), ..CexVars::new() };

  let mut s: Vec<String> = vec!["; variables".to_string()];
  s.extend(declarations);

  SMT2(s, RefinementEqs(vec![], vec![]), cexvars, vec![])
}

fn base_buf(e: Expr, benv: &BufEnv) -> Expr {
  match e.clone() {
    Expr::AbstractBuf(b) => Expr::AbstractBuf(b),
    Expr::ConcreteBuf(b) => Expr::ConcreteBuf(b),
    Expr::GVar(GVar::BufVar(a)) => match benv.get(&(a as usize)) {
      Some(b) => base_buf(b.clone(), benv),
      None => panic!("could not find buffer variable"),
    },
    Expr::WriteByte(_, _, b) => base_buf(*b, benv),
    Expr::WriteWord(_, _, b) => base_buf(*b, benv),
    Expr::CopySlice(_, _, _, _, dst) => base_buf(*dst, benv),
    _ => panic!("unexpected error"),
  }
}

fn discover_max_reads(props: &Vec<Prop>, benv: &BufEnv, senv: &StoreEnv) -> HashMap<String, Expr> {
  // Find all buffer accesses
  let all_reads = {
    let mut reads = find_buffer_access(props);
    reads.extend(find_buffer_access(&benv.values().into_iter().map(|e: &Expr| e.clone()).collect()));
    reads.extend(find_buffer_access(&senv.values().into_iter().map(|e: &Expr| e.clone()).collect()));
    reads
  };

  // Find all buffers
  let all_bufs: HashMap<String, Expr> = {
    let mut buf_set: HashSet<String> = HashSet::new();

    let mut pr: Vec<String> = vec![];
    for p in props {
      pr.extend(referenced_bufs(p));
    }

    let mut rb: Vec<String> = vec![];
    for b in benv.values().into_iter() {
      rb.extend(referenced_bufs(b));
    }

    let mut sb: Vec<String> = vec![];
    for b in senv.values().into_iter() {
      sb.extend(referenced_bufs(b));
    }

    buf_set.extend(pr);
    buf_set.extend(rb);
    buf_set.extend(sb);

    buf_set.into_iter().map(|buf| (buf, Expr::Lit(W256(4, 0)))).collect()
  };

  // Create buffer map
  let buf_map = all_reads.into_iter().fold(HashMap::new(), |mut m, (idx, size, buf)| {
    match base_buf(buf.clone(), benv) {
      Expr::AbstractBuf(b) => {
        m.insert(b.clone(), add(Box::new(idx), Box::new(size)));
      }
      _ => {}
    }
    m
  });

  // Merge buffer map with all buffers
  let merged_map = {
    let mut map = buf_map.clone();
    for (key, value) in all_bufs {
      map.entry(key).and_modify(|e| *e = emax(Box::new(e.clone()), Box::new(value.clone()))).or_insert(value);
    }
    map
  };

  merged_map
}

// Function to declare buffers
fn declare_bufs(props: &Vec<Prop>, buf_env: BufEnv, store_env: StoreEnv) -> SMT2 {
  let cexvars = CexVars { buffers: discover_max_reads(props, &buf_env, &store_env), ..CexVars::new() };

  let all_bufs: Vec<String> = cexvars.buffers.keys().cloned().collect();

  let declare_bufs: Vec<String> =
    all_bufs.iter().map(|n| format!("(declare-fun {} () (Array (_ BitVec 256) (_ BitVec 8)))", n)).collect();

  let declare_lengths: Vec<String> =
    all_bufs.iter().map(|n| format!("(declare-fun {}_length () (_ BitVec 256))", n)).collect();

  SMT2(
    vec!["; buffers".to_string()]
      .into_iter()
      .chain(declare_bufs)
      .chain(vec!["; buffer lengths".to_string()])
      .chain(declare_lengths)
      .collect(),
    RefinementEqs(vec![], vec![]),
    cexvars,
    vec![],
  )
}

// Declare frame context
fn declare_frame_context(names: &Vec<(Builder, Vec<Prop>)>) -> SMT2 {
  let declarations = vec!["; frame context".to_string()]
    .into_iter()
    .chain(names.iter().flat_map(|(n, props)| {
      let mut decls = vec![format!("(declare-fun {} () (_ BitVec 256))", n)];
      decls.extend(props.iter().map(|p| format!("(assert {})", prop_to_smt(p.clone()))));
      decls
    }))
    .collect();

  let cexvars = CexVars { tx_context: names.iter().map(|(n, _)| n.clone()).collect(), ..CexVars::new() };
  let declarations_set: HashSet<String> = declarations;

  SMT2(declarations_set.into_iter().collect(), RefinementEqs(vec![], vec![]), cexvars, vec![])
}

// Declare abstract stores
fn declare_abstract_stores(names: &Vec<Builder>) -> SMT2 {
  let declarations = vec!["; abstract base stores".to_string()]
    .into_iter()
    .chain(names.iter().map(|n| format!("(declare-fun {} () Storage)", n)))
    .collect();

  SMT2(declarations, RefinementEqs(vec![], vec![]), CexVars::new(), vec![])
}

// Declare block context
fn declare_block_context(names: &Vec<(Builder, Vec<Prop>)>) -> SMT2 {
  let declarations = vec!["; block context".to_string()]
    .into_iter()
    .chain(names.iter().flat_map(|(n, props)| {
      let mut decls = vec![format!("(declare-fun {} () (_ BitVec 256))", n)];
      decls.extend(props.iter().map(|p| format!("(assert {})", prop_to_smt(p.clone()))));
      decls
    }))
    .collect();

  let cexvars = CexVars { block_context: names.iter().map(|(n, _)| n.clone()).collect(), ..CexVars::new() };

  SMT2(declarations, RefinementEqs(vec![], vec![]), cexvars, vec![])
}

fn abstract_away_props(conf: &Config, ps: Vec<Prop>) -> (Vec<Prop>, AbstState) {
  let mut state = AbstState { words: HashMap::new(), count: 0 };
  let abstracted = ps.iter().map(|prop| abstract_away(conf, prop, &mut state)).collect::<Vec<_>>();
  (abstracted, state)
}

pub fn abstract_away(_conf: &Config, _prop: &Prop, _state: &mut AbstState) -> Prop {
  todo!()
}

pub fn abstr_expr(e: &Expr, state: &mut AbstState) -> Expr {
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

fn safe_to_decompose(_prop: &Prop) -> Option<()> {
  // Implementation for checking if a Prop is safe to decompose
  Some(())
}

fn safe_to_decompose_prop(_prop: &Prop) -> bool {
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
  fn f(x: &Expr) -> AddableVec<String> {
    match x.clone() {
      Expr::AbstractStore(s, idx) => {
        let mut set = vec![];
        set.push(store_name(unbox(s.clone()), idx.clone()));
        AddableVec::from_vec(set)
      }
      _ => AddableVec::from_vec(vec![]),
    }
  }
  let v = term.fold_term(&mut f, AddableVec::from_vec(vec![]));
  HashSet::from_iter(v.to_vec().into_iter())
}

fn referenced_waddrs<T: TraversableTerm>(term: &T) -> HashSet<Builder> {
  fn f(x: &Expr) -> AddableVec<String> {
    match x {
      Expr::WAddr(a) => {
        let mut set = vec![];
        set.push(format_e_addr(unbox(a.clone())));
        AddableVec::from_vec(set)
      }
      _ => AddableVec::from_vec(vec![]),
    }
  }
  let v = term.fold_term(&mut f, AddableVec::from_vec(vec![]));
  HashSet::from_iter(v.to_vec().into_iter())
}

fn referenced_bufs<T: TraversableTerm>(term: &T) -> Vec<Builder> {
  fn f(x: &Expr) -> AddableVec<String> {
    match x {
      Expr::AbstractBuf(s) => AddableVec::from_vec(vec![s.clone()]),
      _ => AddableVec::from_vec(vec![]),
    }
  }
  let bufs = term.fold_term(&mut f, AddableVec::from_vec(vec![]));

  bufs.to_vec().iter().map(|s| (*s).clone()).collect()
}

fn referenced_vars<T: TraversableTerm>(expr: &T) -> Vec<Builder> {
  fn f(x: &Expr) -> AddableVec<String> {
    match x {
      Expr::Var(s) => {
        // var_set.insert(s);
        AddableVec::from_vec(vec![s.clone()])
      }
      _ => AddableVec::from_vec(vec![]),
    }
  }
  let vars = expr.fold_term(&mut f, AddableVec::from_vec(vec![]));

  vars.to_vec().iter().map(|s| (*s).clone()).collect()
}

fn referenced_frame_context<T: TraversableTerm>(expr: &T) -> Vec<(Builder, Vec<Prop>)> {
  fn go(x: Expr) -> AddableVec<(Builder, Vec<Prop>)> {
    match x.clone() {
      Expr::TxValue => AddableVec::from_vec(vec![("txvalue".to_string(), vec![])]),
      Expr::Balance(a) => AddableVec::from_vec(vec![(
        format!("balance_{}", format_e_addr(*a.clone())),
        vec![Prop::PLT(x.clone(), Expr::Lit(W256(2, 0) ^ W256(96, 0)))],
      )]),
      Expr::Gas { .. } => {
        panic!("TODO: GAS");
      }
      _ => AddableVec::from_vec(vec![]),
    }
  }
  let context = expr.fold_term(&mut |x: &Expr| go(x.clone()), AddableVec::from_vec(vec![]));

  context.to_vec().into_iter().map(|(b, p)| (b.to_string(), p)).collect()
}

fn referenced_block_context<T: TraversableTerm>(expr: &T) -> Vec<(Builder, Vec<Prop>)> {
  fn f(x: &Expr) -> AddableVec<(Builder, Vec<Prop>)> {
    match x {
      Expr::Origin => {
        //context_set.insert((("origin"), vec![in_range(160, Origin.clone())]));
        AddableVec::from_vec(vec![(("origin".to_string()), vec![in_range(160, Box::new(Expr::Origin))])])
      }
      Expr::Coinbase => {
        //context_set.insert((("coinbase"), vec![in_range(160, Coinbase.clone())]));
        AddableVec::from_vec(vec![(("coinbase".to_string()), vec![in_range(160, Box::new(Expr::Coinbase))])])
      }
      Expr::Timestamp => {
        //context_set.insert((("timestamp"), vec![]));
        AddableVec::from_vec(vec![(("timestamp".to_string()), vec![])])
      }
      Expr::BlockNumber => {
        //context_set.insert((("blocknumber"), vec![]));
        AddableVec::from_vec(vec![(("blocknumber".to_string()), vec![])])
      }
      Expr::PrevRandao => {
        //context_set.insert((("prevrandao"), vec![]));
        AddableVec::from_vec(vec![(("prevrandao".to_string()), vec![])])
      }
      Expr::GasLimit => {
        //context_set.insert((("gaslimit"), vec![]));
        AddableVec::from_vec(vec![(("gaslimit".to_string()), vec![])])
      }
      Expr::ChainId => {
        //context_set.insert((("chainid"), vec![]));
        AddableVec::from_vec(vec![(("chainid".to_string()), vec![])])
      }
      Expr::BaseFee => {
        //context_set.insert((("basefee"), vec![]));
        AddableVec::from_vec(vec![(("basefee".to_string()), vec![])])
      }
      _ => AddableVec::from_vec(vec![]),
    }
  }

  let context = expr.fold_term(&mut f, AddableVec::from_vec(vec![]));

  context.to_vec().into_iter().map(|(b, p)| (b.to_string(), p)).collect()
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
// Define the assert_reads function
fn assert_reads(props: &[Prop], benv: &BufEnv, senv: &StoreEnv) -> Vec<Prop> {
  let mut all_reads = HashSet::new();

  // Collect all buffer access reads
  all_reads.extend(find_buffer_access(&props.to_vec()));
  all_reads.extend(find_buffer_access(&benv.values().cloned().collect()));
  all_reads.extend(find_buffer_access(&senv.values().cloned().collect()));

  // Filter out unnecessary reads
  let all_reads: Vec<_> = all_reads.into_iter().filter(|read| keep_read(read, benv)).collect();

  // Generate assertions for all reads
  all_reads.into_iter().flat_map(assert_read).collect()
}

// Define the function to assert reads
fn assert_read(read: (Expr, Expr, Expr)) -> Vec<Prop> {
  let (idx, size, buf) = read;

  match size {
    Expr::Lit(sz) if sz == W256(32, 0) => {
      vec![Prop::PImpl(
        Box::new(Prop::PGEq(idx.clone(), buf_length(buf.clone()))),
        Box::new(Prop::PEq(Expr::ReadWord(Box::new(idx), Box::new(buf)), Expr::Lit(W256(0, 0)))),
      )]
    }
    Expr::Lit(sz) => (0..(sz.0 as usize))
      .map(|i| {
        Prop::PImpl(
          Box::new(Prop::PGEq(idx.clone(), buf_length(buf.clone()))),
          Box::new(Prop::PEq(Expr::ReadByte(Box::new(idx.clone()), Box::new(buf.clone())), Expr::LitByte(i as u8))),
        )
      })
      .collect(),
    _ => panic!("Cannot generate assertions for accesses of symbolic size"),
  }
}

// Define a function to keep only necessary reads
fn keep_read(read: &(Expr, Expr, Expr), benv: &BufEnv) -> bool {
  match read {
    (Expr::Lit(idx), Expr::Lit(size), buf) => {
      if let Some(l) = min_length(benv, Box::new(buf.clone())) {
        idx.clone() + size.clone() <= W256(l as u128, 0)
      } else {
        true
      }
    }
    _ => true,
  }
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

pub fn assert_props(config: &Config, ps_pre_conc: Vec<Prop>) -> SMT2 {
  let simplified_ps = decompose(simplify_props(ps_pre_conc.clone()), config);

  let ps = conc_keccak_props(simplified_ps);
  let (ps_elim, bufs, stores) = eliminate_props(ps.clone());
  let (ps_elim_abst, ref abst @ AbstState { words: ref abst_expr_to_int, count: _ }) =
    if config.abst_refine_arith || config.abst_refine_mem {
      abstract_away_props(config, ps_elim.clone())
    } else {
      (ps_elim.clone(), AbstState { words: HashMap::new(), count: 0 })
    };

  let abst_props = abst_expr_to_int.into_iter().map(|(e, num)| to_prop(e.clone(), *num)).collect::<Vec<Prop>>();

  let buf_vals = bufs.values().cloned().collect::<Vec<_>>();
  let store_vals = stores.values().cloned().collect::<Vec<_>>();

  let kecc_assump = keccak_assumptions(&ps_pre_conc, &buf_vals, &store_vals);
  let kecc_comp = keccak_compute(&ps_pre_conc, &buf_vals, &store_vals);
  let keccak_assertions = create_keccak_assertions(&kecc_assump, &kecc_comp);

  // Props storing info that need declaration(s)
  let to_declare_ps = concatenate_props(&ps, &kecc_assump, &kecc_comp);
  let to_declare_ps_elim = concatenate_props(&ps_elim, &kecc_assump, &kecc_comp);

  //let storage_reads = to_declare_ps.into_iter().map(|p: Prop| find_storage_reads(&p)).collect();
  let storage_reads: HashMap<(Expr, Option<W256>), HashSet<Expr>> = to_declare_ps
    .clone()
    .into_iter()
    .flat_map(|p: Prop| find_storage_reads(&p)) // Flatten HashMap into an iterator of tuples
    .fold(HashMap::new(), |mut acc, (key, value)| {
      acc.entry(key).or_insert_with(HashSet::new).extend(value);
      acc
    });
  let abstract_stores_set: HashSet<Builder> =
    to_declare_ps.clone().into_iter().flat_map(|term: Prop| referenced_abstract_stores(&term)).collect();
  let abstract_stores: Vec<Builder> = abstract_stores_set.into_iter().collect();
  let addresses = to_declare_ps.into_iter().flat_map(|term: Prop| referenced_waddrs(&term)).collect();

  /*allVars = fmap referencedVars toDeclarePsElim <> fmap referencedVars bufVals <> fmap referencedVars storeVals <> [abstrVars abst] */

  let all_vars = gather_all_vars(&to_declare_ps_elim, &buf_vals, &store_vals, &abst);
  let frame_ctx = gather_frame_context(&to_declare_ps_elim, &buf_vals, &store_vals);
  let block_ctx = gather_block_context(&to_declare_ps_elim, &buf_vals, &store_vals);

  // assert that reads beyond size of buffer & storage is zero
  let read_assumes = create_read_assumptions(&ps_elim, &bufs, &stores);

  // ----------------------------------------------------- //
  let encs = ps_elim_abst.iter().map(|p| prop_to_smt(p.clone())).collect::<Vec<_>>();
  let abst_smt = abst_props.iter().map(|p| prop_to_smt(p.clone())).collect::<Vec<_>>();
  let intermediates = declare_intermediates(&bufs, &stores);
  // let decls = declare_intermediates(&bufs, &stores);

  let mut concatenated_frame_ctx = vec![];
  for fc in &frame_ctx {
    concatenated_frame_ctx.push(fc.clone());
  }
  let mut concatenated_block_ctx = vec![];
  for bc in &block_ctx {
    concatenated_block_ctx.push(bc.clone());
  }

  let mut smt2 = prelude()
    + (smt2_line("; intermediate buffers & stores".to_owned()))
    + (declare_abstract_stores(&abstract_stores))
    + (smt2_line("".to_owned()))
    + (declare_addrs(addresses))
    + (smt2_line("".to_owned()))
    + (declare_bufs(&to_declare_ps_elim, bufs, stores))
    + (smt2_line("".to_owned()))
    + (declare_vars(all_vars.iter().fold(Vec::new(), |mut acc, x| {
      acc.push(x.clone());
      acc
    })))
    + (smt2_line("".to_owned()))
    + (declare_frame_context(&concatenated_frame_ctx))
    + (smt2_line("".to_owned()))
    + (declare_block_context(&concatenated_block_ctx))
    + (smt2_line("".to_owned()))
    + (intermediates)
    + (smt2_line("".to_owned()));

  for ka in keccak_assertions {
    smt2 = smt2 + ka;
  }
  for ra in read_assumes {
    smt2 = smt2 + ra;
  }
  smt2 = smt2 + (smt2_line("".to_owned()));

  encs.iter().for_each(|p| {
    smt2 += SMT2(vec![(format!("(assert {})", p))], RefinementEqs::new(), CexVars::new(), vec![]);
  });

  let mut cps = ps_elim_abst.clone();
  cps.extend(abst_props);
  smt2 += SMT2(
    vec![],
    RefinementEqs(abst_smt.iter().map(|s| format!("(assert {})", s)).collect(), cps),
    CexVars::new(),
    vec![],
  );
  smt2
    + (SMT2(vec![], RefinementEqs::new(), CexVars::new(), vec![]))
    + (SMT2(
      vec![],
      RefinementEqs::new(),
      CexVars {
        store_reads: storage_reads,
        calldata: vec![],
        addrs: vec![],
        buffers: HashMap::new(),
        block_context: vec![],
        tx_context: vec![],
      },
      vec![],
    ))
    + (SMT2(vec![], RefinementEqs::new(), CexVars::new(), ps_pre_conc))
}

fn expr_to_smt(expr: Expr) -> String {
  match expr.clone() {
    Expr::Lit(w) => format!("(_ bv{} 256)", w.to_decimal()),
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
      let cond = op2("=", *a, Expr::Lit(W256(0, 0)));
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
    Expr::SymAddr(_) => format_e_addr(expr),
    Expr::WAddr(a) => format!("(concat (_ bv0 96) {})", expr_to_smt(*a)),
    Expr::LitByte(b) => format!("(_ bv{} 8)", b),
    Expr::IndexWord(idx, w) => match *idx {
      Expr::Lit(n) => {
        if n >= W256(0, 0) && n < W256(32, 0) {
          let enc = expr_to_smt(*w);
          format!("(indexWord{}, {})", n, enc)
        } else {
          expr_to_smt(Expr::LitByte(0))
        }
      }
      _ => op2("indexWord", *idx, *w),
    },
    Expr::ReadByte(idx, src) => op2("select", *src, *idx),
    Expr::ConcreteBuf(bs) if bs.len() == 0 => "((as const Buf) #b00000000)".to_string(),
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
    Expr::ConcreteStore(s) => encode_concrete_store(&s),
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
    Expr::Lit(W256(0, 0)) => dst,
    _ => {
      let size_prime = sub(Box::new(size), Box::new(Expr::Lit(W256(1, 0))));
      let enc_dst_off = expr_to_smt(add(Box::new(dst_offset.clone()), Box::new(size_prime.clone())));
      let enc_src_off = expr_to_smt(add(Box::new(src_offset.clone()), Box::new(size_prime.clone())));
      let child = internal(size_prime, src_offset.clone(), dst_offset.clone(), dst);
      format!("(store {} {} (select src {}))", child, enc_dst_off, enc_src_off)
    }
  }
}

// Unrolls an exponentiation into a series of multiplications
fn expand_exp(base: Expr, expnt: W256) -> Builder {
  if expnt == W256(1, 0) {
    expr_to_smt(base)
  } else {
    let b = expr_to_smt(base.clone());
    let n = expand_exp(base, expnt - W256(1, 0));
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
      let idx_smt = expr_to_smt(Expr::Lit(W256(idx, 0)));
      inner = format!("(store {} {} {})", inner, idx_smt, byte_smt);
      idx += 1;
    }
  }
  inner
}

fn encode_concrete_store(s: &W256W256Map) -> Builder {
  s.clone().iter().fold(
    "((as const Storage) #x0000000000000000000000000000000000000000000000000000000000000000)".to_string(),
    |prev, (key, val)| {
      let enc_key = expr_to_smt(Expr::Lit(key.clone()));
      let enc_val = expr_to_smt(Expr::Lit(val.clone()));
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

/*
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
*/

fn prelude() -> SMT2 {
  SMT2(
    vec!["; logic".to_string(),
    "(set-info :smt-lib-version 2.6)".to_string(),
    ";(set-logic QF_AUFBV)".to_string(),
    "(set-logic ALL)".to_string(),
    "(set-info :source |".to_string(),
    "Generator: rhoevm".to_string(),
    "Application: rhoevm symbolic execution system".to_string(),
    "|)".to_string(),
    "(set-info :category \"industrial\")".to_string(),
    "".to_string(),
    "; types".to_string(),
    "(define-sort Byte () (_ BitVec 8))".to_string(),
    "(define-sort Word () (_ BitVec 256))".to_string(),
    "(define-sort Addr () (_ BitVec 160))".to_string(),
    "(define-sort Buf () (Array Word Byte))".to_string(),
    "".to_string(),
    "; slot -> value".to_string(),
    "(define-sort Storage () (Array Word Word))".to_string(),
    "".to_string(),
    "; hash functions".to_string(),
    "(declare-fun keccak (Buf) Word)".to_string(),
    "(declare-fun sha256 (Buf) Word)".to_string(),
    "(define-fun max ((a (_ BitVec 256)) (b (_ BitVec 256))) (_ BitVec 256) (ite (bvult a b) b a))".to_string(),
    "".to_string(),
    "; word indexing".to_string(),
    "(define-fun indexWord31 ((w Word)) Byte ((_ extract 7 0) w))".to_string(),
    "(define-fun indexWord30 ((w Word)) Byte ((_ extract 15 8) w))".to_string(),
    "(define-fun indexWord29 ((w Word)) Byte ((_ extract 23 16) w))".to_string(),
    "(define-fun indexWord28 ((w Word)) Byte ((_ extract 31 24) w))".to_string(),
    "(define-fun indexWord27 ((w Word)) Byte ((_ extract 39 32) w))".to_string(),
    "(define-fun indexWord26 ((w Word)) Byte ((_ extract 47 40) w))".to_string(),
    "(define-fun indexWord25 ((w Word)) Byte ((_ extract 55 48) w))".to_string(),
    "(define-fun indexWord24 ((w Word)) Byte ((_ extract 63 56) w))".to_string(),
    "(define-fun indexWord23 ((w Word)) Byte ((_ extract 71 64) w))".to_string(),
    "(define-fun indexWord22 ((w Word)) Byte ((_ extract 79 72) w))".to_string(),
    "(define-fun indexWord21 ((w Word)) Byte ((_ extract 87 80) w))".to_string(),
    "(define-fun indexWord20 ((w Word)) Byte ((_ extract 95 88) w))".to_string(),
    "(define-fun indexWord19 ((w Word)) Byte ((_ extract 103 96) w))".to_string(),
    "(define-fun indexWord18 ((w Word)) Byte ((_ extract 111 104) w))".to_string(),
    "(define-fun indexWord17 ((w Word)) Byte ((_ extract 119 112) w))".to_string(),
    "(define-fun indexWord16 ((w Word)) Byte ((_ extract 127 120) w))".to_string(),
    "(define-fun indexWord15 ((w Word)) Byte ((_ extract 135 128) w))".to_string(),
    "(define-fun indexWord14 ((w Word)) Byte ((_ extract 143 136) w))".to_string(),
    "(define-fun indexWord13 ((w Word)) Byte ((_ extract 151 144) w))".to_string(),
    "(define-fun indexWord12 ((w Word)) Byte ((_ extract 159 152) w))".to_string(),
    "(define-fun indexWord11 ((w Word)) Byte ((_ extract 167 160) w))".to_string(),
    "(define-fun indexWord10 ((w Word)) Byte ((_ extract 175 168) w))".to_string(),
    "(define-fun indexWord9 ((w Word)) Byte ((_ extract 183 176) w))".to_string(),
    "(define-fun indexWord8 ((w Word)) Byte ((_ extract 191 184) w))".to_string(),
    "(define-fun indexWord7 ((w Word)) Byte ((_ extract 199 192) w))".to_string(),
    "(define-fun indexWord6 ((w Word)) Byte ((_ extract 207 200) w))".to_string(),
    "(define-fun indexWord5 ((w Word)) Byte ((_ extract 215 208) w))".to_string(),
    "(define-fun indexWord4 ((w Word)) Byte ((_ extract 223 216) w))".to_string(),
    "(define-fun indexWord3 ((w Word)) Byte ((_ extract 231 224) w))".to_string(),
    "(define-fun indexWord2 ((w Word)) Byte ((_ extract 239 232) w))".to_string(),
    "(define-fun indexWord1 ((w Word)) Byte ((_ extract 247 240) w))".to_string(),
    "(define-fun indexWord0 ((w Word)) Byte ((_ extract 255 248) w))".to_string(),
    "".to_string(),
    "; symbolic word indexing".to_string(),
    "; a bitshift based version might be more performant here...".to_string(),
    "(define-fun indexWord ((idx Word) (w Word)) Byte".to_string(),
    "  (ite (bvuge idx (_ bv32 256)) (_ bv0 8)".to_string(),
    "  (ite (= idx (_ bv31 256)) (indexWord31 w)".to_string(),
    "  (ite (= idx (_ bv30 256)) (indexWord30 w)".to_string(),
    "  (ite (= idx (_ bv29 256)) (indexWord29 w)".to_string(),
    "  (ite (= idx (_ bv28 256)) (indexWord28 w)".to_string(),
    "  (ite (= idx (_ bv27 256)) (indexWord27 w)".to_string(),
    "  (ite (= idx (_ bv26 256)) (indexWord26 w)".to_string(),
    "  (ite (= idx (_ bv25 256)) (indexWord25 w)".to_string(),
    "  (ite (= idx (_ bv24 256)) (indexWord24 w)".to_string(),
    "  (ite (= idx (_ bv23 256)) (indexWord23 w)".to_string(),
    "  (ite (= idx (_ bv22 256)) (indexWord22 w)".to_string(),
    "  (ite (= idx (_ bv21 256)) (indexWord21 w)".to_string(),
    "  (ite (= idx (_ bv20 256)) (indexWord20 w)".to_string(),
    "  (ite (= idx (_ bv19 256)) (indexWord19 w)".to_string(),
    "  (ite (= idx (_ bv18 256)) (indexWord18 w)".to_string(),
    "  (ite (= idx (_ bv17 256)) (indexWord17 w)".to_string(),
    "  (ite (= idx (_ bv16 256)) (indexWord16 w)".to_string(),
    "  (ite (= idx (_ bv15 256)) (indexWord15 w)".to_string(),
    "  (ite (= idx (_ bv14 256)) (indexWord14 w)".to_string(),
    "  (ite (= idx (_ bv13 256)) (indexWord13 w)".to_string(),
    "  (ite (= idx (_ bv12 256)) (indexWord12 w)".to_string(),
    "  (ite (= idx (_ bv11 256)) (indexWord11 w)".to_string(),
    "  (ite (= idx (_ bv10 256)) (indexWord10 w)".to_string(),
    "  (ite (= idx (_ bv9 256)) (indexWord9 w)".to_string(),
    "  (ite (= idx (_ bv8 256)) (indexWord8 w)".to_string(),
    "  (ite (= idx (_ bv7 256)) (indexWord7 w)".to_string(),
    "  (ite (= idx (_ bv6 256)) (indexWord6 w)".to_string(),
    "  (ite (= idx (_ bv5 256)) (indexWord5 w)".to_string(),
    "  (ite (= idx (_ bv4 256)) (indexWord4 w)".to_string(),
    "  (ite (= idx (_ bv3 256)) (indexWord3 w)".to_string(),
    "  (ite (= idx (_ bv2 256)) (indexWord2 w)".to_string(),
    "  (ite (= idx (_ bv1 256)) (indexWord1 w)".to_string(),
    "  (indexWord0 w)".to_string(),
    "  ))))))))))))))))))))))))))))))))".to_string(),
    ")".to_string(),
    "".to_string(),
    "(define-fun readWord ((idx Word) (buf Buf)) Word".to_string(),
    "  (concat".to_string(),
    "    (select buf idx)".to_string(),
    "    (concat (select buf (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000001))".to_string(),
    "    (concat (select buf (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000002))".to_string(),
    "    (concat (select buf (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000003))".to_string(),
    "    (concat (select buf (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000004))".to_string(),
    "    (concat (select buf (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000005))".to_string(),
    "    (concat (select buf (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000006))".to_string(),
    "    (concat (select buf (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000007))".to_string(),
    "    (concat (select buf (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000008))".to_string(),
    "    (concat (select buf (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000009))".to_string(),
    "    (concat (select buf (bvadd idx #x000000000000000000000000000000000000000000000000000000000000000a))".to_string(),
    "    (concat (select buf (bvadd idx #x000000000000000000000000000000000000000000000000000000000000000b))".to_string(),
    "    (concat (select buf (bvadd idx #x000000000000000000000000000000000000000000000000000000000000000c))".to_string(),
    "    (concat (select buf (bvadd idx #x000000000000000000000000000000000000000000000000000000000000000d))".to_string(),
    "    (concat (select buf (bvadd idx #x000000000000000000000000000000000000000000000000000000000000000e))".to_string(),
    "    (concat (select buf (bvadd idx #x000000000000000000000000000000000000000000000000000000000000000f))".to_string(),
    "    (concat (select buf (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000010))".to_string(),
    "    (concat (select buf (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000011))".to_string(),
    "    (concat (select buf (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000012))".to_string(),
    "    (concat (select buf (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000013))".to_string(),
    "    (concat (select buf (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000014))".to_string(),
    "    (concat (select buf (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000015))".to_string(),
    "    (concat (select buf (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000016))".to_string(),
    "    (concat (select buf (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000017))".to_string(),
    "    (concat (select buf (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000018))".to_string(),
    "    (concat (select buf (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000019))".to_string(),
    "    (concat (select buf (bvadd idx #x000000000000000000000000000000000000000000000000000000000000001a))".to_string(),
    "    (concat (select buf (bvadd idx #x000000000000000000000000000000000000000000000000000000000000001b))".to_string(),
    "    (concat (select buf (bvadd idx #x000000000000000000000000000000000000000000000000000000000000001c))".to_string(),
    "    (concat (select buf (bvadd idx #x000000000000000000000000000000000000000000000000000000000000001d))".to_string(),
    "    (concat (select buf (bvadd idx #x000000000000000000000000000000000000000000000000000000000000001e))".to_string(),
    "    (select buf (bvadd idx #x000000000000000000000000000000000000000000000000000000000000001f))".to_string(),
    "    ))))))))))))))))))))))))))))))".to_string(),
    "  )".to_string(),
    ")".to_string(),
    "".to_string(),
    "(define-fun writeWord ((idx Word) (val Word) (buf Buf)) Buf".to_string(),
    "    (store (store (store (store (store (store (store (store (store (store (store (store (store (store (store (store (store".to_string(),
    "    (store (store (store (store (store (store (store (store (store (store (store (store (store (store (store buf".to_string(),
    "    (bvadd idx #x000000000000000000000000000000000000000000000000000000000000001f) (indexWord31 val))".to_string(),
    "    (bvadd idx #x000000000000000000000000000000000000000000000000000000000000001e) (indexWord30 val))".to_string(),
    "    (bvadd idx #x000000000000000000000000000000000000000000000000000000000000001d) (indexWord29 val))".to_string(),
    "    (bvadd idx #x000000000000000000000000000000000000000000000000000000000000001c) (indexWord28 val))".to_string(),
    "    (bvadd idx #x000000000000000000000000000000000000000000000000000000000000001b) (indexWord27 val))".to_string(),
    "    (bvadd idx #x000000000000000000000000000000000000000000000000000000000000001a) (indexWord26 val))".to_string(),
    "    (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000019) (indexWord25 val))".to_string(),
    "    (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000018) (indexWord24 val))".to_string(),
    "    (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000017) (indexWord23 val))".to_string(),
    "    (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000016) (indexWord22 val))".to_string(),
    "    (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000015) (indexWord21 val))".to_string(),
    "    (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000014) (indexWord20 val))".to_string(),
    "    (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000013) (indexWord19 val))".to_string(),
    "    (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000012) (indexWord18 val))".to_string(),
    "    (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000011) (indexWord17 val))".to_string(),
    "    (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000010) (indexWord16 val))".to_string(),
    "    (bvadd idx #x000000000000000000000000000000000000000000000000000000000000000f) (indexWord15 val))".to_string(),
    "    (bvadd idx #x000000000000000000000000000000000000000000000000000000000000000e) (indexWord14 val))".to_string(),
    "    (bvadd idx #x000000000000000000000000000000000000000000000000000000000000000d) (indexWord13 val))".to_string(),
    "    (bvadd idx #x000000000000000000000000000000000000000000000000000000000000000c) (indexWord12 val))".to_string(),
    "    (bvadd idx #x000000000000000000000000000000000000000000000000000000000000000b) (indexWord11 val))".to_string(),
    "    (bvadd idx #x000000000000000000000000000000000000000000000000000000000000000a) (indexWord10 val))".to_string(),
    "    (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000009) (indexWord9 val))".to_string(),
    "    (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000008) (indexWord8 val))".to_string(),
    "    (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000007) (indexWord7 val))".to_string(),
    "    (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000006) (indexWord6 val))".to_string(),
    "    (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000005) (indexWord5 val))".to_string(),
    "    (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000004) (indexWord4 val))".to_string(),
    "    (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000003) (indexWord3 val))".to_string(),
    "    (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000002) (indexWord2 val))".to_string(),
    "    (bvadd idx #x0000000000000000000000000000000000000000000000000000000000000001) (indexWord1 val))".to_string(),
    "    idx (indexWord0 val))".to_string(),
    ")".to_string(),
    "".to_string(),
    "; block context".to_string(),
    "(declare-fun blockhash (Word) Word)".to_string(),
    "(declare-fun codesize (Addr) Word)".to_string(),
    "".to_string(),
    "; macros".to_string(),
    "(define-fun signext ( (b Word) (val Word)) Word".to_string(),
    "  (ite (= b (_ bv0  256)) ((_ sign_extend 248) ((_ extract 7    0) val))".to_string(),
    "  (ite (= b (_ bv1  256)) ((_ sign_extend 240) ((_ extract 15   0) val))".to_string(),
    "  (ite (= b (_ bv2  256)) ((_ sign_extend 232) ((_ extract 23   0) val))".to_string(),
    "  (ite (= b (_ bv3  256)) ((_ sign_extend 224) ((_ extract 31   0) val))".to_string(),
    "  (ite (= b (_ bv4  256)) ((_ sign_extend 216) ((_ extract 39   0) val))".to_string(),
    "  (ite (= b (_ bv5  256)) ((_ sign_extend 208) ((_ extract 47   0) val))".to_string(),
    "  (ite (= b (_ bv6  256)) ((_ sign_extend 200) ((_ extract 55   0) val))".to_string(),
    "  (ite (= b (_ bv7  256)) ((_ sign_extend 192) ((_ extract 63   0) val))".to_string(),
    "  (ite (= b (_ bv8  256)) ((_ sign_extend 184) ((_ extract 71   0) val))".to_string(),
    "  (ite (= b (_ bv9  256)) ((_ sign_extend 176) ((_ extract 79   0) val))".to_string(),
    "  (ite (= b (_ bv10 256)) ((_ sign_extend 168) ((_ extract 87   0) val))".to_string(),
    "  (ite (= b (_ bv11 256)) ((_ sign_extend 160) ((_ extract 95   0) val))".to_string(),
    "  (ite (= b (_ bv12 256)) ((_ sign_extend 152) ((_ extract 103  0) val))".to_string(),
    "  (ite (= b (_ bv13 256)) ((_ sign_extend 144) ((_ extract 111  0) val))".to_string(),
    "  (ite (= b (_ bv14 256)) ((_ sign_extend 136) ((_ extract 119  0) val))".to_string(),
    "  (ite (= b (_ bv15 256)) ((_ sign_extend 128) ((_ extract 127  0) val))".to_string(),
    "  (ite (= b (_ bv16 256)) ((_ sign_extend 120) ((_ extract 135  0) val))".to_string(),
    "  (ite (= b (_ bv17 256)) ((_ sign_extend 112) ((_ extract 143  0) val))".to_string(),
    "  (ite (= b (_ bv18 256)) ((_ sign_extend 104) ((_ extract 151  0) val))".to_string(),
    "  (ite (= b (_ bv19 256)) ((_ sign_extend 96 ) ((_ extract 159  0) val))".to_string(),
    "  (ite (= b (_ bv20 256)) ((_ sign_extend 88 ) ((_ extract 167  0) val))".to_string(),
    "  (ite (= b (_ bv21 256)) ((_ sign_extend 80 ) ((_ extract 175  0) val))".to_string(),
    "  (ite (= b (_ bv22 256)) ((_ sign_extend 72 ) ((_ extract 183  0) val))".to_string(),
    "  (ite (= b (_ bv23 256)) ((_ sign_extend 64 ) ((_ extract 191  0) val))".to_string(),
    "  (ite (= b (_ bv24 256)) ((_ sign_extend 56 ) ((_ extract 199  0) val))".to_string(),
    "  (ite (= b (_ bv25 256)) ((_ sign_extend 48 ) ((_ extract 207  0) val))".to_string(),
    "  (ite (= b (_ bv26 256)) ((_ sign_extend 40 ) ((_ extract 215  0) val))".to_string(),
    "  (ite (= b (_ bv27 256)) ((_ sign_extend 32 ) ((_ extract 223  0) val))".to_string(),
    "  (ite (= b (_ bv28 256)) ((_ sign_extend 24 ) ((_ extract 231  0) val))".to_string(),
    "  (ite (= b (_ bv29 256)) ((_ sign_extend 16 ) ((_ extract 239  0) val))".to_string(),
    "  (ite (= b (_ bv30 256)) ((_ sign_extend 8  ) ((_ extract 247  0) val)) val))))))))))))))))))))))))))))))))".to_string()
    ],
    RefinementEqs(vec![], vec![]),
    CexVars::new(),
    vec![],
  )
}

fn smt2_line(txt: Builder) -> SMT2 {
  SMT2(vec![txt], RefinementEqs(vec![], vec![]), CexVars::new(), vec![])
}

fn is_abstract_store(e: Expr) -> bool {
  match e {
    Expr::AbstractStore(_, _) => true,
    _ => false,
  }
}

/// Finds storage reads from an abstract storage property.
fn find_storage_reads(p: &Prop) -> HashMap<(Expr, Option<W256>), HashSet<Expr>> {
  fn f(expr: &Expr) -> AddableVec<((Expr, Option<W256>), HashSet<Expr>)> {
    match expr {
      Expr::SLoad(slot, store) => {
        if contains_node(|e: &Expr| is_abstract_store(e.clone()), store.clone()) {
          let addr = get_addr(store.clone()).unwrap_or_else(|| panic!("could not extract address from store"));
          let idx = get_logical_idx(store.clone());
          let hs = HashSet::from([*slot.clone()]);
          AddableVec::from_vec(vec![((addr, idx), hs)])
        } else {
          AddableVec::from_vec(vec![])
        }
      }
      _ => AddableVec::from_vec(vec![]),
    }
  }
  let result = fold_prop(&mut &f, AddableVec::from_vec(vec![]), p.clone());

  result.to_vec().into_iter().map(|item| (item.0, item.1)).collect()
}

fn find_buffer_access<T: TraversableTerm>(term: &Vec<T>) -> Vec<(Expr, Expr, Expr)> {
  fn go(a: &Expr) -> AddableVec<(Expr, Expr, Expr)> {
    match a.clone() {
      Expr::ReadWord(idx, buf) => AddableVec::from_vec(vec![(*idx, Expr::Lit(W256(32, 0)), *buf)]),
      Expr::ReadByte(idx, buf) => AddableVec::from_vec(vec![(*idx, Expr::Lit(W256(1, 0)), *buf)]),
      Expr::CopySlice(src_off, _, size, src, _) => AddableVec::from_vec(vec![(*src_off, *size, *src)]),
      _ => AddableVec::from_vec(vec![]),
    }
  }

  let mut result: Vec<(Expr, Expr, Expr)> = vec![];
  for t in term {
    result.extend(t.fold_term(&mut go, AddableVec::from_vec(vec![])).to_vec());
  }
  result
}

// Function to parse Z3 output and extract variable assignments
pub fn parse_z3_output(z3_output: &str) -> HashMap<String, (String, u128)> {
  // Regular expression to match (define-fun <name> () (_ BitVec 256) #x<value>)
  let pattern = r"\(define-fun\s+(\w+)\s+\(\)\s+\(_\s+BitVec\s+256\)\s+#x([0-9a-fA-F]+)\)";
  let regex = Regex::new(pattern).unwrap();

  // Create a HashMap to store the results
  let mut result = HashMap::new();

  // Find all matches in the Z3 output
  for cap in regex.captures_iter(z3_output) {
    let name = cap[1].to_string();
    let hex_value = cap[2].to_string();
    // Convert hex to decimal (u128 to handle large numbers)
    let decimal_value = u128::from_str_radix(&hex_value, 16).unwrap();
    result.insert(name, (hex_value, decimal_value));
  }

  result
}
