use crate::modules::types::{Addr, Expr, Prop, W256};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::Hash;

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
#[derive(Debug, PartialEq, Eq)]
struct RefinementEqs(Vec<Builder>, Vec<Prop>);

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
#[derive(Debug, PartialEq, Eq)]
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
#[derive(Debug, PartialEq, Eq)]
struct CexVars {
  calldata: Vec<Text>,
  addrs: Vec<Text>,
  buffers: HashMap<Text, Expr>,
  store_reads: HashMap<(Expr, Option<W256>), HashSet<Expr>>,
  block_context: Vec<Text>,
  tx_context: Vec<Text>,
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

// Implementing Eq and Show traits for CexVars
impl Eq for CexVars {}

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
  let buffers = cex
    .buffers
    .into_iter()
    .map(|(k, v)| {
      match v {
        BufModel::Comp(compressed) => collapse(compressed).map(BufModel::Flat),
        BufModel::Flat(bytes) => Some(BufModel::Flat(bytes)),
      }
      .map(|flat| (k, flat))
    })
    .collect::<Option<HashMap<Expr, BufModel>>>()?;

  Some(SMTCex {
    vars: cex.vars,
    addrs: cex.addrs,
    buffers,
    store: cex.store,
    block_context: cex.block_context,
    tx_context: cex.tx_context,
  })
}

// Function to collapse a BufModel
fn collapse(model: CompressedBuf) -> Option<BufModel> {
  match model {
    CompressedBuf::Base { byte, length } if length <= 120_000_000 => {
      let bytes = vec![byte; unsafe_into(length)];
      Some(BufModel::Flat(bytes))
    }
    CompressedBuf::Write { byte, idx, next } => collapse(*next).map(|flat| {
      let mut flat_bytes = flat.into_flat_bytes();
      write_byte(&mut flat_bytes, idx, byte);
      BufModel::Flat(flat_bytes)
    }),
    CompressedBuf::Flat(bytes) => Some(BufModel::Flat(bytes)),
  }
}

struct AbstState {
  words: HashMap<Expr, i32>,
  count: i32,
}

fn get_var(cex: &SMTCex, name: &str) -> TS::Text {
  cex.vars.get(&Var(name.to_string())).unwrap().clone()
}

fn declare_intermediates(bufs: &BufEnv, stores: &StoreEnv) -> SMT2 {
  let enc_ss = stores.iter().map(|(k, v)| encode_store(k, v)).collect::<Vec<_>>();
  let enc_bs = bufs.iter().map(|(k, v)| encode_buf(k, v)).collect::<Vec<_>>();
  let mut sorted = enc_ss;
  sorted.extend(enc_bs);
  sorted.sort_by(|(l, _), (r, _)| l.cmp(r));

  let decls = sorted.iter().map(|(_, decl)| decl.clone()).collect::<Vec<_>>();
  let mut smt2 = SMT2 {
    ls: vec![from_text("; intermediate buffers & stores")],
    refps: RefinementEqs::new(),
    cex_vars: CexVars::new(),
    props: vec![],
  };
  for decl in decls.iter().rev() {
    smt2 = smt2.combine(decl.clone());
  }
  smt2
}

fn encode_store(n: &str, expr: &Expr) -> (usize, SMT2) {
  let expr_to_smt = expr_to_smt(expr);
  let txt = format!("(define-fun store{} () Storage {})", n, expr_to_smt);
  (
    n.parse().unwrap(),
    SMT2::new(vec![from_text(&txt)], RefinementEqs::new(), CexVars::new(), vec![]),
  )
}

fn encode_buf(n: &str, expr: &Expr) -> (usize, SMT2) {
  let expr_to_smt = expr_to_smt(expr);
  let txt = format!("(define-fun buf{} () Buf {})", n, expr_to_smt);
  (
    n.parse().unwrap(),
    SMT2::new(vec![from_text(&txt)], RefinementEqs::new(), CexVars::new(), vec![]),
  )
}

fn abstract_away_props(conf: &Config, ps: Vec<Prop>) -> (Vec<Prop>, AbstState) {
  let mut state = AbstState {
    words: HashMap::new(),
    count: 0,
  };
  let abstracted = ps.iter().map(|prop| abstract_away(conf, prop, &mut state)).collect::<Vec<_>>();
  (abstracted, state)
}

fn abstract_away(conf: &Config, prop: &Prop, state: &mut AbstState) -> Prop {
  map_prop_m(conf, prop, state)
}

fn map_prop_m(conf: &Config, prop: &Prop, state: &mut AbstState) -> Prop {
  match prop {
    Mod(_) if conf.abst_refine_arith => abstr_expr(prop, state),
    SMod(_) if conf.abst_refine_arith => abstr_expr(prop, state),
    MulMod(_) if conf.abst_refine_arith => abstr_expr(prop, state),
    AddMod(_) if conf.abst_refine_arith => abstr_expr(prop, state),
    Mul(_) if conf.abst_refine_arith => abstr_expr(prop, state),
    Div(_) if conf.abst_refine_arith => abstr_expr(prop, state),
    SDiv(_) if conf.abst_refine_arith => abstr_expr(prop, state),
    ReadWord(_) if conf.abst_refine_mem => abstr_expr(prop, state),
    _ => prop.clone(),
  }
}

fn abstr_expr(prop: &Prop, state: &mut AbstState) -> Prop {
  let v = match state.words.get(&prop) {
    Some(&v) => v,
    None => {
      let next = state.count;
      state.words.insert(prop.clone(), next);
      state.count += 1;
      next
    }
  };
  let name = format!("abst_{}", v);
  Var(name.into())
}

fn assert_props(conf: &Config, ps: Vec<Prop>) -> SMT2 {
  let simplified_ps = decompose(simplify_props(ps));
  let decls = declare_intermediates(bufs, stores);
  let encs = ps.iter().map(|p| prop_to_smt(p)).collect::<Vec<_>>();
  let abst_smt = abst_props.iter().map(|p| prop_to_smt(p)).collect::<Vec<_>>();
  let smt2 = SMT2::new(vec![], RefinementEqs::new(), CexVars::new(), vec![])
    .combine(smt2_line("; intermediate buffers & stores"))
    .combine(decls)
    .combine(smt2_line(""))
    .combine(declare_addrs(addresses))
    .combine(smt2_line(""))
    .combine(declare_bufs(to_declare_ps_elim, bufs, stores))
    .combine(smt2_line(""))
    .combine(declare_vars(nub_ord(all_vars.iter().fold(Vec::new(), |mut acc, x| {
      acc.extend(x.clone());
      acc
    }))))
    .combine(smt2_line(""))
    .combine(declare_frame_context(nub_ord(frame_ctx.iter().fold(
      Vec::new(),
      |mut acc, x| {
        acc.extend(x.clone());
        acc
      },
    ))))
    .combine(smt2_line(""))
    .combine(declare_block_context(nub_ord(block_ctx.iter().fold(
      Vec::new(),
      |mut acc, x| {
        acc.extend(x.clone());
        acc
      },
    ))))
    .combine(smt2_line(""))
    .combine(intermediates)
    .combine(smt2_line(""))
    .combine(keccak_assertions)
    .combine(read_assumes)
    .combine(smt2_line(""));

  encs.iter().for_each(|p| {
    smt2.combine(SMT2::new(
      vec![from_text(&format!("(assert {})", p))],
      RefinementEqs::new(),
      CexVars::new(),
      vec![],
    ));
  });
  SMT2::new(vec![], RefinementEqs::new(), CexVars::new(), vec![])
    .combine(smt2_line("; keccak assumptions"))
    .combine(SMT2::new(
      kecc_assump.iter().map(|p| from_text(&format!("(assert {})", prop_to_smt(p)))).collect::<Vec<_>>(),
      RefinementEqs::new(),
      CexVars::new(),
      vec![],
    ))
    .combine(smt2_line("; keccak computations"))
    .combine(SMT2::new(
      kecc_comp.iter().map(|p| from_text(&format!("(assert {})", prop_to_smt(p)))).collect::<Vec<_>>(),
      RefinementEqs::new(),
      CexVars::new(),
      vec![],
    ))
    .combine(smt2_line(""))
    .combine(SMT2::new(vec![], RefinementEqs::new(), storage_reads, vec![]))
    .combine(SMT2::new(vec![], RefinementEqs::new(), CexVars::new(), ps_pre_conc))
}
