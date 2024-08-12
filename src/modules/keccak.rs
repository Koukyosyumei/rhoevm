use std::collections::HashSet;

use crate::modules::expr::simplify;
use crate::modules::traversals::{fold_expr, fold_prop, map_prop_m};
use crate::modules::types::{keccak, keccak_prime, AddableVec, Expr, Prop, W256};

/// A store that maintains a set of expressions involving the Keccak hash function.
#[derive(Debug, Clone)]
struct KeccakStore {
  /// A set of expressions that are identified as involving the Keccak hash function.
  keccak_eqs: HashSet<Expr>,
}

impl KeccakStore {
  /// Creates a new `KeccakStore`.
  ///
  /// # Returns
  ///
  /// A new, empty instance of `KeccakStore`.
  fn new() -> Self {
    KeccakStore { keccak_eqs: HashSet::new() }
  }
}

/// Identifies and stores Keccak expressions found in the given expression.
///
/// # Arguments
///
/// * `e` - An expression to be analyzed.
/// * `store` - A mutable reference to a `KeccakStore` where identified Keccak expressions will be stored.
///
/// # Returns
///
/// The original expression `e`.
fn keccak_finder(e: Expr, store: &mut KeccakStore) -> Expr {
  match e {
    Expr::Keccak(_) => {
      store.keccak_eqs.insert(e.clone());
      e
    }
    _ => e,
  }
}

/// Finds and stores Keccak expressions in the given expression.
///
/// # Arguments
///
/// * `e` - An expression to be analyzed.
/// * `store` - A mutable reference to a `KeccakStore` where identified Keccak expressions will be stored.
///
/// # Returns
///
/// The original expression `e`.
fn find_keccak_expr(e: Expr, store: &mut KeccakStore) -> Expr {
  match e {
    Expr::Keccak(_) => {
      store.keccak_eqs.insert(e.clone());
      e
    }
    _ => e,
  }
}

/// Finds and stores Keccak expressions within the given proposition.
///
/// # Arguments
///
/// * `p` - A proposition to be analyzed.
/// * `store` - A mutable reference to a `KeccakStore` where identified Keccak expressions will be stored.
///
/// # Returns
///
/// The original proposition `p`.
fn find_keccak_prop(p: Prop, mut store: &mut KeccakStore) -> Prop {
  let mut kf = |e: &Expr| keccak_finder(e.clone(), &mut store);
  map_prop_m(&mut kf, p)
}

/// Identifies and stores Keccak expressions found in a list of propositions, buffers, and stores.
///
/// # Arguments
///
/// * `ps` - A slice of boxed propositions to be analyzed.
/// * `bufs` - A slice of expressions (buffers) to be analyzed.
/// * `stores` - A slice of expressions (stores) to be analyzed.
/// * `store` - A mutable reference to a `KeccakStore` where identified Keccak expressions will be stored.
fn find_keccak_props_exprs(ps: &[Box<Prop>], bufs: &[Expr], stores: &[Expr], store: &mut KeccakStore) {
  for p in ps {
    find_keccak_prop(*p.clone(), store);
  }
  for b in bufs {
    find_keccak_expr(b.clone(), store);
  }
  for s in stores {
    find_keccak_expr(s.clone(), store);
  }
}

/// Combines elements of a list into pairs.
///
/// # Arguments
///
/// * `lst` - A slice of elements to be paired.
///
/// # Returns
///
/// A vector containing pairs of elements from the input slice.
fn combine<T: Clone>(lst: &[T]) -> Vec<(T, T)> {
  let mut result = Vec::new();
  for (i, x) in lst.iter().enumerate() {
    for y in &lst[i + 1..] {
      result.push((x.clone(), y.clone()));
    }
  }
  result
}

/// Creates a minimal proposition involving a Keccak expression.
///
/// # Arguments
///
/// * `k` - An expression expected to be a Keccak expression.
///
/// # Returns
///
/// A boxed proposition involving the Keccak expression `k`.
///
/// # Panics
///
/// Panics if the input expression is not a Keccak expression.
fn min_prop(k: Expr) -> Box<Prop> {
  match k {
    Expr::Keccak(_) => Box::new(Prop::PGT(k, Expr::Lit(W256(256, 0)))),
    _ => panic!("expected keccak expression"),
  }
}

/// Creates a proposition representing the concrete value of a Keccak expression.
///
/// # Arguments
///
/// * `k` - A Keccak expression.
///
/// # Returns
///
/// A boxed proposition representing the concrete value of the Keccak expression.
fn conc_val(k: Expr) -> Box<Prop> {
  match k.clone() {
    Expr::Keccak(cbuf) => match *cbuf.clone() {
      Expr::ConcreteBuf(bs) => Box::new(Prop::PEq(Expr::Lit(keccak_prime(&bs)), k)),
      _ => Box::new(Prop::PBool(true)),
    },
    _ => Box::new(Prop::PBool(true)),
  }
}

/// Creates a proposition representing the injectivity property of two Keccak expressions.
///
/// # Arguments
///
/// * `k1` - The first Keccak expression.
/// * `k2` - The second Keccak expression.
///
/// # Returns
///
/// A proposition representing the injectivity property of the two Keccak expressions.
///
/// # Panics
///
/// Panics if the input expressions are not both Keccak expressions.
fn inj_prop(k1: Expr, k2: Expr) -> Prop {
  match (k1.clone(), k2.clone()) {
    (Expr::Keccak(b1), Expr::Keccak(b2)) => Prop::POr(
      Box::new(Prop::PAnd(
        Box::new(Prop::PEq(*b1.clone(), *b2.clone())),
        Box::new(Prop::PEq(Expr::BufLength(Box::new(*b1)), Expr::BufLength(Box::new(*b2)))),
      )),
      Box::new(Prop::PNeg(Box::new(Prop::PEq(k1, k2)))),
    ),
    _ => panic!("expected keccak expression"),
  }
}

/// Generates assumptions based on identified Keccak expressions in the provided propositions, buffers, and stores.
///
/// # Arguments
///
/// * `ps` - A slice of boxed propositions to be analyzed.
/// * `bufs` - A slice of expressions (buffers) to be analyzed.
/// * `stores` - A slice of expressions (stores) to be analyzed.
///
/// # Returns
///
/// A vector of boxed propositions representing the generated assumptions.
pub fn keccak_assumptions(ps: &[Box<Prop>], bufs: &[Expr], stores: &[Expr]) -> Vec<Box<Prop>> {
  let mut store = KeccakStore::new();
  find_keccak_props_exprs(ps, bufs, stores, &mut store);

  let injectivity: Vec<Box<Prop>> = combine(&store.keccak_eqs.iter().cloned().collect::<Vec<_>>())
    .into_iter()
    .map(|(a, b)| Box::new(inj_prop(a, b)))
    .collect();

  let conc_values: Vec<Box<Prop>> = store.keccak_eqs.iter().cloned().map(conc_val).collect();
  let min_value: Vec<Box<Prop>> = store.keccak_eqs.iter().cloned().map(min_prop).collect();

  let min_diff_of_pairs: Vec<Box<Prop>> = store
    .keccak_eqs
    .iter()
    .cloned()
    .flat_map(|a| store.keccak_eqs.iter().cloned().map(move |b| (a.clone(), b.clone())))
    .filter(|(a, b)| a != b)
    .map(|(ka, kb)| Box::new(min_distance(ka, kb)))
    .collect();

  injectivity.into_iter().chain(conc_values).chain(min_value).chain(min_diff_of_pairs).collect()
}

/// Creates a proposition representing the minimum distance between two distinct Keccak expressions.
///
/// # Arguments
///
/// * `ka` - The first Keccak expression.
/// * `kb` - The second Keccak expression.
///
/// # Returns
///
/// A proposition representing the minimum distance between the two Keccak expressions.
///
/// # Panics
///
/// Panics if the input expressions are not both Keccak expressions.
fn min_distance(ka: Expr, kb: Expr) -> Prop {
  match (ka.clone(), kb.clone()) {
    (Expr::Keccak(a), Expr::Keccak(b)) => Prop::PImpl(
      Box::new(Prop::PNeg(Box::new(Prop::PEq(*a, *b)))),
      Box::new(Prop::PAnd(
        Box::new(Prop::PGEq(Expr::Sub(Box::new(ka.clone()), Box::new(kb.clone())), Expr::Lit(W256(256, 0)))),
        Box::new(Prop::PGEq(Expr::Sub(Box::new(kb), Box::new(ka)), Expr::Lit(W256(256, 0)))),
      )),
    ),
    _ => panic!("expected Keccak expression"),
  }
}

/// Computes the implications of an expression involving the Keccak hash function.
///
/// # Arguments
///
/// * `e` - A reference to the expression to be analyzed.
///
/// # Returns
///
/// An `AddableVec` containing boxed propositions derived from the analysis.
fn compute(e: &Expr) -> AddableVec<Box<Prop>> {
  match e.clone() {
    Expr::Keccak(buf) => {
      let b = simplify(buf);
      match keccak(b).unwrap() {
        lit @ Expr::Lit(_) => AddableVec::from_vec(vec![Box::new(Prop::PEq(e.clone(), lit))]),
        _ => AddableVec::from_vec(vec![]),
      }
    }
    _ => AddableVec::from_vec(vec![]),
  }
}

/// Computes the implications of Keccak expressions found in a given expression.
///
/// # Arguments
///
/// * `e` - An expression to be analyzed.
///
/// # Returns
///
/// An `AddableVec` containing boxed propositions derived from the analysis.
fn compute_keccak_expr(e: Expr) -> AddableVec<Box<Prop>> {
  fold_expr(&mut compute, AddableVec::from_vec(vec![]), &e)
}

/// Computes the implications of Keccak expressions found in a given proposition.
///
/// # Arguments
///
/// * `p` - A proposition to be analyzed.
///
/// # Returns
///
/// An `AddableVec` containing boxed propositions derived from the analysis.
fn compute_keccak_prop(p: Prop) -> AddableVec<Box<Prop>> {
  fold_prop(&mut compute, AddableVec::from_vec(vec![]), p)
}

/// Computes the implications of Keccak expressions found in the provided propositions, buffers, and stores.
///
/// # Arguments
///
/// * `ps` - A slice of boxed propositions to be analyzed.
/// * `bufs` - A slice of expressions (buffers) to be analyzed.
/// * `stores` - A slice of expressions (stores) to be analyzed.
///
/// # Returns
///
/// A vector of boxed propositions representing the computed implications.
pub fn keccak_compute(ps: &[Box<Prop>], bufs: &[Expr], stores: &[Expr]) -> Vec<Box<Prop>> {
  let mut result = Vec::new();
  for p in ps {
    result.extend(compute_keccak_prop(*p.clone()).to_vec());
  }
  for b in bufs {
    result.extend(compute_keccak_expr(b.clone()).to_vec());
  }
  for s in stores {
    result.extend(compute_keccak_expr(s.clone()).to_vec());
  }
  result
}
