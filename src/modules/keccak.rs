// SPDX-License-Identifier: MIT

/// Module: evm::keccak
/// Description: Functions to determine Keccak assumptions
use std::collections::HashSet;

use crate::modules::expr::simplify;
use crate::modules::traversals::{fold_expr, fold_prop, map_prop_m};
use crate::modules::types::{keccak, keccak_prime, unbox, AddableVec, Expr, Prop, W256};

#[derive(Debug, Clone)]
struct KeccakStore {
  keccak_eqs: HashSet<Expr>,
}

impl KeccakStore {
  fn new() -> Self {
    KeccakStore { keccak_eqs: HashSet::new() }
  }
}

fn keccak_finder(e: Expr, store: &mut KeccakStore) -> Expr {
  match e {
    Expr::Keccak(_) => {
      store.keccak_eqs.insert(e.clone());
      e
    }
    _ => e,
  }
}

fn find_keccak_expr(e: Expr, store: &mut KeccakStore) -> Expr {
  match e {
    Expr::Keccak(_) => {
      store.keccak_eqs.insert(e.clone());
      e
    }
    _ => e,
  }
}

fn find_keccak_prop(p: Prop, mut store: &mut KeccakStore) -> Prop {
  let mut kf = |e: &Expr| keccak_finder(e.clone(), &mut store);
  map_prop_m(&mut kf, p)
}

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

fn combine<T: Clone>(lst: &[T]) -> Vec<(T, T)> {
  let mut result = Vec::new();
  for (i, x) in lst.iter().enumerate() {
    for y in &lst[i + 1..] {
      result.push((x.clone(), y.clone()));
    }
  }
  result
}

fn min_prop(k: Expr) -> Box<Prop> {
  match k {
    Expr::Keccak(_) => Box::new(Prop::PGT(k, Expr::Lit(W256(256, 0)))),
    _ => panic!("expected keccak expression"),
  }
}

fn conc_val(k: Expr) -> Box<Prop> {
  match k.clone() {
    Expr::Keccak(cbuf) => match unbox(cbuf) {
      Expr::ConcreteBuf(bs) => Box::new(Prop::PEq(Expr::Lit(keccak_prime(&bs)), k)),
      _ => Box::new(Prop::PBool(true)),
    },
    _ => Box::new(Prop::PBool(true)),
  }
}

fn inj_prop(k1: Expr, k2: Expr) -> Prop {
  match (k1.clone(), k2.clone()) {
    (Expr::Keccak(b1), Expr::Keccak(b2)) => Prop::POr(
      Box::new(Prop::PAnd(
        Box::new(Prop::PEq(unbox(b1.clone()), unbox(b2.clone()))),
        Box::new(Prop::PEq(Expr::BufLength(Box::new(*b1)), Expr::BufLength(Box::new(*b2)))),
      )),
      Box::new(Prop::PNeg(Box::new(Prop::PEq(k1, k2)))),
    ),
    _ => panic!("expected keccak expression"),
  }
}

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

fn compute_keccak_expr(e: Expr) -> AddableVec<Box<Prop>> {
  fold_expr(&mut compute, AddableVec::from_vec(vec![]), &e)
}

fn compute_keccak_prop(p: Prop) -> AddableVec<Box<Prop>> {
  fold_prop(&mut compute, AddableVec::from_vec(vec![]), p)
}

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
