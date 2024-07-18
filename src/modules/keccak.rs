// SPDX-License-Identifier: MIT

use std::collections::HashMap;
/// Module: evm::keccak
/// Description: Functions to determine Keccak assumptions
use std::collections::HashSet;

use crate::modules::traversals::{map_expr_m, map_prop_m};
use crate::modules::types::{unbox, Expr, Prop};

#[derive(Debug, Clone)]
struct KeccakStore {
  keccak_eqs: HashSet<Expr>,
}

impl KeccakStore {
  fn new() -> Self {
    KeccakStore {
      keccak_eqs: HashSet::new(),
    }
  }
}

fn keccak_finder<A>(e: Expr, store: &mut KeccakStore) -> Expr {
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

fn find_keccak_prop(p: Prop, store: &mut KeccakStore) -> Prop {
  // map_prop_m(keccak_finder, p, store).await
  todo!()
}

fn find_keccak_props_exprs(ps: &[Prop], bufs: &[Expr], stores: &[Expr], store: &mut KeccakStore) {
  for p in ps {
    find_keccak_prop(p.clone(), store);
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

fn min_prop(k: Expr) -> Prop {
  match k {
    Expr::Keccak(_) => Prop::PGT(k, Expr::Lit(256)),
    _ => panic!("expected keccak expression"),
  }
}

fn conc_val(k: Expr) -> Prop {
  match k {
    Expr::Keccak(cbuf) => match unbox(cbuf) {
      Expr::ConcreteBuf(bs) => Prop::PEq(Expr::Lit(keccak(&bs)), k),
      _ => Prop::PBool(true),
    },
    _ => Prop::PBool(true),
  }
}

fn inj_prop(k1: Expr, k2: Expr) -> Prop {
  match (k1.clone(), k2.clone()) {
    (Expr::Keccak(b1), Expr::Keccak(b2)) => Prop::POr(
      Box::new(Prop::PAnd(
        Box::new(Prop::PEq(unbox(b1.clone()), unbox(b2.clone()))),
        Box::new(Prop::PEq(
          Expr::BufLength(Box::new(*b1)),
          Expr::BufLength(Box::new(*b2)),
        )),
      )),
      Box::new(Prop::PNeg(Box::new(Prop::PEq(k1, k2)))),
    ),
    _ => panic!("expected keccak expression"),
  }
}

pub fn keccak_assumptions(ps: &[Prop], bufs: &[Expr], stores: &[Expr]) -> Vec<Prop> {
  let mut store = KeccakStore::new();
  find_keccak_props_exprs(ps, bufs, stores, &mut store);

  let injectivity: Vec<Prop> =
    combine(&store.keccak_eqs.iter().cloned().collect::<Vec<_>>()).into_iter().map(|(a, b)| inj_prop(a, b)).collect();

  let conc_values: Vec<Prop> = store.keccak_eqs.iter().cloned().map(conc_val).collect();
  let min_value: Vec<Prop> = store.keccak_eqs.iter().cloned().map(min_prop).collect();

  let min_diff_of_pairs: Vec<Prop> = store
    .keccak_eqs
    .iter()
    .cloned()
    .flat_map(|a| store.keccak_eqs.iter().cloned().map(move |b| (a.clone(), b.clone())))
    .filter(|(a, b)| a != b)
    .map(|(ka, kb)| min_distance(ka, kb))
    .collect();

  injectivity.into_iter().chain(conc_values).chain(min_value).chain(min_diff_of_pairs).collect()
}

fn min_distance(ka: Expr, kb: Expr) -> Prop {
  match (ka.clone(), kb.clone()) {
    (Expr::Keccak(a), Expr::Keccak(b)) => Prop::PImpl(
      Box::new(Prop::PNeg(Box::new(Prop::PEq(*a, *b)))),
      Box::new(Prop::PAnd(
        Box::new(Prop::PGEq(
          (Expr::Sub(Box::new(ka.clone()), Box::new(kb.clone()))),
          (Expr::Lit(256)),
        )),
        Box::new(Prop::PGEq((Expr::Sub(Box::new(kb), Box::new(ka))), (Expr::Lit(256)))),
      )),
    ),
    _ => panic!("expected Keccak expression"),
  }
}

fn compute<A>(e: Expr) -> Vec<Prop> {
  match e {
    Expr::Keccak(buf) => {
      let b = simplify(buf);
      match keccak(&b) {
        Expr::Lit(_) => vec![Prop::PEq(e, Expr::Lit(keccak(&b)))],
        _ => vec![],
      }
    }
    _ => vec![],
  }
}

fn compute_keccak_expr(e: Expr) -> Vec<Prop> {
  // fold_expr(compute, vec![], e)
  todo!()
}

fn compute_keccak_prop(p: Prop) -> Vec<Prop> {
  // fold_prop(compute, vec![], p)
  todo!()
}

pub fn keccak_compute(ps: &[Prop], bufs: &[Expr], stores: &[Expr]) -> Vec<Prop> {
  let mut result = Vec::new();
  for p in ps {
    result.extend(compute_keccak_prop(p.clone()));
  }
  for b in bufs {
    result.extend(compute_keccak_expr(b.clone()));
  }
  for s in stores {
    result.extend(compute_keccak_expr(s.clone()));
  }
  result
}
