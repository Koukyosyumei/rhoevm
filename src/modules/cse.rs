use std::collections::HashMap;
use std::hash::Hash;

use crate::modules::traversals::map_prop_m;
use crate::modules::types::{Expr, GVar, Prop};

#[derive(Debug, Default, Clone)]
pub struct BuilderState {
  bufs: HashMap<Expr, usize>,
  stores: HashMap<Expr, usize>,
  count: usize,
}

pub type BufEnv = HashMap<usize, Expr>;
pub type StoreEnv = HashMap<usize, Expr>;

pub fn init_state() -> BuilderState {
  BuilderState { bufs: HashMap::new(), stores: HashMap::new(), count: 0 }
}

fn go(state: &mut BuilderState, expr: Expr) -> (&mut BuilderState, Expr) {
  match expr.clone() {
    // Buffers
    e @ Expr::WriteWord(_, _, _) | e @ Expr::WriteByte(_, _, _) | e @ Expr::CopySlice(_, _, _, _, _) => {
      if let Some(&v) = state.bufs.get(&e) {
        (state, Expr::GVar(GVar::BufVar(v as i32)))
      } else {
        let next = state.count;
        state.bufs.insert(e.clone(), next);
        state.count += 1;
        (state, Expr::GVar(GVar::BufVar(next as i32)))
      }
    }
    // Storage
    e @ Expr::SStore(_, _, _) => {
      if let Some(&v) = state.stores.get(&e) {
        (state, Expr::GVar(GVar::StoreVar(v as i32)))
      } else {
        let next = state.count;
        state.stores.insert(e.clone(), next);
        state.count += 1;
        (state, Expr::GVar(GVar::StoreVar(next as i32)))
      }
    }
    e @ _ => (state, e),
  }
}

fn invert_key_val<K, V>(map: HashMap<K, V>) -> HashMap<V, K>
where
  K: Eq + Hash + Clone,
  V: Eq + Hash + Clone,
{
  map.into_iter().map(|(k, v)| (v, k)).collect()
}

fn eliminate_expr<'a>(e: Expr) -> (Expr, BufEnv, StoreEnv) {
  let mut state = init_state();
  let (_, e_prime) = go(&mut state, e);
  (e_prime, invert_key_val(state.bufs.clone()), invert_key_val(state.stores.clone()))
}

fn eliminate_prop<'a>(mut state: &mut BuilderState, prop: Prop) -> (&mut BuilderState, Prop) {
  let mut go_ = |expr: &Expr| go(&mut state, expr.clone()).1;
  let new_prop = map_prop_m(&mut go_, prop);
  (state, new_prop)
}

pub fn eliminate_props_prime<'a>(state: &mut BuilderState, props: Vec<Prop>) -> (&mut BuilderState, Vec<Prop>) {
  let mut result = vec![];
  for p in props {
    result.push(eliminate_prop(state, p).1);
  }
  (state, result)
}

pub fn eliminate_props(props: Vec<Prop>) -> (Vec<Prop>, BufEnv, StoreEnv) {
  let mut state = init_state();
  let (_, props_prime) = eliminate_props_prime(&mut state, props);
  (props_prime, invert_key_val(state.bufs.clone()), invert_key_val(state.stores.clone()))
}

fn map_expr_m<F, S>(f: F, expr: Expr) -> (S, Expr)
where
  F: Fn(Expr) -> (S, Expr),
  S: Clone,
{
  // Dummy implementation for map_expr_m
  f(expr)
}
