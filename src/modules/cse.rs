use crate::modules::traversals::map_prop_m;
use crate::modules::types::{Expr, GVar, Prop};
use std::collections::HashMap;
use std::hash::Hash;

#[derive(Debug, Default, Clone)]
struct BuilderState {
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

fn go_ep(a: Expr, s: &mut BuilderState) -> Expr {
  match a {
    e @ Expr::WriteWord(_, _, _) => match s.bufs.get(&e) {
      Some(v) => Expr::GVar(GVar::BufVar(*v as i32)),
      None => {
        let next = s.count;
        *s.bufs.entry(e).or_insert(0) = next;
        s.count = next + 1;
        Expr::GVar(GVar::BufVar(next as i32))
      }
    },
    _ => a,
  }
}

fn eliminate_expr<'a>(e: Expr) -> (Expr, BufEnv, StoreEnv) {
  let mut state = init_state();
  let (_, e_prime) = go(&mut state, e);
  (e_prime, invert_key_val(state.bufs.clone()), invert_key_val(state.stores.clone()))
}

fn eliminate_prop<'a>(prop: Prop) -> (BuilderState, Prop) {
  todo!()
}

pub fn eliminate_props_prime<'a>(props: Vec<Prop>) -> (BuilderState, Vec<Prop>) {
  map_m(eliminate_prop, props)
}

pub fn eliminate_props(props: Vec<Prop>) -> (Vec<Prop>, BufEnv, StoreEnv) {
  let mut state = init_state();
  let (_, props_prime) = eliminate_props_prime(props);
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

fn map_m<F, S, T>(f: F, items: Vec<T>) -> (S, Vec<T>)
where
  F: Fn(T) -> (S, T),
  S: Clone,
  T: Clone,
{
  // Dummy implementation for map_m
  todo!()
}
