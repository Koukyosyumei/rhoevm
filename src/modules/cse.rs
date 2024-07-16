use crate::modules::types::{Expr, Prop};
use std::collections::HashMap;
use std::hash::Hash;

#[derive(Debug, Default)]
struct BuilderState {
  bufs: HashMap<Expr, usize>,
  stores: HashMap<Expr, usize>,
  count: usize,
}

type BufEnv = HashMap<usize, Expr>;
type StoreEnv = HashMap<usize, Expr>;

fn init_state() -> BuilderState {
  BuilderState {
    bufs: HashMap::new(),
    stores: HashMap::new(),
    count: 0,
  }
}

fn go(expr: Expr) -> State<BuilderState, Expr> {
  State::new(move |state: &mut BuilderState| {
    match expr.clone() {
      // Buffers
      e @ Expr::WriteWord(_) | e @ Expr::WriteByte(_) | e @ Expr::CopySlice(_) => {
        if let Some(&v) = state.bufs.get(&e) {
          (Expr::GVar(BufVar(v)), state.clone())
        } else {
          let next = state.count;
          state.bufs.insert(e.clone(), next);
          state.count += 1;
          (Expr::GVar(BufVar(next)), state.clone())
        }
      }
      // Storage
      e @ Expr::SStore(_) => {
        if let Some(&v) = state.stores.get(&e) {
          (Expr::GVar(StoreVar(v)), state.clone())
        } else {
          let next = state.count;
          state.stores.insert(e.clone(), next);
          state.count += 1;
          (Expr::GVar(StoreVar(next)), state.clone())
        }
      }
      _ => (e, state.clone()),
    }
  })
}

fn invert_key_val<K, V>(map: HashMap<K, V>) -> HashMap<V, K>
where
  K: Eq + Hash + Clone,
  V: Eq + Hash + Clone,
{
  map.into_iter().map(|(k, v)| (v, k)).collect()
}

fn eliminate_expr<'a>(e: Expr) -> (Expr, BufEnv, StoreEnv) {
  let mut state_machine = StateMachine::new(init_state());
  let e_prime = state_machine.run(go(e));
  let state = state_machine.state();
  (
    e_prime,
    invert_key_val(state.bufs.clone()),
    invert_key_val(state.stores.clone()),
  )
}

fn eliminate_prop<'a>(prop: Prop) -> State<BuilderState, Prop> {
  map_prop_m(go, prop)
}

fn eliminate_props<'a>(props: Vec<Prop>) -> State<BuilderState, Vec<Prop>> {
  map_m(eliminate_prop, props)
}

fn eliminate_props_top_level(props: Vec<Prop>) -> (Vec<Prop>, BufEnv, StoreEnv) {
  let mut state_machine = StateMachine::new(init_state());
  let props_prime = state_machine.run(eliminate_props(props));
  let state = state_machine.state();
  (
    props_prime,
    invert_key_val(state.bufs.clone()),
    invert_key_val(state.stores.clone()),
  )
}

fn map_expr_m<F, S>(f: F, expr: Expr) -> State<S, Expr>
where
  F: Fn(Expr) -> State<S, Expr>,
  S: Clone,
{
  // Dummy implementation for map_expr_m
  f(expr)
}

fn map_prop_m<F, S>(f: F, prop: Prop) -> State<S, Prop>
where
  F: Fn(Expr) -> State<S, Expr>,
  S: Clone,
{
  // Dummy implementation for map_prop_m
  State::new(move |state: &mut S| (prop.clone(), state.clone()))
}

fn map_m<F, S, T>(f: F, items: Vec<T>) -> State<S, Vec<T>>
where
  F: Fn(T) -> State<S, T>,
  S: Clone,
  T: Clone,
{
  // Dummy implementation for map_m
  State::new(move |state: &mut S| (items.clone(), state.clone()))
}
