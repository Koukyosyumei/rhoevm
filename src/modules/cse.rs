use std::collections::HashMap;
use std::hash::Hash;

use crate::modules::traversals::map_prop_m;
use crate::modules::types::{Expr, GVar, Prop};

/// Represents the internal state used during the expression elimination process.
///
/// The state contains buffers, storage mappings, and a counter to track unique indices.
#[derive(Debug, Default, Clone)]
pub struct BuilderState {
  bufs: HashMap<Expr, usize>,
  stores: HashMap<Expr, usize>,
  count: usize,
}

/// Type alias for a buffer environment, mapping unique indices to expressions.
pub type BufEnv = HashMap<usize, Expr>;

/// Type alias for a storage environment, mapping unique indices to expressions.
pub type StoreEnv = HashMap<usize, Expr>;

/// Initializes and returns a new `BuilderState` instance with empty mappings and a zeroed counter.
///
/// # Returns
///
/// * `BuilderState` - A new instance with initialized state.
pub fn init_state() -> BuilderState {
  BuilderState { bufs: HashMap::new(), stores: HashMap::new(), count: 0 }
}

/// Processes an expression and updates the `BuilderState` accordingly.
///
/// This function checks if an expression corresponds to a buffer or storage operation and maps it
/// to a global variable in the state. If the expression has not been encountered before, it is assigned
/// a new unique index.
///
/// # Arguments
///
/// * `state` - A mutable reference to the current `BuilderState`.
/// * `expr` - The expression to process.
///
/// # Returns
///
/// * `(&mut BuilderState, Expr)` - The updated state and the processed expression.
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

/// Inverts the key-value pairs of a `HashMap`, creating a new map with values as keys and keys as values.
///
/// # Type Parameters
///
/// * `K` - The type of keys in the input map, which must implement `Eq`, `Hash`, and `Clone`.
/// * `V` - The type of values in the input map, which must implement `Eq`, `Hash`, and `Clone`.
///
/// # Arguments
///
/// * `map` - The `HashMap` to invert.
///
/// # Returns
///
/// * `HashMap<V, K>` - A new map with keys and values swapped.
fn invert_key_val<K, V>(map: HashMap<K, V>) -> HashMap<V, K>
where
  K: Eq + Hash + Clone,
  V: Eq + Hash + Clone,
{
  map.into_iter().map(|(k, v)| (v, k)).collect()
}

/// Eliminates an expression by processing it through a state machine and returns the transformed expression
/// along with buffer and storage environments.
///
/// # Arguments
///
/// * `e` - The expression to be processed.
///
/// # Returns
///
/// * `(Expr, BufEnv, StoreEnv)` - The transformed expression and the corresponding buffer and storage environments.
pub fn eliminate_expr<'a>(e: Expr) -> (Expr, BufEnv, StoreEnv) {
  let mut state = init_state();
  let (_, e_prime) = go(&mut state, e);
  (e_prime, invert_key_val(state.bufs.clone()), invert_key_val(state.stores.clone()))
}

/// Recursively processes a proposition by eliminating expressions within it.
///
/// # Arguments
///
/// * `state` - A mutable reference to the current `BuilderState`.
/// * `prop` - The proposition to process.
///
/// # Returns
///
/// * `(&mut BuilderState, Prop)` - The updated state and the processed proposition.
fn eliminate_prop(mut state: &mut BuilderState, prop: Box<Prop>) -> (&mut BuilderState, Prop) {
  let mut go_ = |expr: &Expr| go(&mut state, expr.clone()).1;
  let new_prop = map_prop_m(&mut go_, *prop);
  (state, new_prop)
}

/// Eliminates expressions from a list of propositions, returning the updated state and the transformed propositions.
///
/// # Arguments
///
/// * `state` - A mutable reference to the current `BuilderState`.
/// * `props` - A reference to a vector of boxed propositions to process.
///
/// # Returns
///
/// * `(&mut BuilderState, Vec<Box<Prop>>)` - The updated state and the list of transformed propositions.
pub fn eliminate_props_prime<'a>(
  state: &'a mut BuilderState,
  props: &'a Vec<Box<Prop>>,
) -> (&'a mut BuilderState, Vec<Box<Prop>>) {
  let mut result = vec![];
  for p in props {
    result.push(Box::new(eliminate_prop(state, p.clone()).1));
  }
  (state, result)
}

/// Processes a list of propositions by eliminating expressions within them and returns the transformed propositions
/// along with buffer and storage environments.
///
/// # Arguments
///
/// * `props` - A reference to a vector of boxed propositions to process.
///
/// # Returns
///
/// * `(Vec<Box<Prop>>, BufEnv, StoreEnv)` - The list of transformed propositions and the corresponding buffer and storage environments.
pub fn eliminate_props(props: &Vec<Box<Prop>>) -> (Vec<Box<Prop>>, BufEnv, StoreEnv) {
  let mut state = init_state();
  let (_, props_prime) = eliminate_props_prime(&mut state, props);
  (props_prime, invert_key_val(state.bufs.clone()), invert_key_val(state.stores.clone()))
}
