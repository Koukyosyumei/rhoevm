use crate::modules::types::{Expr, Prop};

pub fn in_range(sz: u32, e: Expr) -> Prop {
  Prop::PAnd(
    Box::new(Prop::PGEq(e, Expr::Lit(0))),
    Box::new(Prop::PLEq(e, Expr::Lit(2 ^ sz - 1))),
  )
}
