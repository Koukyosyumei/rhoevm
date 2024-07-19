use rhoevm::modules::expr::{add, addmod, div, geq, gt, leq, lt, mul, mulmod, sub};
use rhoevm::modules::types::Expr;

#[test]
fn test_add_concrete() {
  let x = Expr::Lit(3);
  let y = Expr::Lit(4);
  assert_eq!(add(x, y), Expr::Lit(7));
}

#[test]
fn test_add_symbolic() {
  let x = Expr::Lit(3);
  let y = Expr::Sub(Box::new(Expr::Lit(4)), Box::new(Expr::Lit(2)));
  assert_eq!(
    add(x, y),
    Expr::Add(
      Box::new(Expr::Lit(3)),
      Box::new(Expr::Sub(Box::new(Expr::Lit(4)), Box::new(Expr::Lit(2))))
    )
  );
}

#[test]
fn test_sub_concrete() {
  let x = Expr::Lit(10);
  let y = Expr::Lit(3);
  assert_eq!(sub(x, y), Expr::Lit(7));
}

#[test]
fn test_mul_concrete() {
  let x = Expr::Lit(3);
  let y = Expr::Lit(4);
  assert_eq!(mul(x, y), Expr::Lit(12));
}

#[test]
fn test_div_concrete() {
  let x = Expr::Lit(10);
  let y = Expr::Lit(2);
  assert_eq!(div(x, y), Expr::Lit(5));
}

#[test]
fn test_div_by_zero() {
  let x = Expr::Lit(10);
  let y = Expr::Lit(0);
  assert_eq!(div(x, y), Expr::Lit(0));
}

#[test]
fn test_lt_concrete() {
  let x = Expr::Lit(3);
  let y = Expr::Lit(4);
  assert_eq!(lt(x, y), Expr::Lit(1));
}

#[test]
fn test_lt_concrete_false() {
  let x = Expr::Lit(5);
  let y = Expr::Lit(4);
  assert_eq!(lt(x, y), Expr::Lit(0));
}

#[test]
fn test_gt_concrete() {
  let x = Expr::Lit(5);
  let y = Expr::Lit(4);
  assert_eq!(gt(x, y), Expr::Lit(1));
}

#[test]
fn test_gt_concrete_false() {
  let x = Expr::Lit(3);
  let y = Expr::Lit(4);
  assert_eq!(gt(x, y), Expr::Lit(0));
}

#[test]
fn test_leq_concrete() {
  let x = Expr::Lit(4);
  let y = Expr::Lit(4);
  assert_eq!(leq(x, y), Expr::Lit(1));
}

#[test]
fn test_leq_concrete_false() {
  let x = Expr::Lit(5);
  let y = Expr::Lit(4);
  assert_eq!(leq(x, y), Expr::Lit(0));
}

#[test]
fn test_geq_concrete() {
  let x = Expr::Lit(4);
  let y = Expr::Lit(4);
  assert_eq!(geq(x, y), Expr::Lit(1));
}

#[test]
fn test_geq_concrete_false() {
  let x = Expr::Lit(3);
  let y = Expr::Lit(4);
  assert_eq!(geq(x, y), Expr::Lit(0));
}

#[test]
fn test_addmod_concrete() {
  let x = Expr::Lit(7);
  let y = Expr::Lit(4);
  let z = Expr::Lit(3);
  assert_eq!(addmod(x, y, z), Expr::Lit(2));
}

#[test]
fn test_addmod_concrete_zero() {
  let x = Expr::Lit(5);
  let y = Expr::Lit(4);
  let z = Expr::Lit(0);
  assert_eq!(addmod(x, y, z), Expr::Lit(0));
}

#[test]
fn test_mulmod_concrete() {
  let x = Expr::Lit(5);
  let y = Expr::Lit(4);
  let z = Expr::Lit(3);
  assert_eq!(mulmod(x, y, z), Expr::Lit(2));
}

#[test]
fn test_mulmod_concrete_zero() {
  let x = Expr::Lit(5);
  let y = Expr::Lit(4);
  let z = Expr::Lit(0);
  assert_eq!(mulmod(x, y, z), Expr::Lit(0));
}
