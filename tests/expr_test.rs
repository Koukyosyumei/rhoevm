use rhoevm::modules::expr::add;
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
