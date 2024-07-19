use rhoevm::modules::expr::{
  add, addmod, count_leading_zeros, div, geq, gt, is_byte_aligned, is_power_of_two, leq, lt, mul, mulmod, sub,
  write_byte,
};
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

#[test]
fn test_write_byte_concrete() {
  let offset = Expr::Lit(1);
  let byte = Expr::LitByte(0xAB);
  let src = Expr::ConcreteBuf(vec![0x00, 0x00, 0x00]);

  let expected = Expr::ConcreteBuf(vec![0x00, 0xAB, 0x00]);
  assert_eq!(write_byte(offset, byte, src), expected);
}

#[test]
fn test_write_byte_symbolic() {
  let offset = Expr::Lit(1);
  let byte = Expr::LitByte(0xAB);
  let src = Expr::AbstractBuf("src".to_string());

  let expected = Expr::WriteByte(
    Box::new(Expr::Lit(1)),
    Box::new(Expr::LitByte(0xAB)),
    Box::new(Expr::AbstractBuf("src".to_string())),
  );
  assert_eq!(write_byte(offset, byte, src), expected);
}

#[test]
fn test_is_power_of_two() {
  assert!(is_power_of_two(2));
  assert!(is_power_of_two(4));
  assert!(!is_power_of_two(3));
}

#[test]
fn test_count_leading_zeros() {
  assert_eq!(count_leading_zeros(0b1000), 60);
  assert_eq!(count_leading_zeros(0b0100), 61);
}

#[test]
fn test_is_byte_aligned() {
  assert!(is_byte_aligned(0x00000000000000FF)); // Aligned
  assert!(is_byte_aligned(0x000000000000FF00)); // Aligned
  assert!(!is_byte_aligned(0x0000000000000FF0)); // Not aligned
  assert!(is_byte_aligned(0x00000000FF000000)); // Aligned
  assert!(!is_byte_aligned(0x0000000F00000000)); // Not aligned
  assert!(is_byte_aligned(0xFF00000000000000)); // Aligned
}
