use rhoevm::modules::expr::{
  add, addmod, count_leading_zeros, div, geq, gt, index_word, is_byte_aligned, is_power_of_two, leq, lt, mul, mulmod,
  read_byte, sub, write_byte,
};
use rhoevm::modules::types::{Expr, W256};

#[test]
fn test_add_concrete() {
  let x = Expr::Lit(W256(3, 0));
  let y = Expr::Lit(W256(4, 0));
  assert_eq!(add(x, y), Expr::Lit(W256(7, 0)));
}

#[test]
fn test_add_symbolic() {
  let x = Expr::Lit(W256(3, 0));
  let y = Expr::Sub(Box::new(Expr::Lit(W256(4, 0))), Box::new(Expr::Lit(W256(2, 0))));
  assert_eq!(
    add(x, y),
    Expr::Add(
      Box::new(Expr::Lit(W256(3, 0))),
      Box::new(Expr::Sub(
        Box::new(Expr::Lit(W256(4, 0))),
        Box::new(Expr::Lit(W256(2, 0)))
      ))
    )
  );
}

#[test]
fn test_sub_concrete() {
  let x = Expr::Lit(W256(10, 0));
  let y = Expr::Lit(W256(3, 0));
  assert_eq!(sub(x, y), Expr::Lit(W256(7, 0)));
}

#[test]
fn test_mul_concrete() {
  let x = Expr::Lit(W256(3, 0));
  let y = Expr::Lit(W256(4, 0));
  assert_eq!(mul(x, y), Expr::Lit(W256(12, 0)));
}

#[test]
fn test_div_concrete() {
  let x = Expr::Lit(W256(10, 0));
  let y = Expr::Lit(W256(2, 0));
  assert_eq!(div(x, y), Expr::Lit(W256(5, 0)));
}

#[test]
fn test_div_by_zero() {
  let x = Expr::Lit(W256(10, 0));
  let y = Expr::Lit(W256(0, 0));
  assert_eq!(div(x, y), Expr::Lit(W256(0, 0)));
}

#[test]
fn test_lt_concrete() {
  let x = Expr::Lit(W256(3, 0));
  let y = Expr::Lit(W256(4, 0));
  assert_eq!(lt(x, y), Expr::Lit(W256(1, 0)));
}

#[test]
fn test_lt_concrete_false() {
  let x = Expr::Lit(W256(5, 0));
  let y = Expr::Lit(W256(4, 0));
  assert_eq!(lt(x, y), Expr::Lit(W256(0, 0)));
}

#[test]
fn test_gt_concrete() {
  let x = Expr::Lit(W256(5, 0));
  let y = Expr::Lit(W256(4, 0));
  assert_eq!(gt(x, y), Expr::Lit(W256(1, 0)));
}

#[test]
fn test_gt_concrete_false() {
  let x = Expr::Lit(W256(3, 0));
  let y = Expr::Lit(W256(4, 0));
  assert_eq!(gt(x, y), Expr::Lit(W256(0, 0)));
}

#[test]
fn test_leq_concrete() {
  let x = Expr::Lit(W256(4, 0));
  let y = Expr::Lit(W256(4, 0));
  assert_eq!(leq(x, y), Expr::Lit(W256(1, 0)));
}

#[test]
fn test_leq_concrete_false() {
  let x = Expr::Lit(W256(5, 0));
  let y = Expr::Lit(W256(4, 0));
  assert_eq!(leq(x, y), Expr::Lit(W256(0, 0)));
}

#[test]
fn test_geq_concrete() {
  let x = Expr::Lit(W256(4, 0));
  let y = Expr::Lit(W256(4, 0));
  assert_eq!(geq(x, y), Expr::Lit(W256(1, 0)));
}

#[test]
fn test_geq_concrete_false() {
  let x = Expr::Lit(W256(3, 0));
  let y = Expr::Lit(W256(4, 0));
  assert_eq!(geq(x, y), Expr::Lit(W256(0, 0)));
}

#[test]
fn test_addmod_concrete() {
  let x = Expr::Lit(W256(7, 0));
  let y = Expr::Lit(W256(4, 0));
  let z = Expr::Lit(W256(3, 0));
  assert_eq!(addmod(x, y, z), Expr::Lit(W256(2, 0)));
}

#[test]
fn test_addmod_concrete_zero() {
  let x = Expr::Lit(W256(5, 0));
  let y = Expr::Lit(W256(4, 0));
  let z = Expr::Lit(W256(0, 0));
  assert_eq!(addmod(x, y, z), Expr::Lit(W256(0, 0)));
}

#[test]
fn test_mulmod_concrete() {
  let x = Expr::Lit(W256(5, 0));
  let y = Expr::Lit(W256(4, 0));
  let z = Expr::Lit(W256(3, 0));
  assert_eq!(mulmod(x, y, z), Expr::Lit(W256(2, 0)));
}

#[test]
fn test_mulmod_concrete_zero() {
  let x = Expr::Lit(W256(5, 0));
  let y = Expr::Lit(W256(4, 0));
  let z = Expr::Lit(W256(0, 0));
  assert_eq!(mulmod(x, y, z), Expr::Lit(W256(0, 0)));
}

#[test]
fn test_write_byte_concrete() {
  let offset = Expr::Lit(W256(1, 0));
  let byte = Expr::LitByte(0xAB);
  let src = Expr::ConcreteBuf(vec![0x00, 0x00, 0x00]);

  let expected = Expr::ConcreteBuf(vec![0x00, 0xAB, 0x00]);
  assert_eq!(write_byte(offset, byte, src), expected);
}

#[test]
fn test_write_byte_symbolic() {
  let offset = Expr::Lit(W256(1, 0));
  let byte = Expr::LitByte(0xAB);
  let src = Expr::AbstractBuf("src".to_string());

  let expected = Expr::WriteByte(
    Box::new(Expr::Lit(W256(1, 0))),
    Box::new(Expr::LitByte(0xAB)),
    Box::new(Expr::AbstractBuf("src".to_string())),
  );
  assert_eq!(write_byte(offset, byte, src), expected);
}

#[test]
fn test_is_power_of_two() {
  assert!(is_power_of_two(W256(2, 0)));
  assert!(is_power_of_two(W256(4, 0)));
  assert!(!is_power_of_two(W256(3, 0)));
}

#[test]
fn test_count_leading_zeros() {
  assert_eq!(count_leading_zeros(W256(0b1000, 0)), 60);
  assert_eq!(count_leading_zeros(W256(0b0100, 0)), 61);
}

#[test]
fn test_is_byte_aligned() {
  assert!(is_byte_aligned(W256(0x00000000000000FF, 0))); // Aligned
  assert!(is_byte_aligned(W256(0x000000000000FF00, 0))); // Aligned
  assert!(!is_byte_aligned(W256(0x0000000000000FF0, 0))); // Not aligned
  assert!(is_byte_aligned(W256(0x00000000FF000000, 0))); // Aligned
  assert!(!is_byte_aligned(W256(0x0000000F00000000, 0))); // Not aligned
  assert!(is_byte_aligned(W256(0xFF00000000000000, 0))); // Aligned
}

#[test]
fn test_index_word_concrete_lit() {
  let i = Expr::Lit(W256(1, 0));
  let w = Expr::Lit(W256(0x12345678_9ABCDEF0, 0));

  let expected = Expr::LitByte(0x9A);
  assert_eq!(index_word(i, w), expected);
}

#[test]
fn test_index_word_symbolic() {
  let i = Expr::Lit(W256(1, 0));
  let w = Expr::And(
    Box::new(Expr::Lit(W256(0xFFFF_FFFF_FFFF_FFFF, 0))),
    Box::new(Expr::Lit(W256(0x12345678_9ABCDEF0, 0))),
  );

  let expected = Expr::IndexWord(
    Box::new(i.clone()),
    Box::new(Expr::And(
      Box::new(Expr::Lit(W256(0xFFFF_FFFF_FFFF_FFFF, 0))),
      Box::new(Expr::Lit(W256(0x12345678_9ABCDEF0, 0))),
    )),
  );
  assert_eq!(index_word(i, w), expected);
}

#[test]
fn test_read_byte_concrete() {
  let idx = Expr::Lit(W256(1, 0));
  let buf = Expr::ConcreteBuf(vec![0x00, 0xAB, 0x00]);

  let expected = Expr::Lit(W256(0xAB, 0));
  assert_eq!(read_byte(idx, buf), expected);
}
