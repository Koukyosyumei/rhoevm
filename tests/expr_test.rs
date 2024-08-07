use rhoevm::modules::expr::{
  add, addmod, copy_slice, count_leading_zeros, div, geq, gt, index_word, is_byte_aligned, is_power_of_two, leq, lt,
  mul, mulmod, read_byte, sub, write_byte,
};
use rhoevm::modules::types::{word256_bytes, Expr, W256};

#[test]
fn test_word256_bytes() {
  let w = W256(0x80, 0);
  let mut v: Vec<u8> = vec![0; 32];
  v[31] = 0x80;
  assert_eq!(word256_bytes(w), v);
}

#[test]
fn test_add_concrete() {
  let x = Expr::Lit(W256(3, 0));
  let y = Expr::Lit(W256(4, 0));
  assert_eq!(add(Box::new(x), Box::new(y)), Expr::Lit(W256(7, 0)));
}

#[test]

fn test_add_symbolic() {
  let x = Expr::Lit(W256(3, 0));
  let y = Expr::Sub(Box::new(Expr::Lit(W256(4, 0))), Box::new(Expr::Lit(W256(2, 0))));
  assert_eq!(
    add(Box::new(x), Box::new(y)),
    Expr::Add(
      Box::new(Expr::Lit(W256(3, 0))),
      Box::new(Expr::Sub(Box::new(Expr::Lit(W256(4, 0))), Box::new(Expr::Lit(W256(2, 0)))))
    )
  );
}

#[test]
fn test_sub_concrete() {
  let x = Expr::Lit(W256(10, 0));
  let y = Expr::Lit(W256(3, 0));
  assert_eq!(sub(Box::new(x), Box::new(y)), Expr::Lit(W256(7, 0)));
}

#[test]
fn test_mul_concrete() {
  let x = Expr::Lit(W256(3, 0));
  let y = Expr::Lit(W256(4, 0));
  assert_eq!(mul(Box::new(x), Box::new(y)), Expr::Lit(W256(12, 0)));
}

#[test]

fn test_div_concrete() {
  let x = Expr::Lit(W256(10, 0));
  let y = Expr::Lit(W256(2, 0));
  assert_eq!(div(Box::new(x), Box::new(y)), Expr::Lit(W256(5, 0)));
}

#[test]
fn test_div_by_zero() {
  let x = Expr::Lit(W256(10, 0));
  let y = Expr::Lit(W256(0, 0));
  assert_eq!(div(Box::new(x), Box::new(y)), Expr::Lit(W256(0, 0)));
}

#[test]
fn test_lt_concrete() {
  let x = Expr::Lit(W256(3, 0));
  let y = Expr::Lit(W256(4, 0));
  assert_eq!(lt(Box::new(x), Box::new(y)), Expr::Lit(W256(1, 0)));
}

#[test]
fn test_lt_concrete_false() {
  let x = Expr::Lit(W256(5, 0));
  let y = Expr::Lit(W256(4, 0));
  assert_eq!(lt(Box::new(x), Box::new(y)), Expr::Lit(W256(0, 0)));
}

#[test]
fn test_gt_concrete() {
  let x = Expr::Lit(W256(5, 0));
  let y = Expr::Lit(W256(4, 0));
  assert_eq!(gt(Box::new(x), Box::new(y)), Expr::Lit(W256(1, 0)));
}

#[test]
fn test_gt_concrete_false() {
  let x = Expr::Lit(W256(3, 0));
  let y = Expr::Lit(W256(4, 0));
  assert_eq!(gt(Box::new(x), Box::new(y)), Expr::Lit(W256(0, 0)));
}

#[test]
fn test_leq_concrete() {
  let x = Expr::Lit(W256(4, 0));
  let y = Expr::Lit(W256(4, 0));
  assert_eq!(leq(Box::new(x), Box::new(y)), Expr::Lit(W256(1, 0)));
}

#[test]
fn test_leq_concrete_false() {
  let x = Expr::Lit(W256(5, 0));
  let y = Expr::Lit(W256(4, 0));
  assert_eq!(leq(Box::new(x), Box::new(y)), Expr::Lit(W256(0, 0)));
}

#[test]
fn test_geq_concrete() {
  let x = Expr::Lit(W256(4, 0));
  let y = Expr::Lit(W256(4, 0));
  assert_eq!(geq(Box::new(x), Box::new(y)), Expr::Lit(W256(1, 0)));
}

#[test]
fn test_geq_concrete_false() {
  let x = Expr::Lit(W256(3, 0));
  let y = Expr::Lit(W256(4, 0));
  assert_eq!(geq(Box::new(x), Box::new(y)), Expr::Lit(W256(0, 0)));
}

#[test]
fn test_addmod_concrete() {
  let x = Expr::Lit(W256(7, 0));
  let y = Expr::Lit(W256(4, 0));
  let z = Expr::Lit(W256(3, 0));
  assert_eq!(addmod(Box::new(x), Box::new(y), Box::new(z)), Expr::Lit(W256(2, 0)));
}

#[test]
fn test_addmod_concrete_zero() {
  let x = Expr::Lit(W256(5, 0));
  let y = Expr::Lit(W256(4, 0));
  let z = Expr::Lit(W256(0, 0));
  assert_eq!(addmod(Box::new(x), Box::new(y), Box::new(z)), Expr::Lit(W256(0, 0)));
}

#[test]
fn test_mulmod_concrete() {
  let x = Expr::Lit(W256(5, 0));
  let y = Expr::Lit(W256(4, 0));
  let z = Expr::Lit(W256(3, 0));
  assert_eq!(mulmod(Box::new(x), Box::new(y), Box::new(z)), Expr::Lit(W256(2, 0)));
}

#[test]
fn test_mulmod_concrete_zero() {
  let x = Expr::Lit(W256(5, 0));
  let y = Expr::Lit(W256(4, 0));
  let z = Expr::Lit(W256(0, 0));
  assert_eq!(mulmod(Box::new(x), Box::new(y), Box::new(z)), Expr::Lit(W256(0, 0)));
}

#[test]
fn test_write_byte_concrete() {
  let offset = Expr::Lit(W256(1, 0));
  let byte = Expr::LitByte(0xAB);
  let src = Expr::ConcreteBuf(vec![0x00, 0x00, 0x00]);

  let expected = Expr::ConcreteBuf(vec![0x00, 0xAB, 0x00]);
  assert_eq!(write_byte(Box::new(offset), Box::new(byte), Box::new(src)), expected);
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
  assert_eq!(write_byte(Box::new(offset), Box::new(byte), Box::new(src)), expected);
}

#[test]
fn test_is_power_of_two() {
  assert!(is_power_of_two(W256(2, 0)));
  assert!(is_power_of_two(W256(4, 0)));
  assert!(!is_power_of_two(W256(3, 0)));
}

#[test]
fn test_count_leading_zeros() {
  assert_eq!(count_leading_zeros(W256(0b1000, 0)), 128 + 124);
  assert_eq!(count_leading_zeros(W256(0b0100, 0)), 128 + 125);
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
fn test_index_word_literal_masked() {
  // Test case where i and w are literals, and w is a masked word (Expr::And)
  let idx = Expr::Lit(W256(5, 0));
  let mask = Expr::Lit(W256(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF));
  let word = Expr::Lit(W256(0x11223344556677889900AABBCCDDEEFF, 0));
  let w = Expr::And(Box::new(mask.clone()), Box::new(word.clone()));

  let result = index_word(Box::new(idx), Box::new(w));

  assert_eq!(result, Expr::LitByte(0xAA));
}

#[test]
fn test_index_word_join_bytes() {
  // Test case where i is a literal and w is a joined byte array
  let idx = Expr::Lit(W256(3, 0));
  let bytes = vec![
    Expr::LitByte(0x11),
    Expr::LitByte(0x22),
    Expr::LitByte(0x33),
    Expr::LitByte(0x44),
    Expr::LitByte(0x55),
    Expr::LitByte(0x66),
    Expr::LitByte(0x77),
    Expr::LitByte(0x88),
    Expr::LitByte(0x99),
    Expr::LitByte(0xAA),
    Expr::LitByte(0xBB),
    Expr::LitByte(0xCC),
    Expr::LitByte(0xDD),
    Expr::LitByte(0xEE),
    Expr::LitByte(0xFF),
    Expr::LitByte(0x00),
    Expr::LitByte(0x11),
    Expr::LitByte(0x22),
    Expr::LitByte(0x33),
    Expr::LitByte(0x44),
    Expr::LitByte(0x55),
    Expr::LitByte(0x66),
    Expr::LitByte(0x77),
    Expr::LitByte(0x88),
    Expr::LitByte(0x99),
    Expr::LitByte(0xAA),
    Expr::LitByte(0xBB),
    Expr::LitByte(0xCC),
    Expr::LitByte(0xDD),
    Expr::LitByte(0xEE),
    Expr::LitByte(0xFF),
    Expr::LitByte(0x00),
  ];
  let w = Expr::JoinBytes(bytes);

  let result = index_word(Box::new(idx), Box::new(w));

  assert_eq!(result, Expr::LitByte(0x44));
}

#[test]
fn test_index_word_non_literal() {
  // Test case where i and w are non-literals
  let idx = Expr::Var("i".to_string());
  let word = Expr::Var("w".to_string());

  let result = index_word(Box::new(idx.clone()), Box::new(word.clone()));

  assert_eq!(result, Expr::IndexWord(Box::new(idx), Box::new(word)));
}

#[test]
fn test_index_word_literal() {
  // Test case where i and w are literals
  let idx = Expr::Lit(W256(3, 0));
  let word = Expr::Lit(W256(0x11223344556677889900AABBCCDDEEFF, 0));

  let result = index_word(Box::new(idx), Box::new(word));

  assert_eq!(result, Expr::LitByte(0xCC));
}

#[test]
fn test_index_word_concrete_lit() {
  let i = Expr::Lit(W256(3, 0));
  let w = Expr::Lit(W256(0x12345678_9ABCDEF0, 0));

  let expected = Expr::LitByte(0x9A);
  assert_eq!(index_word(Box::new(i), Box::new(w)), expected);
}

#[test]
fn test_index_word_symbolic() {
  let i = Expr::Lit(W256(1, 0));
  let w = Expr::And(
    Box::new(Expr::Lit(W256(0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF))),
    Box::new(Expr::Lit(W256(0x12345678_9ABCDEF0, 0))),
  );

  let expected = Expr::IndexWord(
    Box::new(i.clone()),
    Box::new(Expr::And(
      Box::new(Expr::Lit(W256(0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF))),
      Box::new(Expr::Lit(W256(0x12345678_9ABCDEF0, 0))),
    )),
  );
  assert_eq!(index_word(Box::new(i), Box::new(w)), expected);
}

#[test]
fn test_read_byte_concrete() {
  let idx = Expr::Lit(W256(1, 0));
  let buf = Expr::ConcreteBuf(vec![0x00, 0xAB, 0x00]);

  let expected = Expr::LitByte(0xAB);
  assert_eq!(read_byte(Box::new(idx), Box::new(buf)), expected);
}

#[test]
fn test_copy_slice_empty_buffers() {
  let src_offset = Expr::Lit(W256(0, 0));
  let dst_offset = Expr::Lit(W256(0, 0));
  let size = Expr::Lit(W256(0, 0));
  let src = Expr::ConcreteBuf(vec![]);
  let dst = Expr::ConcreteBuf(vec![]);
  let result = copy_slice(
    Box::new(src_offset),
    Box::new(dst_offset),
    Box::new(size),
    Box::new(src.clone()),
    Box::new(dst.clone()),
  );
  assert_eq!(result, dst);
}

#[test]
fn test_copy_slice_concrete_empty_buffers() {
  let src_offset = Expr::Lit(W256(0, 0));
  let dst_offset = Expr::Lit(W256(0, 0));
  let size = Expr::Lit(W256(10, 0));
  let src = Expr::ConcreteBuf(vec![]);
  let dst = Expr::ConcreteBuf(vec![]);
  let result = copy_slice(
    Box::new(src_offset),
    Box::new(dst_offset),
    Box::new(size),
    Box::new(src.clone()),
    Box::new(dst.clone()),
  );
  assert_eq!(result, Expr::ConcreteBuf(vec![0; 10]));
}

#[test]
fn test_copy_slice_fully_concrete() {
  let src_offset = Expr::Lit(W256(2, 0));
  let dst_offset = Expr::Lit(W256(0, 0));
  let size = Expr::Lit(W256(2, 0));
  let src = Expr::ConcreteBuf(vec![1, 2, 3, 4]);
  let dst = Expr::ConcreteBuf(vec![]);
  let result = copy_slice(
    Box::new(src_offset),
    Box::new(dst_offset),
    Box::new(size),
    Box::new(src.clone()),
    Box::new(dst.clone()),
  );
  assert_eq!(result, Expr::ConcreteBuf(vec![3, 4]));
}

#[test]
fn test_copy_slice_with_padding() {
  let src_offset = Expr::Lit(W256(2, 0));
  let dst_offset = Expr::Lit(W256(2, 0));
  let size = Expr::Lit(W256(2, 0));
  let src = Expr::ConcreteBuf(vec![1, 2, 3, 4]);
  let dst = Expr::ConcreteBuf(vec![5, 6]);
  let result = copy_slice(
    Box::new(src_offset),
    Box::new(dst_offset),
    Box::new(size),
    Box::new(src.clone()),
    Box::new(dst.clone()),
  );
  assert_eq!(result, Expr::ConcreteBuf(vec![5, 6, 3, 4]));
}

#[test]
fn test_copy_slice_abstract_src() {
  let src_offset = Expr::Lit(W256(0, 0));
  let dst_offset = Expr::Lit(W256(0, 0));
  let size = Expr::Lit(W256(31, 0));
  let src = Expr::CopySlice(
    Box::new(Expr::Lit(W256(0, 0))),
    Box::new(Expr::Lit(W256(0, 0))),
    Box::new(Expr::Lit(W256(32, 0))),
    Box::new(Expr::ConcreteBuf(vec![1; 32])),
    Box::new(Expr::ConcreteBuf(vec![0; 32])),
  );
  let dst = Expr::ConcreteBuf(vec![0; 32]);
  let result = copy_slice(
    Box::new(src_offset),
    Box::new(dst_offset),
    Box::new(size),
    Box::new(src.clone()),
    Box::new(dst.clone()),
  );
  assert_eq!(
    result,
    Expr::ConcreteBuf(vec![
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0
    ])
  );
}
