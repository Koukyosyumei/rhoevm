use crate::modules::types::{Expr, Prop};

pub fn in_range(sz: u32, e: Expr) -> Prop {
  Prop::PAnd(
    Box::new(Prop::PGEq(e.clone(), Expr::Lit(0))),
    Box::new(Prop::PLEq(e.clone(), Expr::Lit(2 ^ sz - 1))),
  )
}

pub const MAX_BYTES: u64 = (u32::MAX as u64) / 8;

pub fn write_byte(offset: Expr, byte: Expr, src: Expr) -> Expr {
  match (offset, byte, src) {
    (Expr::Lit(offset), Expr::LitByte(val), Expr::ConcreteBuf(src)) if offset < MAX_BYTES => {
      let mut buffer = vec![0; offset as usize];
      buffer.push(val);
      buffer.extend(vec![0; MAX_BYTES as usize - offset as usize - 1]);
      Expr::ConcreteBuf(buffer)
    }
    (Expr::Lit(offset), Expr::LitByte(byte), Expr::ConcreteBuf(src)) if offset < MAX_BYTES => {
      let mut buffer = src.clone();
      buffer.truncate(offset as usize);
      buffer.push(byte);
      buffer.extend(src[offset as usize + 1..].to_vec());
      Expr::ConcreteBuf(buffer)
    }
    (offset, byte, src) => Expr::WriteByte(Box::new(offset), Box::new(byte), Box::new(src)),
  }
}
