use std::fmt::Debug;

use crate::modules::types::Expr;

#[derive(Debug, PartialEq, Clone, Hash)]
pub enum Op {
  Stop,
  Add,
  Mul,
  Sub,
  Div,
  Sdiv,
  Mod,
  Smod,
  Addmod,
  Mulmod,
  Exp,
  Signextend,
  Lt,
  Gt,
  Slt,
  Sgt,
  Eq,
  Iszero,
  And,
  Or,
  Xor,
  Not,
  Byte,
  Shl,
  Shr,
  Sar,
  Sha3,
  Address,
  Balance,
  Origin,
  Caller,
  Callvalue,
  Calldataload,
  Calldatasize,
  Calldatacopy,
  Codesize,
  Codecopy,
  Gasprice,
  Extcodesize,
  Extcodecopy,
  Returndatasize,
  Returndatacopy,
  Extcodehash,
  Blockhash,
  Coinbase,
  Timestamp,
  Number,
  PrevRandao,
  Gaslimit,
  Chainid,
  Selfbalance,
  BaseFee,
  Pop,
  Mload,
  Mstore,
  Mstore8,
  Sload,
  Sstore,
  Jump,
  Jumpi,
  Pc,
  Msize,
  Gas,
  Jumpdest,
  Create,
  Call,
  Staticcall,
  Callcode,
  Return,
  Delegatecall,
  Create2,
  Selfdestruct,
  Dup(u8),
  Swap(u8),
  Log(u8),
  Push0,
  Push(u8),
  PushExpr(Expr),
  Revert,
  Unknown(u8),
}

pub fn op_size(x: u8) -> usize {
  match x {
    0x60..=0x7f => x as usize - 0x60 + 2,
    _ => 1,
  }
}

pub fn get_op(x: u8) -> Op {
  match x {
    0x80..=0x8f => Op::Dup(x - 0x80 + 1),
    0x90..=0x9f => Op::Swap(x - 0x90 + 1),
    0xa0..=0xa4 => Op::Log(x - 0xa0),
    0x60..=0x7f => Op::Push(x - 0x60 + 1),
    0x00 => Op::Stop,
    0x01 => Op::Add,
    0x02 => Op::Mul,
    0x03 => Op::Sub,
    0x04 => Op::Div,
    0x05 => Op::Sdiv,
    0x06 => Op::Mod,
    0x07 => Op::Smod,
    0x08 => Op::Addmod,
    0x09 => Op::Mulmod,
    0x0a => Op::Exp,
    0x0b => Op::Signextend,
    0x10 => Op::Lt,
    0x11 => Op::Gt,
    0x12 => Op::Slt,
    0x13 => Op::Sgt,
    0x14 => Op::Eq,
    0x15 => Op::Iszero,
    0x16 => Op::And,
    0x17 => Op::Or,
    0x18 => Op::Xor,
    0x19 => Op::Not,
    0x1a => Op::Byte,
    0x1b => Op::Shl,
    0x1c => Op::Shr,
    0x1d => Op::Sar,
    0x20 => Op::Sha3,
    0x30 => Op::Address,
    0x31 => Op::Balance,
    0x32 => Op::Origin,
    0x33 => Op::Caller,
    0x34 => Op::Callvalue,
    0x35 => Op::Calldataload,
    0x36 => Op::Calldatasize,
    0x37 => Op::Calldatacopy,
    0x38 => Op::Codesize,
    0x39 => Op::Codecopy,
    0x3a => Op::Gasprice,
    0x3b => Op::Extcodesize,
    0x3c => Op::Extcodecopy,
    0x3d => Op::Returndatasize,
    0x3e => Op::Returndatacopy,
    0x3f => Op::Extcodehash,
    0x40 => Op::Blockhash,
    0x41 => Op::Coinbase,
    0x42 => Op::Timestamp,
    0x43 => Op::Number,
    0x44 => Op::PrevRandao,
    0x45 => Op::Gaslimit,
    0x46 => Op::Chainid,
    0x47 => Op::Selfbalance,
    0x48 => Op::BaseFee,
    0x50 => Op::Pop,
    0x51 => Op::Mload,
    0x52 => Op::Mstore,
    0x53 => Op::Mstore8,
    0x54 => Op::Sload,
    0x55 => Op::Sstore,
    0x56 => Op::Jump,
    0x57 => Op::Jumpi,
    0x58 => Op::Pc,
    0x59 => Op::Msize,
    0x5a => Op::Gas,
    0x5b => Op::Jumpdest,
    0x5f => Op::Push0,
    0xf0 => Op::Create,
    0xf1 => Op::Call,
    0xf2 => Op::Callcode,
    0xf3 => Op::Return,
    0xf4 => Op::Delegatecall,
    0xf5 => Op::Create2,
    0xfd => Op::Revert,
    0xfa => Op::Staticcall,
    0xff => Op::Selfdestruct,
    _ => Op::Unknown(x),
  }
}

fn show_hex(x: u64, prefix: &str) -> String {
  // Replace this with your actual hex formatting logic (e.g., using format!("{:x}", x))
  format!("{}{:x}", prefix, x)
}

pub fn op_string(o: &Op) -> String {
  let result = match o {
    Op::Stop => "STOP",
    Op::Add => "ADD",
    Op::Mul => "MUL",
    Op::Sub => "SUB",
    Op::Div => "DIV",
    Op::Sdiv => "SDIV",
    Op::Mod => "MOD",
    Op::Smod => "SMOD",
    Op::Addmod => "ADDMOD",
    Op::Mulmod => "MULMOD",
    Op::Exp => "EXP",
    Op::Signextend => "SIGNEXTEND",
    Op::Lt => "LT",
    Op::Gt => "GT",
    Op::Slt => "SLT",
    Op::Sgt => "SGT",
    Op::Eq => "EQ",
    Op::Iszero => "ISZERO",
    Op::And => "AND",
    Op::Or => "OR",
    Op::Xor => "XOR",
    Op::Not => "NOT",
    Op::Byte => "BYTE",
    Op::Shl => "SHL",
    Op::Shr => "SHR",
    Op::Sar => "SAR",
    Op::Sha3 => "SHA3",
    Op::Address => "ADDRESS",
    Op::Balance => "BALANCE",
    Op::Origin => "ORIGIN",
    Op::Caller => "CALLER",
    Op::Callvalue => "CALLVALUE",
    Op::Calldataload => "CALLDATALOAD",
    Op::Calldatasize => "CALLDATASIZE",
    Op::Calldatacopy => "CALLDATACOPY",
    Op::Codesize => "CODESIZE",
    Op::Codecopy => "CODECOPY",
    Op::Gasprice => "GASPRICE",
    Op::Extcodesize => "EXTCODESIZE",
    Op::Extcodecopy => "EXTCODECOPY",
    Op::Returndatasize => "RETURNDATASIZE",
    Op::Returndatacopy => "RETURNDATACOPY",
    Op::Extcodehash => "EXTCODEHASH",
    Op::Blockhash => "BLOCKHASH",
    Op::Coinbase => "COINBASE",
    Op::Timestamp => "TIMESTAMP",
    Op::Number => "NUMBER",
    Op::PrevRandao => "PREVRANDAO",
    Op::Gaslimit => "GASLIMIT",
    Op::Chainid => "CHAINID",
    Op::Selfbalance => "SELFBALANCE",
    Op::BaseFee => "BASEFEE",
    Op::Pop => "POP",
    Op::Mload => "MLOAD",
    Op::Mstore => "MSTORE",
    Op::Mstore8 => "MSTORE8",
    Op::Sload => "SLOAD",
    Op::Sstore => "SSTORE",
    Op::Jump => "JUMP",
    Op::Jumpi => "JUMPI",
    Op::Pc => "PC",
    Op::Msize => "MSIZE",
    Op::Gas => "GAS",
    Op::Jumpdest => "JUMPDEST",
    Op::Create => "CREATE",
    Op::Call => "CALL",
    Op::Staticcall => "STATICCALL",
    Op::Callcode => "CALLCODE",
    Op::Return => "RETURN",
    Op::Delegatecall => "DELEGATECALL",
    Op::Create2 => "CREATE2",
    Op::Selfdestruct => "SELFDESTRUCT",
    Op::Dup(x) => &format!("{}{}", &&"DUP", x).to_string(),
    Op::Swap(x) => &format!("{}{}", &&"SWAP", x).to_string(),
    Op::Log(x) => &format!("{}{}", &&"LOG", x).to_string(),
    Op::Push0 => "PUSH0",
    Op::Push(x) => &format!("{}{}", &&"PUSH", x).to_string(),
    Op::PushExpr(x) => match x {
      Expr::Lit(v) => &format!("{} {}", &&"PUSH 0x{}", show_hex(v.0 as u64, "")).to_string(),
      _ => panic!("invalid expr"),
    },
    Op::Revert => "REVERT",
    Op::Unknown(_) => &format!("{}", &&"UNKNOWN").to_string(),
  };
  result.to_string()
}
