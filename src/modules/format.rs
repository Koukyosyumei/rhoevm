use hex::decode as hex_decode;

use crate::modules::types::{Expr, Prop};

pub fn strip_0x(bs: &[u8]) -> Vec<u8> {
  if bs.starts_with(b"0x") {
    bs[2..].to_vec()
  } else {
    bs.to_vec()
  }
}

pub fn strip_0x_str(s: &str) -> String {
  if s.starts_with("0x") {
    s[2..].to_string()
  } else {
    s.to_string()
  }
}

pub fn hex_byte_string(msg: &str, bs: &[u8]) -> Vec<u8> {
  match hex_decode(bs) {
    Ok(x) => x,
    Err(_) => panic!("invalid hex bytestring for {}", msg),
  }
}

pub fn hex_text(t: &str) -> Vec<u8> {
  let t_trimmed = &t[2..]; // Remove "0x" prefix
  match hex_decode(t_trimmed.as_bytes()) {
    Ok(x) => x,
    Err(_) => panic!("invalid hex bytestring {}", t),
  }
}

// Utility function for formatting expressions
pub fn format_expr(expr: &Expr) -> String {
  expr.to_string()
}

// Utility function for indenting lines
fn indent(spaces: usize, text: &str) -> String {
  let padding = " ".repeat(spaces);
  text.lines().map(|line| format!("{}{}", padding, line)).collect::<Vec<String>>().join("\n")
}

// Function to format a property
pub fn format_prop(prop: &Prop) -> String {
  // Function to format a list of expressions
  fn fmt(name: &str, args: &[&Expr]) -> String {
    let formatted_args = args.iter().map(|arg| format_expr(arg)).collect::<Vec<String>>().join("\n");

    format!("({}\n{})\n)", name, indent(2, &formatted_args),)
  }

  fn fmt_prime(name: &str, args: &[&Prop]) -> String {
    let formatted_args = args.iter().map(|arg| format_prop(arg)).collect::<Vec<String>>().join("\n");

    format!("({}\n{})\n)", name, indent(2, &formatted_args),)
  }

  // Function to format a single expression
  fn fmt_single(name: &str, arg: &Prop) -> String {
    format!("({}\n{})\n)", name, indent(2, &format_prop(arg)))
  }

  match prop {
    Prop::PEq(a, b) => fmt("PEq", &[a, b]),
    Prop::PLT(a, b) => fmt("PLT", &[a, b]),
    Prop::PGT(a, b) => fmt("PGT", &[a, b]),
    Prop::PGEq(a, b) => fmt("PGEq", &[a, b]),
    Prop::PLEq(a, b) => fmt("PLEq", &[a, b]),
    Prop::PNeg(a) => fmt_single("PNeg", a),
    Prop::PAnd(a, b) => fmt_prime("PAnd", &[a, b]),
    Prop::POr(a, b) => fmt_prime("POr", &[a, b]),
    Prop::PImpl(a, b) => fmt_prime("PImpl", &[a, b]),
    Prop::PBool(a) => format!("{}", a),
  }
  .trim_end()
  .to_string()
}
