use hex::decode as hex_decode;

use crate::modules::types::{Expr, Prop};

/// Removes the "0x" prefix from a byte slice, if present.
///
/// This function checks if the byte slice starts with "0x". If it does, the prefix is stripped off,
/// and the rest of the byte slice is returned. If the prefix is not present, the original byte slice is returned unchanged.
///
/// # Parameters
/// - `bs`: A reference to a byte slice that may contain a "0x" prefix.
///
/// # Returns
/// - A `Vec<u8>` representing the byte slice without the "0x" prefix.
pub fn strip_0x(bs: &[u8]) -> Vec<u8> {
  if bs.starts_with(b"0x") {
    bs[2..].to_vec()
  } else {
    bs.to_vec()
  }
}

/// Removes the "0x" prefix from a string, if present.
///
/// This function checks if the string starts with "0x". If it does, the prefix is stripped off,
/// and the rest of the string is returned. If the prefix is not present, the original string is returned unchanged.
///
/// # Parameters
/// - `s`: A reference to a string that may contain a "0x" prefix.
///
/// # Returns
/// - A `String` representing the string without the "0x" prefix.
pub fn strip_0x_str(s: &str) -> String {
  if s.starts_with("0x") {
    s[2..].to_string()
  } else {
    s.to_string()
  }
}

/// Decodes a hexadecimal byte string, panicking if the byte string is invalid.
///
/// This function attempts to decode the provided byte slice as a hexadecimal string. If the decoding fails,
/// it panics with a message containing the provided `msg`.
///
/// # Parameters
/// - `msg`: A reference to a string used in the panic message if decoding fails.
/// - `bs`: A reference to a byte slice representing the hexadecimal string to be decoded.
///
/// # Returns
/// - A `Vec<u8>` containing the decoded bytes if successful.
///
/// # Panics
/// - Panics with a message including `msg` if the hexadecimal decoding fails.
pub fn hex_byte_string(msg: &str, bs: &[u8]) -> Vec<u8> {
  match hex_decode(bs) {
    Ok(x) => x,
    Err(_) => panic!("invalid hex bytestring for {}", msg),
  }
}

/// Decodes a hexadecimal string, assuming it starts with "0x", and panicking if the string is invalid.
///
/// This function removes the "0x" prefix from the string and attempts to decode the remaining characters
/// as a hexadecimal string. If the decoding fails, it panics with a message containing the original string.
///
/// # Parameters
/// - `t`: A reference to the hexadecimal string to be decoded (starting with "0x").
///
/// # Returns
/// - A `Vec<u8>` containing the decoded bytes if successful.
///
/// # Panics
/// - Panics with a message including `t` if the hexadecimal decoding fails.
pub fn hex_text(t: &str) -> Vec<u8> {
  let t_trimmed = &t[2..]; // Remove "0x" prefix
  match hex_decode(t_trimmed.as_bytes()) {
    Ok(x) => x,
    Err(_) => panic!("invalid hex bytestring {}", t),
  }
}

/// Formats an expression (`Expr`) into a string representation.
///
/// This function converts an `Expr` instance into its corresponding string representation, which can be useful for debugging or serialization.
///
/// # Parameters
/// - `expr`: A reference to the expression to be formatted.
///
/// # Returns
/// - A `String` representing the formatted expression.
pub fn format_expr(expr: &Expr) -> String {
  expr.to_string()
}

/// Indents each line of a given text by a specified number of spaces.
///
/// This function adds a specified number of spaces to the beginning of each line in the provided text,
/// making it useful for formatting and readability.
///
/// # Parameters
/// - `spaces`: The number of spaces to indent each line.
/// - `text`: A reference to the text that needs to be indented.
///
/// # Returns
/// - A `String` containing the indented text.
fn indent(spaces: usize, text: &str) -> String {
  let padding = " ".repeat(spaces);
  text.lines().map(|line| format!("{}{}", padding, line)).collect::<Vec<String>>().join("\n")
}

/// Formats a property (`Prop`) into a string representation.
///
/// This function converts a `Prop` instance into its corresponding string representation,
/// including nested expressions, which can be useful for debugging or serialization.
///
/// # Parameters
/// - `prop`: A reference to the property to be formatted.
///
/// # Returns
/// - A `String` representing the formatted property.
pub fn format_prop(prop: &Prop) -> String {
  // Function to format a list of expressions
  fn fmt(name: &str, args: &[&Expr]) -> String {
    let formatted_args = args.iter().map(|arg| format_expr(arg)).collect::<Vec<String>>().join("\n");

    format!("({}\n{})\n", name, indent(2, &formatted_args),)
  }

  fn fmt_prime(name: &str, args: &[&Prop]) -> String {
    let formatted_args = args.iter().map(|arg| format_prop(arg)).collect::<Vec<String>>().join("\n");

    format!("({}\n{})\n", name, indent(2, &formatted_args),)
  }

  // Function to format a single expression
  fn fmt_single(name: &str, arg: &Prop) -> String {
    format!("({}\n{})\n", name, indent(2, &format_prop(arg)))
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
