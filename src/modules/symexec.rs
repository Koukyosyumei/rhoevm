use log::info;

use crate::modules::abi::Sig;
use crate::modules::abi::{make_abi_value, selector, AbiType, AbiValue};
use crate::modules::expr::{add, buf_length, in_range, read_byte, write_byte, write_word};
use crate::modules::types::{Expr, Prop, W256};

/// Represents a fragment of calldata in different forms.
///
/// - `St(Vec<Prop>, Expr)`: A static fragment with a list of properties and an expression.
/// - `Dy(Vec<Prop>, Expr, Expr)`: A dynamic fragment with properties and two expressions.
/// - `Comp(Vec<CalldataFragment>)`: A compound fragment containing other fragments.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CalldataFragment {
  St(Vec<Box<Prop>>, Expr),
  Dy(Vec<Box<Prop>>, Expr, Expr),
  Comp(Vec<CalldataFragment>),
}

/// Converts an expression to a boolean property. The function asserts that
/// the expression represents either a `true` (1) or `false` (0) value.
///
/// # Arguments
///
/// * `e` - A reference to the expression to convert.
///
/// # Returns
///
/// A `Prop` representing the boolean value of the expression.
pub fn to_bool(e: &Expr) -> Prop {
  Prop::POr(
    Box::new(Prop::PEq(e.clone(), Expr::Lit(W256(1, 0)))),
    Box::new(Prop::PEq(e.clone(), Expr::Lit(W256(0, 0)))),
  )
}

/// Generates a symbolic representation of an ABI argument.
///
/// # Arguments
///
/// * `name` - The name of the argument.
/// * `abi_type` - The ABI type of the argument.
///
/// # Returns
///
/// A `CalldataFragment` representing the symbolic ABI argument.
///
/// # Panics
///
/// Panics if the ABI type is not supported or if the type parameters are invalid.
pub fn sym_abi_arg(name: &str, abi_type: AbiType) -> CalldataFragment {
  match abi_type {
    AbiType::AbiUIntType(n) => {
      if n % 8 == 0 && n <= 256 {
        let v = Expr::Var(name.into());
        CalldataFragment::St(vec![Box::new(in_range(n as u32, Box::new(v.clone())))], v)
      } else {
        panic!("bad type")
      }
    }
    AbiType::AbiIntType(n) => {
      if n % 8 == 0 && n <= 256 {
        let v = Expr::Var(name.into());
        CalldataFragment::St(vec![Box::new(in_range(n as u32, Box::new(v.clone())))], v)
      } else {
        panic!("bad type")
      }
    }
    AbiType::AbiBoolType => {
      let v = Expr::Var(name.into());
      CalldataFragment::St(vec![Box::new(to_bool(&v))], v)
    }
    AbiType::AbiAddressType => CalldataFragment::St(vec![], Expr::SymAddr(name.into())),
    AbiType::AbiBytesType(n) => {
      if n > 0 && n <= 32 {
        let v = Expr::Var(name.into());
        CalldataFragment::St(vec![Box::new(in_range((n * 8) as u32, Box::new(v.clone())))], v)
      } else {
        panic!("bad type")
      }
    }
    AbiType::AbiArrayType(sz, tp) => {
      CalldataFragment::Comp((0..sz).map(|n| sym_abi_arg(&format!("{}{}", name, n), *tp.clone())).collect())
    }
    _ => panic!("TODO: symbolic abi encoding for {:?}", abi_type),
  }
}

/// Checks if a given calldata fragment is static.
///
/// # Arguments
///
/// * `cf` - A reference to the `CalldataFragment` to check.
///
/// # Returns
///
/// `true` if the fragment is static, otherwise `false`.
fn is_st(cf: &CalldataFragment) -> bool {
  match cf {
    CalldataFragment::St(_, _) => true,
    _ => false,
  }
}

/// Combines multiple calldata fragments into a single buffer, starting from a base expression.
///
/// # Arguments
///
/// * `fragments` - A slice of `CalldataFragment` to combine.
/// * `base` - The base expression to start from.
///
/// # Returns
///
/// A tuple containing the combined expression and a vector of properties associated with the calldata.
fn combine_fragments(fragments: &[CalldataFragment], base: &Expr) -> (Expr, Vec<Box<Prop>>) {
  fn go(idx: Expr, fragments: &[CalldataFragment], acc: (Expr, Vec<Box<Prop>>)) -> (Expr, Vec<Box<Prop>>) {
    if fragments.is_empty() {
      return acc;
    }

    let (buf, ps) = acc;

    let (fragment, rest) = fragments.split_first().unwrap();
    match fragment {
      // Static fragments get written as a word in place
      CalldataFragment::St(p, w) => {
        let new_idx = add(Box::new(idx.clone()), Box::new(Expr::Lit(W256(32, 0)))); // Add 32 to index
        let new_buf = write_word(Box::new(idx), Box::new(w.clone()), Box::new(buf));
        go(new_idx, &rest.to_vec(), (new_buf, [p.clone(), ps].concat()))
      }
      // Compound fragments that contain only static fragments get written in place
      CalldataFragment::Comp(xs) if xs.iter().all(is_st) => {
        let mut new_xs = xs.clone();
        new_xs.extend(rest.to_vec());
        go(idx, &new_xs, (buf, ps))
      }
      // Dynamic fragments are not yet supported
      s => {
        panic!("{}", &format!("unsupported cd fragment: {:?}", s));
      }
    }
  }

  // Initial call to go with starting index and fragments
  go(Expr::Lit(W256(4, 0)), fragments, (base.clone(), vec![]))
}

/// Writes a function selector into a buffer.
///
/// # Arguments
///
/// * `buf` - The buffer expression to write to.
/// * `sig` - The function signature to generate the selector from.
///
/// # Returns
///
/// An expression representing the buffer with the function selector written into it.
fn write_selector(buf: &Expr, sig: &str) -> Expr {
  let selector = selector(&(sig.to_string()));
  (0..4).fold(buf.clone(), |buf, idx| {
    write_byte(
      Box::new(Expr::Lit(W256(idx, 0))),
      Box::new(read_byte(Box::new(Expr::Lit(W256(idx, 0))), Box::new(Expr::ConcreteBuf(selector.clone())))),
      Box::new(buf),
    )
  })
}

/// Generates symbolic calldata for a given function signature and ABI types, with optional concrete arguments.
///
/// # Arguments
///
/// * `sig` - The function signature.
/// * `type_signature` - A slice of `AbiType` representing the function's input types.
/// * `concrete_args` - A slice of strings representing concrete argument values, if any.
/// * `base` - The base expression to start from.
/// * `offset` - The number of existing variables
///
/// # Returns
///
/// A tuple containing the generated calldata expression and a vector of properties.
///
/// # Panics
///
/// Panics if any ABI type is unsupported or concrete arguments cannot be parsed.
pub fn sym_calldata(
  sig: &str,
  type_signature: &[AbiType],
  concrete_args: &[String],
  base: &Expr,
  offset: usize,
) -> (Expr, Vec<Box<Prop>>) {
  let binding = "<symbolic>".to_string();
  let args = concrete_args.iter().chain(std::iter::repeat(&binding)).take(type_signature.len()).collect::<Vec<_>>();
  let mk_arg = |typ: &AbiType, arg: &String, n: usize| -> CalldataFragment {
    match arg.as_str() {
      "<symbolic>" => sym_abi_arg(&format!("arg{}", n), typ.clone()),
      _ => match make_abi_value(typ, arg) {
        AbiValue::AbiUInt(_, w) => CalldataFragment::St(vec![], Expr::Lit(W256(w as u128, 0))),
        AbiValue::AbiInt(_, w) => CalldataFragment::St(vec![], Expr::Lit(W256(w as u128, 0))),
        AbiValue::AbiAddress(w) => CalldataFragment::St(vec![], Expr::Lit(w)),
        AbiValue::AbiBool(w) => CalldataFragment::St(vec![], Expr::Lit(if w { W256(1, 0) } else { W256(0, 0) })),
        _ => panic!("TODO"),
      },
    }
  };
  let calldatas: Vec<CalldataFragment> = type_signature
    .iter()
    .zip(args.iter())
    .enumerate()
    .map(|(i, (typ, arg))| mk_arg(typ, arg, i + 1 + offset))
    .collect();
  let (cd_buf, props) = combine_fragments(&calldatas, &base);
  let with_selector = write_selector(&cd_buf, sig);
  let size_constraints = Box::new(Prop::PAnd(
    Box::new(Prop::PGEq(Expr::BufLength(Box::new(with_selector.clone())), cd_len(&calldatas))),
    Box::new(Prop::PLT(Expr::BufLength(Box::new(with_selector.clone())), Expr::Lit(W256(2_u128.pow(64), 0)))),
  ));
  (with_selector, vec![size_constraints].into_iter().chain(props).collect())
}

/// Calculates the length of the calldata for a given set of fragments.
///
/// # Arguments
///
/// * `cfs` - A vector of `CalldataFragment` to calculate the length for.
///
/// # Returns
///
/// An expression representing the total length of the calldata.
fn cd_len(cfs: &Vec<CalldataFragment>) -> Expr {
  let mut cfs_ = cfs.clone();
  let mut s = Expr::Lit(W256(4, 0));
  while !cfs_.is_empty() {
    let c = cfs_.pop().unwrap();
    match c {
      CalldataFragment::St(_, _) => {
        s = add(Box::new(s), Box::new(Expr::Lit(W256(32, 0))));
      }
      CalldataFragment::Comp(xs) => {
        if xs.iter().all(is_st) {
          for x in xs {
            cfs_.push(x);
          }
        }
      }
      _ => panic!("unsupported"),
    }
  }
  s
}

/// Creates symbolic or concrete calldata based on a given function signature and arguments.
///
/// # Arguments
///
/// * `sig` - An optional `Sig` representing the function signature and input types.
/// * `concrete_args` - A slice of strings representing concrete argument values, if any.
/// * `offset` - The number of existing variables
///
/// # Returns
///
/// A tuple containing the generated calldata expression and a vector of properties.
///
/// # Panics
///
/// Panics if any argument type is unsupported or concrete arguments cannot be parsed.
pub fn mk_calldata(sig: &Option<Sig>, concrete_args: &[String], offset: usize) -> (Expr, Vec<Box<Prop>>) {
  match sig {
    Some(Sig { method_signature: name, inputs: types }) => {
      sym_calldata(&name, &types, concrete_args, &Expr::AbstractBuf("txdata".to_string()), offset)
    }
    None => (
      Expr::AbstractBuf("txdata".to_string()),
      vec![Box::new(Prop::PLEq(buf_length(Expr::AbstractBuf("txdata".to_string())), Expr::Lit(W256(2 ^ 64, 0))))],
    ),
  }
}
