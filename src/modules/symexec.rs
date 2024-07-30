use crate::modules::abi::Sig;
use crate::modules::abi::{make_abi_value, selector, AbiType, AbiValue};
use crate::modules::expr::{add, buf_length, in_range, read_byte, write_byte, write_word};
use crate::modules::types::{Expr, Prop, W256};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CalldataFragment {
  St(Vec<Prop>, Expr),
  Dy(Vec<Prop>, Expr, Expr),
  Comp(Vec<CalldataFragment>),
}

pub fn to_bool(e: Expr) -> Prop {
  Prop::POr(Box::new(Prop::PEq(e.clone(), Expr::Lit(W256(1, 0)))), Box::new(Prop::PEq(e, Expr::Lit(W256(0, 0)))))
}

pub fn sym_abi_arg(name: &str, abi_type: AbiType) -> CalldataFragment {
  match abi_type {
    AbiType::AbiUIntType(n) => {
      if n % 8 == 0 && n <= 256 {
        let v = Expr::Var(name.into());
        CalldataFragment::St(vec![in_range(n as u32, Box::new(v.clone()))], v)
      } else {
        panic!("bad type")
      }
    }
    AbiType::AbiIntType(n) => {
      if n % 8 == 0 && n <= 256 {
        let v = Expr::Var(name.into());
        CalldataFragment::St(vec![in_range(n as u32, Box::new(v.clone()))], v)
      } else {
        panic!("bad type")
      }
    }
    AbiType::AbiBoolType => {
      let v = Expr::Var(name.into());
      CalldataFragment::St(vec![to_bool(v.clone())], v)
    }
    AbiType::AbiAddressType => CalldataFragment::St(vec![], Expr::SymAddr(name.into())),
    AbiType::AbiBytesType(n) => {
      if n > 0 && n <= 32 {
        let v = Expr::Var(name.into());
        CalldataFragment::St(vec![in_range((n * 8) as u32, Box::new(v.clone()))], v)
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

fn is_st(cf: &CalldataFragment) -> bool {
  match cf {
    CalldataFragment::St(_, _) => true,
    _ => false,
  }
}

// Function to combine calldata fragments
fn combine_fragments(fragments: &[CalldataFragment], base: Expr) -> (Expr, Vec<Prop>) {
  fn go(idx: Expr, fragments: &[CalldataFragment], acc: (Expr, Vec<Prop>)) -> (Expr, Vec<Prop>) {
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
  go(Expr::Lit(W256(4, 0)), fragments, (base, vec![]))
}

fn write_selector(buf: Expr, sig: &str) -> Expr {
  let selector = selector(&(sig.to_string()));
  (0..4).fold(buf, |buf, idx| {
    write_byte(
      Box::new(Expr::Lit(W256(idx, 0))),
      Box::new(read_byte(Box::new(Expr::Lit(W256(idx, 0))), Box::new(Expr::ConcreteBuf(selector.clone())))),
      Box::new(buf),
    )
  })
}

/*
-- | Generates calldata matching given type signature, optionally specialized
-- with concrete arguments.
-- Any argument given as "<symbolic>" or omitted at the tail of the list are
-- kept symbolic.
*/
pub fn sym_calldata(sig: &str, type_signature: &[AbiType], concrete_args: &[String], base: Expr) -> (Expr, Vec<Prop>) {
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
  let calldatas: Vec<CalldataFragment> =
    type_signature.iter().zip(args.iter()).enumerate().map(|(i, (typ, arg))| mk_arg(typ, arg, i + 1)).collect();
  let (cd_buf, props) = combine_fragments(&calldatas, base);
  let with_selector = write_selector(cd_buf, sig);
  let size_constraints = Prop::PAnd(
    Box::new(Prop::PGEq(
      Expr::BufLength(Box::new(with_selector.clone())),
      Expr::Lit(W256((calldatas.len() as u128 * 32 + 4 as u128).into(), 0)),
    )),
    Box::new(Prop::PBool(true)), //Box::new(Prop::PLT((Expr::BufLength(Box::new(with_selector.clone()))), (Expr::Lit(W256(2_u128.pow(64), 0))))),
  );
  (with_selector, vec![size_constraints].into_iter().chain(props).collect())
}

pub fn mk_calldata(sig: Option<Sig>, concrete_args: &[String]) -> (Expr, Vec<Prop>) {
  match sig {
    Some(Sig { method_signature: name, inputs: types }) => {
      sym_calldata(&name, &types, concrete_args, Expr::AbstractBuf("txdata".to_string()))
    }
    None => (
      Expr::AbstractBuf("txdata".to_string()),
      vec![Prop::PLEq(buf_length(Expr::AbstractBuf("txdata".to_string())), Expr::Lit(W256(2 ^ 64, 0)))],
    ),
  }
}
