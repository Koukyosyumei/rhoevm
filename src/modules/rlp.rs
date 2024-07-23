use std::fmt;

use crate::modules::types::{Addr, ByteString, W256};

#[derive(PartialEq, Debug)]
enum RLP {
  BS(ByteString),
  List(Vec<RLP>),
}

impl fmt::Display for RLP {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      RLP::BS(bytes) => write!(f, "{:?}", bytes),
      RLP::List(list) => write!(f, "{:?}", list),
    }
  }
}

fn slice(offset: usize, size: usize, bs: &ByteString) -> ByteString {
  bs[offset..offset + size].to_vec()
}

fn item_info(bs: &ByteString) -> (usize, usize, bool, bool) {
  if bs.is_empty() {
    return (0, 0, false, false);
  }

  match bs[0] {
    0..=127 => (0, 1, false, true), // directly encoded byte
    128..=183 => {
      let len = bs[0] as usize - 128;
      (1, len, false, bs.len() != 2 || bs.get(1).map_or(false, |&b| b > 127))
    }
    184..=191 => {
      let pre = (bs[0] as usize - 183) as usize;
      let len = bytes_to_int(&slice(1, pre, bs)) as usize;
      (1 + pre, len, false, len > 55 && bs.get(1).map_or(false, |&b| b != 0))
    }
    192..=247 => (1, (bs[0] as usize - 192) as usize, true, true),
    _ => {
      let pre = (bs[0] as usize - 247) as usize;
      let len = bytes_to_int(&slice(1, pre, bs)) as usize;
      (1 + pre, len, true, len > 55 && bs.get(1).map_or(false, |&b| b != 0))
    }
  }
}

fn rlpdecode(bs: &ByteString) -> Option<RLP> {
  let (pre, len, is_list, optimal) = item_info(bs);
  if optimal && pre + len == bs.len() {
    let content = &bs[pre..].to_vec();
    if is_list {
      let items = rlplengths(content.clone(), 0, len)
        .iter()
        .map(|(s, e)| rlpdecode(&slice(*s, *e, content)))
        .collect::<Option<Vec<_>>>()?;

      Some(RLP::List(items))
    } else {
      Some(RLP::BS(content.to_vec()))
    }
  } else {
    None
  }
}

fn rlplengths(bs: ByteString, acc: usize, top: usize) -> Vec<(usize, usize)> {
  let mut result = Vec::new();
  let mut current_acc = acc;
  let mut current_bs = bs;

  while current_acc < top {
    let (pre, len, _, _) = item_info(&current_bs);
    result.push((current_acc, pre + len));
    current_acc += pre + len;
    current_bs = current_bs[pre + len..].to_vec();
  }

  result
}

fn rlpencode(rlp: &RLP) -> Vec<u8> {
  match rlp {
    RLP::BS(bs) => {
      if bs.len() == 1 && bs[0] < 128 {
        bs.clone()
      } else {
        encode_len(128, bs)
      }
    }
    RLP::List(items) => {
      let encoded_items: Vec<u8> = items.iter().flat_map(rlpencode).collect();
      encode_len(192, &encoded_items)
    }
  }
}

fn encode_len(offset: u8, bs: &[u8]) -> Vec<u8> {
  if bs.len() <= 55 {
    let mut result = vec![offset + bs.len() as u8];
    result.extend_from_slice(bs);
    result
  } else {
    let len_bytes = int_to_bytes(bs.len());
    let mut result = vec![offset + len_bytes.len() as u8 + 55];
    result.extend_from_slice(&len_bytes);
    result.extend_from_slice(bs);
    result
  }
}

fn int_to_bytes(mut num: usize) -> Vec<u8> {
  let mut bytes = Vec::new();
  while num > 0 {
    bytes.push((num & 0xFF) as u8);
    num >>= 8;
  }
  bytes.reverse();
  bytes
}

fn bytes_to_int(bs: &[u8]) -> usize {
  bs.iter().fold(0, |acc, &b| (acc << 8) | b as usize)
}

pub fn rlp_list(items: Vec<RLP>) -> Vec<u8> {
  rlpencode(&RLP::List(items))
}

fn octets(x: W256) -> Vec<u8> {
  (0..32).rev().map(|i| ((x.clone() >> (i as u32 * 8)) & W256(0xFF, 0)).0 as u8).skip_while(|&b| b == 0).collect()
}

fn octets_full(n: usize, x: W256) -> Vec<u8> {
  (0..n).rev().map(|i| ((x.clone() >> (i as u32 * 8)) & W256(0xFF, 0)).0 as u8).collect()
}

fn octets_160(x: Addr) -> Vec<u8> {
  (0..20).rev().map(|i| ((x.clone() >> (i as u32 * 8)) & W256(0xFF, 0)).0 as u8).skip_while(|&b| b == 0).collect()
}

pub fn rlp_word_256(x: W256) -> RLP {
  if x == W256(0, 0) {
    RLP::BS(Vec::new())
  } else {
    RLP::BS(octets(x))
  }
}

pub fn rlp_word_full(x: W256) -> RLP {
  RLP::BS(octets_full(31, x))
}

pub fn rlp_addr_full(x: Addr) -> RLP {
  RLP::BS(octets_full(19, x))
}

pub fn rlp_word_160(x: Addr) -> RLP {
  if x == W256(0, 0) {
    RLP::BS(Vec::new())
  } else {
    RLP::BS(octets_160(x))
  }
}
