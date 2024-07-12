use hex::decode as hex_decode;

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
