use secp256k1::{ecdsa::RecoverableSignature, ecdsa::RecoveryId, Message, Secp256k1};
use sha3::{Digest, Sha3_256};

pub fn precompile_ecrecover(
  ctx: &Secp256k1<secp256k1::All>,
  in_data: &[u8],
  out: &mut [u8],
) -> Result<(), &'static str> {
  /*
  Inputs
        Byte range	     | Name	 |                  Description
    ----------------------------------------------------------------------------------
    [0; 31] (32 bytes)	 | hash	 | Keccack-256 hash of the transaction
    [32; 63] (32 bytes)	 |  v	   | Recovery identifier, expected to be either 27 or 28
    [64; 95] (32 bytes)	 |  r	   | x-value, expected to be in the range ]0; secp256k1n[
    [96; 127] (32 bytes) |	s	   | Expected to be in the range ]0; secp256k1n[

  Output
        Byte range	     |     Name	     |                    Description
    ----------------------------------------------------------------------------------------------
    [0; 31] (32 bytes)	 | publicAddress | The recovered 20-byte address right aligned to 32 bytes
  */

  // Check input size
  if in_data.len() != 128 {
    return Err("Invalid input size");
  }

  // Check output size
  if out.len() != 32 {
    return Err("Invalid output size");
  }

  // Extract recovery ID from V (last byte of in_data)
  let recid = match RecoveryId::from_i32((in_data[63] - 27) as i32) {
    Ok(id) => id,
    Err(_) => return Err("Invalid recid"),
  };

  // Check higher bytes of V are zero
  if in_data[32..63].iter().all(|&x| x != 0) {
    return Err("Invalid higher bytes of V");
  }

  // Prepare the signature and message
  let sig = match RecoverableSignature::from_compact(&in_data[64..128], recid) {
    Ok(s) => s,
    Err(_) => return Err("Failed to parse signature"),
  };
  let message = match Message::from_digest_slice(&in_data[0..32]) {
    Ok(m) => m,
    Err(_) => return Err("Failed to parse message"),
  };

  // Recover the public key
  let pubkey = match ctx.recover_ecdsa(&message, &sig) {
    Ok(pk) => pk,
    Err(_) => return Err("Failed to recover public key"),
  };

  // Serialize the public key to uncompressed form
  let pubkey_uncompressed = pubkey.serialize_uncompressed();

  // Hash the public key with SHA3-256
  let mut hasher = Sha3_256::new();
  hasher.update(&pubkey_uncompressed[1..65]); // skip the first byte
  let hash = hasher.finalize();

  // Copy the first 32 bytes of the hash to the output
  out.copy_from_slice(&hash[0..32]);

  Ok(())
}
