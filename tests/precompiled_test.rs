use secp256k1::rand::rngs::OsRng;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha3::{Digest, Sha3_256};

use rhoevm::modules::precompiled::precompiled_ecrecover;

#[test]
fn test_ecrecover_success() {
  let secp = Secp256k1::new();
  let mut rng = OsRng;

  // Generate a random secret key and corresponding public key
  let sk = SecretKey::new(&mut rng);
  let pk = PublicKey::from_secret_key(&secp, &sk);

  // Create a message and its corresponding recoverable signature
  let message = Message::from_digest_slice(&[0xab; 32]).unwrap();
  let (recid, sig) = secp.sign_ecdsa_recoverable(&message, &sk).serialize_compact();

  // Prepare the input (message, V, R, S concatenated)
  let mut input = [0u8; 128];
  input[0..32].copy_from_slice(&message[..]);
  input[63] = (recid.to_i32() + 27) as u8;
  input[64..128].copy_from_slice(&sig);

  // Prepare the output buffer
  let mut output = [0u8; 32];

  // Call the function
  let result = precompiled_ecrecover(&secp, &input, &mut output);

  // Assert the function succeeded
  assert!(result.is_ok());

  // Compute the expected output (SHA3-256 of the public key)
  let mut hasher = Sha3_256::new();
  hasher.update(&pk.serialize_uncompressed()[1..65]);
  let expected_hash = hasher.finalize();

  // The output should match the first 32 bytes of the expected hash
  assert_eq!(&output, &expected_hash[..32]);
}

#[test]
fn test_ecrecover_invalid_recid() {
  let secp = Secp256k1::new();
  let mut input = [0u8; 128];
  let mut output = [0u8; 32];

  // Set an invalid recid value
  input[63] = 31; // recid would be 4, which is invalid

  let result = precompiled_ecrecover(&secp, &input, &mut output);
  assert!(result.is_err());
  assert_eq!(result.err().unwrap(), "Invalid recid");
}
