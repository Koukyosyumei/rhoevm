use rhoevm::modules::types::{pad_left_prime_vec, W256};

#[test]
fn test_pad_left_prime() {
  // Test case: input vector shorter than size
  let input = vec![1, 2, 3];
  let expected = vec![0; 29];
  let mut expected = [expected, vec![1, 2, 3]].concat();
  assert_eq!(pad_left_prime_vec(32, input), expected);

  // Test case: input vector exactly the size
  let input = vec![1; 32];
  assert_eq!(pad_left_prime_vec(32, input.clone()), input);

  // Test case: input vector longer than size (should be truncated)
  //let input = vec![1; 33];
  //let expected = vec![1; 32];
  //assert_eq!(pad_left_prime(32, input), expected);
}

#[test]
fn test_w256_from_bytes() {
  // Test case: input vector shorter than 32 bytes
  let input = vec![1, 2, 3];
  let expected_high = 0u128;
  let expected_low =
    u128::from_be_bytes([0; 13].iter().chain(&[1, 2, 3]).cloned().collect::<Vec<u8>>()[..16].try_into().unwrap());
  assert_eq!(W256::from_bytes(input), W256(expected_high, expected_low));

  // Test case: input vector exactly 32 bytes
  let input = vec![1; 32];
  let expected_high = u128::from_be_bytes([1; 16].try_into().unwrap());
  let expected_low = u128::from_be_bytes([1; 16].try_into().unwrap());
  assert_eq!(W256::from_bytes(input), W256(expected_high, expected_low));

  // Test case: input vector longer than 32 bytes (should be truncated)
  //let input = vec![1; 33];
  //let expected_high = u128::from_be_bytes([1; 16].try_into().unwrap());
  //let expected_low = u128::from_be_bytes([1; 16].try_into().unwrap());
  //assert_eq!(W256::from_bytes(input), W256(expected_high, expected_low));
}
