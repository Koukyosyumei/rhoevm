#[derive(Debug, Clone)]
pub struct FeeSchedule {
  pub g_zero: u64,
  pub g_base: u64,
  pub g_verylow: u64,
  pub g_low: u64,
  pub g_mid: u64,
  pub g_high: u64,
  pub g_extcode: u64,
  pub g_balance: u64,
  pub g_sload: u64,
  pub g_jumpdest: u64,
  pub g_sset: u64,
  pub g_sreset: u64,
  r_sclear: u64,
  pub g_selfdestruct: u64,
  pub g_selfdestruct_newaccount: u64,
  r_selfdestruct: u64,
  pub g_create: u64,
  pub g_codedeposit: u64,
  pub g_call: u64,
  pub g_callvalue: u64,
  pub g_callstipend: u64,
  pub g_newaccount: u64,
  pub g_exp: u64,
  pub g_expbyte: u64,
  pub g_memory: u64,
  pub g_txcreate: u64,
  pub g_txdatazero: u64,
  pub g_txdatanonzero: u64,
  pub g_transaction: u64,
  pub g_log: u64,
  pub g_logdata: u64,
  pub g_logtopic: u64,
  pub g_sha3: u64,
  pub g_sha3word: u64,
  pub g_initcodeword: u64,
  pub g_copy: u64,
  pub g_blockhash: u64,
  pub g_extcodehash: u64,
  pub g_quaddivisor: u64,
  pub g_ecadd: u64,
  pub g_ecmul: u64,
  pub g_pairing_point: u64,
  pub g_pairing_base: u64,
  pub g_fround: u64,
  r_block: u64,
  pub g_cold_sload: u64,
  pub g_cold_account_access: u64,
  pub g_warm_storage_read: u64,
  pub g_access_list_address: u64,
  pub g_access_list_storage_key: u64,
}

pub const FEE_SCHEDULE: FeeSchedule = FeeSchedule {
  g_zero: 0,
  g_base: 2,
  g_verylow: 3,
  g_low: 5,
  g_mid: 8,
  g_high: 10,
  g_extcode: 2600,
  g_balance: 2600,
  g_sload: 100,
  g_jumpdest: 1,
  g_sset: 20000,
  g_sreset: 2900,
  r_sclear: 15000,
  g_selfdestruct: 5000,
  g_selfdestruct_newaccount: 25000,
  r_selfdestruct: 24000,
  g_create: 32000,
  g_codedeposit: 200,
  g_call: 2600,
  g_callvalue: 9000,
  g_callstipend: 2300,
  g_newaccount: 25000,
  g_exp: 10,
  g_expbyte: 50,
  g_memory: 3,
  g_txcreate: 32000,
  g_txdatazero: 4,
  g_txdatanonzero: 16,
  g_transaction: 21000,
  g_log: 375,
  g_logdata: 8,
  g_logtopic: 375,
  g_sha3: 30,
  g_sha3word: 6,
  g_initcodeword: 2,
  g_copy: 3,
  g_blockhash: 20,
  g_extcodehash: 2600,
  g_quaddivisor: 20,
  g_ecadd: 150,
  g_ecmul: 6000,
  g_pairing_point: 34000,
  g_pairing_base: 45000,
  g_fround: 1,
  r_block: 2_000_000_000_000_000_000,
  g_cold_sload: 2100,
  g_cold_account_access: 2600,
  g_warm_storage_read: 100,
  g_access_list_address: 2400,
  g_access_list_storage_key: 1900,
};
