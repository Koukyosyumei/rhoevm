use std::os::raw::{c_char, c_int, c_void};
use std::ptr::NonNull;
use std::sync::Once;

extern "C" {
  /// Initializes the Ethjet context in the C library.
  ///
  /// # Safety
  /// This function interacts directly with the underlying C library and should be
  /// used with caution. Ensure that the context is properly freed after use.
  pub fn ethjet_init() -> *mut c_void;

  /// Frees the Ethjet context in the C library.
  ///
  /// # Safety
  /// This function must only be called with a valid, non-null pointer returned by
  /// `ethjet_init`.
  pub fn ethjet_free(context: *mut c_void);

  /// Executes an operation using the Ethjet context in the C library.
  ///
  /// # Arguments
  ///
  /// * `context` - A pointer to the initialized Ethjet context.
  /// * `operation` - The operation to be performed (contract number).
  /// * `input` - A pointer to the input data buffer.
  /// * `input_len` - The length of the input data buffer.
  /// * `output` - A pointer to the output data buffer.
  /// * `output_len` - The desired length of the output data buffer.
  ///
  /// # Returns
  ///
  /// Returns `1` if the operation was successful, otherwise returns a non-1 value.
  ///
  /// # Safety
  /// This function interacts directly with the underlying C library, so ensure that
  /// all pointers passed to it are valid.
  pub fn ethjet(
    context: *mut c_void,
    operation: c_int,
    input: *const c_char,
    input_len: c_int,
    output: *mut c_char,
    output_len: c_int,
  ) -> c_int;
}

/// A wrapper around the Ethjet context provided by the C library.
///
/// This struct manages the lifetime of the context, ensuring that it is properly
/// initialized and freed.
pub struct EthjetContext(NonNull<c_void>);

impl EthjetContext {
  /// Creates a new `EthjetContext` by initializing the context via the C library.
  ///
  /// # Returns
  ///
  /// Returns `Some(EthjetContext)` if the context was successfully initialized,
  /// otherwise returns `None`.
  pub fn new() -> Option<Self> {
    let context_ptr = unsafe { ethjet_init() };
    NonNull::new(context_ptr).map(EthjetContext)
  }

  /// Executes a precompiled contract using the Ethjet context.
  ///
  /// # Arguments
  ///
  /// * `contract` - The number of the precompiled contract to execute.
  /// * `input` - A byte slice containing the input data.
  /// * `output_size` - The desired size of the output buffer.
  ///
  /// # Returns
  ///
  /// Returns `Some(Vec<u8>)` containing the output data if the operation was successful,
  /// otherwise returns `None`.
  pub fn execute(&self, contract: i32, input: &[u8], output_size: usize) -> Option<Vec<u8>> {
    let mut output = vec![0u8; output_size];
    let status = unsafe {
      ethjet(
        self.0.as_ptr(),
        contract,
        input.as_ptr() as *const c_char,
        input.len() as c_int,
        output.as_mut_ptr() as *mut c_char,
        output_size as c_int,
      )
    };

    match status {
      1 => Some(output),
      _ => None,
    }
  }
}

impl Drop for EthjetContext {
  /// Frees the Ethjet context when the `EthjetContext` struct is dropped.
  ///
  /// This ensures that the C library's resources are properly released when the Rust
  /// wrapper goes out of scope.
  fn drop(&mut self) {
    unsafe {
      ethjet_free(self.0.as_ptr());
    }
  }
}

static INIT: Once = Once::new();
static mut GLOBAL_CONTEXT: Option<EthjetContext> = None;

/// Retrieves the global `EthjetContext`, initializing it if necessary.
///
/// # Returns
///
/// Returns a reference to the global `EthjetContext`. If initialization fails,
/// the program will panic.
///
/// # Safety
///
/// This function should only be called from a single thread during the initialization phase,
/// as it uses unsafe code to manage the global context.
pub fn get_global_context() -> &'static EthjetContext {
  unsafe {
    INIT.call_once(|| {
      GLOBAL_CONTEXT = EthjetContext::new();
    });
    GLOBAL_CONTEXT.as_ref().expect("Failed to initialize EthjetContext")
  }
}

/// Executes a precompiled contract using the global `EthjetContext`.
///
/// # Arguments
///
/// * `contract` - The number of the precompiled contract to execute.
/// * `input` - A byte slice containing the input data.
/// * `output_size` - The desired size of the output buffer.
///
/// # Returns
///
/// Returns `Some(Vec<u8>)` containing the output data if the operation was successful,
/// otherwise returns `None`.
pub fn execute(contract: i32, input: &[u8], output_size: usize) -> Option<Vec<u8>> {
  let context = get_global_context();
  context.execute(contract, input, output_size)
}
