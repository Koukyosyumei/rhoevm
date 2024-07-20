// Define the phantom types
#[derive(Debug, Clone, PartialEq, Hash)]
pub struct EWord;
#[derive(Debug, Clone, PartialEq, Hash)]
pub struct EAddr;
#[derive(Debug, Clone, PartialEq, Hash)]
pub struct EContract;
#[derive(Debug, Clone, PartialEq, Hash)]
pub struct Byte;
#[derive(Debug, Clone, PartialEq, Hash)]
pub struct End;
#[derive(Debug, Clone, PartialEq, Hash)]
pub struct Storage;
#[derive(Debug, Clone, PartialEq, Hash)]
pub struct Buf;
#[derive(Debug, Clone, PartialEq, Hash)]
pub struct Log;

// Trait for type name retrieval
pub trait ETypeTrait {
  fn type_name(&self) -> &'static str;
}

// Implement the trait for each type
impl ETypeTrait for EWord {
  fn type_name(&self) -> &'static str {
    "EWord"
  }
}

impl ETypeTrait for EAddr {
  fn type_name(&self) -> &'static str {
    "EAddr"
  }
}

impl ETypeTrait for EContract {
  fn type_name(&self) -> &'static str {
    "EContract"
  }
}

impl ETypeTrait for Byte {
  fn type_name(&self) -> &'static str {
    "Byte"
  }
}

impl ETypeTrait for End {
  fn type_name(&self) -> &'static str {
    "End"
  }
}

impl ETypeTrait for Storage {
  fn type_name(&self) -> &'static str {
    "Storage"
  }
}

impl ETypeTrait for Buf {
  fn type_name(&self) -> &'static str {
    "Buf"
  }
}

impl ETypeTrait for Log {
  fn type_name(&self) -> &'static str {
    "Log"
  }
}
