use std::fmt;

/// Error types for the secure memory library
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Buffer overflow error
    BufferOverflow,
    /// Invalid operation
    InvalidOperation,
    /// Memory allocation failed
    AllocationFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferOverflow => write!(f, "Buffer overflow: operation would exceed buffer bounds"),
            Self::InvalidOperation => write!(f, "Invalid operation"),
            Self::AllocationFailed => write!(f, "Memory allocation failed"),
        }
    }
}

impl std::error::Error for Error {}

/// Result type alias for this crate
pub type Result<T> = std::result::Result<T, Error>;