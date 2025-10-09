//! # Secure Memory
//!
//! A library for secure memory management operations.
//!
//! ## Features
//!
//! - Secure memory allocation and deallocation
//! - Memory wiping capabilities
//! - Type-safe abstractions
//!
//! ## Example
//!
//! ```rust
//! use secure_memory::SecureBuffer;
//!
//! let buffer = SecureBuffer::new(1024);
//! // Use the buffer...
//! // Memory is automatically wiped on drop
//! ```

#![deny(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]

/// Secure buffer implementation
pub mod buffer;
/// Error types and handling
pub mod error;
/// Utility functions for secure operations
pub mod utils;
/// TPM crypto operations
pub mod tpmcrypto;

pub use buffer::SecureBuffer;
pub use error::{Error, Result};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_functionality() {
        let buffer = SecureBuffer::new(100);
        assert_eq!(buffer.len(), 100);
    }
}