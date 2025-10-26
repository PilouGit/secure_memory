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


/// Utility functions for secure operations
pub mod utils;
/// TPM service for cryptographic operations
pub mod tpm_service;
/// Secure key operation
pub mod secure_key;
/// Secure Memory buffer
pub mod secure_memory;
/// FFI interface for SecureMemory (C-compatible for JNA/JNI)
pub mod secure_memory_ffi;
pub mod process_key_deriver;

pub mod secure_error;

 mod anti_debug;

pub use anti_debug::harden_process;

/// Active les protections anti-debug pour ce processus.
/// À appeler explicitement par l’application avant toute opération sensible.
///
/// Exemple:
/// ```
/// secure_memory::init_secure_env().expect("anti-debug setup failed");
/// ```
#[cfg(all(not(test), not(debug_assertions)))]
#[ctor::ctor]
pub fn init_secure_env() -> Result<(), String> {
    anti_debug::harden_process()
}