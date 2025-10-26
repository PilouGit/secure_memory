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

