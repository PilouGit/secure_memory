//! Types d'erreur pour les opérations de sécurité

use rand::rand_core::OsError;
use std::io;
use linux_keyutils::KeyError;

/// Erreurs liées aux opérations de sécurité
#[derive(Debug)]
pub enum SecurityError {
    /// Erreur lors de la génération aléatoire
    ProcessAuthError(OsError),
    /// Erreur TPM
    TpmError(tss_esapi::Error),
    /// Erreur I/O (lecture de fichier, etc.)
    IoError(io::Error),
    /// Erreur cryptographique (HKDF, etc.)
    CryptoError(String),
    /// Keyring error
    KeyError(KeyError),
    /// Memory allocation failed
    AllocationFailed,
    /// Buffer canary corruption detected (buffer overflow attempt)
    CanaryCorruption,
    /// Write-once memory violation (attempted to write twice)
    WriteOnceViolation,
    /// Memory protection (mprotect) failed
    MemoryProtectionFailed,
    /// Encryption/Decryption failed
    CryptoOperationFailed,
}


impl From<OsError> for SecurityError {
    fn from(err: OsError) -> Self {
        SecurityError::ProcessAuthError(err)
    }
}

impl From<KeyError> for SecurityError {
    fn from(err: KeyError) -> Self {
        SecurityError::KeyError(err)
    }
}


impl From<tss_esapi::Error> for SecurityError {
    fn from(err: tss_esapi::Error) -> Self {
        SecurityError::TpmError(err)
    }
}

impl From<io::Error> for SecurityError {
    fn from(err: io::Error) -> Self {
        SecurityError::IoError(err)
    }
}

impl std::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityError::ProcessAuthError(e) => write!(f, "Process authentication error: {}", e),
            SecurityError::TpmError(e) => write!(f, "TPM error: {:?}", e),
            SecurityError::IoError(e) => write!(f, "I/O error: {}", e),
            SecurityError::CryptoError(s) => write!(f, "Cryptographic error: {}", s),
            SecurityError::KeyError(e) => write!(f, "Keyring error: {:?}", e),
            SecurityError::AllocationFailed => write!(f, "Memory allocation failed"),
            SecurityError::CanaryCorruption => write!(f, "SECURITY VIOLATION: Buffer canary corruption detected"),
            SecurityError::WriteOnceViolation => write!(f, "SECURITY VIOLATION: Attempted to write to write-once memory"),
            SecurityError::MemoryProtectionFailed => write!(f, "Memory protection (mprotect) failed"),
            SecurityError::CryptoOperationFailed => write!(f, "Encryption/Decryption operation failed"),
        }
    }
}

impl std::error::Error for SecurityError {}