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
    KeyError(KeyError)
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