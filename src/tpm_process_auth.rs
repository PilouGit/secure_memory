//! Dérivation de secrets d'authentification TPM basés sur le processus
//!
//! Ce module fournit une méthode pour dériver des secrets d'authentification
//! uniques basés sur :
//! - Le hash du binaire actuel (protection contre modification)
//! - Le PID du processus (isolation par processus)
//! - Un salt aléatoire (entropie cryptographique)

use std::{env, fs};
use std::io::Read;
use rand::rand_core::{OsError, OsRng};
use rand::TryRngCore;
use sha2::{Sha256, Digest};
use hkdf::Hkdf;
use zeroize::Zeroize;
use crate::secure_error::SecurityError;

/// Structure pour dériver des secrets d'authentification TPM
pub struct TpmProcessAuth
{
    salt:Vec<u8>
}

impl TpmProcessAuth {
    /// Crée une nouvelle instance avec un salt aléatoire
    pub fn create() -> Result<Self, SecurityError> {
        let mut salt = vec![0u8; 32];
        OsRng.try_fill_bytes(&mut salt)?; // Erreur automatiquement convertie en anyhow::Error
        Ok(Self { salt })
    }

    fn hash_current_binary() -> Result<Vec<u8>, SecurityError> {
        let exe = env::current_exe()?;
        let mut file = fs::File::open(exe)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 4096];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        Ok(hasher.finalize().to_vec())
    }
    pub fn derive(&self) -> Result<Vec<u8>, SecurityError> {
        let salt = &self.salt; // OK, tu empruntes
        let bin_hash = Self::hash_current_binary()?;
        let pid = std::process::id().to_be_bytes();

        let mut ikm = Vec::new();
        ikm.extend_from_slice(&bin_hash);
        ikm.extend_from_slice(&pid);

        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = [0u8; 32];
        hk.expand(b"tpm-authvalue-derive", &mut okm)
            .expect("HKDF failed");

        Ok(okm.to_vec())
    }

}
impl Drop for TpmProcessAuth {
    fn drop(&mut self) {
        self.salt.zeroize();
    }
}