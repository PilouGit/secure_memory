//! Dérivation de secrets d'authentification TPM basés sur le processus
//!
//! Ce module fournit une méthode pour dériver des secrets d'authentification
//! uniques basés sur :
//! - Le hash du binaire actuel (protection contre modification)
//! - Le PID du processus (isolation par processus)
//! - Un salt aléatoire (entropie cryptographique)
//!
//! ## Garanties de sécurité
//!
//! - Toutes les données sensibles sont automatiquement effacées (zeroization)
//! - Le secret dérivé est retourné dans un `Zeroizing<Vec<u8>>`
//! - Pas de panic sur erreur (gestion d'erreur propre)

use std::{env, fs};
use std::io::Read;
use rand::rand_core::{OsError, OsRng};
use rand::TryRngCore;
use sha2::{Sha256, Digest};
use hkdf::Hkdf;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{Data, HashScheme, PublicKeyRsa, RsaDecryptionScheme};
use zeroize::{Zeroize, Zeroizing};
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

    /// Hash le binaire actuel avec zeroization du buffer
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

        // ✅ Effacer le dernier chunk lu
        buffer.zeroize();

        Ok(hasher.finalize().to_vec())
    }
    /// Dérive un secret d'authentification
    ///
    /// Le secret est automatiquement protégé par zeroization.
    /// Toutes les valeurs intermédiaires (bin_hash, ikm, okm) sont effacées.
    ///
    /// # Retour
    ///
    /// Retourne un `Zeroizing<Vec<u8>>` qui sera automatiquement effacé
    /// lorsqu'il sortira du scope.
    pub fn derive(&self) -> Result<Zeroizing<Vec<u8>>, SecurityError> {
        let salt = &self.salt;

        // ✅ bin_hash sera automatiquement zeroizé
        let bin_hash = Zeroizing::new(Self::hash_current_binary()?);
        let pid = std::process::id().to_be_bytes();

        // ✅ ikm sera automatiquement zeroizé
        let mut ikm = Zeroizing::new(Vec::new());
        ikm.extend_from_slice(&bin_hash);
        ikm.extend_from_slice(&pid);

        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = [0u8; 32];

        // ✅ Gestion d'erreur propre au lieu de panic
        hk.expand(b"tpm-authvalue-derive", &mut okm)
            .map_err(|_| SecurityError::CryptoError("HKDF expansion failed".into()))?;

        // ✅ Créer le résultat protégé
        let result = Zeroizing::new(okm.to_vec());

        // ✅ Effacer okm avant de retourner
        okm.zeroize();

        Ok(result)
    }

    
}
impl Drop for TpmProcessAuth {
    fn drop(&mut self) {
        self.salt.zeroize();
    }
}