//! Dérivation de clés cryptographiques liées au processus
//!
//! Ce module fournit une méthode pour dériver des clés cryptographiques
//! uniques basées sur :
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
use rand::rand_core::OsRng;
use rand::{rng,  Rng, TryRngCore};
use sha2::{Sha256, Digest};
use hkdf::Hkdf;
use linux_keyutils::{KeyPermissionsBuilder, KeyRing, KeyRingIdentifier, Permission};
use rand::distr::Alphanumeric;
use zeroize::{Zeroize, Zeroizing};
use crate::secure_error::SecurityError;

/// Structure pour dériver des clés cryptographiques liées au processus
pub struct ProcessKeyDeriver
{
    key:String
}
fn random_string(longueur: usize) -> String {
    rng()
        .sample_iter(&Alphanumeric)
        .take(longueur)
        .map(char::from)
        .collect()
}

impl ProcessKeyDeriver {
    /// Crée une nouvelle instance avec un salt aléatoire
    pub fn create() -> Result<Self, SecurityError> {
        let mut salt = vec![0u8; 32];
        let  key_description = random_string(10);
        OsRng.try_fill_bytes(&mut salt)?;
          let ring = KeyRing::from_special_id(KeyRingIdentifier::Session, false)?;
        let key=ring.add_key(&key_description,&salt)?;
        let perms = KeyPermissionsBuilder::builder()
            .posessor(Permission::ALL)
            .user(Permission::ALL)
            .group(Permission::VIEW | Permission::READ)
            .build();

        // Perform manipulations on the key such as setting permissions
        key.set_perms(perms)?;
   
        Ok(Self { key:key_description })
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
        let ring = KeyRing::from_special_id(KeyRingIdentifier::Session, false)?;

        // Lookup an existing key
        let salt = ring.search(&self.key)?.read_to_vec()?;


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
impl Drop for ProcessKeyDeriver {
    fn drop(&mut self) {
        // ✅ SÉCURITÉ: Gestion gracieuse des erreurs dans Drop
        // Drop ne doit JAMAIS paniquer (undefined behavior)

        match KeyRing::from_special_id(KeyRingIdentifier::Session, false) {
            Ok(ring) => {
                match ring.search(&self.key) {
                    Ok(key) => {
                        // Invalider la clé du keyring
                        if let Err(e) = key.invalidate() {
                            eprintln!("⚠️  WARNING: Failed to invalidate keyring key during cleanup: {:?}", e);
                        }
                    }
                    Err(e) => {
                        eprintln!("⚠️  WARNING: Failed to find keyring key '{}' during cleanup: {:?}", self.key, e);
                        // Clé peut avoir déjà été invalidée ou ne jamais avoir existé
                        // Ce n'est pas fatal - continuons le cleanup
                    }
                }
            }
            Err(e) => {
                eprintln!("⚠️  WARNING: Failed to access session keyring during cleanup: {:?}", e);
                eprintln!("   This may indicate:");
                eprintln!("   - Keyring support not available in kernel");
                eprintln!("   - Permission issues");
                eprintln!("   - Session keyring already destroyed");
                // Non-fatal - le processus peut se terminer normalement
            }
        }
    }
}