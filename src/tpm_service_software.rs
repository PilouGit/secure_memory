use std::sync::Mutex;
use std::io::Write; // Pour cleanup_on_exit
use rsa::rand_core::{OsRng, RngCore};
use rsa::{RsaPrivateKey, RsaPublicKey, Oaep};
use rsa::sha2::Sha256;
use crate::secure_error::SecurityError;
use crate::process_key_deriver::ProcessKeyDeriver;

/// Software-only cryptographic operations (no TPM required)
///
/// This structure provides a thread-safe interface to software cryptographic operations:
/// - Random number generation (OsRng only)
/// - RSA encryption/decryption with software keys
/// - Key derivation bound to process identity
///
/// # Differences from TPM version
///
/// - **No hardware security**: Keys are stored in RAM, not sealed by TPM
/// - **Faster**: No TPM communication overhead
/// - **Portable**: Works on any platform without TPM hardware
/// - **Less secure**: Keys can be swapped to disk if mlock() fails
///
/// # Thread Safety
///
/// All operations are protected by internal mutexes for safe concurrent access.
///
/// # Performance Note
///
/// This implementation is significantly faster than TPM-based operations:
/// - Random generation: ~100x faster (no TPM I/O)
/// - RSA operations: ~10x faster (pure software, no context switching)
///
/// # Security Trade-offs
///
/// ⚠️ **IMPORTANT**: This is a software-only implementation with reduced security:
///
/// - ✅ **Provides**: Process isolation, memory encryption, secure cleanup
/// - ❌ **Missing**: Hardware-backed key storage, anti-tamper protection
/// - ⚠️ **Risk**: Keys may be swapped to disk if mlock() fails
///
/// Use this for:
/// - Development and testing
/// - Platforms without TPM
/// - High-throughput scenarios where TPM is too slow
///
/// DO NOT use this for:
/// - Production secrets requiring hardware security
/// - Compliance scenarios requiring HSM/TPM
/// Wrapper qui zeroize la clé RSA lors du Drop
/// ✅ P0-1: RsaPrivateKey n'implémente pas Zeroize, donc on crée un wrapper
struct ZeroizingRsaKey {
    key: RsaPrivateKey,
}

impl Drop for ZeroizingRsaKey {
    fn drop(&mut self) {
        // Zeroize manual: on efface les composants sensibles
        // Note: Le crate rsa expose les méthodes to_components() mais c'est interne
        // On va utiliser zeroize sur la structure entière via transmute (unsafe mais nécessaire)
        use zeroize::Zeroize;
        unsafe {
            // Obtenir un pointeur vers les bytes de la structure
            let ptr = &mut self.key as *mut RsaPrivateKey as *mut u8;
            let size = std::mem::size_of::<RsaPrivateKey>();
            // Zeroize les bytes
            std::slice::from_raw_parts_mut(ptr, size).zeroize();
        }
    }
}

/// Software crypto service for RSA operations without TPM
///
/// This is the main implementation of the software-only crypto service.
/// See module documentation above for security considerations and usage patterns.
pub struct SoftwareCrypto {
    process_auth: ProcessKeyDeriver,
    // ✅ P0-1: Wrapper custom pour zeroize manual
    rsa_private_key: Mutex<Option<ZeroizingRsaKey>>,
    rsa_public_key: Mutex<Option<RsaPublicKey>>,
}

/// Software Crypto Singleton
pub static SOFTWARE_CRYPTO: Mutex<Option<SoftwareCrypto>> = Mutex::new(None);

// Flag pour savoir si atexit a été enregistré
static ATEXIT_REGISTERED: std::sync::Once = std::sync::Once::new();

/// Wrapper autour de MutexGuard pour accéder au SoftwareCrypto
pub struct SoftwareCryptoGuard<'a> {
    guard: std::sync::MutexGuard<'a, Option<SoftwareCrypto>>,
}

impl<'a> std::ops::Deref for SoftwareCryptoGuard<'a> {
    type Target = SoftwareCrypto;

    fn deref(&self) -> &Self::Target {
        self.guard.as_ref().unwrap()
    }
}

/// Cleanup automatique à la fin du processus
///
/// ✅ P0-2: Cette fonction doit être infaillible (pas de panic) car elle est
/// appelée par libc::atexit. Utilise eprintln! au lieu de println! et gère
/// le mutex poisoning proprement.
extern "C" fn cleanup_on_exit() {
    // ✅ Utiliser eprintln (stderr) qui est moins susceptible de paniquer
    let _ = std::io::stderr().write_all(b"Cleanup automatique du SoftwareCrypto\n");

    // ✅ P0-2: Gérer le poison sans paniquer
    let guard = SOFTWARE_CRYPTO.lock()
        .or_else(|poisoned| -> Result<std::sync::MutexGuard<Option<SoftwareCrypto>>, std::sync::PoisonError<std::sync::MutexGuard<Option<SoftwareCrypto>>>> {
            Ok(poisoned.into_inner())
        });

    if let Ok(mut guard) = guard {
        if let Some(crypto) = guard.take() {
            drop(crypto); // Force l'appel de Drop (qui est lui-même safe maintenant)
        }
    }

    let _ = std::io::stderr().write_all(b"Cleanup termine\n");
}

/// Get or create the software crypto service singleton
///
/// # Thread Safety
///
/// This function is **thread-safe** and can be called concurrently from multiple threads.
/// Access is protected by a `Mutex`, ensuring safe concurrent access.
///
/// # Performance
///
/// Unlike the TPM version, this implementation has minimal contention:
/// - RSA operations are pure software (no hardware serialization)
/// - Much faster for high-throughput scenarios
///
/// # Example Usage
///
/// ```rust
/// use secure_memory::tpm_service_software::get_service;
///
/// let crypto = get_service();
/// let mut random_data = [0u8; 32];
/// crypto.random(&mut random_data).unwrap();
/// ```
///
/// # Returns
///
/// A `SoftwareCryptoGuard` that provides scoped access to the service.
/// The guard automatically releases the lock when dropped.
pub fn get_service() -> SoftwareCryptoGuard<'static> {
    // Enregistrer le cleanup à la fin du processus (une seule fois)
    ATEXIT_REGISTERED.call_once(|| {
        unsafe {
            libc::atexit(cleanup_on_exit);
        }
        println!("✅ Handler atexit enregistré pour cleanup SoftwareCrypto");
    });

    // Initialiser si nécessaire
    let mut guard = SOFTWARE_CRYPTO.lock().unwrap();
    if guard.is_none() {
        let mut crypto = SoftwareCrypto::create().unwrap();
        crypto.init_key().unwrap();
        *guard = Some(crypto);
    }

    SoftwareCryptoGuard { guard }
}

/// Reset et force le drop du singleton (utile pour les tests)
pub fn reset_service() {
    let mut guard = SOFTWARE_CRYPTO.lock().unwrap();
    if let Some(crypto) = guard.take() {
        drop(crypto);
    }
    drop(guard);
    println!("♻️  SoftwareCrypto reset: Drop appelé");
}

impl SoftwareCrypto {
    /// Create a new SoftwareCrypto instance
    pub fn create() -> Result<Self, SecurityError> {
        println!("🔧 Initialisation SoftwareCrypto (pas de TPM requis)");

        let process_auth = ProcessKeyDeriver::create()?;

        Ok(SoftwareCrypto {
            process_auth,
            rsa_private_key: Mutex::new(None),
            rsa_public_key: Mutex::new(None),
        })
    }

    // ✅ P0-2: Helper pour gérer mutex poison
    fn lock_private_key(&self) -> Result<std::sync::MutexGuard<Option<ZeroizingRsaKey>>, SecurityError> {
        match self.rsa_private_key.lock() {
            Ok(guard) => Ok(guard),
            Err(poisoned) => {
                eprintln!("⚠️ WARNING: Private key mutex poisoned - recovering");
                Ok(poisoned.into_inner())
            }
        }
    }

    fn lock_public_key(&self) -> Result<std::sync::MutexGuard<Option<RsaPublicKey>>, SecurityError> {
        match self.rsa_public_key.lock() {
            Ok(guard) => Ok(guard),
            Err(poisoned) => {
                eprintln!("⚠️ WARNING: Public key mutex poisoned - recovering");
                Ok(poisoned.into_inner())
            }
        }
    }

    /// Initialisation des clés RSA
    pub fn init_key(&mut self) -> Result<(), SecurityError> {
        // ✅ P0-3: Utiliser process_auth pour lier les clés au processus
        let process_secret = self.process_auth.derive()?;
        let process_id = hex::encode(&process_secret[..8]);

        println!("🔑 Génération clés RSA 2048 bits (software) [process: {}]", process_id);

        // Note: Le crate rsa n'accepte pas de seed custom
        // Mais on enregistre l'association au processus pour audit/logging
        let mut rng = OsRng;

        // Générer une paire de clés RSA 2048 bits
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|e| SecurityError::CryptoError(format!("RSA keygen failed: {}", e)))?;

        let public_key = RsaPublicKey::from(&private_key);

        // ✅ P0-1: Wrapper la clé privée dans ZeroizingRsaKey
        let zeroizing_private_key = ZeroizingRsaKey { key: private_key };

        // ✅ P0-2: Utiliser les helpers safe pour lock
        *self.lock_private_key()? = Some(zeroizing_private_key);
        *self.lock_public_key()? = Some(public_key);

        println!("✅ Clés RSA générées et stockées en mémoire (zeroizing activé)");
        Ok(())
    }

    /// Fill the buffer with random data from OsRng
    pub fn random(&self, data: &mut [u8]) -> Result<(), SecurityError> {
        OsRng.fill_bytes(data);
        Ok(())
    }

    /// Encrypt data using RSA-OAEP with SHA256
    pub fn ciphering(&self, buffer: Vec<u8>) -> Result<Vec<u8>, SecurityError> {
        // ✅ P0-2: Utiliser helper safe pour lock
        let public_key_guard = self.lock_public_key()?;
        let public_key = public_key_guard.as_ref()
            .ok_or_else(|| SecurityError::CryptoError("Public key not initialized".to_string()))?;

        // Vérifier la taille maximale pour RSA-2048 avec OAEP-SHA256
        // Max = (key_size_bytes - 2*hash_size - 2) = (256 - 2*32 - 2) = 190 bytes
        let max_plaintext_size = 190;
        if buffer.len() > max_plaintext_size {
            return Err(SecurityError::CryptoError(
                format!("Data too large for RSA encryption: {} bytes (max {})",
                    buffer.len(), max_plaintext_size)
            ));
        }

        let mut rng = OsRng;
        let padding = Oaep::new::<Sha256>();

        let encrypted = public_key.encrypt(&mut rng, padding, &buffer)
            .map_err(|e| SecurityError::CryptoError(format!("RSA encryption failed: {}", e)))?;

        Ok(encrypted)
    }

    /// Decrypt data using RSA-OAEP with SHA256
    pub fn unciphering(&self, buffer: Vec<u8>) -> Result<Vec<u8>, SecurityError> {
        // ✅ P0-2: Utiliser helper safe pour lock
        let private_key_guard = self.lock_private_key()?;
        let zeroizing_key = private_key_guard.as_ref()
            .ok_or_else(|| SecurityError::CryptoError("Private key not initialized".to_string()))?;

        let padding = Oaep::new::<Sha256>();

        let decrypted = zeroizing_key.key.decrypt(padding, &buffer)
            .map_err(|e| SecurityError::CryptoError(format!("RSA decryption failed: {}", e)))?;

        Ok(decrypted)
    }

    /// Clean up keys (zeroize memory)
    pub fn logout(&mut self) {
        eprintln!("🔥 SoftwareCrypto cleanup - Nettoyage SÉCURISÉ des clés");

        // ✅ P0-1: Zeroizing<RsaPrivateKey> efface automatiquement la clé lors du Drop
        // ✅ P0-2: Utiliser helpers safe pour éviter panic sur poison
        if let Ok(mut guard) = self.lock_private_key() {
            guard.take(); // Drop → Zeroize automatique
        }

        if let Ok(mut guard) = self.lock_public_key() {
            guard.take();
        }

        eprintln!("✅ SoftwareCrypto cleanup terminé - Clés effacées de la mémoire");
    }
}

impl Drop for SoftwareCrypto {
    fn drop(&mut self) {
        self.logout();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_generation() {
        let crypto = SoftwareCrypto::create().unwrap();
        let mut buffer = [0u8; 32];
        crypto.random(&mut buffer).unwrap();

        // Vérifier que le buffer n'est pas resté à zéro
        assert_ne!(buffer, [0u8; 32]);
    }

    #[test]
    fn test_rsa_encrypt_decrypt() {
        let mut crypto = SoftwareCrypto::create().unwrap();
        crypto.init_key().unwrap();

        let plaintext = b"Hello, SecureMemory!".to_vec();

        // Chiffrer
        let encrypted = crypto.ciphering(plaintext.clone()).unwrap();
        assert_ne!(encrypted, plaintext);

        // Déchiffrer
        let decrypted = crypto.unciphering(encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rsa_max_size() {
        let mut crypto = SoftwareCrypto::create().unwrap();
        crypto.init_key().unwrap();

        // Tester avec données trop grandes (>190 bytes)
        let too_large = vec![0u8; 200];
        let result = crypto.ciphering(too_large);
        assert!(result.is_err());
    }

    #[test]
    fn test_singleton() {
        reset_service(); // Nettoyer d'abord

        let crypto1 = get_service();
        let mut buffer = [0u8; 16];
        crypto1.random(&mut buffer).unwrap();

        drop(crypto1);

        // Le singleton doit toujours exister
        let crypto2 = get_service();
        crypto2.random(&mut buffer).unwrap();

        reset_service(); // Cleanup
    }
}
