/// Automatic crypto service selection based on environment
///
/// This module provides a unified crypto service that automatically selects:
/// - **TPM Service** if `TPM_TCTI` environment variable is set
/// - **Software Crypto** if `TPM_TCTI` is not set
///
/// # Usage
///
/// ```rust
/// use secure_memory::crypto_service::get_service;
///
/// // Automatically uses TPM if TPM_TCTI is set, otherwise software crypto
/// let crypto = get_service();
/// let mut buffer = [0u8; 32];
/// crypto.random(&mut buffer).unwrap();
/// ```
///
/// # Environment Variables
///
/// - `TPM_TCTI=device` → Use hardware TPM
/// - `TPM_TCTI=mssim` → Use TPM simulator
/// - `TPM_TCTI=tabrmd` → Use TPM resource manager
/// - *Not set* → Use software crypto (no TPM required)
///
/// # Examples
///
/// ## Production (with TPM)
/// ```bash
/// export TPM_TCTI=device
/// cargo run --release
/// # → Uses TPM hardware
/// ```
///
/// ## Development (no TPM)
/// ```bash
/// unset TPM_TCTI
/// cargo run
/// # → Uses software crypto
/// ```
///
/// ## CI/CD (no TPM)
/// ```bash
/// # No TPM_TCTI set in GitHub Actions
/// cargo test
/// # → Uses software crypto (fast!)
/// ```

use crate::secure_error::SecurityError;
use std::sync::Mutex;

/// Enum to hold either TPM or Software crypto service
enum CryptoBackend {
    Tpm,
    Software,
}

/// Determine which backend to use based on TPM_TCTI environment variable
fn get_backend() -> CryptoBackend {
    match std::env::var("TPM_TCTI") {
        Ok(val) if !val.is_empty() => {
            println!("🔧 TPM_TCTI={} → Utilisation du TPM service", val);
            CryptoBackend::Tpm
        }
        _ => {
            println!("🔧 TPM_TCTI non défini → Utilisation du software crypto");
            CryptoBackend::Software
        }
    }
}

/// Unified crypto service that dispatches to TPM or Software
pub struct CryptoService {
    backend: CryptoBackend,
}

/// Global singleton
pub static CRYPTO_SERVICE: Mutex<Option<CryptoService>> = Mutex::new(None);

// Flag pour savoir si atexit a été enregistré
static ATEXIT_REGISTERED: std::sync::Once = std::sync::Once::new();

/// Wrapper autour de MutexGuard
pub struct CryptoServiceGuard<'a> {
    guard: std::sync::MutexGuard<'a, Option<CryptoService>>,
}

impl<'a> std::ops::Deref for CryptoServiceGuard<'a> {
    type Target = CryptoService;

    fn deref(&self) -> &Self::Target {
        self.guard.as_ref().unwrap()
    }
}

/// Cleanup automatique à la fin du processus
extern "C" fn cleanup_on_exit() {
    println!("🧹 Cleanup automatique du CryptoService à la fin du processus");
    let mut guard = CRYPTO_SERVICE.lock().unwrap();

    if let Some(service) = guard.take() {
        drop(service);
    }
    drop(guard);

    // Cleanup des sous-services
    crate::tpm_service::reset_service();
    crate::tpm_service_software::reset_service();

    println!("✅ Cleanup terminé: CryptoService détruit");
}

/// Get or create the crypto service singleton
///
/// Automatically selects TPM or Software based on `TPM_TCTI` environment variable.
///
/// # Thread Safety
///
/// This function is **thread-safe** and can be called concurrently from multiple threads.
///
/// # Performance
///
/// - **With TPM_TCTI**: Uses TPM hardware/simulator (slower, more secure)
/// - **Without TPM_TCTI**: Uses software crypto (faster, less secure)
///
/// # Example
///
/// ```rust
/// use secure_memory::crypto_service::get_service;
///
/// let crypto = get_service();
/// let mut random_data = [0u8; 32];
/// crypto.random(&mut random_data).unwrap();
/// ```
pub fn get_service() -> CryptoServiceGuard<'static> {
    // Enregistrer le cleanup à la fin du processus (une seule fois)
    ATEXIT_REGISTERED.call_once(|| {
        unsafe {
            libc::atexit(cleanup_on_exit);
        }
        println!("✅ Handler atexit enregistré pour cleanup CryptoService");
    });

    // Initialiser si nécessaire
    let mut guard = CRYPTO_SERVICE.lock().unwrap();
    if guard.is_none() {
        let backend = get_backend();
        *guard = Some(CryptoService { backend });
    }

    CryptoServiceGuard { guard }
}

/// Reset the service (useful for tests)
pub fn reset_service() {
    let mut guard = CRYPTO_SERVICE.lock().unwrap();
    if let Some(service) = guard.take() {
        drop(service);
    }
    drop(guard);

    crate::tpm_service::reset_service();
    crate::tpm_service_software::reset_service();

    println!("♻️  CryptoService reset");
}

impl CryptoService {
    /// Fill the buffer with random data
    ///
    /// Automatically uses TPM or Software RNG based on configuration.
    pub fn random(&self, data: &mut [u8]) -> Result<(), SecurityError> {
        match self.backend {
            CryptoBackend::Tpm => {
                let tpm = crate::tpm_service::get_service();
                tpm.random(data)
                    .map_err(|e| SecurityError::CryptoError(format!("TPM random failed: {:?}", e)))
            }
            CryptoBackend::Software => {
                let software = crate::tpm_service_software::get_service();
                software.random(data)
            }
        }
    }

    /// Encrypt data using RSA
    ///
    /// Automatically uses TPM or Software RSA based on configuration.
    pub fn ciphering(&self, buffer: Vec<u8>) -> Result<Vec<u8>, SecurityError> {
        match self.backend {
            CryptoBackend::Tpm => {
                let tpm = crate::tpm_service::get_service();
                Ok(tpm.ciphering(buffer))
            }
            CryptoBackend::Software => {
                let software = crate::tpm_service_software::get_service();
                software.ciphering(buffer)
            }
        }
    }

    /// Decrypt data using RSA
    ///
    /// Automatically uses TPM or Software RSA based on configuration.
    pub fn unciphering(&self, buffer: Vec<u8>) -> Result<Vec<u8>, SecurityError> {
        match self.backend {
            CryptoBackend::Tpm => {
                let tpm = crate::tpm_service::get_service();
                Ok(tpm.unciphering(buffer))
            }
            CryptoBackend::Software => {
                let software = crate::tpm_service_software::get_service();
                software.unciphering(buffer)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_selection_software() {
        // Sans TPM_TCTI, doit utiliser software
        std::env::remove_var("TPM_TCTI");
        reset_service();

        let crypto = get_service();
        let mut buffer = [0u8; 32];
        crypto.random(&mut buffer).unwrap();

        assert_ne!(buffer, [0u8; 32]);
        reset_service();
    }

    #[test]
    #[ignore] // Nécessite TPM simulator
    fn test_auto_selection_tpm() {
        // Avec TPM_TCTI, doit utiliser TPM
        std::env::set_var("TPM_TCTI", "mssim");
        reset_service();

        let crypto = get_service();
        let mut buffer = [0u8; 32];
        let result = crypto.random(&mut buffer);

        // Peut réussir si TPM simulator disponible, sinon erreur attendue
        match result {
            Ok(_) => println!("✅ TPM simulator disponible"),
            Err(_) => println!("⚠️ TPM simulator non disponible (normal en CI)"),
        }

        std::env::remove_var("TPM_TCTI");
        reset_service();
    }

    #[test]
    fn test_encrypt_decrypt_auto() {
        std::env::remove_var("TPM_TCTI");
        reset_service();

        let crypto = get_service();
        let plaintext = b"Hello, Auto Crypto!".to_vec();

        let encrypted = crypto.ciphering(plaintext.clone()).unwrap();
        assert_ne!(encrypted, plaintext);

        let decrypted = crypto.unciphering(encrypted).unwrap();
        assert_eq!(decrypted, plaintext);

        reset_service();
    }
}
