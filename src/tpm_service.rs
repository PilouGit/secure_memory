use std::sync::Mutex;
use rand::rand_core::OsRng;
use rand::TryRngCore;
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::{Context, Error, Result};
use tss_esapi::TctiNameConf;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::{StartupType, Tss2ResponseCodeKind};
use tss_esapi::structures::*;
use tss_esapi::interface_types::algorithm::*;
use crate::secure_error::SecurityError;
use crate::process_key_deriver::ProcessKeyDeriver;

/// TPM cryptographic operations wrapper
///
/// This structure provides a thread-safe interface to TPM 2.0 operations including:
/// - Random number generation (hardware RNG)
/// - RSA encryption/decryption with TPM-sealed keys
/// - Key derivation bound to process identity
///
/// # Thread Safety
///
/// All TPM operations are protected by internal mutexes:
/// - `context`: Mutex<Context> - Protects TPM context
/// - `primary`: Mutex<Option<...>>` - Protects primary key
/// - `rsa_key_handle`: Mutex<Option<...>>` - Protects RSA key handle
///
/// This ensures memory safety but **does NOT** improve performance in multi-threaded scenarios.
/// The TPM hardware is fundamentally single-threaded, so concurrent calls will be serialized.
///
/// # Performance Note
///
/// For high-performance applications:
/// - Minimize TPM calls by caching results
/// - Prefer bulk operations over many small calls
/// - Consider using the TPM only for key sealing, not frequent operations
pub struct TpmCrypto {
    context: Mutex<Context>,
    tpm_process_auth: ProcessKeyDeriver,
    primary: Mutex<Option<CreatePrimaryKeyResult>>,
    rsa_key_handle: Mutex<Option<KeyHandle>>,
    public_rsa_key: Mutex<Option<KeyHandle>>
}

///Tpm Singleton
pub static TPM: Mutex<Option<TpmCrypto>> = Mutex::new(None);

// Flag pour savoir si atexit a été enregistré
static ATEXIT_REGISTERED: std::sync::Once = std::sync::Once::new();

/// Wrapper autour de MutexGuard pour accéder au TpmCrypto
pub struct TpmServiceGuard<'a> {
    guard: std::sync::MutexGuard<'a, Option<TpmCrypto>>,
}

impl<'a> std::ops::Deref for TpmServiceGuard<'a> {
    type Target = TpmCrypto;

    fn deref(&self) -> &Self::Target {
        self.guard.as_ref().unwrap()
    }
}

/// Cleanup automatique du TPM à la fin du processus
extern "C" fn cleanup_on_exit() {
    println!("🧹 Cleanup automatique du TPM à la fin du processus");
    let mut guard = TPM.lock().unwrap();
    
    if let Some(tpm) = guard.take() {
        drop(tpm); // Force l'appel de Drop (qui fait shutdown)
    }
    drop(guard); // Libérer le lock

    // ✅ Nettoyer aussi les fichiers NVChip pour garantir un état propre au prochain run
    
    println!("✅ Cleanup terminé: Drop + NVChip nettoyé");
}

/// Parse la variable d'environnement TPM_TCTI pour déterminer le TCTI à utiliser
///
/// Valeurs supportées:
/// - "mssim" ou "simulator" → Simulateur TPM (défaut)
/// - "device" ou "device:/dev/tpm0" → TPM matériel
/// - "tabrmd" → TPM Access Broker & Resource Manager
///
/// Exemples:
/// ```bash
/// export TPM_TCTI=device          # Utilise /dev/tpm0
/// export TPM_TCTI=device:/dev/tpmrm0  # Utilise /dev/tpmrm0
/// export TPM_TCTI=mssim           # Utilise le simulateur (défaut)
/// export TPM_TCTI=tabrmd          # Utilise le resource manager
/// ```
fn get_tcti_from_env() -> TctiNameConf {
    match std::env::var("TPM_TCTI") {
        Ok(val) => {
            let val_lower = val.to_lowercase();

            if val_lower == "mssim" || val_lower == "simulator" {
                println!("🔧 TPM_TCTI=mssim → Utilisation du simulateur TPM");
                TctiNameConf::Mssim(Default::default())
            } else if val_lower.starts_with("device") {
                // Support "device" (utilise /dev/tpm0 ou /dev/tpmrm0 par défaut)
                println!("🔧 TPM_TCTI=device → Utilisation du TPM matériel");
                TctiNameConf::Device(Default::default())
            } else if val_lower == "tabrmd" {
                println!("🔧 TPM_TCTI=tabrmd → Utilisation du TPM Resource Manager");
                TctiNameConf::Tabrmd(Default::default())
            } else {
                eprintln!("⚠️  TPM_TCTI='{}' non reconnu, utilisation du simulateur par défaut", val);
                eprintln!("    Valeurs supportées: mssim, simulator, device, device:/dev/tpm0, tabrmd");
                TctiNameConf::Mssim(Default::default())
            }
        },
        Err(_) => {
            println!("🔧 TPM_TCTI non défini → Utilisation du simulateur par défaut");
            TctiNameConf::Mssim(Default::default())
        }
    }
}

/// Get or create the TPM service singleton
///
/// # Thread Safety
///
/// This function is **thread-safe** and can be called concurrently from multiple threads.
/// Access to the TPM service is protected by a `Mutex`, ensuring safe concurrent access.
///
/// However, note these important limitations:
///
/// ## Performance Considerations
///
/// - **The underlying TPM hardware is single-threaded**: Even though this Rust API is thread-safe
///   via mutexes, the TPM chip itself can only process one command at a time.
/// - **Contention under load**: Heavy concurrent usage from multiple threads will experience
///   contention and serialization at the mutex level.
/// - **Not suitable for high-throughput scenarios**: If your application requires high-throughput
///   cryptographic operations, consider:
///   1. Caching derived keys instead of deriving them repeatedly
///   2. Using a pool of pre-generated keys
///   3. Batching operations to minimize TPM calls
///
/// ## Example Usage
///
/// ```rust
/// use secure_memory::tpm_service::get_service;
///
/// // Thread-safe: can be called from multiple threads
/// let tpm = get_service();
/// let mut random_data = [0u8; 32];
/// tpm.random(&mut random_data).unwrap();
/// ```
///
/// ## Recommendations
///
/// - ✅ **DO**: Use for key derivation, sealing, and occasional random number generation
/// - ✅ **DO**: Cache results when possible to reduce TPM calls
/// - ⚠️ **AVOID**: Calling from tight loops or high-frequency code paths
/// - ⚠️ **AVOID**: Heavy concurrent usage from many threads (will serialize)
///
/// # Returns
///
/// A `TpmServiceGuard` that provides scoped access to the TPM service.
/// The guard automatically releases the lock when dropped.
pub fn get_service() -> TpmServiceGuard<'static> {
    // Enregistrer le cleanup à la fin du processus (une seule fois)
    ATEXIT_REGISTERED.call_once(|| {
        unsafe {
            libc::atexit(cleanup_on_exit);
        }
        println!("✅ Handler atexit enregistré pour cleanup TPM");
    });

    // Initialiser si nécessaire
    let mut guard = TPM.lock().unwrap();
    if guard.is_none() {
        let tcti = get_tcti_from_env();
        let s = TpmCrypto::create(tcti).unwrap();
        s.init_key(); // ✅ Appel explicite après construction
        *guard = Some(s);
    }

    TpmServiceGuard { guard }
}

/// Reset et force le drop du singleton (utile pour les tests)
///
/// ⚠️ ATTENTION : Cette fonction force la destruction du singleton TPM.
/// Elle doit être appelée uniquement dans les tests pour nettoyer l'état entre les tests.
///
/// Cette fonction :
/// 1. Appelle Drop sur le TpmCrypto (flush handles + shutdown TPM)
/// 2. Nettoie les fichiers NVChip et *.ctx du simulateur TPM
///    → NÉCESSAIRE car le simulateur persiste l'état sur disque même après shutdown()
pub fn reset_service() {
    let mut guard = TPM.lock().unwrap();
    if let Some(tpm) = guard.take() {
        drop(tpm); // Force l'appel de Drop::drop() qui fait shutdown()
    }
    drop(guard); // Libérer le lock avant les I/O

    // ✅ CRITIQUE : Nettoyer les fichiers d'état du simulateur TPM
    // Même après shutdown(), le simulateur sauvegarde l'état dans NVChip
    // Sans ce nettoyage, les objets NV persistent et causent TPM_RC_NV_DEFINED
    let _ = std::fs::remove_file("NVChip");
    for entry in std::fs::read_dir(".").unwrap().flatten() {
        if let Some(name) = entry.file_name().to_str() {
            if name.ends_with(".ctx") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    println!("♻️  TPM reset: Drop appelé + fichiers NVChip nettoyés");
}
fn ensure_tpm_started(context: &mut Context) -> Result<()> {
    match context.get_random(8) {
        Ok(_) => Ok(()), // déjà initialisé
        Err(Error::Tss2Error(e)) => {
            // TPM_RC_INITIALIZE
            if e.kind()== Some(Tss2ResponseCodeKind::Initialize)
            {
                println!("TPM not started, sending Startup(Clear)... {:?} ", e.kind());
                context.startup(StartupType::Clear)?;
                Ok(())
            }else {
                Err(Error::Tss2Error(e))
            }
        }
        Err(e) => Err(e),
    }
}
impl TpmCrypto {
    /// Create a new TpmCrypto instance with TPM context
    pub fn create(tcti_name_conf: TctiNameConf)  -> std::result::Result<Self, SecurityError> {
        let mut context = Context::new(tcti_name_conf)?;
        let _ = ensure_tpm_started(&mut context);
        let tpm_process_auth = ProcessKeyDeriver::create()?;

        Ok(TpmCrypto {
            context: Mutex::new(context),
            tpm_process_auth,
            primary: Mutex::new(None),
            rsa_key_handle: Mutex::new(None),
            public_rsa_key: Mutex::new(None)
        })
    }

    /// Initialisation
    pub fn init_key(&self) {
        let primary_key = self.create_primary_with_password().unwrap();
        let (private_keyhandle, public_keyhandle) = self.create_and_load_symmetric_with_password(&primary_key).unwrap();

        *self.primary.lock().unwrap() = Some(primary_key);
        *self.rsa_key_handle.lock().unwrap() = Some(private_keyhandle);
        *self.public_rsa_key.lock().unwrap() = Some(public_keyhandle);
    }
    /// fill the buffer with random data
    pub fn random(&self, data: &mut [u8]) -> Result<()> {
        let mut offset = 0;
        let mut context = self.context.lock().unwrap();

        while offset < data.len() {
            let remaining = data.len() - offset;
            let random_buffer = context.get_random(remaining)?;
            let random_len = random_buffer.len();
            data[offset..offset + random_len].copy_from_slice(&random_buffer);
            offset += random_len;
        }

        let mut mask = vec![0u8; data.len()];
        let _ = OsRng.try_fill_bytes(&mut mask);
        for (d, m) in data.iter_mut().zip(mask.iter()) {
            *d ^= *m;
        }
        Ok(())
    }

    fn create_primary_with_password(&self) -> Result<CreatePrimaryKeyResult> {
        // Dériver le secret (Zeroizing<Vec<u8>>)
        let derived_secret = self.tpm_process_auth.derive()
            .map_err(|_| tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::InvalidParam))?;

        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(true)  // ✅ MODIFIÉ: true = objet nettoyé au Startup(Clear)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)  // ✅ Requiert authentification
            .with_decrypt(true)
            .with_restricted(true)
            .build()
            .expect("Failed to build object attributes");

        let primary_pub = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::SymCipher)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(
                SymmetricDefinitionObject::AES_128_CFB,
            ))
            .with_symmetric_cipher_unique_identifier(Digest::default())
            .build()  .expect("Failed to build primary pub ");

        // ✅ Créer Auth depuis le secret dérivé (extraire la valeur de Zeroizing)
        let auth = Auth::try_from(derived_secret.as_slice())?;

        let mut context = self.context.lock().unwrap();
        context.execute_with_nullauth_session(|ctx| {
            ctx.create_primary(
                Hierarchy::Null,
                primary_pub,
                Some(auth),  // ✅ Mot de passe défini
                None,
                None,
                None
            )
        })
    }
    fn create_and_load_symmetric_with_password(
        &self,
        primary: &CreatePrimaryKeyResult
    ) -> std::result::Result<(KeyHandle, KeyHandle), Box<dyn std::error::Error>> {

        let parent_password = self.tpm_process_auth.derive().unwrap();
        let key_password = parent_password.clone();

        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(false)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)  // ✅ Requiert authentification
            .with_decrypt(true)
            .build()
            .expect("Failed to build object attributes");

        let rsa_params = PublicRsaParametersBuilder::new()
            .with_scheme(RsaScheme::Null)
            .with_key_bits(RsaKeyBits::Rsa2048)
            .with_exponent(RsaExponent::default())
            .with_is_decryption_key(true)
            .with_restricted(false)
            .build()
            .expect("Failed to build rsa parameters");

        let key_pub = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_rsa_parameters(rsa_params)
            .with_rsa_unique_identifier(PublicKeyRsa::default())
            .build()
            .unwrap();

        // ✅ Créer une session d'authentification avec le mot de passe du parent
        let parent_auth = Auth::try_from(parent_password.to_vec())?;
        let key_auth = Auth::try_from(key_password.to_vec())?;

        // Définir l'auth pour la clé primaire
        let mut context = self.context.lock().unwrap();
        context.tr_set_auth(primary.key_handle.into(), parent_auth.clone())?;

        // ✅ Envelopper dans une session pour créer ET charger la clé
        let (key_handle, publickey_handle) = context.execute_with_nullauth_session(|ctx| -> std::result::Result<(KeyHandle, KeyHandle), tss_esapi::Error> {
            // Créer la clé avec son propre mot de passe
            let create_result = ctx.create(
                primary.key_handle,
                key_pub,
                Some(key_auth),  // ✅ Mot de passe pour la nouvelle clé
                None,
                None,
                None
            )?;

            // Charger immédiatement (enc_private n'est jamais stockée)
            let key_handle = ctx.load(
                primary.key_handle,
                create_result.out_private,
                create_result.out_public.clone()
            )?;
            let publickey_handle = ctx.load_external_public(create_result.out_public, Hierarchy::Null)?;

            Ok((key_handle, publickey_handle))
        }).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        Ok((key_handle, publickey_handle))
    }

    ///ciphering a buffer with TPM
    pub fn ciphering(&self, buffer: Vec<u8>) -> Vec<u8> {
        let data_to_encrypt = PublicKeyRsa::try_from(buffer)
            .expect("Failed to create buffer for data to encrypt.");

        println!("✅ Chiffrement des données");

        let public_key = *self.public_rsa_key.lock().unwrap();
        let mut context = self.context.lock().unwrap();

        // Chiffrement (pas besoin d'auth pour utiliser la partie publique)
        let encrypted_data = context
            .execute_with_nullauth_session(|ctx| {
                ctx.rsa_encrypt(
                    public_key.unwrap(),
                    data_to_encrypt.clone(),
                    RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha1)),
                    Data::default(),
                )
            })
            .unwrap();
        encrypted_data.value().to_vec()
    }
    /// unciphering a buff from the TPM
    pub fn unciphering(&self, buffer: Vec<u8>) -> Vec<u8> {
        let rsa_key_password = self.tpm_process_auth.derive().unwrap().to_vec();

        let data_to_dencrypt = PublicKeyRsa::try_from(buffer)
            .expect("Failed to create buffer for data to encrypt.");

        let rsa_auth = Auth::try_from(rsa_key_password).unwrap();
        let rsa_key = *self.rsa_key_handle.lock().unwrap();
        let mut context = self.context.lock().unwrap();

        let _ = context.tr_set_auth(rsa_key.unwrap().into(), rsa_auth);

        // ✅ Envelopper dans une session pour le déchiffrement
        let decrypted_data = context.execute_with_nullauth_session(|ctx| {
            ctx.rsa_decrypt(
                rsa_key.unwrap(),
                data_to_dencrypt.clone(),
                RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha1)),
                Data::default(),
            )
        }).unwrap();
        decrypted_data.value().to_vec()
    }
/// clean up the key
pub fn logout(&mut self) {
        println!("🔥 TpmCrypto Drop appelé - Nettoyage du TPM");
        let mut context = self.context.lock().unwrap();

        // Flush RSA private key handle
        if let Some(key_handle) = self.rsa_key_handle.lock().unwrap().take() {
            let _ = context.flush_context(key_handle.into());
        }

        // Flush RSA public key handle
        if let Some(public_handle) = self.public_rsa_key.lock().unwrap().take() {
            let _ = context.flush_context(public_handle.into());
        }

        // Flush primary key handle
        if let Some(primary) = self.primary.lock().unwrap().take() {
            let _ = context.flush_context(primary.key_handle.into());
        }

        // Clear all sessions
        context.clear_sessions();

       
        println!("✅ TpmCrypto Drop terminé - Handles TPM nettoyés");
    }    

}

impl Drop for TpmCrypto {
    fn drop(&mut self) {
        self.logout();
    }
}