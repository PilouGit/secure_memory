use std::ptr::NonNull;

use crate::secure_key::SecureKey;
use crate::secure_error::SecurityError;
use libc;

use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Error, Nonce};
use zeroize::Zeroize;
use subtle::ConstantTimeEq;
use crate::tpm_service::get_service;

// Constantes pour AES-GCM
const NONCE_LEN: usize = 12;        // Taille du nonce pour AES-GCM (96 bits)
const GCM_TAG_LEN: usize = 16;      // Taille du tag d'authentification GCM (128 bits)
// AAD version prefix pour identifier le contexte de chiffrement
const AAD_VERSION: &[u8] = b"SecureMemory_v2";

// Constantes pour les canaries de protection
const CANARY_SIZE: usize = 8;       // Taille du canary (64 bits)

/// Get the system page size
fn get_page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

/// Round up size to next page boundary
fn round_to_page_size(size: usize) -> usize {
    let page_size = get_page_size();
    (size + page_size - 1) / page_size * page_size
}

/// Options for creating SecureMemory
#[derive(Clone, Debug)]
pub struct SecureMemoryOptions {
    /// Size of the memory buffer in bytes
    pub size: usize,
    /// If true, the memory can only be written once
    pub write_once: bool,
    /// If true, abort if mlock() fails (guarantees no swap to disk)
    /// If false, only warn if mlock() fails
    pub strict_mlock: bool,
}

impl SecureMemoryOptions {
    /// Create default options with given size
    pub fn new(size: usize) -> Self {
        Self {
            size,
            write_once: false,
            strict_mlock: false,
        }
    }

    /// Set write-once mode
    pub fn with_write_once(mut self, write_once: bool) -> Self {
        self.write_once = write_once;
        self
    }

    /// Set strict mlock mode
    pub fn with_strict_mlock(mut self, strict_mlock: bool) -> Self {
        self.strict_mlock = strict_mlock;
        self
    }
}

/// SecureMemory with buffer overflow protection using canaries and mmap-based memory protection
pub struct SecureMemory {
    ptr: NonNull<u8>,
    size: usize,
    ptr_size: usize,
    mapped_size: usize,  // Taille arrondie à la page (pour munmap)
    ciphered_key: Vec<u8>,
    canary_start: u64,  // Canary placé au début du buffer
    canary_end: u64,    // Canary placé à la fin du buffer
    write_once: bool,   // Flag pour indiquer si la mémoire est write-once
    has_been_written: bool,
     // Flag pour tracker si une écriture a déjà eu lieu
}

impl SecureMemory {

     /// Create a secure Memory with default settings (write_once = false, strict_mlock = false)
     pub fn new(size: usize) -> Option<Self> {
        Self::create(SecureMemoryOptions::new(size))
     }

     /// Create a secure Memory with write-once option
     ///
     /// # Arguments
     /// * `size` - Size of the memory buffer in bytes
     /// * `write_once` - If true, the memory can only be written once. Subsequent writes will be rejected.
     ///
     /// # Returns
     /// * `Some(SecureMemory)` - Successfully allocated secure memory
     /// * `None` - Allocation failed (size = 0 or malloc failed)
     pub fn new_with_options(size: usize, write_once: bool) -> Option<Self> {
        Self::create(SecureMemoryOptions::new(size).with_write_once(write_once))
     }

     /// Create a secure Memory with full options control
     ///
     /// # Arguments
     /// * `options` - SecureMemoryOptions containing all configuration
     ///
     /// # Returns
     /// * `Some(SecureMemory)` - Successfully allocated secure memory
     /// * `None` - Allocation failed
     ///
     /// # Example
     /// ```
     /// use secure_memory::secure_memory::{SecureMemory, SecureMemoryOptions};
     ///
     /// let opts = SecureMemoryOptions::new(256)
     ///     .with_write_once(true)
     ///     .with_strict_mlock(true);
     ///
     /// let memory = SecureMemory::create(opts).expect("Failed to create");
     /// ```
     pub fn create(options: SecureMemoryOptions) -> Option<Self> {
        let size = options.size;
        // Refuse zero-sized allocations
        if size == 0 {
            return None;
        }

        // ✅ SÉCURITÉ CRITIQUE : Gérer l'échec de génération de clé
        let key = SecureKey::new()?;

        unsafe {
            let key_buff = key.as_slice();
            let tpm = get_service();
            let ciphered_key = tpm.ciphering(key_buff.to_vec());

            // Format stocké avec canaries:
            // [canary_start (8)] + [write_once_flag (1)] + [nonce (12) + ciphertext (size) + gcm_tag (16)] + [canary_end (8)]
            let data_size = NONCE_LEN + size + GCM_TAG_LEN;
            let ptr_size = CANARY_SIZE + 1 + data_size + CANARY_SIZE; // +1 pour write_once flag

            // 🛡️ SÉCURITÉ CRITIQUE : Utiliser mmap() au lieu de malloc()
            // Arrondir à la taille de page pour mmap
            let mapped_size = round_to_page_size(ptr_size);

            // Allouer avec mmap et PROT_NONE (aucun accès par défaut)
            let ptr = libc::mmap(
                std::ptr::null_mut(),
                mapped_size,
                libc::PROT_NONE,  // 🔒 Aucun accès par défaut !
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0
            );

            if ptr == libc::MAP_FAILED { return None; }

            // 🔒 SÉCURITÉ CRITIQUE : Locker la mémoire pour empêcher le swap sur disque
            // Cela empêche les secrets d'être écrits dans le fichier de swap
            let mlock_result = libc::mlock(ptr as *const libc::c_void, mapped_size);
            if mlock_result != 0 {
                if options.strict_mlock {
                    // ✅ STRICT MODE: Échec de mlock() est fatal
                    eprintln!("CRITICAL: mlock() failed in strict mode!");
                    eprintln!("   Secure memory REQUIRES mlock() to prevent swap to disk.");
                    eprintln!("   Solutions:");
                    eprintln!("   1. Run with CAP_IPC_LOCK capability");
                    eprintln!("   2. Increase RLIMIT_MEMLOCK (ulimit -l)");
                    eprintln!("   3. Use non-strict mode (not recommended for production)");
                    libc::munmap(ptr, mapped_size);
                    return None;
                } else {
                    // ⚠️ NON-STRICT MODE: Warning seulement
                    eprintln!("⚠️  WARNING: mlock() failed - memory may be swapped to disk!");
                    eprintln!("   Consider running with CAP_IPC_LOCK or increasing RLIMIT_MEMLOCK");
                    eprintln!("   Or use strict_mlock mode for production environments");
                }
            }

            // 🔓 Temporairement autoriser l'écriture pour l'initialisation
            if libc::mprotect(ptr, mapped_size, libc::PROT_READ | libc::PROT_WRITE) != 0 {
                libc::munmap(ptr, mapped_size);
                return None;
            }

            // Générer des canaries aléatoires via TPM
            let mut canary_start_bytes = [0u8; 8];
            let mut canary_end_bytes = [0u8; 8];
            tpm.random(&mut canary_start_bytes).ok()?;
            tpm.random(&mut canary_end_bytes).ok()?;

            let canary_start = u64::from_le_bytes(canary_start_bytes);
            let canary_end = u64::from_le_bytes(canary_end_bytes);

            // Écrire les canaries au début et à la fin
            std::ptr::write(ptr as *mut u64, canary_start);

            // Écrire le flag write_once après le premier canary
            std::ptr::write((ptr as *mut u8).add(CANARY_SIZE), if options.write_once { 1u8 } else { 0u8 });

            std::ptr::write((ptr as *mut u8).add(CANARY_SIZE + 1 + data_size) as *mut u64, canary_end);

            // Initialiser la zone de données à zéro (entre write_once flag et canary_end)
            std::ptr::write_bytes((ptr as *mut u8).add(CANARY_SIZE + 1), 0, data_size);

            // 🔒 Remettre en PROT_NONE après l'initialisation
            if libc::mprotect(ptr, mapped_size, libc::PROT_NONE) != 0 {
                libc::munmap(ptr, mapped_size);
                return None;
            }

            Some(Self {
                ptr: NonNull::new(ptr as *mut u8)?,
                size,
                ptr_size,
                mapped_size,
                ciphered_key,
                canary_start,
                canary_end,
                write_once: options.write_once,
                has_been_written: false,
            })
        }
     }

     /// Vérifie l'intégrité des canaries et du flag write_once
     /// Retourne true si les canaries sont intacts, false si corruption détectée
     fn check_canaries(&self) -> bool {
        unsafe {
            // 🔓 Autoriser temporairement la lecture pour vérifier les canaries
            if libc::mprotect(self.ptr.as_ptr() as *mut libc::c_void, self.mapped_size, libc::PROT_READ) != 0 {
                eprintln!("⚠️ WARNING: mprotect(PROT_READ) failed in check_canaries");
                return false;
            }

            let data_size = NONCE_LEN + self.size + GCM_TAG_LEN;

            // Lire le canary au début
            let stored_canary_start = std::ptr::read(self.ptr.as_ptr() as *const u64);

            // Lire le flag write_once stocké en mémoire (après le premier canary)
            let stored_write_once_flag = std::ptr::read((self.ptr.as_ptr() as *const u8).add(CANARY_SIZE));

            // Lire le canary à la fin (avec +1 pour le flag write_once)
            let stored_canary_end = std::ptr::read(
                (self.ptr.as_ptr() as *const u8).add(CANARY_SIZE + 1 + data_size) as *const u64
            );

            // 🔒 Remettre en PROT_NONE immédiatement
            if libc::mprotect(self.ptr.as_ptr() as *mut libc::c_void, self.mapped_size, libc::PROT_NONE) != 0 {
                eprintln!("⚠️ WARNING: mprotect(PROT_NONE) failed in check_canaries");
            }

            // 🔒 SÉCURITÉ: Vérification constant-time pour éviter timing attacks
            // Vérifier que les canaries n'ont pas été modifiés (constant-time)
            let canary_start_ok = stored_canary_start.ct_eq(&self.canary_start);
            let canary_end_ok = stored_canary_end.ct_eq(&self.canary_end);

            // Vérifier que le flag write_once correspond (constant-time)
            let expected_flag = if self.write_once { 1u8 } else { 0u8 };
            let flag_ok = stored_write_once_flag.ct_eq(&expected_flag);

            // Combiner les résultats de manière constant-time
            let all_ok = canary_start_ok & canary_end_ok & flag_ok;
            bool::from(all_ok)
        }
     }

     /// Build AAD (Additional Authenticated Data) including canaries and write_once flag
     fn build_aad(&self) -> Vec<u8> {
         let mut aad = Vec::with_capacity(AAD_VERSION.len() + 8 + 1 + 8);

         // Version prefix
         aad.extend_from_slice(AAD_VERSION);

         // Canary start (8 bytes)
         aad.extend_from_slice(&self.canary_start.to_le_bytes());

         // Write-once flag (1 byte)
         aad.push(if self.write_once { 1u8 } else { 0u8 });

         // Canary end (8 bytes)
         aad.extend_from_slice(&self.canary_end.to_le_bytes());

         aad
     }

    fn ciphering(&self, buffer: &[u8]) -> Result<Vec<u8>, Error> {
        let tpm = get_service();
        let unciphered_key = tpm.unciphering(self.ciphered_key.clone());
        let cipher = Aes256Gcm::new_from_slice(&unciphered_key).unwrap();

        // Générer un nonce aléatoire via TPM
        let mut nonce_byte_array = [0u8; NONCE_LEN];
        tpm.random(&mut nonce_byte_array).map_err(|_| Error)?;
        let nonce = Nonce::from_slice(&nonce_byte_array);

         // Construire l'AAD avec les canaries et write_once
         let aad = self.build_aad();

         // Chiffrer avec AAD
         let result = match cipher.encrypt(nonce, Payload { msg: buffer, aad: &aad }) {
             Ok(res) => res,
             Err(err) => {
                 // ✅ SÉCURITÉ : Pas de fuite d'information détaillée
                 eprintln!("Cryptographic operation failed");
                 return Err(err);
             }
         };

         // Stocker seulement: nonce + ciphertext (l'AAD n'est pas stocké, mais il est authentifié)
         let mut out = Vec::with_capacity(nonce_byte_array.len() + result.len());
         out.extend_from_slice(&nonce_byte_array);
         out.extend_from_slice(&result);
         Ok(out)
     }
    fn unciphering(&self, buffer: &Vec<u8>) -> Result<Vec<u8>, Error> {
        let tpm = get_service();
        let unciphered_key = tpm.unciphering(self.ciphered_key.clone());
        let cipher = Aes256Gcm::new_from_slice(&unciphered_key).unwrap();
        // ✅ SÉCURITÉ : Gestion d'erreur propre au lieu de unwrap
        let nonce_byte_array: [u8; NONCE_LEN] = buffer[0..NONCE_LEN]
            .try_into()
            .map_err(|_| {
                eprintln!("Invalid nonce length in encrypted data");
                Error
            })?;
        let msg = &buffer[NONCE_LEN..];  // Le reste est ciphertext + tag
        let nonce = Nonce::from_slice(&nonce_byte_array);

        // Construire le même AAD avec les canaries et write_once
        let aad = self.build_aad();

        // Déchiffrer et vérifier l'AAD
        // Si l'AAD a été modifié (canaries ou write_once altérés), le déchiffrement échouera
        let result = match cipher.decrypt(nonce, Payload { msg, aad: &aad }) {
            Ok(res) => res,
            Err(err) => {
                // ✅ SÉCURITÉ : Pas de fuite d'information détaillée
                eprintln!("Cryptographic operation failed");
                return Err(err);
            }
        };

        Ok(result)
    }
    /// Create a new secure memory with encrypted data
     fn access<F>(&mut self, mut f: F, is_write: bool)
        where F: FnMut(&mut [u8]){
          unsafe {
              // Vérifier l'intégrité des canaries AVANT tout accès
              if !self.check_canaries() {
                  // ✅ SÉCURITÉ CRITIQUE : Zeroize immédiat et abort
                  // Autoriser temporairement l'écriture pour zeroize
                  libc::mprotect(self.ptr.as_ptr() as *mut libc::c_void, self.mapped_size, libc::PROT_WRITE);
                  let slice = std::slice::from_raw_parts_mut(
                      self.ptr.as_ptr(),
                      self.ptr_size
                  );
                  slice.zeroize();
                  eprintln!("SECURITY VIOLATION: Buffer overflow detected! Terminating immediately.");
                  std::process::abort(); // Pas d'interception possible
              }

              let data_size = NONCE_LEN + self.size + GCM_TAG_LEN;

              // 🔓 PHASE 1 : Autoriser READ pour lire les données chiffrées
              if libc::mprotect(self.ptr.as_ptr() as *mut libc::c_void, self.mapped_size, libc::PROT_READ) != 0 {
                  eprintln!("CRITICAL: mprotect(PROT_READ) failed!");
                  std::process::abort();
              }

              // Lire la zone de données (après canary_start + write_once flag)
              let data_ptr = self.ptr.as_ptr().add(CANARY_SIZE + 1); // +1 pour le flag write_once
              let slice = std::slice::from_raw_parts(data_ptr, data_size);

              let mut vec = Vec::with_capacity(data_size);
              vec.extend_from_slice(slice);

              // 🔒 Remettre en PROT_NONE après la lecture
              if libc::mprotect(self.ptr.as_ptr() as *mut libc::c_void, self.mapped_size, libc::PROT_NONE) != 0 {
                  eprintln!("CRITICAL: mprotect(PROT_NONE) failed after read!");
                  std::process::abort();
              }

              // Tenter de déchiffrer
              // Si le déchiffrement échoue (première utilisation ou données corrompues),
              // utiliser un buffer vide/zéro
              let mut plaintext = if vec.len() >= NONCE_LEN + GCM_TAG_LEN {

                  self.unciphering( &vec)
                      .unwrap_or_else(|_| vec![0u8; self.size])
              } else {
                  // Première utilisation - buffer initialisé à zéro
                  vec![0u8; self.size]
              };

              // S'assurer que le plaintext a la bonne taille
              plaintext.resize(self.size, 0);

              // Callback utilisateur avec le buffer déchiffré
              f(plaintext.as_mut_slice());

              // Re-chiffrement des données (seulement self.size octets, pas plus)
              // ✅ SÉCURITÉ CRITIQUE : Gestion d'erreur avec zeroization
              let ciphertext = match self.ciphering(&plaintext[..self.size]) {
                  Ok(ct) => ct,
                  Err(_) => {
                      // Corruption critique du système crypto
                      plaintext.zeroize();
                      vec.zeroize();
                      // Autoriser temporairement l'écriture pour zeroize
                      libc::mprotect(self.ptr.as_ptr() as *mut libc::c_void, self.mapped_size, libc::PROT_WRITE);
                      let slice = std::slice::from_raw_parts_mut(
                          self.ptr.as_ptr(),
                          self.ptr_size
                      );
                      slice.zeroize();
                      eprintln!("CRITICAL: Encryption failed! Terminating immediately.");
                      std::process::abort();
                  }
              };

              // 🔓 PHASE 2 : Autoriser WRITE pour écrire les données chiffrées
              if libc::mprotect(self.ptr.as_ptr() as *mut libc::c_void, self.mapped_size, libc::PROT_WRITE) != 0 {
                  eprintln!("CRITICAL: mprotect(PROT_WRITE) failed!");
                  std::process::abort();
              }

              // Copier le ciphertext dans la zone de données (après write_once flag)
              let copy_len = ciphertext.len().min(data_size);
              std::ptr::copy_nonoverlapping(
                  ciphertext.as_ptr(),
                  data_ptr,
                  copy_len
              );

              // 🔒 Remettre en PROT_NONE immédiatement après l'écriture
              if libc::mprotect(self.ptr.as_ptr() as *mut libc::c_void, self.mapped_size, libc::PROT_NONE) != 0 {
                  eprintln!("CRITICAL: mprotect(PROT_NONE) failed after write!");
                  std::process::abort();
              }

              // Si c'était une écriture, marquer comme écrit
              if is_write {
                  self.has_been_written = true;
              }

              // Vérifier l'intégrité des canaries APRÈS l'opération
              if !self.check_canaries() {
                  // ✅ SÉCURITÉ CRITIQUE : Zeroize immédiat et abort
                  // Autoriser temporairement l'écriture pour zeroize
                  libc::mprotect(self.ptr.as_ptr() as *mut libc::c_void, self.mapped_size, libc::PROT_WRITE);
                  let slice = std::slice::from_raw_parts_mut(
                      self.ptr.as_ptr(),
                      self.ptr_size
                  );
                  slice.zeroize();
                  eprintln!("SECURITY VIOLATION: Buffer overflow detected after operation! Terminating immediately.");
                  std::process::abort(); // Pas d'interception possible
              }
        }
    }
    /// Allow ReadAccess to the memory
    pub fn read<F>(&mut self,  f: F)
        where F: FnMut(&mut [u8])
        {
            self.access(f, false);
        }

   /// Allow WriteAccess to the memory
   ///
   /// # Returns
   /// Returns `Ok(())` on success, `Err(SecurityError::WriteOnceViolation)` if write-once violation
   pub fn write<F>(&mut self,  f: F) -> Result<(), SecurityError>
        where F: FnMut(&mut [u8])
        {
            // Vérifier le flag write_once
            if self.write_once && self.has_been_written {
                return Err(SecurityError::WriteOnceViolation);
            }

            self.access(f, true);
            Ok(())
        }

    /// Get the size of the secure memory buffer
    pub fn get_size(&self) -> usize {
        self.size
    }

}

impl Drop for SecureMemory {
    fn drop(&mut self) {
        // Vérifier les canaries une dernière fois avant de libérer
        if !self.check_canaries() {
            eprintln!("WARNING: Buffer overflow detected during drop! Canaries corrupted.");
        }

        unsafe {
            // 🔓 Autoriser WRITE pour zeroize
            if libc::mprotect(self.ptr.as_ptr() as *mut libc::c_void, self.mapped_size, libc::PROT_WRITE) != 0 {
                eprintln!("⚠️  WARNING: mprotect(PROT_WRITE) failed in drop");
            }

            // Zero out sensitive data (toute la zone incluant les canaries)
            let slice = std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.ptr_size);
            slice.zeroize();

            // 🔓 Délocker la mémoire avant de la libérer
            // Note: munlock() doit être appelé AVANT munmap() mais APRÈS zeroize()
            let munlock_result = libc::munlock(self.ptr.as_ptr() as *const libc::c_void, self.mapped_size);
            if munlock_result != 0 {
                // munlock() a échoué mais ce n'est pas critique car on va libérer la mémoire
                eprintln!("⚠️  WARNING: munlock() failed during cleanup");
            }

            // 🗑️ Libérer la mémoire mappée
            if libc::munmap(self.ptr.as_ptr() as *mut libc::c_void, self.mapped_size) != 0 {
                eprintln!("⚠️  WARNING: munmap() failed during cleanup");
            }
        }
    }
}

// ✅ THREAD SAFETY: SecureMemory implements Send automatically
// SecureMemory can be moved between threads safely because it owns all its data
unsafe impl Send for SecureMemory {}

// ❌ REMOVED: Sync implementation was unsafe without internal synchronization
// SecureMemory does NOT implement Sync because it has no internal mutex
// to protect concurrent access. Users must wrap in Arc<Mutex<SecureMemory>>
// if they need to share across threads.
//
// Previous implementation:
// unsafe impl Sync for SecureMemory {}
//
// This was incorrect because:
// 1. No mutex protects mutable operations (read/write)
// 2. Multiple threads could call mprotect() concurrently → race condition
// 3. Could cause data races in plaintext buffers during callbacks
//
// Correct usage for multi-threading:
//   let mem = Arc::new(Mutex::new(SecureMemory::new(256)?));
//   let mem_clone = Arc::clone(&mem);
//   thread::spawn(move || {
//       let mut guard = mem_clone.lock().unwrap();
//       guard.write(|buf| ...);
//   });