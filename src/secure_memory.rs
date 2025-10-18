use std::ptr::NonNull;

use crate::secure_key::SecureKey;
use libc;

use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Error, Key, Nonce};
use rand::{rand_core::OsRng, TryRngCore};
use zeroize::Zeroize;

// Constantes pour AES-GCM
const NONCE_LEN: usize = 12;        // Taille du nonce pour AES-GCM (96 bits)
const GCM_TAG_LEN: usize = 16;      // Taille du tag d'authentification GCM (128 bits)
// AAD version prefix pour identifier le contexte de chiffrement
const AAD_VERSION: &[u8] = b"SecureMemory_v2";

// Constantes pour les canaries de protection
const CANARY_SIZE: usize = 8;       // Taille du canary (64 bits)
/// SecureMemory with buffer overflow protection using canaries
pub struct SecureMemory {
    ptr: NonNull<u8>,
    size: usize,
    ptr_size: usize,
    cipher: Aes256Gcm,
    canary_start: u64,  // Canary placé au début du buffer
    canary_end: u64,    // Canary placé à la fin du buffer
    write_once: bool,   // Flag pour indiquer si la mémoire est write-once
    has_been_written: bool, // Flag pour tracker si une écriture a déjà eu lieu
}

impl SecureMemory {

     /// Create a secure Memory with default settings (write_once = false)
     pub fn new(size: usize) -> Option<Self> {
        Self::new_with_options(size, false)
     }

     /// Create a secure Memory with options
     ///
     /// # Arguments
     /// * `size` - Size of the memory buffer in bytes
     /// * `write_once` - If true, the memory can only be written once. Subsequent writes will be rejected.
     ///
     /// # Returns
     /// * `Some(SecureMemory)` - Successfully allocated secure memory
     /// * `None` - Allocation failed (size = 0 or malloc failed)
     pub fn new_with_options(size: usize, write_once: bool) -> Option<Self> {
        // Refuse zero-sized allocations
        if size == 0 {
            return None;
        }
         let key = SecureKey::new();

         unsafe {
            let cipher_key = Key::<Aes256Gcm>::from_slice(key.as_slice());

            // Format stocké avec canaries:
            // [canary_start (8)] + [write_once_flag (1)] + [nonce (12) + ciphertext (size) + gcm_tag (16)] + [canary_end (8)]
            let data_size = NONCE_LEN + size + GCM_TAG_LEN;
            let ptr_size = CANARY_SIZE + 1 + data_size + CANARY_SIZE; // +1 pour write_once flag
            let ptr = libc::malloc(ptr_size);

            if ptr.is_null() { return None; }
            let cipher = Aes256Gcm::new(cipher_key);

            // Générer des canaries aléatoires
            let mut canary_start_bytes = [0u8; 8];
            let mut canary_end_bytes = [0u8; 8];
            OsRng.try_fill_bytes(&mut canary_start_bytes).ok()?;
            OsRng.try_fill_bytes(&mut canary_end_bytes).ok()?;

            let canary_start = u64::from_le_bytes(canary_start_bytes);
            let canary_end = u64::from_le_bytes(canary_end_bytes);

            // Écrire les canaries au début et à la fin
            std::ptr::write(ptr as *mut u64, canary_start);

            // Écrire le flag write_once après le premier canary
            std::ptr::write((ptr as *mut u8).add(CANARY_SIZE), if write_once { 1u8 } else { 0u8 });

            std::ptr::write((ptr as *mut u8).add(CANARY_SIZE + 1 + data_size) as *mut u64, canary_end);

            // Initialiser la zone de données à zéro (entre write_once flag et canary_end)
            std::ptr::write_bytes((ptr as *mut u8).add(CANARY_SIZE + 1), 0, data_size);

            Some(Self {
                ptr: NonNull::new(ptr as *mut u8)?,
                size,
                ptr_size,
                cipher,
                canary_start,
                canary_end,
                write_once,
                has_been_written: false,
            })
        }
     }

     /// Vérifie l'intégrité des canaries et du flag write_once
     /// Retourne true si les canaries sont intacts, false si corruption détectée
     fn check_canaries(&self) -> bool {
        unsafe {
            let data_size = NONCE_LEN + self.size + GCM_TAG_LEN;

            // Lire le canary au début
            let stored_canary_start = std::ptr::read(self.ptr.as_ptr() as *const u64);

            // Lire le flag write_once stocké en mémoire (après le premier canary)
            let stored_write_once_flag = std::ptr::read((self.ptr.as_ptr() as *const u8).add(CANARY_SIZE));

            // Lire le canary à la fin (avec +1 pour le flag write_once)
            let stored_canary_end = std::ptr::read(
                (self.ptr.as_ptr() as *const u8).add(CANARY_SIZE + 1 + data_size) as *const u64
            );

            // Vérifier que les canaries n'ont pas été modifiés
            let canaries_ok = stored_canary_start == self.canary_start && stored_canary_end == self.canary_end;

            // Vérifier que le flag write_once correspond
            let expected_flag = if self.write_once { 1u8 } else { 0u8 };
            let flag_ok = stored_write_once_flag == expected_flag;

            canaries_ok && flag_ok
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

     fn ciphering(&self, cipher: &Aes256Gcm, buffer: &[u8]) -> Result<Vec<u8>, Error>
     {
         let mut nonce_byte_array = [0u8; NONCE_LEN];
         OsRng.try_fill_bytes(&mut nonce_byte_array)
             .map_err(|_| Error)?;
         let nonce = Nonce::from_slice(&nonce_byte_array);

         // Construire l'AAD avec les canaries et write_once
         let aad = self.build_aad();

         // Chiffrer avec AAD
         let result = match cipher.encrypt(nonce, Payload { msg: buffer, aad: &aad }) {
             Ok(res) => res,
             Err(err) => {
                 println!("Error during encryption: {}", err);
                 return Err(err);
             }
         };

         // Stocker seulement: nonce + ciphertext (l'AAD n'est pas stocké, mais il est authentifié)
         let mut out = Vec::with_capacity(nonce_byte_array.len() + result.len());
         out.extend_from_slice(&nonce_byte_array);
         out.extend_from_slice(&result);
         Ok(out)
     }
    fn unciphering(&self, cipher: &Aes256Gcm, buffer: &Vec<u8>) -> Result<Vec<u8>, Error>
    {
        let nonce_byte_array: [u8; NONCE_LEN] = buffer[0..NONCE_LEN].try_into().unwrap();
        let msg = &buffer[NONCE_LEN..];  // Le reste est ciphertext + tag
        let nonce = Nonce::from_slice(&nonce_byte_array);

        // Construire le même AAD avec les canaries et write_once
        let aad = self.build_aad();

        // Déchiffrer et vérifier l'AAD
        // Si l'AAD a été modifié (canaries ou write_once altérés), le déchiffrement échouera
        let result = match cipher.decrypt(nonce, Payload { msg, aad: &aad }) {
            Ok(res) => res,
            Err(err) => {
                println!("Error during decryption: {}", err);
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
                  panic!("SECURITY VIOLATION: Buffer overflow detected! Canaries have been corrupted.");
              }

              let data_size = NONCE_LEN + self.size + GCM_TAG_LEN;

              // Lire la zone de données (après canary_start + write_once flag)
              let data_ptr = self.ptr.as_ptr().add(CANARY_SIZE + 1); // +1 pour le flag write_once
              let slice = std::slice::from_raw_parts(data_ptr, data_size);

              let mut vec = Vec::with_capacity(data_size);
              vec.extend_from_slice(slice);

              // Tenter de déchiffrer
              // Si le déchiffrement échoue (première utilisation ou données corrompues),
              // utiliser un buffer vide/zéro
              let mut plaintext = if vec.len() >= NONCE_LEN + GCM_TAG_LEN {
                  self.unciphering(&self.cipher, &vec)
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
              let ciphertext = self.ciphering(&self.cipher, &plaintext[..self.size])
                  .expect("Encryption failed");

              // Copier le ciphertext dans la zone de données (après write_once flag)
              let copy_len = ciphertext.len().min(data_size);
              std::ptr::copy_nonoverlapping(
                  ciphertext.as_ptr(),
                  data_ptr,
                  copy_len
              );

              // Si c'était une écriture, marquer comme écrit
              if is_write {
                  self.has_been_written = true;
              }

              // Vérifier l'intégrité des canaries APRÈS l'opération
              if !self.check_canaries() {
                  panic!("SECURITY VIOLATION: Buffer overflow detected after operation! Canaries have been corrupted.");
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
   /// Returns `Ok(())` on success, `Err(())` if write-once violation
   pub fn write<F>(&mut self,  f: F) -> Result<(), ()>
        where F: FnMut(&mut [u8])
        {
            // Vérifier le flag write_once
            if self.write_once && self.has_been_written {
                return Err(()); // Write-once violation
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

        // Zero out sensitive data (toute la zone incluant les canaries)
        unsafe {
            let slice = std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.ptr_size);
            slice.zeroize();
            libc::free(self.ptr.as_ptr() as *mut _);
        }
    }
}

unsafe impl Send for SecureMemory {}
unsafe impl Sync for SecureMemory {}