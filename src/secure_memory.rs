use crate::secure_key::SecureKey;
use libc::{mlock, munlock, mprotect, PROT_READ, PROT_WRITE, PROT_NONE};

use aes_gcm::{aead::{Aead, AeadMut, KeyInit, Payload}, Aes256Gcm, Key, Nonce};
use rand::{rand_core::OsRng, TryRngCore};
use zeroize::Zeroize;
/// A secure memory structure with encrypted data and key
pub struct SecureMemory {
     ptr: NonNull<u8>,
    size: usize,
    cipher: Aes256Gcm,
    nonce: [u8; 12],
    aad: [u8; 16]
}

impl SecureMemory {

     pub fn new(size: usize, key: &SecureKey) -> Option<Self> {
        let ptr = libc::malloc(size);
            if ptr.is_null() { return None; }
        let mut nonce = [0u8; 12];
        let mut aad = [0u8; 16];
        OsRng.try_fill_bytes(&mut nonce);
        OsRng.try_fill_bytes(&mut aad);

        let cipher_key = Key::<Aes256Gcm>::from_slice(key.as_slice());
      Some(Self {
                ptr: NonNull::new(ptr as *mut u8)?,
                size,
                cipher,
                nonce,
                aad,
            })
     }
    /// Create a new secure memory with encrypted data
    pub fn access<F>(&mut self, mut f: F)
        where F: FnMut(&mut [u8]){
          unsafe {
       let slice = std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.size);

        
       let plaintext = self.cipher.decrypt(
                Nonce::from_slice(&self.nonce),
                Payload { msg: slice, aad: &self.aad }
            ).unwrap_or_else(|_| slice.to_vec());

            // Copier dans slice pour callback
            slice.copy_from_slice(&plaintext[..slice.len()]);

            // Callback utilisateur
            f(slice);

            // Re-chiffrement
            let ciphertext = self.cipher.encrypt(
                Nonce::from_slice(&self.nonce),
                Payload { msg: slice, aad: &self.aad }
            ).unwrap();
            slice.copy_from_slice(&ciphertext[..slice.len()]);

            // Re-protéger
        }
    }

    /// Decrypt the secure memory content
    
}

impl Drop for SecureMemory {
    fn drop(&mut self) {
        // Zero out sensitive data
         unsafe {
            let slice = std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.size);
            slice.zeroize();
            libc::free(self.ptr.as_ptr() as *mut _);
         }
        self.nonce.zeroize();
        self.aad.zeroize();
    }
}

unsafe impl Send for SecureMemory {}
unsafe impl Sync for SecureMemory {}