use rand::{rand_core::OsRng, TryRngCore};
use zeroize::Zeroize;

/// An AES Secure Key
pub struct SecureKey {
    key: [u8; 32],
}
impl SecureKey {
    /// create a new secure key
    pub fn new() -> Self {
        
        let mut k = SecureKey { key: [0u8; 32] };
        let _ = OsRng.try_fill_bytes(&mut k.key);

        
        k
    }

    /// get the value of the key
    pub fn as_slice(&self) -> &[u8] {
        &self.key
    }
}
impl Drop for SecureKey {
    fn drop(&mut self) {
        // effacer la clé
        self.key.zeroize();
    }
}