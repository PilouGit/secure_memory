use rand::{rand_core::OsRng, TryRngCore};
use zeroize::Zeroize;

/// An AES Secure Key
pub struct SecureKey {
    key: [u8; 32],
}
impl SecureKey {
    /// Create a new secure key
    ///
    /// Returns `None` if random number generation fails.
    /// ✅ SÉCURITÉ CRITIQUE : Ne JAMAIS retourner une clé remplie de zéros.
    pub fn new() -> Option<Self> {
        let mut k = SecureKey { key: [0u8; 32] };

        // ✅ Gérer proprement l'erreur au lieu de l'ignorer
        OsRng.try_fill_bytes(&mut k.key).ok()?;

        Some(k)
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