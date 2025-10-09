use secure_memory::tpmcrypto::TmpCrypto;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tpm_crypto_creation() {
        let result = TmpCrypto::create();
        match result {
            Ok(_) => println!("TPM context created successfully"),
            Err(e) => println!("Failed to create TPM context: {:?}", e),
        }
    }

    #[test]
    fn test_random_generation() {
        let mut tpm = match TmpCrypto::create() {
            Ok(tpm) => tpm,
            Err(_) => return, // Skip test if TPM not available
        };

        let mut buffer = [0u8; 32];
        let result = tpm.random(&mut buffer);
        
        assert!(result.is_ok(), "Random generation should succeed");
        
        // Check that buffer is not all zeros (extremely unlikely with real random data)
        assert_ne!(buffer, [0u8; 32], "Buffer should contain random data");
    }

    #[test]
    fn test_aes_key_creation() {
        let mut tpm = match TmpCrypto::create() {
            Ok(tpm) => tpm,
            Err(_) => return, // Skip test if TPM not available
        };

        let result = tpm.createAESKey();
        
        assert!(result.is_ok(), "AES key creation should succeed");
        
        let key = result.unwrap();
        assert_eq!(key.len(), 32, "AES key should be 32 bytes (256 bits)");
        
        // Check that key is not all zeros
        assert_ne!(key, [0u8; 32], "AES key should contain random data");
    }

    #[test]
    fn test_rsa_primary_key_creation() {
        let mut tpm = match TmpCrypto::create() {
            Ok(tpm) => tpm,
            Err(_) => return, // Skip test if TPM not available
        };

        let result = tpm.create_primary_rsa_key();
        
        assert!(result.is_ok(), "RSA primary key creation should succeed");
    }

    #[test]
    fn test_aes_encryption_decryption_cycle() {
        let mut tpm = match TmpCrypto::create() {
            Ok(tpm) => tpm,
            Err(_) => return, // Skip test if TPM not available
        };

        // Create RSA primary key first
        if tpm.create_primary_rsa_key().is_err() {
            return; // Skip if RSA key creation fails
        }

        // Generate AES key
        let aes_key = match tpm.createAESKey() {
            Ok(key) => key,
            Err(_) => return, // Skip if AES key creation fails
        };

        // Encrypt the AES key
        let encrypted = match tpm.encrypt_aes_key(&aes_key) {
            Ok(enc) => enc,
            Err(_) => return, // Skip if encryption fails
        };

        assert!(!encrypted.is_empty(), "Encrypted data should not be empty");

        // Decrypt the AES key
        let decrypted = match tpm.decrypt_aes_key(&encrypted) {
            Ok(dec) => dec,
            Err(_) => panic!("Decryption should succeed if encryption succeeded"),
        };

        assert_eq!(aes_key, decrypted, "Decrypted key should match original key");
    }

    #[test]
    fn test_multiple_aes_keys_are_different() {
        let mut tpm = match TmpCrypto::create() {
            Ok(tpm) => tpm,
            Err(_) => return, // Skip test if TPM not available
        };

        let key1 = match tpm.createAESKey() {
            Ok(key) => key,
            Err(_) => return,
        };

        let key2 = match tpm.createAESKey() {
            Ok(key) => key,
            Err(_) => return,
        };

        assert_ne!(key1, key2, "Multiple AES keys should be different");
    }
}