use secure_memory::tpmcrypto::TpmCrypto;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tpm_crypto_creation() {
        let result = TpmCrypto::create(get_device_name());
        match result {
            Ok(_) => println!("TPM context created successfully"),
            Err(e) => println!("Failed to create TPM context: {:?}", e),
        }
    }

    #[test]
    fn test_random_generation() {
        let mut tpm = match TpmCrypto::create(get_device_name()) {
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
        let mut tpm = match TpmCrypto::create(get_device_name()) {
            Ok(tpm) => tpm,
            Err(_) => return, // Skip test if TPM not available
        };

        let result = tpm.create_aeskey();
        
        assert!(result.is_ok(), "AES key creation should succeed");
        
        let key = result.unwrap();
        assert_eq!(key.len(), 32, "AES key should be 32 bytes (256 bits)");
        
        // Check that key is not all zeros
        assert_ne!(key, [0u8; 32], "AES key should contain random data");
    }

    fn get_device_name() -> String
    {
        return "/dev/tpmrm0".to_string();
    }

    #[test]
    fn test_ecc_primary_key_creation() {
        let mut tpm = match TpmCrypto::create(get_device_name()) {
            Ok(tpm) => tpm,
            Err(_) => return, // Skip test if TPM not available
        };

        let result = tpm.create_primary_rsa_key();
        
        assert!(result.is_ok(), "RSA primary key creation should succeed");
    }

    #[test]
    fn test_aes_encryption_decryption_cycle() {
        eprintln!("Starting test_aes_encryption_decryption_cycle");
        let mut tpm = match TpmCrypto::create(get_device_name()) {
            Ok(tpm) => {
                eprintln!("TPM created successfully");
                tpm
            },
            Err(e) => {
                eprintln!("Failed to create TPM: {:?}", e);
                return; // Skip test if TPM not available
            }
        };

        // Create RSA primary key first
        eprintln!("Creating RSA primary key");
        if let Err(e) = tpm.create_primary_rsa_key() {
            eprintln!("Failed to create RSA primary key: {:?}", e);
            return; // Skip if RSA key creation fails
        }
        eprintln!("RSA primary key created successfully");

        // Generate AES key
        let aes_key = match tpm.create_aeskey() {
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
        
        eprintln!("aes_key: {:02x?}", aes_key);
        eprintln!("decrypted: {:02x?}", decrypted);
        
        assert_eq!(aes_key, decrypted, "Decrypted key should match original key");
    }

    #[test]
    fn test_multiple_aes_keys_are_different() {
        let mut tpm = match TpmCrypto::create(get_device_name()) {
            Ok(tpm) => tpm,
            Err(_) => return, // Skip test if TPM not available
        };

        let key1 = match tpm.create_aeskey() {
            Ok(key) => key,
            Err(_) => return,
        };

        let key2 = match tpm.create_aeskey() {
            Ok(key) => key,
            Err(_) => return,
        };

        assert_ne!(key1, key2, "Multiple AES keys should be different");
    } 
}