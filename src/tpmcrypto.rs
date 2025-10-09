use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::{Context, Result, Error, WrapperErrorKind};
use tss_esapi::TctiNameConf;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::structures::*;
use tss_esapi::interface_types::algorithm::*;
/// TPM cryptographic operations wrapper
pub struct TpmCrypto {
    context: Context,
    primary_key: Option<KeyHandle>
}

impl TpmCrypto {
    /// Create a new TpmCrypto instance with TPM context
    pub fn create() -> Result<TpmCrypto> {
        let tcti = TctiNameConf::from_environment_variable()?;
        let context = Context::new(tcti)?;
        Ok(TpmCrypto { context,primary_key:None })
    }
    /// fill the buffer with random data
    pub fn random(&mut self, data: &mut [u8])-> Result<()> {
        let mut offset = 0;

        while offset < data.len() {
            let remaining = data.len() - offset;
    
            let random_buffer = self.context.get_random(remaining)?;
            let random_len = random_buffer.len();
    
            // Copie dans data
            data[offset..offset + random_len].copy_from_slice(&random_buffer);
    
            offset += random_len;
    
            // Si le TPM retourne moins de bytes que demandé, la boucle continue
        }
    
        Ok(())
    }
    /// Create a transient RSA primary key (disappears on reboot)
    pub fn create_primary_rsa_key(&mut self) -> Result<KeyHandle> {
         let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_st_clear(false)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
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
        .build()
        .unwrap();
    
        let primary_key = self.context.create_primary(
            Hierarchy::Owner
            , primary_pub, None, None, None, None).expect("Failed to build object attributes");
        
        self.primary_key = Some(primary_key.key_handle);
        Ok( self.primary_key.unwrap())
    }
/// create an AESKEY
    pub fn create_aeskey(&mut self) -> Result<[u8; 32]> {
        let mut aes_key = [0u8; 32]; // 256-bit AES key
        self.random(&mut aes_key)?;
        Ok(aes_key)
    }

   /* /// Encrypt AES key using RSA key in TPM
    pub fn encrypt_aes_key(&mut self, aes_key: &[u8; 32]) -> Result<Vec<u8>> {
        let primary_key = self.primary_key.ok_or(Error::WrapperError(WrapperErrorKind::UnsupportedParam))?;

        // Get the public key from the primary key handle
        let (public_key, _, _) = self.context.read_public(primary_key)?;
        
        let data = Data::try_from(aes_key.as_slice())?;
        let decryption_scheme = RsaDecryptionScheme::create(RsaDecryptAlgorithm::RsaOaep, Some(HashingAlgorithm::Sha256))?;
        
        let encrypted = self.context.rsa_encrypt(
            primary_key,
            public_key.try_into()?,
            decryption_scheme,
            data,
        )?;

        Ok(encrypted.value().to_vec())
    }

    /// Decrypt AES key using RSA key in TPM
    pub fn decrypt_aes_key(&mut self, encrypted_key: &[u8]) -> Result<[u8; 32]> {
        let primary_key = self.primary_key.ok_or(Error::WrapperError(WrapperErrorKind::UnsupportedParam))?;

        let data = Data::try_from(encrypted_key)?;
        let decryption_scheme = RsaDecryptionScheme::create(RsaDecryptAlgorithm::RsaOaep, Some(HashingAlgorithm::Sha256))?;
        
        let decrypted = self.context.rsa_decrypt(
            primary_key,
            decryption_scheme,
            data,
        )?;

        let mut aes_key = [0u8; 32];
        let decrypted_bytes = decrypted.value();
        if decrypted_bytes.len() != 32 {
            return Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
        }
        aes_key.copy_from_slice(decrypted_bytes);
        Ok(aes_key)
    } */
}