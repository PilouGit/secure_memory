use std::str::FromStr;

use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::tcti_ldr::DeviceConfig;
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
    pub fn create(device:String ) -> Result<TpmCrypto> {
        let deviceConfig=DeviceConfig::from_str(&device)?;
         let tcti = TctiNameConf::Device(deviceConfig);
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
       //  let key_auth = Auth::try_from("monSuperMotDePasse".)?;
  let object_attributes = ObjectAttributesBuilder::new()
    .with_fixed_tpm(true)
    .with_fixed_parent(true)
    .with_sensitive_data_origin(true)
    .with_user_with_auth(true)
    .with_decrypt(true)                // AJOUTÉ
    .with_restricted(false)            // CHANGÉ - non restreinte pour OAEP
    .build()
    .expect("Failed to build object attributes");

let rsa_params = PublicRsaParametersBuilder::new()
    .with_scheme(RsaScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha256)))  // OK avec restricted=false
    .with_key_bits(RsaKeyBits::Rsa2048)
    .with_exponent(RsaExponent::default())
    .with_is_decryption_key(true)
    .with_restricted(false)            // CHANGÉ - doit correspondre
    .build()
    .expect("Failed to build RSA parameters");

let public = PublicBuilder::new()
    .with_public_algorithm(PublicAlgorithm::Rsa)
    .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
    .with_rsa_parameters(rsa_params)
    .with_object_attributes(object_attributes)
    .with_rsa_unique_identifier(PublicKeyRsa::default())
    .build().expect("Échec de create_primary")  ;  
   /* {
    Ok(key) => key,
    Err(e) => {
       println!("Erreur complète : {:#?}", e);
        panic!("Échec de create_primary");
    }
        };*/
   
   // let auth_value = Auth(Some("mysecret".as_bytes().to_vec()));
    
        let primary_key = self.context.create_primary(
        Hierarchy::Owner,
        public,
         None, None, None, None
    )?;
        self.primary_key = Some(primary_key.key_handle);
        Ok( self.primary_key.unwrap())
    }
/// create an AESKEY
    pub fn create_aeskey(&mut self) -> Result<[u8; 32]> {
        let mut aes_key = [0u8; 32]; // 256-bit AES key
        self.random(&mut aes_key)?;
        Ok(aes_key)
    }

    /// Encrypt AES key using RSA key in TPM
    pub fn encrypt_aes_key(&mut self, aes_key: &[u8; 32]) -> Result<Vec<u8>> {
          let data_to_encrypt = PublicKeyRsa::try_from(aes_key.to_vec())
        .expect("Failed to create buffer for data to encrypt.");

        let primary_key = self.primary_key.ok_or(Error::WrapperError(WrapperErrorKind::UnsupportedParam))?;

        // Get the public key from the primary key handle
        let (public_key, _, _) = self.context.read_public(primary_key)?;
        
        let data = Data::try_from(aes_key.as_slice())?;
        let decryption_scheme = RsaDecryptionScheme::create(RsaDecryptAlgorithm::Oaep, Some(HashingAlgorithm::Sha256))?;
        
        let encrypted = self.context.rsa_encrypt(
            primary_key,
            data_to_encrypt,
            decryption_scheme,
            data,
        )?;

        Ok(encrypted.value().to_vec())
    }

    /// Decrypt AES key using RSA key in TPM
    pub fn decrypt_aes_key(&mut self, encrypted_key: &[u8]) -> Result<[u8; 32]> {
        let primary_key = self.primary_key.ok_or(Error::WrapperError(WrapperErrorKind::UnsupportedParam))?;

        let data = PublicKeyRsa::try_from(encrypted_key)?;
        let decryption_scheme = RsaDecryptionScheme::create(RsaDecryptAlgorithm::Oaep, Some(HashingAlgorithm::Sha256))?;
        
       
  let decrypted = self.context.rsa_decrypt(
        primary_key,
        data,
        decryption_scheme,
        Data::default()
    )?;
        let mut aes_key = [0u8; 32];
        let decrypted_bytes = decrypted.value();
        if decrypted_bytes.len() != 32 {
            return Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
        }
        aes_key.copy_from_slice(decrypted_bytes);
        Ok(aes_key)
    } 
}