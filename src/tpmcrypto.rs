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
use crate::secure_error::SecurityError;
use crate::tpm_process_auth::TpmProcessAuth;

const HIERARCHY: Hierarchy = Hierarchy::Null;

/// TPM cryptographic operations wrapper
pub struct TpmCrypto {
    context: Context,

     tpm_process_auth: TpmProcessAuth,
}

impl TpmCrypto {
    /// Create a new TpmCrypto instance with TPM context
    pub fn create(tcti_name_conf: TctiNameConf)  -> std::result::Result<Self, SecurityError> {
         let context = Context::new(tcti_name_conf)?;
        let tpmProcessAuth=TpmProcessAuth::create()?;
        Ok(TpmCrypto { context, tpm_process_auth: tpmProcessAuth })
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

        }
    
        Ok(())
    }

    fn create_primary_with_password(
        &mut self,
        password: &str
    ) -> Result<CreatePrimaryKeyResult,SecurityError> {
        let password=self.tpm_process_auth.derive()?;

        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(false)
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
            .build()
            .unwrap();

        // ✅ Créer avec un mot de passe
        let auth = Auth::try_from(password)
            .expect("Failed to create auth");

        self.context
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(
                    Hierarchy::Null,
                    primary_pub,
                    Some(auth),  // ✅ Mot de passe défini
                    None,
                    None,
                    None
                )
            })
            .unwrap()
    }
}