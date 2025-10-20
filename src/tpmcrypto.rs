use std::str::FromStr;
use std::sync::OnceLock;
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
use zeroize::Zeroize;
use crate::secure_error::SecurityError;
use crate::tpm_process_auth::TpmProcessAuth;

const HIERARCHY: Hierarchy = Hierarchy::Null;

/// TPM cryptographic operations wrapper
pub struct TpmCrypto {
    context: Context,

    tpm_process_auth: TpmProcessAuth,
    primary:Option<CreatePrimaryKeyResult>,
    rsa_key_handle:Option<KeyHandle>,
    public_rsa_key:Option<KeyHandle>
}

static TPM: OnceLock<TpmCrypto> = OnceLock::new();

/// get or create
pub fn get_service() -> &'static TpmCrypto {
    TPM.get_or_init(|| {
        let mut s = TpmCrypto::create(TctiNameConf::Mssim(Default::default())).unwrap();
        s.init_key(); // ✅ Appel explicite après construction
        s
    })
}

impl TpmCrypto {
    /// Create a new TpmCrypto instance with TPM context
    pub fn create(tcti_name_conf: TctiNameConf)  -> std::result::Result<Self, SecurityError> {
         let context = Context::new(tcti_name_conf)?;
        let tpm_process_auth =TpmProcessAuth::create()?;

        Ok(TpmCrypto { context, tpm_process_auth,primary:None,rsa_key_handle:None,public_rsa_key:None })
    }
    /// Initialisation
    pub fn init_key(&mut self)
    {
    let primary_key=self.create_primary_with_password().unwrap();
        let (private_keyhandle,public_keyhandle)=self.create_and_load_symmetric_with_password(&primary_key).unwrap();
        self.primary=Some(primary_key);
        self.rsa_key_handle=Some(private_keyhandle);
        self.public_rsa_key=Some(public_keyhandle);


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
        &mut self
    ) -> Result<CreatePrimaryKeyResult> {
        // Dériver le secret (Zeroizing<Vec<u8>>)
        let derived_secret = self.tpm_process_auth.derive()
            .map_err(|e| tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::InvalidParam))?;

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
            .build()?;

        // ✅ Créer Auth depuis le secret dérivé (extraire la valeur de Zeroizing)
        let auth = Auth::try_from(derived_secret.as_slice())?;

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
    }
    fn create_and_load_symmetric_with_password(
         &mut self,
        primary: &CreatePrimaryKeyResult

    ) -> std::result::Result<(KeyHandle, KeyHandle), Box<dyn std::error::Error>> {

        let parent_password= self.tpm_process_auth.derive().unwrap();
        let key_password= parent_password.clone();

        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(false)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)  // ✅ Requiert authentification
            .with_decrypt(true)
            .build()
            .expect("Failed to build object attributes");

        let rsa_params = PublicRsaParametersBuilder::new()
            .with_scheme(RsaScheme::Null)
            .with_key_bits(RsaKeyBits::Rsa2048)
            .with_exponent(RsaExponent::default())
            .with_is_decryption_key(true)
            .with_restricted(false)
            .build()
            .expect("Failed to build rsa parameters");

        let key_pub = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_rsa_parameters(rsa_params)
            .with_rsa_unique_identifier(PublicKeyRsa::default())
            .build()
            .unwrap();

        // ✅ Créer une session d'authentification avec le mot de passe du parent
        let parent_auth = Auth::try_from(parent_password.to_vec())?;
        let key_auth = Auth::try_from(key_password.to_vec())?;

        // Définir l'auth pour la clé primaire
        self.context.tr_set_auth(primary.key_handle.into(), parent_auth.clone())?;

        // ✅ Envelopper dans une session pour créer ET charger la clé
        let (key_handle, publickey_handle) = self.context.execute_with_nullauth_session(|ctx| -> std::result::Result<(KeyHandle, KeyHandle), tss_esapi::Error> {
            // Créer la clé avec son propre mot de passe
            let create_result = ctx.create(
                primary.key_handle,
                key_pub,
                Some(key_auth),  // ✅ Mot de passe pour la nouvelle clé
                None,
                None,
                None
            )?;

            // Charger immédiatement (enc_private n'est jamais stockée)
            let key_handle = ctx.load(
                primary.key_handle,
                create_result.out_private,
                create_result.out_public.clone()
            )?;
            let publickey_handle = ctx.load_external_public(create_result.out_public, Hierarchy::Null)?;


            Ok((key_handle,publickey_handle))
        }).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        Ok((key_handle, publickey_handle))
    }

    fn ciphering(&mut self, buffer: Vec<u8>) -> Vec<u8>
    {
        let data_to_encrypt = PublicKeyRsa::try_from(buffer)
            .expect("Failed to create buffer for data to encrypt.");

        println!("✅ Chiffrement des données");
        // Chiffrement (pas besoin d'auth pour utiliser la partie publique)
        let encrypted_data = self.context
            .execute_with_nullauth_session(|context| {

                context.rsa_encrypt(
                    self.public_rsa_key.unwrap(),
                    data_to_encrypt.clone(),
                    RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha1)),
                    Data::default(),
                )
            })
            .unwrap();
        return encrypted_data.value().to_vec();
    }
    fn unciphering(&mut self,buffer: Vec<u8>) -> Vec<u8>
    {
        let rsa_key_password=self.tpm_process_auth.derive().unwrap().to_vec();

        let data_to_dencrypt = PublicKeyRsa::try_from(buffer)
            .expect("Failed to create buffer for data to encrypt.");

        let rsa_auth = Auth::try_from(rsa_key_password).unwrap();
        self.context.tr_set_auth(self.rsa_key_handle.unwrap().into(), rsa_auth);

        // ✅ Envelopper dans une session pour le déchiffrement
        let decrypted_data = self.context.execute_with_nullauth_session(|context| {
            context.rsa_decrypt(
                self.rsa_key_handle.unwrap(),
                data_to_dencrypt.clone(),
                RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha1)),
                Data::default(),
            )
        }).unwrap();
        return decrypted_data.value().to_vec();
    }

}

impl Drop for TpmCrypto {
    fn drop(&mut self) {
        // Flush RSA private key handle
        if let Some(key_handle) = self.rsa_key_handle.take() {
            let _ = self.context.flush_context(key_handle.into());
        }

        // Flush RSA public key handle
        if let Some(public_handle) = self.public_rsa_key.take() {
            let _ = self.context.flush_context(public_handle.into());
        }

        // Flush primary key handle
        if let Some(primary) = self.primary.take() {
            let _ = self.context.flush_context(primary.key_handle.into());
        }

        // Clear all sessions
        self.context.clear_sessions();
    }
}