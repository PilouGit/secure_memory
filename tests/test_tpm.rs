use tss_esapi::{
    Context, TctiNameConf,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        resource_handles::Hierarchy,
    },
    structures::{
        Digest, PublicBuilder,
        SymmetricCipherParameters, SymmetricDefinitionObject,
    }
};

use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::structures::{CreatePrimaryKeyResult, Data, HashScheme, Public, PublicKeyRsa, PublicRsaParametersBuilder, RsaDecryptionScheme, RsaExponent, RsaScheme};
use tss_esapi::handles::KeyHandle;

/// Crée une clé RSA et la charge IMMÉDIATEMENT dans le TPM
/// ✅ SÉCURISÉ : enc_private n'est jamais exposée en mémoire
/// Retourne le handle de la clé (référence TPM) et la partie publique
fn create_and_load_symmetric(context: &mut Context, primary: &CreatePrimaryKeyResult) -> (KeyHandle, Public)
{
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_st_clear(false)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        // We need a key that can decrypt values - we don't need to worry
        // about signatures.
        .with_decrypt(true)
        // Note that we don't set the key as restricted.
        .build()
        .expect("Failed to build object attributes");

    let rsa_params = PublicRsaParametersBuilder::new()
        // The value for scheme may have requirements set by a combination of the
        // sign, decrypt, and restricted flags. For an unrestricted signing and
        // decryption key then scheme must be NULL. For an unrestricted decryption key,
        // NULL, OAEP or RSAES are valid for use.
        .with_scheme(RsaScheme::Null)
        .with_key_bits(RsaKeyBits::Rsa2048)
        .with_exponent(RsaExponent::default())
        .with_is_decryption_key(true)
        // We don't require signatures, but some users may.
        // .with_is_signing_key(true)
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

    // ✅ Créer ET charger immédiatement la clé dans le TPM
    // enc_private n'existe que dans ce scope limité
    context
        .execute_with_nullauth_session(|ctx| -> Result<(KeyHandle, Public), tss_esapi::Error> {
            // Créer la clé
            let create_result = ctx
                .create(primary.key_handle, key_pub, None, None, None, None)?;

            // IMMÉDIATEMENT charger la clé dans le TPM
            // enc_private est utilisée directement et ne persiste pas
            let key_handle = ctx
                .load(
                    primary.key_handle,
                    create_result.out_private,  // Utilisé directement, jamais stocké
                    create_result.out_public.clone()
                )?;

            // Retourner seulement le handle et la partie publique
            Ok((key_handle, create_result.out_public))
        })
        .unwrap()
}
fn create_primary(context: &mut Context) -> CreatePrimaryKeyResult {
    // Create the primary key. A primary key is the "root" of a collection of objects.
    // These other objects are encrypted by the primary key allowing them to persist
    // over a reboot and reloads.
    //
    // A primary key is derived from a seed, and provided that the same inputs are given
    // the same primary key will be derived in the tpm. This means that you do not need
    // to store or save the details of this key - only the parameters of how it was created.
    let object_attributes = ObjectAttributesBuilder::new()
        // Indicate the key can only exist within this tpm and can not be exported.
        .with_fixed_tpm(true)
        // The primary key and it's descendent keys can't be moved to other primary
        // keys.
        .with_fixed_parent(true)
        // The primary key will persist over suspend and resume of the system.
        .with_st_clear(false)
        // The primary key was generated entirely inside the TPM - only this TPM
        // knows it's content.
        .with_sensitive_data_origin(true)
        // This key requires "authentication" to the TPM to access - this can be
        // an HMAC or password session. HMAC sessions are used by default with
        // the "execute_with_nullauth_session" function.
        .with_user_with_auth(true)
        // This key has the ability to decrypt
        .with_decrypt(true)
        // This key may only be used to encrypt or sign objects that are within
        // the TPM - it can not encrypt or sign external data.
        .with_restricted(true)
        .build()
        .expect("Failed to build object attributes");

    let primary_pub = PublicBuilder::new()
        // This key is a symmetric key.
        .with_public_algorithm(PublicAlgorithm::SymCipher)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(
            SymmetricDefinitionObject::AES_128_CFB,
        ))
        .with_symmetric_cipher_unique_identifier(Digest::default())
        .build()
        .unwrap();

    context
        .execute_with_nullauth_session(|ctx| {
            // Create the key under the "owner" hierarchy. Other hierarchies are platform
            // which is for boot services, null which is ephemeral and resets after a reboot,
            // and endorsement which allows key certification by the TPM manufacturer.
            ctx.create_primary(Hierarchy::Null, primary_pub, None, None, None, None)
        })
        .unwrap()
}
/// Test équivalent au test.sh : Créer hiérarchie RSA -> AES dans TPM
/// ✅ SÉCURISÉ : La clé privée reste dans le TPM, jamais exposée en mémoire
fn test_rsa_aes_hierarchy(context: &mut Context) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Test hiérarchie RSA -> AES (SÉCURISÉ) ===");
    let primary = create_primary(context);

    // ✅ On reçoit directement le handle, pas enc_private
    let (rsa_key_handle, public) = create_and_load_symmetric(context, &primary);
    println!("✅ Clé RSA créée et chargée dans le TPM (clé privée jamais exposée)");

    let data_to_encrypt = PublicKeyRsa::try_from("TPMs are cool.".as_bytes().to_vec())
        .expect("Failed to create buffer for data to encrypt.");

    // To encrypt data to a key, we only need it's public component. We demonstrate how
    // to load that public component into a TPM and then encrypt to it.
    let encrypted_data = context
        .execute_with_nullauth_session(|ctx| -> Result<PublicKeyRsa, tss_esapi::Error> {
            let rsa_pub_key = ctx
                .load_external_public(public.clone(), Hierarchy::Null)?;

            let encrypted = ctx.rsa_encrypt(
                rsa_pub_key,
                data_to_encrypt.clone(),
                RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha1)),
                Data::default(),
            )?;

            // ✅ Nettoyer le handle de la clé publique
            ctx.flush_context(rsa_pub_key.into())?;

            Ok(encrypted)
        })
        .unwrap();

    // The data is now encrypted.
    println!("encrypted_data = {encrypted_data:?}");
    assert_ne!(encrypted_data, data_to_encrypt);

    // ✅ Déchiffrement : utilise directement le handle (clé déjà dans le TPM)
    // Pas besoin de recharger la clé !
    let decrypted_data = context
        .execute_with_nullauth_session(|ctx| {
            ctx.rsa_decrypt(
                rsa_key_handle,  // Utilise le handle directement
                encrypted_data,
                RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha1)),
                Data::default(),
            )
        })
        .unwrap();

    println!("data_to_encrypt = {data_to_encrypt:?}");
    println!("decrypted_data = {decrypted_data:?}");
    // They are the same!
    assert_eq!(data_to_encrypt, decrypted_data);

    // ✅ Nettoyer : décharger TOUTES les clés du TPM
    context.flush_context(rsa_key_handle.into())?;
    println!("✅ Clé RSA déchargée du TPM");

    context.flush_context(primary.key_handle.into())?;
    println!("✅ Clé primaire déchargée du TPM");

    Ok(())
}
/// Test TPM encryption/decryption
///
/// Ce test requiert un TPM simulateur (swtpm) en cours d'exécution.
///
/// Pour lancer swtpm:
/// ```bash
/// mkdir -p /tmp/tpmstate
/// swtpm socket --tpmstate dir=/tmp/tpmstate --ctrl type=unixio,path=/tmp/swtpm-sock --tpm2 --log level=20
/// ```
///
/// Puis lancer le test:
/// ```bash
/// cargo test --test test_tpm -- --ignored
/// ```
#[test]
fn test_tpm_encrypt_decrypt() -> Result<(), Box<dyn std::error::Error>> {
    // Se connecter au TPM mssim
    let mut ctx = Context::new(TctiNameConf::Mssim(Default::default()))?;

    test_rsa_aes_hierarchy(&mut ctx)?;
    ctx.clear_sessions();
    Ok(())
}

/// Test simple sans TPM - juste pour vérifier que le code compile
#[test]
fn test_tpm_code_compiles() {
    // Ce test vérifie juste que le code TPM compile correctement
    println!("✅ Le code TPM compile correctement");
    println!("   Pour tester avec un TPM réel, lancez: cargo test --test test_tpm -- --ignored");
}