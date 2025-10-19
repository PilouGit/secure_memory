/// Exemple de TPM avec AUTHENTIFICATION SÉCURISÉE
///
/// Ce test montre comment protéger les clés TPM avec des mots de passe
/// pour empêcher l'utilisation non autorisée.

use tss_esapi::{
    Context, TctiNameConf,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        resource_handles::Hierarchy,
    },
    structures::{
        Digest, PublicBuilder, Auth,
        SymmetricCipherParameters, SymmetricDefinitionObject,
        CreatePrimaryKeyResult, Data, HashScheme, Public, PublicKeyRsa,
        PublicRsaParametersBuilder, RsaDecryptionScheme, RsaExponent, RsaScheme,
    },
};

use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::handles::KeyHandle;

/// Crée une clé primaire AVEC mot de passe
fn create_primary_with_password(
    context: &mut Context,
    password: &str
) -> CreatePrimaryKeyResult {
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
    let auth = Auth::try_from(password.as_bytes().to_vec())
        .expect("Failed to create auth");

    context
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

/// Crée une clé RSA enfant AVEC mot de passe et la charge immédiatement
fn create_and_load_symmetric_with_password(
    context: &mut Context,
    primary: &CreatePrimaryKeyResult,
    parent_password: &str,
    key_password: &str,
) -> Result<(KeyHandle, Public), Box<dyn std::error::Error>> {
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
    let parent_auth = Auth::try_from(parent_password.as_bytes().to_vec())?;
    let key_auth = Auth::try_from(key_password.as_bytes().to_vec())?;

    // Définir l'auth pour la clé primaire
    context.tr_set_auth(primary.key_handle.into(), parent_auth.clone())?;

    // ✅ Envelopper dans une session pour créer ET charger la clé
    let (key_handle, out_public) = context.execute_with_nullauth_session(|ctx| -> Result<(KeyHandle, Public), tss_esapi::Error> {
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

        Ok((key_handle, create_result.out_public))
    }).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

    Ok((key_handle, out_public))
}

/// Test avec authentification sécurisée
#[test]
fn test_tpm_with_secure_auth() -> Result<(), Box<dyn std::error::Error>> {
    // Se connecter au TPM
    let mut ctx = Context::new(TctiNameConf::Mssim(Default::default()))?;

    println!("\n=== Test TPM avec AUTHENTIFICATION SÉCURISÉE ===\n");

    // Définir les mots de passe
    let primary_password = "SecurePassword123!";
    let rsa_key_password = "RSAKeySecret456!";

    // Créer la clé primaire avec mot de passe
    println!("✅ Création de la clé primaire avec mot de passe");
    let primary = create_primary_with_password(&mut ctx, primary_password);

    // Créer la clé RSA avec mot de passe
    println!("✅ Création de la clé RSA avec mot de passe");
    let (rsa_key_handle, public) = create_and_load_symmetric_with_password(
        &mut ctx,
        &primary,
        primary_password,
        rsa_key_password
    )?;

    // Données à chiffrer
    let data_to_encrypt = PublicKeyRsa::try_from("TPMs are cool with auth!".as_bytes().to_vec())
        .expect("Failed to create buffer for data to encrypt.");

    println!("✅ Chiffrement des données");
    // Chiffrement (pas besoin d'auth pour utiliser la partie publique)
    let encrypted_data = ctx
        .execute_with_nullauth_session(|context| {
            let rsa_pub_key = context
                .load_external_public(public.clone(), Hierarchy::Null)
                .unwrap();

            context.rsa_encrypt(
                rsa_pub_key,
                data_to_encrypt.clone(),
                RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha1)),
                Data::default(),
            )
        })
        .unwrap();

    println!("   Données chiffrées : {} bytes", encrypted_data.len());

    // ✅ Déchiffrement : NÉCESSITE le mot de passe de la clé RSA
    println!("✅ Déchiffrement (avec authentification)");

    let rsa_auth = Auth::try_from(rsa_key_password.as_bytes().to_vec())?;
    ctx.tr_set_auth(rsa_key_handle.into(), rsa_auth)?;

    // ✅ Envelopper dans une session pour le déchiffrement
    let decrypted_data = ctx.execute_with_nullauth_session(|context| {
        context.rsa_decrypt(
            rsa_key_handle,
            encrypted_data.clone(),
            RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha1)),
            Data::default(),
        )
    })?;

    println!("   Données déchiffrées : {:?}", String::from_utf8_lossy(&decrypted_data));
    assert_eq!(data_to_encrypt, decrypted_data);

    // ❌ Test : Tenter de déchiffrer avec MAUVAIS mot de passe
    println!("\n❌ Test avec MAUVAIS mot de passe...");
    let wrong_auth = Auth::try_from("WrongPassword".as_bytes().to_vec())?;
    ctx.tr_set_auth(rsa_key_handle.into(), wrong_auth)?;

    // ✅ Envelopper dans une session pour tester le mauvais mot de passe
    let decrypt_result = ctx.execute_with_nullauth_session(|context| {
        context.rsa_decrypt(
            rsa_key_handle,
            encrypted_data,
            RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha1)),
            Data::default(),
        )
    });

    match decrypt_result {
        Err(_) => println!("   ✅ Déchiffrement refusé (comme attendu)"),
        Ok(_) => panic!("❌ Le déchiffrement aurait dû échouer avec un mauvais mot de passe !"),
    }

    // Nettoyer
    ctx.flush_context(rsa_key_handle.into())?;
    println!("\n✅ Test terminé avec succès - Les clés sont protégées par mot de passe !");

    Ok(())
}

/// Test simple pour la compilation
#[test]
fn test_secure_auth_compiles() {
    println!("✅ Le code d'authentification sécurisée compile");
    println!("   Pour tester avec TPM: cargo test test_tpm_with_secure_auth -- --ignored");
}
