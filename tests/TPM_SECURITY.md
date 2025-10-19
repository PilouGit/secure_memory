# Sécurité TPM : Guide Complet

## Vue d'ensemble des couches de sécurité

Le TPM offre plusieurs couches de sécurité complémentaires :

```
┌─────────────────────────────────────────────────────────────┐
│ 1. PROTECTION MATÉRIELLE                                    │
│    • Clés stockées dans hardware sécurisé                   │
│    • Résistance aux attaques physiques                      │
│    • Clés ne sortent JAMAIS du TPM                          │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. HIÉRARCHIE & CHIFFREMENT                                 │
│    • Primary key dérivée d'une seed interne                 │
│    • Child keys chiffrées par parent                        │
│    • Protection contre extraction                           │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. AUTHENTIFICATION (AUTH) ⬅️ CONTRÔLE D'ACCÈS              │
│    • Password (mot de passe)                                │
│    • HMAC sessions                                          │
│    • Policy (conditions d'utilisation)                      │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. OPÉRATIONS CRYPTOGRAPHIQUES                              │
│    • Encrypt / Decrypt                                      │
│    • Sign / Verify                                          │
└─────────────────────────────────────────────────────────────┘
```

## Rôle de l'authentification (AUTH)

### ❓ Que protège l'AUTH ?

L'AUTH contrôle **qui peut UTILISER** une clé, pas le chiffrement des données.

| Aspect | Protection |
|--------|------------|
| Clé stockée dans le TPM | ✅ Toujours chiffrée (automatique) |
| Clé ne sort jamais du TPM | ✅ Garanti par le hardware |
| **Utilisation de la clé** | ⚠️ **Protégé par AUTH** |
| Déchiffrement autorisé | ⚠️ **Contrôlé par AUTH** |

### Scénarios d'attaque

#### Sans AUTH (fichier `test_tpm.rs` original)

```rust
// ❌ VULNÉRABLE
execute_with_nullauth_session(...)  // Pas de mot de passe
```

**Scénario d'attaque :**
```
Attaquant avec accès au système :
1. Accède au TPM (socket /tmp/swtpm-sock)
2. ✅ Peut utiliser TOUTES les clés chargées
3. ✅ Peut déchiffrer toutes les données
4. ✅ Pas besoin de connaître de mot de passe
```

#### Avec AUTH (fichier `test_tpm_secure_auth.rs`)

```rust
// ✅ SÉCURISÉ
let auth = Auth::try_from("SecurePassword123!".as_bytes())?;
ctx.tr_set_auth(key_handle.into(), auth)?;
```

**Scénario d'attaque :**
```
Attaquant avec accès au système :
1. Accède au TPM (socket /tmp/swtpm-sock)
2. ❌ Ne connaît pas le mot de passe de la clé
3. ❌ Ne peut PAS utiliser la clé
4. ❌ Ne peut PAS déchiffrer les données
```

## Comparaison des deux approches

### test_tpm.rs (SANS AUTH)

```rust
// Création sans mot de passe
ctx.create_primary(Hierarchy::Null, primary_pub, None, ...)
                                                   ^^^^
                                                   Pas d'auth

// Utilisation sans vérification
execute_with_nullauth_session(|ctx| {
    ctx.rsa_decrypt(key_handle, data, ...)  // ✅ Toujours autorisé
})
```

**Usage :** Tests, prototypage
**Sécurité :** ❌ Aucune protection d'accès

### test_tpm_secure_auth.rs (AVEC AUTH)

```rust
// Création avec mot de passe
let password = "SecurePassword123!";
let auth = Auth::try_from(password.as_bytes())?;
ctx.create_primary(Hierarchy::Null, primary_pub, Some(auth), ...)
                                                  ^^^^^^^^^^
                                                  Mot de passe requis

// Utilisation nécessite authentification
ctx.tr_set_auth(key_handle.into(), auth)?;
ctx.rsa_decrypt(key_handle, data, ...)  // ✅ Seulement si bon password
```

**Usage :** Production, données sensibles
**Sécurité :** ✅ Protection par mot de passe

## Types d'authentification TPM

### 1. Password (mot de passe)

```rust
let auth = Auth::try_from("MySecretPassword".as_bytes())?;
ctx.tr_set_auth(key_handle.into(), auth)?;
```

**Avantages :**
- ✅ Simple à implémenter
- ✅ Compatible avec tous les TPMs

**Inconvénients :**
- ⚠️ Mot de passe en clair en mémoire
- ⚠️ Vulnérable aux attaques par force brute

**Solution :** Utiliser `SecureVec` pour stocker le mot de passe !

```rust
use secure_memory::SecureVec;

let password = SecureVec::from("MySecretPassword".as_bytes());
let auth = Auth::try_from(password.as_slice().to_vec())?;
ctx.tr_set_auth(key_handle.into(), auth)?;
// password est effacé automatiquement à la destruction
```

### 2. HMAC Sessions

```rust
let session = ctx.start_auth_session(...)?;
ctx.execute_with_session(session, |ctx| {
    ctx.rsa_decrypt(key_handle, data, ...)
})?;
```

**Avantages :**
- ✅ Pas de mot de passe en transit
- ✅ Protection contre replay attacks
- ✅ Chiffrement des communications

### 3. Policy (Politiques d'accès)

```rust
// Exemple : autoriser uniquement si PCR[7] = valeur attendue
let policy = PolicyBuilder::new()
    .with_pcr(7, expected_hash)
    .build()?;
```

**Avantages :**
- ✅ Conditions complexes (PCR, time, locality...)
- ✅ Pas de mot de passe à gérer
- ✅ Ideal pour sealed keys (scellement)

## Recommandations de sécurité

### Pour les tests (développement)

```rust
// test_tpm.rs
execute_with_nullauth_session(...)  // ✅ OK pour tests
```

### Pour la production

1. **Toujours utiliser AUTH**
   ```rust
   let password = SecureVec::from("password".as_bytes());
   let auth = Auth::try_from(password.as_slice().to_vec())?;
   ctx.tr_set_auth(key_handle.into(), auth)?;
   ```

2. **Stocker les mots de passe dans SecureMemory**
   ```rust
   use secure_memory::SecureVec;
   // ✅ Mémoire verrouillée, effacement garanti
   ```

3. **Utiliser des hiérarchies appropriées**
   ```rust
   Hierarchy::Owner  // Pour données utilisateur
   Hierarchy::Null   // Seulement pour tests
   ```

4. **Combiner avec des policies pour sécurité maximale**
   ```rust
   // Exemple : clé utilisable seulement au boot
   .with_policy(boot_policy)
   ```

## Test de sécurité

Pour tester l'authentification :

```bash
# Avec TPM simulateur actif
cargo test test_tpm_with_secure_auth -- --ignored
```

**Résultat attendu :**
```
✅ Création de la clé primaire avec mot de passe
✅ Création de la clé RSA avec mot de passe
✅ Chiffrement des données
✅ Déchiffrement (avec authentification)
❌ Test avec MAUVAIS mot de passe...
   ✅ Déchiffrement refusé (comme attendu)
✅ Test terminé avec succès - Les clés sont protégées par mot de passe !
```

## Conclusion

| Couche | Rôle | Automatique ? |
|--------|------|---------------|
| Hardware TPM | Protège les clés | ✅ Oui |
| Hiérarchie | Chiffre les clés enfants | ✅ Oui |
| **AUTH** | **Contrôle d'accès** | ❌ **NON - À configurer !** |
| Crypto ops | Chiffre/déchiffre données | ✅ Oui |

**L'AUTH est ESSENTIELLE** pour :
- ✅ Empêcher l'utilisation non autorisée
- ✅ Protéger contre les attaquants locaux
- ✅ Implémenter un contrôle d'accès

**Sans AUTH :** Le TPM protège les clés en hardware, mais n'importe qui peut les utiliser !
