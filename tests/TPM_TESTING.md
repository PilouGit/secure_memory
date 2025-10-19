# Testing SecureMemory avec TPM

Ce guide explique comment tester l'intégration TPM de SecureMemory.

## Prérequis

Installez swtpm (TPM simulateur) :

```bash
# Ubuntu/Debian
sudo apt-get install swtpm swtpm-tools

# Fedora/RHEL
sudo dnf install swtpm swtpm-tools

# Arch Linux
sudo pacman -S swtpm
```

## Lancer le TPM simulateur

Dans un terminal séparé, démarrez swtpm :

```bash
# Créer le répertoire d'état
mkdir -p /tmp/tpmstate

# Lancer swtpm en mode socket
swtpm socket \
    --tpmstate dir=/tmp/tpmstate \
    --ctrl type=unixio,path=/tmp/swtpm-sock \
    --tpm2 \
    --log level=20
```

Le simulateur restera actif dans ce terminal. Messages attendus :
```
SWTPM_IO_Read: length 4
SWTPM_IO_Read: length 12
...
```

## Lancer les tests

Dans un autre terminal, depuis le répertoire du projet :

```bash
# Tester que le code TPM compile
cargo test --test test_tpm

# Lancer le test complet avec TPM (nécessite swtpm actif)
cargo test --test test_tpm -- --ignored --nocapture
```

## Structure du test

Le test `test_tpm.rs` fait :

1. **Créer une session TPM** : Authentification HMAC avec chiffrement de session
2. **Générer une clé AES-128 CFB** : Clé symétrique volatile dans la hiérarchie Null
3. **Chiffrer des données** : Texte en clair → ciphertext via TPM
4. **Déchiffrer les données** : Ciphertext → texte en clair
5. **Vérifier l'intégrité** : Assert que plaintext original == déchiffré

## Commandes utiles

### Vérifier l'état du TPM simulateur

```bash
# Lister les processus swtpm
ps aux | grep swtpm

# Vérifier le socket
ls -la /tmp/swtpm-sock
```

### Nettoyer l'état du TPM

```bash
# Arrêter swtpm (Ctrl+C dans son terminal)
# Puis supprimer l'état
rm -rf /tmp/tpmstate
```

### Tester avec un TPM matériel

Si vous avez un TPM matériel (ex: `/dev/tpm0`) :

```bash
# Le test essaiera automatiquement Device, puis Mssim, puis Swtpm
cargo test --test test_tpm -- --ignored
```

## Dépannage

### Erreur: "Error 0x00000100 (TPM_RC_INITIALIZE)"

**Problème** : Le TPM n'est pas démarré ou mal initialisé.

**Solution** :
1. Vérifier que swtpm est lancé : `ps aux | grep swtpm`
2. Redémarrer swtpm proprement
3. Nettoyer l'état : `rm -rf /tmp/tpmstate`

### Erreur: "Not enough sessions provided"

**Problème** : Le TPM 2.0 exige une session pour certaines commandes.

**Solution** : Le code crée maintenant automatiquement une session HMAC avant d'utiliser la clé.

### Erreur: "Connection refused"

**Problème** : swtpm n'est pas accessible via le socket.

**Solution** :
```bash
# Vérifier que le socket existe
ls -la /tmp/swtpm-sock

# Si absent, relancer swtpm avec le chemin correct
swtpm socket --tpmstate dir=/tmp/tpmstate --ctrl type=unixio,path=/tmp/swtpm-sock --tpm2
```

## Exemple de sortie réussie

```
running 1 test
✅ Session TPM créée: AuthSession(0x02000000)
✅ Clé AES créée (hiérarchie Null) : KeyHandle(0x80000000)
Plaintext: "ABCDEFGHIJKLMNOP"
Ciphertext (32 bytes) : [e3, 7a, 45, ...]
Decrypted (16 bytes) : [41, 42, 43, ...]
Decrypted string: ABCDEFGHIJKLMNOP
✅ Test réussi : chiffrement/déchiffrement TPM fonctionne!
test test_tpm_encrypt_decrypt ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.15s
```

## Limitations

- **Clé volatile** : La clé est créée dans la hiérarchie `Null`, elle disparaît au reboot du TPM
- **Pas d'authentification** : Pas de mot de passe sur la clé pour simplifier les tests
- **Simulateur** : Les performances ne reflètent pas un TPM matériel

## Pour aller plus loin

Pour une utilisation en production :

1. Utiliser la hiérarchie `Owner` ou `Platform` avec authentification
2. Persister les clés avec `TPM2_EvictControl`
3. Utiliser le sealing pour lier les clés à l'état du système (PCRs)
4. Implémenter la gestion d'erreurs robuste

Voir `src/tpmcrypto.rs` pour l'implémentation complète avec sealing.
