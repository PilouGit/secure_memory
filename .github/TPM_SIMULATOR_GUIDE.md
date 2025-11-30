# Guide des Simulateurs TPM pour CI/CD

## Simulateurs Disponibles

### 1. IBM TPM Simulator ⭐ RECOMMANDÉ pour CI/CD

**Avantages:**
- ✅ Compilation simple (gcc + make seulement)
- ✅ Peu de dépendances
- ✅ Fiable sur Ubuntu 22.04 et 24.04
- ✅ Utilisé dans nos workflows CI/CD

**Installation:**
```bash
wget https://downloads.sourceforge.net/project/ibmswtpm2/ibmtpm1682.tar.gz
mkdir ibmtpm && cd ibmtpm
tar -xvf ../ibmtpm1682.tar.gz
cd src && make
./tpm_server &  # Démarre sur port 2321
```

**Dépendances:**
```bash
sudo apt-get install -y build-essential
```

---

### 2. Microsoft TPM Simulator ⚠️ Problèmes autotools

**Avantages:**
- ✅ Support officiel Microsoft
- ✅ Conforme TPM 2.0 spec

**Inconvénients:**
- ❌ Nécessite autoconf/automake/libtool
- ❌ Échecs de compilation fréquents
- ❌ Plus de dépendances

**Erreur typique:**
```
configure.ac:44: error: possibly undefined macro: AC_SUBST
autoreconf: error: /usr/bin/autoconf failed with exit status: 1
```

**Solution si vous DEVEZ utiliser Microsoft:**
```bash
# Installer TOUTES les dépendances autotools
sudo apt-get install -y \
  build-essential \
  autoconf \
  automake \
  libtool \
  pkg-config \
  m4

# Puis compiler
git clone https://github.com/microsoft/ms-tpm-20-ref.git
cd ms-tpm-20-ref/TPMCmd
./bootstrap
./configure
make
./tpm2-simulator &
```

---

### 3. swtpm (Alternative moderne) 🚀

**Avantages:**
- ✅ Package Ubuntu disponible (pas de compilation)
- ✅ Très léger
- ✅ Supporte socket et device modes

**Installation:**
```bash
sudo apt-get install -y swtpm swtpm-tools

# Démarrer
mkdir -p /tmp/myvtpm
swtpm socket \
  --tpmstate dir=/tmp/myvtpm \
  --ctrl type=tcp,port=2322 \
  --server type=tcp,port=2321 \
  --tpm2 &
```

**Configuration tss-esapi:**
```bash
export TPM_TCTI=swtpm:host=localhost,port=2321
```

---

## Configuration pour secure_memory

### Variables d'environnement

```bash
# Utiliser le simulateur (défaut)
export TPM_TCTI=mssim

# Ou utiliser TPM hardware
export TPM_TCTI=device

# Ou utiliser swtpm
export TPM_TCTI=swtpm:host=localhost,port=2321
```

### Workflow GitHub Actions

**Recommandation: Utiliser IBM simulator**

```yaml
- name: Install TPM dependencies
  run: |
    sudo apt-get update
    sudo apt-get install -y build-essential libtss2-dev tpm2-tools

- name: Start IBM TPM Simulator
  run: |
    wget https://downloads.sourceforge.net/project/ibmswtpm2/ibmtpm1682.tar.gz
    mkdir ibmtpm && cd ibmtpm
    tar -xvf ../ibmtpm1682.tar.gz
    cd src && make
    ./tpm_server &
    sleep 2

- name: Set TPM environment
  run: echo "TPM_TCTI=mssim" >> $GITHUB_ENV

- name: Run tests
  run: cargo test
```

---

## Debugging

### Vérifier que le TPM est disponible

```bash
# Test avec tpm2-tools
tpm2_getcap properties-fixed

# Test avec Rust
cargo test --lib -- --nocapture
```

### Logs

```bash
# Simulateur IBM
./tpm_server &> tpm.log &

# Logs tss-esapi
export RUST_LOG=debug
cargo test
```

---

## Matrice de Compatibilité

| Simulateur | Ubuntu 22.04 | Ubuntu 24.04 | macOS | Windows |
|------------|--------------|--------------|-------|---------|
| IBM | ✅ | ✅ | ✅ | ⚠️ |
| Microsoft | ⚠️ | ⚠️ | ⚠️ | ✅ |
| swtpm | ✅ | ✅ | ⚠️ | ❌ |

✅ Fonctionne bien
⚠️ Nécessite configuration
❌ Non supporté

---

## En cas de problème

### Erreur: "Failed to connect to TPM"

```bash
# Vérifier que le simulateur tourne
netstat -tlnp | grep 2321

# Redémarrer le simulateur
pkill tpm_server
./tpm_server &
```

### Erreur: "AC_SUBST undefined macro"

➡️ **Solution: Utiliser IBM au lieu de Microsoft**

Ou installer les dépendances manquantes:
```bash
sudo apt-get install -y autoconf automake libtool m4
```

### Erreur: "mlock() failed"

```bash
# Augmenter la limite de mémoire lockée
ulimit -l unlimited
```

---

## Références

- [IBM TPM Simulator](https://sourceforge.net/projects/ibmswtpm2/)
- [Microsoft TPM Reference](https://github.com/microsoft/ms-tpm-20-ref)
- [swtpm](https://github.com/stefanberger/swtpm)
- [tss-esapi Documentation](https://docs.rs/tss-esapi/)

---

**Dernière mise à jour:** 2025-11-30
**Status:** Production-ready avec IBM simulator
