# Secure Memory - Java Examples

Ce répertoire contient des exemples d'utilisation de la bibliothèque Secure Memory en Java.

## Structure

```
examples/
├── basic/              # Exemples basiques d'utilisation
│   ├── Example.java    # Utilisation générale
│   ├── WriteOnceExample.java  # Mémoire write-once
│   ├── MemoryLeakDemo.java    # Démonstration de détection de fuites
│   └── MemorySecurityTester.java  # Tests de sécurité mémoire
└── springboot-example/ # Exemple d'intégration avec Spring Boot
```

## Exemples Basiques

### Prérequis

1. **Build de la bibliothèque principale** :
   ```bash
   cd /home/pilou/myprojects/secure_memory/java
   mvn clean install
   ```

2. **Compilation de la bibliothèque native Rust** :
   ```bash
   cd /home/pilou/myprojects/secure_memory
   cargo build --release --lib
   ```

3. **Copie de la bibliothèque native** (si nécessaire) :
   ```bash
   cp target/release/libsecure_memory.so java/target/classes/linux-x86-64/
   ```

### Exécution des Exemples

#### 1. Example.java - Utilisation Basique

Démontre les opérations de base : création, écriture, lecture, et libération de mémoire sécurisée.

```bash
cd examples/basic
mvn clean compile
mvn exec:java@example
```

**Ce qu'il montre** :
- Allocation de mémoire sécurisée
- Écriture et lecture de données sensibles
- Gestion automatique avec try-with-resources
- Gestion des erreurs

#### 2. WriteOnceExample.java - Mémoire Write-Once

Démontre la mémoire qui ne peut être écrite qu'une seule fois, protégeant contre les écrasements accidentels.

```bash
cd examples/basic
mvn exec:java@write-once
```

**Ce qu'il montre** :
- Création de mémoire write-once
- Protection contre les écritures multiples
- Cas d'usage pour les clés cryptographiques

#### 3. MemoryLeakDemo.java - Détection de Fuites

Permet de vérifier que les secrets sont correctement effacés de la mémoire.

```bash
cd examples/basic
mvn exec:java@memory-leak
```

**Ce qu'il montre** :
- Comment vérifier l'effacement mémoire
- Utilisation d'outils externes (jmap, gcore)
- Inspection de heap dumps

#### 4. MemorySecurityTester.java - Tests de Sécurité

Utilitaire pour tester la sécurité mémoire avec des outils de diagnostic.

**Utilisation** :
```java
import io.github.pilougit.security.examples.MemorySecurityTester;

// Créer un heap dump
String dumpFile = MemorySecurityTester.createHeapDump();

// Chercher un secret dans le dump
boolean found = MemorySecurityTester.searchInHeapDump(dumpFile, "mon-secret");
```

## Exemple Spring Boot

### Description

Exemple complet d'intégration de Secure Memory dans une application Spring Boot, incluant :
- Configuration sécurisée des propriétés
- API REST pour opérations cryptographiques
- Service de base de données avec secrets sécurisés
- Tests d'intégration

### Démarrage

```bash
cd examples/springboot-example
mvn clean package
mvn spring-boot:run
```

### Endpoints Disponibles

L'application démarre sur `http://localhost:8080` avec les endpoints suivants :

1. **GET /api/secure/encrypt?data=<text>**
   - Chiffre des données
   - Retourne les données chiffrées en base64

2. **POST /api/secure/decrypt**
   - Body: `{"data": "<base64-encrypted-data>"}`
   - Déchiffre les données

3. **GET /api/secure/random**
   - Génère des données aléatoires cryptographiquement sécurisées

4. **GET /api/database/connect**
   - Simule une connexion BDD avec credentials sécurisés

5. **GET /api/database/query?sql=<query>**
   - Exécute une requête avec connexion sécurisée

### Configuration

Fichier `application.properties` :
```properties
# API Configuration
api.key=your-api-key-here
api.secret=your-api-secret-here

# Database Configuration
database.host=localhost
database.port=5432
database.name=myapp
database.username=dbuser
database.password=dbpass
```

**⚠️ Sécurité** : Ces propriétés sont automatiquement chargées dans de la mémoire sécurisée au démarrage de l'application.

## Compilation de Tous les Exemples

Pour compiler tous les exemples en une seule commande :

```bash
# Depuis le répertoire racine du projet Java
cd /home/pilou/myprojects/secure_memory/java

# Build la bibliothèque
mvn clean install

# Build les exemples
cd examples/basic
mvn clean compile

cd ../springboot-example
mvn clean package
```

## Tests

### Tests Unitaires

```bash
# Tests de la bibliothèque principale
cd /home/pilou/myprojects/secure_memory/java
mvn test

# Tests du Spring Boot example
cd examples/springboot-example
mvn test
```

### Tests de Sécurité Mémoire

Voir le script `verify-memory-security.sh` dans le répertoire parent.

## Notes Importantes

### Environnement TPM

La bibliothèque supporte deux modes :
- **Mode TPM** : Utilise un TPM hardware ou simulateur
- **Mode Software** : Crypto pure software (sans TPM)

Pour activer le mode TPM :
```bash
export TPM_TCTI=device  # Pour TPM hardware
# ou
export TPM_TCTI=mssim   # Pour TPM simulator
```

Sans `TPM_TCTI`, le mode software est utilisé automatiquement.

### Cleanup des Ressources

Tous les exemples incluent des shutdown hooks pour nettoyer proprement les ressources TPM :

```java
Runtime.getRuntime().addShutdownHook(new Thread(() -> {
    SecureMemory.cleanupTpm();
}));
```

### Dépendances Système

- **Java 11 ou supérieur**
- **Maven 3.6+**
- **Bibliothèque Rust compilée** : `libsecure_memory.so`
- **Optionnel** : TPM 2.0 hardware ou IBM TPM Simulator

## Dépannage

### Erreur : Cannot find libsecure_memory.so

```bash
# Vérifier que la lib est compilée
ls target/release/libsecure_memory.so

# Copier dans le bon répertoire
cp target/release/libsecure_memory.so java/target/classes/linux-x86-64/
```

### Erreur : Class not found

```bash
# Recompiler la bibliothèque Java
cd java
mvn clean install
```

### Erreur TPM

Si vous avez des erreurs TPM et ne voulez pas utiliser de TPM :
```bash
unset TPM_TCTI  # Désactive le mode TPM
```

## Ressources

- **Documentation principale** : `/java/README.md`
- **Vérification mémoire** : `/java/verify-memory-security.sh`
- **Documentation Rust** : `/README.md`

## Licence

Voir LICENSE dans le répertoire racine du projet.
