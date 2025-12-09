# SecureMemory Spring Boot Example

Application Spring Boot démontrant comment utiliser **SecureMemory** pour stocker des propriétés sensibles de manière sécurisée.

## 🎯 Concept

Au lieu de stocker les secrets (mots de passe, clés API, tokens) en tant que `String` Java (en clair dans la heap), cette application utilise **SecureMemory** pour:

- ✅ Chiffrer les secrets avec **AES-256-GCM** quand ils ne sont pas utilisés
- ✅ Déchiffrer uniquement lors de l'accès
- ✅ Re-chiffrer automatiquement après utilisation
- ✅ Protéger contre les buffer overflows avec **canaries aléatoires**
- ✅ Mettre à zéro la mémoire lors de la destruction

## 📁 Structure du projet

```
springboot-example/
├── pom.xml
├── README.md
└── src/main/
    ├── java/com/securememory/springboot/
    │   ├── SecureMemoryApplication.java       # Classe principale
    │   ├── config/
    │   │   └── SecurePropertiesConfig.java    # Configuration des SecureMemory beans
    │   ├── service/
    │   │   ├── SecureDatabaseService.java     # Service utilisant le password
    │   │   └── SecureApiService.java          # Service utilisant l'API key
    │   └── controller/
    │       └── SecureMemoryController.java    # Endpoints REST
    └── resources/
        └── application.properties             # Propriétés (secrets chargés dans SecureMemory)
```

## 🔧 Configuration

### `application.properties`

Les propriétés sensibles définies ici sont automatiquement chargées dans SecureMemory:

```properties
# Ces propriétés sont stockées en SecureMemory (chiffrées)
app.database.password=MySecretDatabasePassword123!
app.api.key=sk_live_1234567890abcdefghijklmnopqrstuvwxyz
app.encryption.secret=ThisIsAVerySecretEncryptionKey2024!
```

### `SecurePropertiesConfig.java`

Création des beans SecureMemory à partir des propriétés:

```java
@Bean(name = "databasePassword")
public SecureMemory databasePassword(@Value("${app.database.password}") String password) {
    return createSecureMemory("databasePassword", password);
}
```

**Important**: Le `String password` passé en paramètre existe brièvement pendant l'injection, puis est copié dans SecureMemory et le garbage collector peut le nettoyer.

## 🚀 Comment lancer

### Prérequis

1. **Bibliothèque Rust compilée**
   ```bash
   cd /home/pilou/myprojects/secure_memory
   cargo build --release --lib
   ```

2. **JAR des bindings Java compilé**
   ```bash
   cd java/
   mvn clean package
   ```

3. **Java 17+** et **Maven 3.6+**

### Lancement

```bash
cd java/springboot-example/

# Définir le chemin de la bibliothèque native
export LD_LIBRARY_PATH=../../target/release:$LD_LIBRARY_PATH

# Option 1: Avec Maven
mvn spring-boot:run

# Option 2: Avec le JAR compilé
mvn clean package
java -jar target/springboot-example-1.0.0.jar
```

L'application démarre sur **http://localhost:8080**

## 📡 Endpoints disponibles

### 1. Status de SecureMemory

```bash
curl http://localhost:8080/api/secure/status
```

**Réponse:**
```json
{
  "secureMemoryCount": 3,
  "totalMemorySize": 192,
  "sizeByProperty": {
    "databasePassword": 64,
    "apiKey": 64,
    "encryptionSecret": 64
  },
  "message": "All properties are encrypted with AES-256-GCM"
}
```

### 2. Test de connexion base de données

```bash
curl -X POST http://localhost:8080/api/secure/database/connect
```

**Réponse:**
```json
{
  "status": "success",
  "message": "Connected to database successfully",
  "security": {
    "memorySize": 64,
    "isActive": true,
    "encryptionType": "AES-256-GCM with random canaries"
  }
}
```

### 3. Vérification de mot de passe

```bash
curl -X POST http://localhost:8080/api/secure/database/verify \
  -H "Content-Type: application/json" \
  -d '{"password": "MySecretDatabasePassword123!"}'
```

**Réponse:**
```json
{
  "valid": true,
  "message": "Password matches"
}
```

### 4. Appel API externe

```bash
curl -X POST http://localhost:8080/api/secure/api/call \
  -H "Content-Type: application/json" \
  -d '{"endpoint": "https://api.example.com/data"}'
```

**Réponse:**
```json
{
  "status": "success",
  "result": "API call to https://api.example.com/data successful (key length: 43)",
  "apiKeyPreview": "sk_l...wxyz"
}
```

### 5. Informations de sécurité

```bash
curl http://localhost:8080/api/secure/info
```

### 6. Health check

```bash
curl http://localhost:8080/api/secure/health
```

## 🔐 Comment ça fonctionne

### Flux de données

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Démarrage Spring Boot                                    │
├─────────────────────────────────────────────────────────────┤
│ application.properties:                                     │
│   app.database.password=MySecretPassword                    │
│                                                             │
│ ↓ Spring charge la property en tant que String             │
│                                                             │
│ SecurePropertiesConfig:                                     │
│   @Bean databasePassword(@Value("...") String password)    │
│   {                                                         │
│     SecureMemory mem = new SecureMemory(64);               │
│     mem.write(password.getBytes());  // Stocké chiffré     │
│     return mem;                                            │
│   }                                                         │
└─────────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. Utilisation (ex: connexion DB)                          │
├─────────────────────────────────────────────────────────────┤
│ SecureDatabaseService.connectToDatabase()                   │
│   {                                                         │
│     byte[] pwd = databasePassword.read();  // Déchiffré    │
│     String password = new String(pwd);                      │
│     // Utilisation...                                      │
│     // password re-chiffré automatiquement                 │
│   }                                                         │
└─────────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. Shutdown                                                 │
├─────────────────────────────────────────────────────────────┤
│ SecurePropertiesConfig.cleanup() [@PreDestroy]             │
│   {                                                         │
│     databasePassword.close();  // Zeroing + libération     │
│   }                                                         │
└─────────────────────────────────────────────────────────────┘
```

### Comparaison: String vs SecureMemory

#### ❌ Approche traditionnelle (String)

```java
@Value("${app.database.password}")
private String password;  // ⚠️ En clair dans la heap Java!

public void connect() {
    DataSource ds = createDataSource("jdbc:...", "user", password);
    // Le password reste en mémoire jusqu'au GC
    // Vulnérable aux memory dumps
}
```

#### ✅ Avec SecureMemory

```java
@Autowired
@Qualifier("databasePassword")
private SecureMemory password;  // ✓ Chiffré avec AES-256-GCM

public void connect() {
    byte[] pwd = password.read();  // Déchiffré temporairement
    String passwordStr = new String(pwd);
    DataSource ds = createDataSource("jdbc:...", "user", passwordStr);
    // password re-chiffré automatiquement
    // passwordStr sera GC, pwd est temporaire
}
```

## 🔒 Garanties de sécurité

### Côté Rust (libsecure_memory.so)

- ✅ **Chiffrement AES-256-GCM** des données au repos
- ✅ **Canaries aléatoires** (8 octets avant + 8 octets après)
- ✅ **Vérification automatique** des canaries avant/après chaque opération
- ✅ **Zeroing systématique** lors du `Drop`
- ✅ **Détection de corruption** avec panic si canaries modifiés

### Côté Java

- ✅ **Lifecycle Spring** géré avec `@PreDestroy`
- ✅ **AutoCloseable** pour try-with-resources si nécessaire
- ✅ **Exceptions typées** pour chaque type d'erreur
- ✅ **Validation** des paramètres
- ✅ **Protection** contre use-after-free

### Format mémoire

```
Allocation SecureMemory (par exemple, 64 bytes de données):

┌──────────┬────────┬──────────┬─────────┬──────────┐
│ Canary   │ Nonce  │ Data     │ GCM Tag │ Canary   │
│ Start    │ 12 B   │ 64 B     │ 16 B    │ End      │
│ 8 bytes  │        │          │         │ 8 bytes  │
│ (random) │        │(chiffré) │         │ (random) │
└──────────┴────────┴──────────┴─────────┴──────────┘

Total: 8 + 12 + 64 + 16 + 8 = 108 bytes
Overhead: 44 bytes
```

## 📊 Performance

### Overhead mémoire

- **Par allocation**: +44 octets (canaries + nonce + tag)
- **Exemple**: Pour stocker 32 bytes → 76 bytes au total

### Overhead CPU

- **Write**: ~50-100 µs (déchiffrement + chiffrement)
- **Read**: ~50-100 µs (déchiffrement)
- **Négligeable** pour des opérations ponctuelles (connexion DB, appels API)

## 🐛 Dépannage

### "Unable to load library 'secure_memory'"

```bash
# Vérifier que la bibliothèque existe
ls -lh ../../target/release/libsecure_memory.so

# Définir correctement le chemin
export LD_LIBRARY_PATH=../../target/release:$LD_LIBRARY_PATH

# Vérifier que Java trouve la bibliothèque
java -Djava.library.path=../../target/release -version
```

### "SECURITY VIOLATION: Buffer overflow detected"

C'est une **fonctionnalité de sécurité**, pas un bug!

- Les canaries ont détecté une corruption mémoire
- L'opération a été bloquée pour votre sécurité
- Vérifiez votre code pour des écritures hors limites

### Logs de démarrage

Si vous voyez:
```
✓ Property 'databasePassword' loaded into SecureMemory (size: 64 bytes)
✓ Property 'apiKey' loaded into SecureMemory (size: 64 bytes)
✓ Property 'encryptionSecret' loaded into SecureMemory (size: 64 bytes)
```

Tout fonctionne correctement! 🎉

## 📚 Références

- **SecureMemory Rust**: `../../src/secure_memory.rs`
- **FFI Interface**: `../../src/secure_memory_ffi.rs`
- **Java Bindings**: `../src/main/java/com/securememory/`
- **Spring Boot Docs**: https://spring.io/projects/spring-boot

## 🎓 Cas d'usage

Cette approche est recommandée pour:

- ✅ Mots de passe de bases de données
- ✅ Clés API externes
- ✅ Tokens OAuth/JWT
- ✅ Secrets de chiffrement
- ✅ Credentials cloud (AWS, GCP, Azure)
- ✅ Certificats/Private keys

**Note**: Pour les applications critiques, combinez avec:
- Vault (HashiCorp Vault, AWS Secrets Manager)
- Rotation automatique des secrets
- Chiffrement au niveau applicatif

## ✅ TODO pour production

- [ ] Intégrer avec Spring Cloud Config
- [ ] Support pour recharger les secrets à chaud
- [ ] Métriques Prometheus/Micrometer
- [ ] Tests unitaires avec TestContainers
- [ ] CI/CD avec GitHub Actions
- [ ] Documentation OpenAPI/Swagger
- [ ] Support multi-plateforme (Windows, macOS)

---

**Tous les secrets sont maintenant protégés!** 🔒
