# Vérification de la Sécurité Mémoire

Ce guide explique comment vérifier que `SecureMemory` ne laisse pas de traces des secrets en mémoire.

## Pourquoi vérifier la mémoire ?

Lorsque vous stockez des mots de passe ou autres données sensibles dans une JVM, elles peuvent persister dans :
- **La heap JVM** : objets String, tableaux de bytes
- **La mémoire native** : allocations via JNI/JNA
- **Les core dumps** : si le processus crash
- **Le swap** : si la mémoire est swappée sur disque

`SecureMemory` est conçu pour :
1. Stocker les données en **mémoire native** (hors heap JVM)
2. **Verrouiller** la mémoire pour éviter le swap (`mlock`)
3. **Effacer** (zero) la mémoire lors de la libération
4. **Détecter la corruption** avec des canaries

## Méthodes de Vérification

### Méthode 1 : Test Automatisé avec Script

Le moyen le plus simple est d'utiliser le script fourni :

```bash
cd java
./verify-memory-security.sh
```

Ce script va :
1. Démarrer un programme Java avec SecureMemory
2. Créer un dump de la heap
3. Chercher le secret dans le dump
4. Rapporter si le secret a été trouvé ou non

**Résultat attendu** : Le secret ne devrait **PAS** être trouvé dans la heap.

### Méthode 2 : Vérification Manuelle avec jmap

#### Étape 1 : Compiler et exécuter le programme de test

```bash
cd java
mvn compile

# Exécuter MemoryLeakDemo
java -cp target/classes:$(mvn dependency:build-classpath -q -DincludeScope=runtime -Dmdep.outputFile=/dev/stdout) \
    com.securememory.MemoryLeakDemo
```

Le programme affichera son PID et attendra 60 secondes.

#### Étape 2 : Créer un heap dump

Dans un autre terminal :

```bash
# Remplacer <PID> par le PID affiché
jmap -dump:format=b,file=heap.hprof <PID>
```

#### Étape 3 : Rechercher le secret dans le heap dump

```bash
# Chercher le mot de passe dans le dump
strings heap.hprof | grep "MyTopSecretPassword@2025!"

# Si TROUVÉ : le secret a fuité (String normal)
# Si NON TROUVÉ : le secret a été effacé (SecureMemory)
```

### Méthode 3 : VisualVM (Interface Graphique)

1. **Démarrer VisualVM** :
   ```bash
   jvisualvm
   ```

2. **Attacher au processus Java** :
   - Sélectionner le processus dans la liste
   - Cliquer sur "Heap Dump"

3. **Analyser le dump** :
   - Onglet "Classes" → chercher `String`
   - Onglet "Instances" → examiner les valeurs
   - Utiliser la recherche OQL (Object Query Language) :
     ```javascript
     select s from java.lang.String s where s.toString().contains("MyTopSecret")
     ```

4. **Résultat attendu** :
   - Le secret stocké dans un `String` normal sera trouvé
   - Le secret stocké dans `SecureMemory` ne sera **PAS** trouvé

### Méthode 4 : Vérification de la Mémoire Native (Linux)

Cette méthode nécessite les permissions root.

#### Option A : Créer un core dump

```bash
# Obtenir le PID du processus Java
PID=$(jps | grep MemoryLeakDemo | awk '{print $1}')

# Créer un core dump
sudo gcore $PID

# Chercher le secret dans le core dump
strings core.$PID | grep "MyTopSecretPassword@2025!"
```

#### Option B : Lire /proc/[pid]/mem

```bash
# Chercher directement dans la mémoire du processus
sudo grep -a "MyTopSecretPassword@2025!" /proc/$PID/mem 2>/dev/null && echo "FOUND" || echo "NOT FOUND"
```

**Note** : Cette méthode peut trouver le secret même après qu'il ait été effacé de la heap JVM, car :
- Les chaînes de caractères dans les messages de log
- Les copies temporaires créées pour l'affichage
- La mémoire native de SecureMemory **avant** son `close()`

### Méthode 5 : Test Programmatique avec MemorySecurityTester

```bash
cd java
mvn compile

java -cp target/classes:$(mvn dependency:build-classpath -q -DincludeScope=runtime -Dmdep.outputFile=/dev/stdout) \
    com.securememory.MemorySecurityTester
```

Ce programme va :
1. Créer un String normal et vérifier qu'il persiste en mémoire
2. Créer un SecureMemory et vérifier qu'il ne persiste pas
3. Afficher les résultats

## Tests Unitaires

Les tests unitaires vérifient le comportement de SecureMemory :

```bash
cd java
mvn test
```

Tests inclus :
- `testBasicReadWrite` : lecture/écriture de base
- `testMemoryIsZeroedAfterClose` : vérification que close() rend les opérations impossibles
- `testCanaryDetection` : détection de corruption
- `testZeroingByteArrays` : effacement manuel des byte arrays

## Bonnes Pratiques

### ✅ FAIRE

```java
// 1. Utiliser try-with-resources pour fermeture automatique
try (SecureMemory sm = new SecureMemory(256)) {
    sm.write(password.getBytes(StandardCharsets.UTF_8));
    byte[] data = sm.read();

    // Utiliser les données
    processPassword(data);

    // Effacer le tableau immédiatement après usage
    for (int i = 0; i < data.length; i++) {
        data[i] = 0;
    }
}
// SecureMemory est automatiquement fermé et effacé ici

// 2. Effacer les tableaux de bytes après usage
byte[] sensitive = getSensitiveData();
try {
    useSensitiveData(sensitive);
} finally {
    for (int i = 0; i < sensitive.length; i++) {
        sensitive[i] = 0;
    }
}

// 3. Utiliser char[] au lieu de String pour les mots de passe
char[] password = getPasswordFromUser();
try {
    // Convertir en bytes pour SecureMemory
    byte[] passwordBytes = new String(password).getBytes(StandardCharsets.UTF_8);
    try (SecureMemory sm = new SecureMemory(256)) {
        sm.write(passwordBytes);
        // ...
    } finally {
        for (int i = 0; i < passwordBytes.length; i++) {
            passwordBytes[i] = 0;
        }
    }
} finally {
    for (int i = 0; i < password.length; i++) {
        password[i] = '\0';
    }
}
```

### ❌ NE PAS FAIRE

```java
// 1. NE PAS utiliser String pour les secrets
String password = "MyPassword123!"; // RESTE EN MÉMOIRE !

// 2. NE PAS oublier de fermer SecureMemory
SecureMemory sm = new SecureMemory(256);
sm.write(data);
// ... Oubli de close() → fuite de mémoire

// 3. NE PAS logger ou afficher les secrets
System.out.println("Password: " + password); // RESTE EN MÉMOIRE !
logger.info("Secret: {}", secret); // RESTE EN MÉMOIRE !

// 4. NE PAS réutiliser SecureMemory après close()
try (SecureMemory sm = new SecureMemory(256)) {
    sm.write(data);
}
sm.read(); // ERREUR : déjà fermé
```

## Limites de la Vérification

### Ce qui peut causer des faux positifs :

1. **String interning** : La JVM peut mettre en cache les String dans le pool
2. **Messages de log** : Les logs peuvent contenir des copies du secret
3. **Stack traces** : Les exceptions peuvent capturer des valeurs
4. **Garbage collector** : Les données peuvent persister jusqu'au GC
5. **JIT compilation** : Le compilateur peut créer des copies temporaires
6. **Debugger** : Les variables inspectées persistent en mémoire

### Solutions :

- **Éviter String** : Utiliser `char[]` ou `byte[]`
- **Éviter les logs** : Ne jamais logger de secrets
- **Effacer rapidement** : Zéroer les tableaux immédiatement après usage
- **Forcer le GC** : Appeler `System.gc()` (pas garanti)
- **Désactiver le JIT pour les tests** : `-Xint` (très lent)

## Outils Complémentaires

### Memory Analyzer Tool (MAT)

```bash
# Télécharger MAT : https://eclipse.dev/mat/
# Analyser un heap dump
java -jar mat/MemoryAnalyzer.jar heap.hprof
```

### GDB (pour débugger la mémoire native)

```bash
# Attacher GDB au processus
sudo gdb -p <PID>

# Chercher une chaîne en mémoire
(gdb) find /s 0x7f0000000000, 0x7fffffffffff, "MyTopSecret"

# Examiner la mémoire à une adresse
(gdb) x/100s 0x7ffff7a00000
```

## Interprétation des Résultats

| Résultat | Signification | Action |
|----------|---------------|--------|
| Secret trouvé dans heap après String | Normal | String n'est pas sécurisé, utiliser SecureMemory |
| Secret trouvé dans heap après SecureMemory.close() | **PROBLÈME** | Bug dans SecureMemory, investiguer |
| Secret NON trouvé dans heap après SecureMemory.close() | **CORRECT** | SecureMemory fonctionne correctement |
| Secret trouvé dans /proc/mem avant close() | Normal | SecureMemory est encore ouvert |
| Secret trouvé dans /proc/mem après close() | **PROBLÈME** | Le zeroing n'a pas fonctionné |

## Conclusion

Pour une sécurité maximale :

1. ✅ Utiliser `SecureMemory` pour les données sensibles
2. ✅ Toujours utiliser `try-with-resources`
3. ✅ Effacer les `byte[]` immédiatement après usage
4. ✅ Éviter `String` pour les secrets
5. ✅ Ne jamais logger ou afficher des secrets
6. ✅ Tester régulièrement avec les outils de vérification

La sécurité de la mémoire est un processus continu. Utilisez ces outils régulièrement pour vérifier qu'aucun secret ne fuite.
