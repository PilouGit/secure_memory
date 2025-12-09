package io.github.pilougit.security.springboot.config;

import io.github.pilougit.security.SecureMemory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import jakarta.annotation.PreDestroy;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Configuration Spring Boot pour stocker les propriétés sensibles dans SecureMemory.
 *
 * Au lieu de stocker les secrets en tant que String (en clair dans le heap Java),
 * cette configuration les charge dans des instances de SecureMemory où ils sont:
 * - Chiffrés avec AES-256-GCM
 * - Protégés par des canaries contre les buffer overflows
 * - Automatiquement mis à zéro lors de la destruction
 */
@Configuration
public class SecurePropertiesConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurePropertiesConfig.class);

    // Map pour garder les références aux SecureMemory et les libérer proprement
    private final Map<String, SecureMemory> secureMemories = new HashMap<>();

    /**
     * Charge la propriété 'app.database.password' dans une SecureMemory.
     *
     * @param password Le mot de passe depuis application.properties
     * @return SecureMemory contenant le mot de passe chiffré
     */
    @Bean(name = "databasePassword")
    public SecureMemory databasePassword(@Value("${app.database.password}") String password) {
        log.info("Loading database password into SecureMemory");
        return createSecureMemory("databasePassword", password);
    }

    /**
     * Charge la propriété 'app.api.key' dans une SecureMemory.
     *
     * @param apiKey La clé API depuis application.properties
     * @return SecureMemory contenant la clé API chiffrée
     */
    @Bean(name = "apiKey")
    public SecureMemory apiKey(@Value("${app.api.key}") String apiKey) {
        log.info("Loading API key into SecureMemory");
        return createSecureMemory("apiKey", apiKey);
    }

    /**
     * Charge la propriété 'app.encryption.secret' dans une SecureMemory.
     *
     * @param secret Le secret d'encryption depuis application.properties
     * @return SecureMemory contenant le secret chiffré
     */
    @Bean(name = "encryptionSecret")
    public SecureMemory encryptionSecret(@Value("${app.encryption.secret}") String secret) {
        log.info("Loading encryption secret into SecureMemory");
        return createSecureMemory("encryptionSecret", secret);
    }

    /**
     * Méthode utilitaire pour créer une SecureMemory à partir d'une String.
     *
     * @param name Nom de la propriété (pour logging)
     * @param value Valeur à stocker
     * @return SecureMemory contenant la valeur chiffrée
     */
    private SecureMemory createSecureMemory(String name, String value) {
        try {
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);

            // Créer une SecureMemory de taille appropriée
            // Ajouter un peu d'espace supplémentaire pour flexibilité
            SecureMemory memory = new SecureMemory(bytes.length + 64);

            // Écrire la valeur dans la mémoire sécurisée
            memory.write(bytes);

            // Garder la référence pour cleanup
            secureMemories.put(name, memory);

            log.info("✓ Property '{}' loaded into SecureMemory (size: {} bytes)",
                     name, memory.getSize());

            return memory;

        } catch (Exception e) {
            log.error("✗ Failed to create SecureMemory for property '{}'", name, e);
            throw new RuntimeException("Failed to create SecureMemory for " + name, e);
        }
    }

    /**
     * Nettoyage lors de la destruction du contexte Spring.
     * Libère toutes les SecureMemory créées.
     */
    @PreDestroy
    public void cleanup() {
        log.info("Cleaning up SecureMemory instances...");

        secureMemories.forEach((name, memory) -> {
            try {
                if (!memory.isClosed()) {
                    memory.close();
                    log.info("✓ SecureMemory '{}' closed and zeroed", name);
                }
            } catch (Exception e) {
                log.error("✗ Error closing SecureMemory '{}'", name, e);
            }
        });

        secureMemories.clear();
        log.info("All SecureMemory instances cleaned up");
    }

    /**
     * Bean pour exposer des statistiques sur les SecureMemory.
     */
    @Bean
    public SecureMemoryStats secureMemoryStats() {
        return new SecureMemoryStats(secureMemories);
    }

    /**
     * Classe interne pour fournir des statistiques sur les SecureMemory.
     */
    public static class SecureMemoryStats {
        private final Map<String, SecureMemory> memories;

        public SecureMemoryStats(Map<String, SecureMemory> memories) {
            this.memories = memories;
        }

        public int getCount() {
            return memories.size();
        }

        public long getTotalSize() {
            return memories.values().stream()
                .mapToLong(SecureMemory::getSize)
                .sum();
        }

        public Map<String, Long> getSizeByProperty() {
            Map<String, Long> sizes = new HashMap<>();
            memories.forEach((name, memory) ->
                sizes.put(name, memory.getSize())
            );
            return sizes;
        }
    }
}
