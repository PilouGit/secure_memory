package com.securememory.springboot.service;

import com.securememory.SecureMemory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;

/**
 * Service démontrant l'utilisation de SecureMemory pour les credentials de base de données.
 *
 * Au lieu de stocker le mot de passe en tant que String dans la mémoire Java (non chiffré),
 * ce service accède au mot de passe uniquement quand nécessaire via SecureMemory.
 */
@Service
public class SecureDatabaseService {

    private static final Logger log = LoggerFactory.getLogger(SecureDatabaseService.class);

    private final SecureMemory databasePassword;

    public SecureDatabaseService(@Qualifier("databasePassword") SecureMemory databasePassword) {
        this.databasePassword = databasePassword;
        log.info("SecureDatabaseService initialized with secure password");
    }

    /**
     * Simule une connexion à la base de données en utilisant le mot de passe sécurisé.
     *
     * Le mot de passe n'est déchiffré que pendant l'exécution de cette méthode,
     * puis re-chiffré immédiatement après.
     *
     * @return Message de succès
     */
    public String connectToDatabase() {
        log.info("Connecting to database...");

        try {
            // Lire le mot de passe depuis SecureMemory
            byte[] passwordBytes = databasePassword.read();
            String password = new String(passwordBytes, StandardCharsets.UTF_8).trim();

            // Simuler une connexion à la base de données
            log.info("Attempting database connection with secure credentials");

            // Dans un vrai cas, vous feriez:
            // DataSource ds = createDataSource("jdbc:mysql://localhost:3306/mydb", "user", password);
            // Connection conn = ds.getConnection();

            // Pour la démo, on masque le mot de passe
            String maskedPassword = maskPassword(password);
            log.info("✓ Database connection successful (password: {})", maskedPassword);

            return "Connected to database successfully";

        } catch (Exception e) {
            log.error("✗ Failed to connect to database", e);
            return "Failed to connect: " + e.getMessage();
        }
    }

    /**
     * Vérifie si le mot de passe correspond à une valeur donnée.
     *
     * @param testPassword Mot de passe à vérifier
     * @return true si correspond, false sinon
     */
    public boolean verifyPassword(String testPassword) {
        try {
            byte[] storedBytes = databasePassword.read();
            String storedPassword = new String(storedBytes, StandardCharsets.UTF_8).trim();

            boolean matches = storedPassword.equals(testPassword);
            log.info("Password verification: {}", matches ? "SUCCESS" : "FAILED");

            return matches;

        } catch (Exception e) {
            log.error("Error verifying password", e);
            return false;
        }
    }

    /**
     * Récupère des informations sur la sécurité du mot de passe.
     *
     * @return Informations de sécurité
     */
    public SecurityInfo getSecurityInfo() {
        return new SecurityInfo(
            databasePassword.getSize(),
            !databasePassword.isClosed(),
            "AES-256-GCM with random canaries"
        );
    }

    /**
     * Masque un mot de passe pour le logging.
     */
    private String maskPassword(String password) {
        if (password == null || password.length() == 0) {
            return "****";
        }
        if (password.length() <= 4) {
            return "****";
        }
        return password.substring(0, 2) + "****" + password.substring(password.length() - 2);
    }

    /**
     * DTO pour les informations de sécurité.
     */
    public static class SecurityInfo {
        private final long memorySize;
        private final boolean isActive;
        private final String encryptionType;

        public SecurityInfo(long memorySize, boolean isActive, String encryptionType) {
            this.memorySize = memorySize;
            this.isActive = isActive;
            this.encryptionType = encryptionType;
        }

        public long getMemorySize() {
            return memorySize;
        }

        public boolean isActive() {
            return isActive;
        }

        public String getEncryptionType() {
            return encryptionType;
        }
    }
}
