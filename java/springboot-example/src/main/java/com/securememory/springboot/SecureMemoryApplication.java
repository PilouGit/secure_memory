package com.securememory.springboot;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

/**
 * Application Spring Boot démontrant l'utilisation de SecureMemory pour les propriétés sensibles.
 *
 * Cette application montre comment stocker des secrets (mots de passe, clés API, etc.)
 * de manière sécurisée en utilisant SecureMemory au lieu de String Java.
 *
 * Avantages:
 * - Les secrets sont chiffrés avec AES-256-GCM quand non utilisés
 * - Protection contre les buffer overflows avec canaries aléatoires
 * - Zeroing automatique de la mémoire lors de la destruction
 * - Détection de corruption mémoire
 *
 * Pour lancer:
 * 1. Compiler la bibliothèque Rust: cargo build --release --lib
 * 2. Définir LD_LIBRARY_PATH: export LD_LIBRARY_PATH=../../target/release:$LD_LIBRARY_PATH
 * 3. Lancer l'application: mvn spring-boot:run
 */
@SpringBootApplication
public class SecureMemoryApplication {

    private static final Logger log = LoggerFactory.getLogger(SecureMemoryApplication.class);

    public static void main(String[] args) {
        // Banner de démarrage
        printBanner();

        // Lancer l'application Spring Boot
        SpringApplication.run(SecureMemoryApplication.class, args);
    }

    /**
     * CommandLineRunner pour afficher des informations au démarrage.
     */
    @Bean
    public CommandLineRunner startup() {
        return args -> {
            log.info("═══════════════════════════════════════════════════════════");
            log.info("✓ SecureMemory Spring Boot Application Started");
            log.info("═══════════════════════════════════════════════════════════");
            log.info("");
            log.info("🔒 Security Features:");
            log.info("   • Properties stored in encrypted memory (AES-256-GCM)");
            log.info("   • Random canaries for buffer overflow detection");
            log.info("   • Automatic memory zeroing on shutdown");
            log.info("");
            log.info("📡 Available Endpoints:");
            log.info("   GET  http://localhost:8080/api/secure/status");
            log.info("   GET  http://localhost:8080/api/secure/info");
            log.info("   GET  http://localhost:8080/api/secure/health");
            log.info("   POST http://localhost:8080/api/secure/database/connect");
            log.info("   POST http://localhost:8080/api/secure/database/verify");
            log.info("   POST http://localhost:8080/api/secure/api/call");
            log.info("");
            log.info("💡 Try:");
            log.info("   curl http://localhost:8080/api/secure/status");
            log.info("   curl -X POST http://localhost:8080/api/secure/database/connect");
            log.info("");
            log.info("═══════════════════════════════════════════════════════════");
        };
    }

    /**
     * Affiche le banner de démarrage.
     */
    private static void printBanner() {
        System.out.println();
        System.out.println("╔═══════════════════════════════════════════════════════════╗");
        System.out.println("║                                                           ║");
        System.out.println("║         SecureMemory Spring Boot Example                 ║");
        System.out.println("║                                                           ║");
        System.out.println("║   Storing sensitive properties in encrypted memory       ║");
        System.out.println("║   instead of plain Java Strings                          ║");
        System.out.println("║                                                           ║");
        System.out.println("╚═══════════════════════════════════════════════════════════╝");
        System.out.println();
    }
}
