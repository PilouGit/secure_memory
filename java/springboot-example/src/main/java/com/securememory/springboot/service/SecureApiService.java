package com.securememory.springboot.service;

import com.securememory.SecureMemory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;

/**
 * Service utilisant une clé API stockée de manière sécurisée.
 */
@Service
public class SecureApiService {

    private static final Logger log = LoggerFactory.getLogger(SecureApiService.class);

    private final SecureMemory apiKey;

    public SecureApiService(@Qualifier("apiKey") SecureMemory apiKey) {
        this.apiKey = apiKey;
        log.info("SecureApiService initialized with secure API key");
    }

    /**
     * Effectue un appel API avec la clé sécurisée.
     *
     * @param endpoint L'endpoint à appeler
     * @return Résultat de l'appel
     */
    public String callExternalApi(String endpoint) {
        log.info("Calling external API: {}", endpoint);

        try {
            // Récupérer la clé API de manière sécurisée
            byte[] keyBytes = apiKey.read();
            String key = new String(keyBytes, StandardCharsets.UTF_8).trim();

            // Simuler un appel API
            log.info("Making API request to {} with secure key (length: {})", endpoint, key.length());

            // Dans un vrai cas:
            // RestTemplate restTemplate = new RestTemplate();
            // HttpHeaders headers = new HttpHeaders();
            // headers.set("X-API-Key", key);
            // HttpEntity<String> entity = new HttpEntity<>(headers);
            // ResponseEntity<String> response = restTemplate.exchange(endpoint, HttpMethod.GET, entity, String.class);

            return String.format("API call to %s successful (key length: %d)", endpoint, key.length());

        } catch (Exception e) {
            log.error("Failed to call external API", e);
            return "API call failed: " + e.getMessage();
        }
    }

    /**
     * Retourne une version masquée de la clé API pour affichage.
     *
     * @return Clé API masquée
     */
    public String getMaskedApiKey() {
        try {
            byte[] keyBytes = apiKey.read();
            String key = new String(keyBytes, StandardCharsets.UTF_8).trim();

            if (key.length() <= 8) {
                return "********";
            }

            return key.substring(0, 4) + "..." + key.substring(key.length() - 4);

        } catch (Exception e) {
            log.error("Failed to read API key", e);
            return "ERROR";
        }
    }
}
