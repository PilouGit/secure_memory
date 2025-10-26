package io.github.pilougit.security.springboot.controller;

import io.github.pilougit.security.springboot.config.SecurePropertiesConfig;
import io.github.pilougit.security.springboot.service.SecureApiService;
import io.github.pilougit.security.springboot.service.SecureDatabaseService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * Contrôleur REST démontrant l'utilisation de SecureMemory dans une application Spring Boot.
 */
@RestController
@RequestMapping("/api/secure")
public class SecureMemoryController {

    private final SecureDatabaseService databaseService;
    private final SecureApiService apiService;
    private final SecurePropertiesConfig.SecureMemoryStats stats;

    public SecureMemoryController(
            SecureDatabaseService databaseService,
            SecureApiService apiService,
            SecurePropertiesConfig.SecureMemoryStats stats) {
        this.databaseService = databaseService;
        this.apiService = apiService;
        this.stats = stats;
    }

    /**
     * GET /api/secure/status
     * Retourne l'état de SecureMemory.
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("secureMemoryCount", stats.getCount());
        status.put("totalMemorySize", stats.getTotalSize());
        status.put("sizeByProperty", stats.getSizeByProperty());
        status.put("message", "All properties are encrypted with AES-256-GCM");

        return ResponseEntity.ok(status);
    }

    /**
     * POST /api/secure/database/connect
     * Teste la connexion à la base de données avec credentials sécurisés.
     */
    @PostMapping("/database/connect")
    public ResponseEntity<Map<String, Object>> connectToDatabase() {
        String result = databaseService.connectToDatabase();
        SecureDatabaseService.SecurityInfo securityInfo = databaseService.getSecurityInfo();

        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("message", result);
        response.put("security", Map.of(
            "memorySize", securityInfo.getMemorySize(),
            "isActive", securityInfo.isActive(),
            "encryptionType", securityInfo.getEncryptionType()
        ));

        return ResponseEntity.ok(response);
    }

    /**
     * POST /api/secure/database/verify
     * Vérifie un mot de passe (pour demo uniquement).
     */
    @PostMapping("/database/verify")
    public ResponseEntity<Map<String, Object>> verifyPassword(@RequestBody Map<String, String> request) {
        String testPassword = request.get("password");

        if (testPassword == null || testPassword.isEmpty()) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Password is required"));
        }

        boolean isValid = databaseService.verifyPassword(testPassword);

        Map<String, Object> response = new HashMap<>();
        response.put("valid", isValid);
        response.put("message", isValid ? "Password matches" : "Password does not match");

        return ResponseEntity.ok(response);
    }

    /**
     * POST /api/secure/api/call
     * Effectue un appel API externe avec clé sécurisée.
     */
    @PostMapping("/api/call")
    public ResponseEntity<Map<String, Object>> callExternalApi(@RequestBody Map<String, String> request) {
        String endpoint = request.getOrDefault("endpoint", "https://api.example.com/data");

        String result = apiService.callExternalApi(endpoint);
        String maskedKey = apiService.getMaskedApiKey();

        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("result", result);
        response.put("apiKeyPreview", maskedKey);

        return ResponseEntity.ok(response);
    }

    /**
     * GET /api/secure/info
     * Retourne des informations générales sur la sécurité.
     */
    @GetMapping("/info")
    public ResponseEntity<Map<String, Object>> getSecurityInfo() {
        Map<String, Object> info = new HashMap<>();
        info.put("title", "SecureMemory Spring Boot Example");
        info.put("description", "Properties stored in encrypted memory instead of plain String");
        info.put("features", new String[]{
            "AES-256-GCM encryption at rest",
            "Random canary protection",
            "Automatic memory zeroing",
            "Buffer overflow detection"
        });
        info.put("overhead", "44 bytes per allocation");
        info.put("statistics", Map.of(
            "propertiesCount", stats.getCount(),
            "totalSize", stats.getTotalSize() + " bytes"
        ));

        return ResponseEntity.ok(info);
    }

    /**
     * GET /api/secure/health
     * Health check endpoint.
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> healthCheck() {
        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "secureMemory", "operational"
        ));
    }
}
