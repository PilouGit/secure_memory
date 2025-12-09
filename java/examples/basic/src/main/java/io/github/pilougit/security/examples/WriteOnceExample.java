package io.github.pilougit.security.examples;

import io.github.pilougit.security.SecureMemory;

import java.nio.charset.StandardCharsets;

/**
 * Example demonstrating write-once secure memory.
 *
 * Write-once memory can only be written to once, preventing accidental or malicious
 * overwrites of sensitive data like passwords or encryption keys.
 */
public class WriteOnceExample {

    public static void main(String[] args) {
        // ✅ IMPORTANT: Register shutdown hook to cleanup TPM resources
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n🧹 Cleaning up TPM resources...");
            SecureMemory.cleanupTpm();
            System.out.println("✅ TPM cleanup completed");
        }));

        System.out.println("=== Write-Once SecureMemory Example ===\n");

        // Example 1: Normal SecureMemory (allows multiple writes)
        System.out.println("Example 1: Normal SecureMemory");
        System.out.println("--------------------------------");
        try (SecureMemory normalMemory = new SecureMemory(256)) {
            System.out.println("Write-once mode: " + normalMemory.isWriteOnce());

            // First write
            normalMemory.write("First value".getBytes(StandardCharsets.UTF_8));
            System.out.println("✓ First write successful");

            // Second write (allowed)
            normalMemory.write("Second value".getBytes(StandardCharsets.UTF_8));
            System.out.println("✓ Second write successful");

            // Read final value
            byte[] data = normalMemory.read(12);
            System.out.println("✓ Final value: " + new String(data, StandardCharsets.UTF_8));
        }

        System.out.println();

        // Example 2: Write-Once SecureMemory (only one write allowed)
        System.out.println("Example 2: Write-Once SecureMemory");
        System.out.println("-----------------------------------");
        try (SecureMemory writeOnceMemory = new SecureMemory(256, true)) {
            System.out.println("Write-once mode: " + writeOnceMemory.isWriteOnce());
            System.out.println("Has been written: " + writeOnceMemory.hasBeenWritten());

            // First write
            String password = "SuperSecretPassword123!";
            writeOnceMemory.write(password.getBytes(StandardCharsets.UTF_8));
            System.out.println("✓ First write successful");
            System.out.println("Has been written: " + writeOnceMemory.hasBeenWritten());

            // Read the password
            byte[] storedPassword = writeOnceMemory.read(password.length());
            String retrieved = new String(storedPassword, StandardCharsets.UTF_8);
            System.out.println("✓ Retrieved password: " + retrieved);

            // Try to write again (should fail)
            System.out.println("\nAttempting second write...");
            try {
                writeOnceMemory.write("Hacker trying to overwrite!".getBytes(StandardCharsets.UTF_8));
                System.out.println("✗ ERROR: Second write should have been rejected!");
            } catch (IllegalStateException e) {
                System.out.println("✓ Second write correctly rejected:");
                System.out.println("  " + e.getMessage());
            }

            // Verify original password is still intact
            byte[] stillIntact = writeOnceMemory.read(password.length());
            String stillRetrieved = new String(stillIntact, StandardCharsets.UTF_8);
            System.out.println("✓ Password still intact: " + stillRetrieved);
        }

        System.out.println();

        // Example 3: Use case - Storing encryption key
        System.out.println("Example 3: Encryption Key Storage");
        System.out.println("-----------------------------------");
        try (SecureMemory keyMemory = new SecureMemory(32, true)) {
            // Generate or load encryption key (simulated here)
            byte[] encryptionKey = new byte[32];
            for (int i = 0; i < 32; i++) {
                encryptionKey[i] = (byte) i;
            }

            // Store the key (only once!)
            keyMemory.write(encryptionKey);
            System.out.println("✓ Encryption key stored in write-once memory");

            // Read for encryption operations (can read multiple times)
            byte[] key1 = keyMemory.read(32);
            System.out.println("✓ Key read for encryption operation 1");

            byte[] key2 = keyMemory.read(32);
            System.out.println("✓ Key read for encryption operation 2");

            // Verify both reads return the same key
            boolean keysMatch = true;
            for (int i = 0; i < 32; i++) {
                if (key1[i] != key2[i]) {
                    keysMatch = false;
                    break;
                }
            }
            System.out.println("✓ Keys match: " + keysMatch);

            // Zero out the key copies after use
            for (int i = 0; i < 32; i++) {
                key1[i] = 0;
                key2[i] = 0;
            }
            System.out.println("✓ Key copies zeroed after use");
        }

        System.out.println("\n=== All examples completed successfully ===");
    }
}
