package io.github.pilougit.security;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Example demonstrating how to use the SecureMemory library from Java.
 */
public class Example {

    public static void main(String[] args) {
        // ✅ IMPORTANT: Register shutdown hook to cleanup TPM resources
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n🧹 Cleaning up TPM resources...");
            SecureMemory.cleanupTpm();
            System.out.println("✅ TPM cleanup completed");
        }));

        System.out.println("=== SecureMemory Java Example ===\n");

        example1_BasicUsage();
        example2_TryWithResources();
        example3_MultipleOperations();
        example4_ErrorHandling();

        System.out.println("\n=== All examples completed successfully ===");
    }

    /**
     * Example 1: Basic usage with explicit close()
     */
    private static void example1_BasicUsage() {
        System.out.println("Example 1: Basic Usage");
        System.out.println("----------------------");

        SecureMemory memory = new SecureMemory(256);
        try {
            // Write some sensitive data
            String secret = "My secret password: P@ssw0rd123!";
            memory.write(secret.getBytes(StandardCharsets.UTF_8));
            System.out.println("✓ Written: " + secret);

            // Read it back
            byte[] data = memory.read();
            String retrieved = new String(data, 0, secret.length(), StandardCharsets.UTF_8);
            System.out.println("✓ Read back: " + retrieved);

            System.out.println("✓ Buffer size: " + memory.getSize() + " bytes");
        } finally {
            memory.close();
            System.out.println("✓ Memory freed and zeroed");
        }

        System.out.println();
    }

    /**
     * Example 2: Using try-with-resources (recommended)
     */
    private static void example2_TryWithResources() {
        System.out.println("Example 2: Try-with-resources");
        System.out.println("-----------------------------");

        try (SecureMemory memory = new SecureMemory(128)) {
            byte[] credentials = "username:password".getBytes(StandardCharsets.UTF_8);
            memory.write(credentials);
            System.out.println("✓ Stored credentials securely");

            byte[] retrieved = memory.read(credentials.length);
            System.out.println("✓ Retrieved: " + new String(retrieved, StandardCharsets.UTF_8));

            // Memory is automatically freed when exiting this block
            System.out.println("✓ Memory will be automatically freed");
        } catch (Exception e) {
            System.err.println("✗ Error: " + e.getMessage());
        }

        System.out.println();
    }

    /**
     * Example 3: Multiple write/read operations
     */
    private static void example3_MultipleOperations() {
        System.out.println("Example 3: Multiple Operations");
        System.out.println("------------------------------");

        try (SecureMemory memory = new SecureMemory(1024)) {
            // Write multiple times
            for (int i = 1; i <= 3; i++) {
                String data = "Iteration " + i + ": Some sensitive data";
                memory.write(data.getBytes(StandardCharsets.UTF_8));
                System.out.println("✓ Write " + i + " completed");

                // Read back
                byte[] read = memory.read(data.length());
                String retrieved = new String(read, StandardCharsets.UTF_8);
                System.out.println("  Read: " + retrieved);
            }
        }

        System.out.println();
    }

    /**
     * Example 4: Error handling
     */
    private static void example4_ErrorHandling() {
        System.out.println("Example 4: Error Handling");
        System.out.println("-------------------------");

        // Test 1: Invalid size
        try {
            new SecureMemory(0);
            System.out.println("✗ Should have thrown exception for size 0");
        } catch (IllegalArgumentException e) {
            System.out.println("✓ Correctly rejected size 0: " + e.getMessage());
        }

        // Test 2: Using closed memory
        try (SecureMemory memory = new SecureMemory(64)) {
            memory.write("test".getBytes(StandardCharsets.UTF_8));
            memory.close(); // Explicitly close

            // Try to use after close
            try {
                memory.write("this should fail".getBytes(StandardCharsets.UTF_8));
                System.out.println("✗ Should have thrown exception for closed memory");
            } catch (IllegalStateException e) {
                System.out.println("✓ Correctly rejected operation on closed memory: " + e.getMessage());
            }
        }

        // Test 3: Null/empty data
        try (SecureMemory memory = new SecureMemory(64)) {
            try {
                memory.write(null);
                System.out.println("✗ Should have thrown exception for null data");
            } catch (IllegalArgumentException e) {
                System.out.println("✓ Correctly rejected null data: " + e.getMessage());
            }
        }

        System.out.println();
    }
}
