package io.github.pilougit.security.examples;

import io.github.pilougit.security.SecureMemory;

import java.nio.charset.StandardCharsets;

/**
 * Demonstration of memory leak detection.
 *
 * This program keeps running to allow external inspection of memory.
 * Use external tools to verify that secrets are properly cleared.
 *
 * External tools you can use:
 * 1. jmap - Create heap dumps
 * 2. VisualVM - Monitor and analyze JVM memory
 * 3. gcore - Create core dumps (Linux)
 * 4. strings - Search for strings in dumps
 */
public class MemoryLeakDemo {

    public static void main(String[] args) throws Exception {
        // ✅ IMPORTANT: Register shutdown hook to cleanup TPM resources
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n🧹 Cleaning up TPM resources...");
            SecureMemory.cleanupTpm();
            System.out.println("✅ TPM cleanup completed");
        }));

        String secret = "MyTopSecretPassword@2025!";

        System.out.println("=== Memory Leak Detection Demo ===");
        System.out.println("PID: " + ProcessHandle.current().pid());
        System.out.println("\nThis demo will:");
        System.out.println("1. Store a secret using a normal String");
        System.out.println("2. Store the same secret using SecureMemory");
        System.out.println("3. Keep running so you can inspect memory");
        System.out.println("\nSecret to search for: " + secret);
        System.out.println("\n" + "=".repeat(60));

        // Phase 1: Normal String (INSECURE - will leak in memory)
        System.out.println("\n[Phase 1] Using normal String (INSECURE)");
        System.out.println("-".repeat(60));
        String normalString = new String(secret);
        System.out.println("Created normal String: " + normalString);
        System.out.println("Waiting 5 seconds...");
        Thread.sleep(5000);

        // Phase 2: SecureMemory (SECURE - will be zeroed)
        System.out.println("\n[Phase 2] Using SecureMemory (SECURE)");
        System.out.println("-".repeat(60));

        try (SecureMemory sm = new SecureMemory(256)) {
            sm.write(secret.getBytes(StandardCharsets.UTF_8));
            byte[] data = sm.read();
            String retrieved = new String(data, StandardCharsets.UTF_8);
            System.out.println("Stored in SecureMemory: " + retrieved);

            // Zero the byte array
            for (int i = 0; i < data.length; i++) {
                data[i] = 0;
            }
            data = null;
        }

        System.out.println("SecureMemory closed and zeroed");

        // Phase 3: Clear normal string
        System.out.println("\n[Phase 3] Clearing normal String");
        System.out.println("-".repeat(60));
        normalString = null;
        System.gc();
        System.runFinalization();
        System.out.println("Normal String reference cleared (but may still be in memory)");

        // Phase 4: Keep running for inspection
        System.out.println("\n[Phase 4] Ready for memory inspection");
        System.out.println("-".repeat(60));
        System.out.println("\nProcess will keep running for 60 seconds.");
        System.out.println("Use the following commands to inspect memory:\n");

        long pid = ProcessHandle.current().pid();

        System.out.println("1. Create heap dump:");
        System.out.println("   jmap -dump:format=b,file=heap.hprof " + pid);
        System.out.println("   strings heap.hprof | grep '" + secret + "'");

        System.out.println("\n2. Use VisualVM (GUI):");
        System.out.println("   jvisualvm");
        System.out.println("   Then attach to PID " + pid + " and create heap dump");

        System.out.println("\n3. Create core dump (Linux, requires root):");
        System.out.println("   sudo gcore " + pid);
        System.out.println("   strings core." + pid + " | grep '" + secret + "'");

        System.out.println("\n4. Search process memory (Linux, requires root):");
        System.out.println("   sudo grep -a '" + secret + "' /proc/" + pid + "/mem 2>/dev/null && echo 'FOUND' || echo 'NOT FOUND'");

        System.out.println("\n" + "=".repeat(60));
        System.out.println("Waiting 60 seconds for inspection...");

        for (int i = 60; i > 0; i--) {
            System.out.print("\rTime remaining: " + i + " seconds ");
            Thread.sleep(1000);
        }

        System.out.println("\n\nDemo completed.");
    }
}
