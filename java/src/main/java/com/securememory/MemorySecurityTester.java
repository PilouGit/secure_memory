package com.securememory;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/**
 * Utility to verify that sensitive data has been properly erased from memory.
 *
 * This class provides tools to:
 * 1. Dump JVM heap memory to a file
 * 2. Search for sensitive strings in the heap dump
 * 3. Force garbage collection and verify cleanup
 */
public class MemorySecurityTester {

    /**
     * Search for a specific string in the JVM heap.
     * Uses jmap to dump heap and searches for the string.
     *
     * @param searchString The string to search for
     * @return true if the string was found in memory
     */
    public static boolean searchInHeap(String searchString) throws Exception {
        // Get the PID of the current JVM process
        String pid = getPID();
        System.out.println("JVM PID: " + pid);

        // Create a heap dump file
        File heapDumpFile = File.createTempFile("heap_dump_", ".hprof");
        heapDumpFile.deleteOnExit();

        System.out.println("Creating heap dump: " + heapDumpFile.getAbsolutePath());

        // Use jmap to create a heap dump
        ProcessBuilder pb = new ProcessBuilder(
            "jmap",
            "-dump:format=b,file=" + heapDumpFile.getAbsolutePath(),
            pid
        );

        Process process = pb.start();
        int exitCode = process.waitFor();

        if (exitCode != 0) {
            System.err.println("jmap failed with exit code: " + exitCode);
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream())
            );
            String line;
            while ((line = errorReader.readLine()) != null) {
                System.err.println(line);
            }
            throw new RuntimeException("Failed to create heap dump");
        }

        System.out.println("Heap dump created: " + heapDumpFile.length() + " bytes");

        // Search for the string in the heap dump
        boolean found = searchInFile(heapDumpFile, searchString);

        // Clean up
        heapDumpFile.delete();

        return found;
    }

    /**
     * Search for a string in a binary file.
     */
    private static boolean searchInFile(File file, String searchString) throws Exception {
        byte[] searchBytes = searchString.getBytes(StandardCharsets.UTF_8);
        byte[] fileBytes = Files.readAllBytes(file.toPath());

        System.out.println("Searching for '" + searchString + "' in " + fileBytes.length + " bytes");

        // Simple Boyer-Moore style search
        for (int i = 0; i <= fileBytes.length - searchBytes.length; i++) {
            boolean match = true;
            for (int j = 0; j < searchBytes.length; j++) {
                if (fileBytes[i + j] != searchBytes[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                System.out.println("Found at offset: " + i);
                return true;
            }
        }

        return false;
    }

    /**
     * Get the PID of the current JVM process.
     */
    private static String getPID() {
        String jvmName = ManagementFactory.getRuntimeMXBean().getName();
        return jvmName.split("@")[0];
    }

    /**
     * Force garbage collection multiple times.
     */
    public static void forceGC() {
        System.out.println("Forcing garbage collection...");
        for (int i = 0; i < 5; i++) {
            System.gc();
            System.runFinalization();
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        System.out.println("Garbage collection completed");
    }

    /**
     * Test that demonstrates searching for a secret in memory.
     */
    public static void main(String[] args) throws Exception {
        String secret = "SuperSecretPassword123!";

        System.out.println("=== Memory Security Test ===\n");

        // Test 1: Verify that a normal String persists in memory
        System.out.println("Test 1: Normal String (should persist in memory)");
        System.out.println("--------------------------------------------------");
        String normalString = new String(secret); // Create a copy
        System.out.println("Created normal String: " + normalString);

        forceGC();

        boolean foundNormal = searchInHeap(secret);
        System.out.println("Result: Secret " + (foundNormal ? "FOUND" : "NOT FOUND") + " in heap");
        System.out.println("Expected: FOUND (normal strings persist in memory)\n");

        // Test 2: Verify that SecureMemory does NOT persist in memory
        System.out.println("Test 2: SecureMemory (should NOT persist in memory)");
        System.out.println("-----------------------------------------------------");

        // Use SecureMemory
        try (SecureMemory sm = new SecureMemory(256)) {
            sm.write(secret.getBytes(StandardCharsets.UTF_8));
            byte[] data = sm.read();
            String retrieved = new String(data, StandardCharsets.UTF_8);
            System.out.println("Retrieved from SecureMemory: " + retrieved);

            // Zero the byte array manually
            for (int i = 0; i < data.length; i++) {
                data[i] = 0;
            }
        } // SecureMemory is freed here

        // Clear the normal string reference
        normalString = null;

        forceGC();

        boolean foundSecure = searchInHeap(secret);
        System.out.println("Result: Secret " + (foundSecure ? "FOUND" : "NOT FOUND") + " in heap");
        System.out.println("Expected: NOT FOUND (SecureMemory zeros data on close)\n");

        // Test 3: Using /proc/[pid]/mem on Linux (if available)
        if (System.getProperty("os.name").toLowerCase().contains("linux")) {
            System.out.println("Test 3: Searching in process memory (/proc/[pid]/mem)");
            System.out.println("--------------------------------------------------------");
            searchInProcessMemory(secret);
        }

        System.out.println("\n=== Test completed ===");
    }

    /**
     * Search for a string in the process memory using /proc/[pid]/maps and /proc/[pid]/mem.
     * This is Linux-specific and requires appropriate permissions.
     */
    private static void searchInProcessMemory(String searchString) throws Exception {
        String pid = getPID();
        File mapsFile = new File("/proc/" + pid + "/maps");

        if (!mapsFile.exists()) {
            System.out.println("Cannot access /proc/" + pid + "/maps (not Linux or insufficient permissions)");
            return;
        }

        System.out.println("Process memory maps available at: " + mapsFile.getAbsolutePath());
        System.out.println("Note: Searching process memory requires root permissions");
        System.out.println("To search manually, run as root:");
        System.out.println("  sudo cat /proc/" + pid + "/mem | strings | grep '" + searchString + "'");
        System.out.println("Or use tools like 'gcore' to create a core dump:");
        System.out.println("  sudo gcore " + pid);
        System.out.println("  strings core." + pid + " | grep '" + searchString + "'");
    }
}
