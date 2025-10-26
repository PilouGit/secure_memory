package io.github.pilougit.security;

import com.sun.jna.Pointer;
import java.lang.ref.Cleaner;
import java.util.Arrays;

/**
 * Java wrapper for the Rust SecureMemory library.
 *
 * This class provides a safe, object-oriented interface to the secure memory functionality.
 *
 * Features:
 * - AES-256-GCM encryption at rest
 * - Buffer overflow protection with random canaries
 * - Automatic memory zeroing on close
 * - Thread-safe operations
 *
 * Example usage:
 * <pre>{@code
 * try (SecureMemory memory = new SecureMemory(1024)) {
 *     byte[] data = "sensitive data".getBytes();
 *     memory.write(data);
 *
 *     byte[] read = memory.read();
 *     System.out.println(new String(read));
 * } // Automatically freed and zeroed here
 * }</pre>
 */
public class SecureMemory implements AutoCloseable {

    // ✅ JAVA 9+: Cleaner API remplace finalize() déprécié
    private static final Cleaner CLEANER = Cleaner.create();

    private Pointer handle;
    private final long size;
    private boolean closed = false;
    private final boolean writeOnce;
    private boolean hasBeenWritten = false;
    private final Cleaner.Cleanable cleanable;

    /**
     * Cleanup action for Cleaner API.
     * This runs when the object is garbage collected as a fallback if close() wasn't called.
     */
    private static class CleanupAction implements Runnable {
        private final Pointer handle;

        CleanupAction(Pointer handle) {
            this.handle = handle;
        }

        @Override
        public void run() {
            if (handle != null) {
                // Fallback cleanup si close() n'a pas été appelé
                SecureMemoryNative.INSTANCE.secure_memory_free(handle);
            }
        }
    }

    /**
     * Create a new SecureMemory instance (write_once = false).
     *
     * @param size Size of the secure memory buffer in bytes (must be > 0)
     * @throws IllegalArgumentException if size is <= 0
     * @throws SecureMemoryException if allocation fails
     */
    public SecureMemory(long size) {
        this(size, false);
    }

    /**
     * Create a new SecureMemory instance with options.
     *
     * @param size Size of the secure memory buffer in bytes (must be > 0)
     * @param writeOnce If true, the memory can only be written once. Subsequent writes will fail.
     * @throws IllegalArgumentException if size is <= 0
     * @throws SecureMemoryException if allocation fails
     */
    public SecureMemory(long size, boolean writeOnce) {
        if (size <= 0) {
            throw new IllegalArgumentException("Size must be greater than 0");
        }

        this.writeOnce = writeOnce;
        this.handle = SecureMemoryNative.INSTANCE.secure_memory_new_with_options(size, (byte)(writeOnce ? 1 : 0));
        if (this.handle == null) {
            throw new SecureMemoryException("Failed to allocate secure memory");
        }

        this.size = size;

        // ✅ JAVA 9+: Enregistrer le cleaner comme fallback si close() n'est pas appelé
        // Note: try-with-resources est toujours recommandé, ceci est juste un filet de sécurité
        this.cleanable = CLEANER.register(this, new CleanupAction(handle));
    }

    /**
     * Check if this SecureMemory is write-once.
     *
     * @return true if this memory can only be written once
     */
    public boolean isWriteOnce() {
        return writeOnce;
    }

    /**
     * Check if this SecureMemory has been written to.
     *
     * @return true if write() has been called at least once
     */
    public boolean hasBeenWritten() {
        return hasBeenWritten;
    }

    /**
     * Write data to the secure memory.
     *
     * If the data is smaller than the buffer, the remaining bytes are zeroed.
     * If the data is larger than the buffer, it will be truncated.
     *
     * @param data Data to write
     * @throws IllegalStateException if the memory has been closed or if write-once memory has already been written
     * @throws SecureMemoryException if the write operation fails
     * @throws SecurityException if canary corruption is detected
     */
    public void write(byte[] data) {
        checkNotClosed();

        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data cannot be null or empty");
        }

        int result = SecureMemoryNative.INSTANCE.secure_memory_write(handle, data, data.length);
        handleResult(result, "write");

        // Si l'écriture a réussi, marquer comme écrit
        hasBeenWritten = true;
    }

    /**
     * Read data from the secure memory.
     *
     * @return Copy of the decrypted data
     * @throws IllegalStateException if the memory has been closed
     * @throws SecureMemoryException if the read operation fails
     * @throws SecurityException if canary corruption is detected
     */
    public byte[] read() {
        checkNotClosed();

        byte[] buffer = new byte[(int) size];
        int result = SecureMemoryNative.INSTANCE.secure_memory_read(handle, buffer, size);
        handleResult(result, "read");

        return buffer;
    }

    /**
     * Read a portion of the secure memory.
     *
     * @param length Number of bytes to read (must be <= size)
     * @return Copy of the decrypted data (may be zero-padded if length > actual data)
     * @throws IllegalArgumentException if length is invalid
     * @throws IllegalStateException if the memory has been closed
     * @throws SecureMemoryException if the read operation fails
     * @throws SecurityException if canary corruption is detected
     */
    public byte[] read(int length) {
        checkNotClosed();

        if (length <= 0 || length > size) {
            throw new IllegalArgumentException("Length must be between 1 and " + size);
        }

        byte[] buffer = new byte[length];
        int result = SecureMemoryNative.INSTANCE.secure_memory_read(handle, buffer, length);
        handleResult(result, "read");

        return buffer;
    }

    /**
     * Get the size of the secure memory buffer.
     *
     * @return Size in bytes
     */
    public long getSize() {
        return size;
    }

    /**
     * Check if this SecureMemory has been closed.
     *
     * @return true if closed, false otherwise
     */
    public boolean isClosed() {
        return closed;
    }

    /**
     * Free the secure memory and zero all data.
     *
     * This method is idempotent - calling it multiple times is safe.
     * After close(), the Cleaner will not run (it's automatically deregistered).
     */
    @Override
    public void close() {
        if (!closed && handle != null) {
            // Désenregistrer le cleaner (cleanup explicite)
            cleanable.clean();
            handle = null;
            closed = true;
        }
    }

    /**
     * Handle the result code from native operations.
     *
     * @param result Result code from native function
     * @param operation Name of the operation (for error messages)
     * @throws SecureMemoryException if result indicates an error
     * @throws SecurityException if canary corruption is detected
     */
    private void handleResult(int result, String operation) {
        switch (result) {
            case 0:
                // Success
                return;
            case -1:
                throw new SecureMemoryException("Invalid parameters for " + operation + " operation");
            case -2:
                throw new SecurityException(
                    "SECURITY VIOLATION: Buffer overflow detected during " + operation +
                    "! Canaries have been corrupted."
                );
            case -3:
                throw new IllegalStateException(
                    "SECURITY VIOLATION: Attempted to write to write-once memory that has already been written!"
                );
            default:
                throw new SecureMemoryException("Unknown error during " + operation + ": " + result);
        }
    }

    /**
     * Cleanup TPM resources.
     *
     * <p>This static method should be called when the application is shutting down
     * to properly clean up TPM resources and flush all keys.</p>
     *
     * <p><b>IMPORTANT</b>: This must be called before the JVM exits to ensure
     * proper cleanup of TPM handles and sessions. It's recommended to call this
     * in a shutdown hook or in a finally block of your main method.</p>
     *
     * <p>Example usage:</p>
     * <pre>{@code
     * public static void main(String[] args) {
     *     // Register shutdown hook
     *     Runtime.getRuntime().addShutdownHook(new Thread(() -> {
     *         SecureMemory.cleanupTpm();
     *     }));
     *
     *     // Your application code...
     * }
     * }</pre>
     *
     * <p>Thread-safe but should only be called once during application shutdown.</p>
     */
    public static void cleanupTpm() {
        SecureMemoryNative.INSTANCE.secure_memory_cleanup_tpm();
    }

    /**
     * Check if the memory has been closed and throw if it has.
     *
     * @throws IllegalStateException if closed
     */
    private void checkNotClosed() {
        if (closed) {
            throw new IllegalStateException("SecureMemory has been closed");
        }
    }

    /**
     * Exception thrown when secure memory operations fail.
     */
    public static class SecureMemoryException extends RuntimeException {
        public SecureMemoryException(String message) {
            super(message);
        }

        public SecureMemoryException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
