package io.github.pilougit.security;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

/**
 * JNA bindings for the secure_memory Rust library.
 *
 * This interface maps directly to the C FFI functions exposed by the Rust library.
 * The native library is automatically loaded from the JAR by JNA.
 *
 * @see <a href="https://github.com/java-native-access/jna">JNA Documentation</a>
 */
public interface SecureMemoryNative extends Library {

    /**
     * Load the native library.
     * JNA automatically extracts and loads the library from the JAR.
     * The library name should be "secure_memory" (without lib prefix or .so/.dll extension)
     */
    SecureMemoryNative INSTANCE = Native.load("secure_memory", SecureMemoryNative.class);

    /**
     * Create a new SecureMemory instance with default options (write_once = false).
     *
     * @param size Size of the secure memory buffer in bytes (must be > 0)
     * @return Opaque handle to SecureMemory, or null on failure
     */
    Pointer secure_memory_new(long size);

    /**
     * Create a new SecureMemory instance with options.
     *
     * @param size Size of the secure memory buffer in bytes (must be > 0)
     * @param writeOnce If non-zero (true), the memory can only be written once. Subsequent writes will fail.
     * @return Opaque handle to SecureMemory, or null on failure
     */
    Pointer secure_memory_new_with_options(long size, byte writeOnce);

    /**
     * Free a SecureMemory instance.
     *
     * This will:
     * - Check canaries for corruption
     * - Zero all memory
     * - Free the allocation
     *
     * @param handle Handle returned by secure_memory_new (must not be null)
     */
    void secure_memory_free(Pointer handle);

    /**
     * Read data from SecureMemory into a buffer.
     *
     * @param handle Valid SecureMemory handle
     * @param buffer Output buffer to receive the data
     * @param bufferLen Length of the output buffer
     * @return 0 on success, -1 on invalid parameters, -2 on canary corruption
     */
    int secure_memory_read(Pointer handle, byte[] buffer, long bufferLen);

    /**
     * Write data to SecureMemory from a buffer.
     *
     * @param handle Valid SecureMemory handle
     * @param buffer Input buffer containing data to write
     * @param bufferLen Length of the input buffer
     * @return 0 on success, -1 on invalid parameters, -2 on canary corruption
     */
    int secure_memory_write(Pointer handle, byte[] buffer, long bufferLen);

    /**
     * Get the size of the SecureMemory buffer.
     *
     * @param handle Valid SecureMemory handle
     * @return Size in bytes, or 0 if handle is null
     */
    long secure_memory_size(Pointer handle);

    /**
     * Cleanup TPM resources.
     *
     * This function should be called when the application is shutting down
     * to properly clean up TPM resources and flush all keys.
     *
     * <p><b>IMPORTANT</b>: This must be called before the JVM exits to ensure
     * proper cleanup of TPM handles and sessions.</p>
     *
     * <p>Thread-safe but should only be called once during application shutdown.</p>
     */
    void secure_memory_cleanup_tpm();
}
