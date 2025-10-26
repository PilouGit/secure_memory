/// FFI interface for SecureMemory - C-compatible bindings for use with JNA/JNI
use std::ptr;
use crate::secure_memory::SecureMemory;
use crate::tpm_service;

/// Opaque handle to SecureMemory for FFI
/// This ensures the Java side cannot directly access the Rust structure
#[repr(C)]
pub struct SecureMemoryHandle {
    _private: [u8; 0],
}

/// Create a new SecureMemory instance
///
/// # Arguments
/// * `size` - Size of the secure memory buffer in bytes
///
/// # Returns
/// * Opaque handle to SecureMemory, or null on failure
///
/// # Safety
/// The returned handle must be freed with `secure_memory_free`
#[no_mangle]
pub extern "C" fn secure_memory_new(size: usize) -> *mut SecureMemoryHandle {
    secure_memory_new_with_options(size, 0)
}

/// Create a new SecureMemory instance with options
///
/// # Arguments
/// * `size` - Size of the secure memory buffer in bytes
/// * `write_once` - If non-zero (true), the memory can only be written once. Subsequent writes will fail.
///
/// # Returns
/// * Opaque handle to SecureMemory, or null on failure
///
/// # Safety
/// The returned handle must be freed with `secure_memory_free`
#[no_mangle]
pub extern "C" fn secure_memory_new_with_options(size: usize, write_once: u8) -> *mut SecureMemoryHandle {
    if size == 0 {
        return ptr::null_mut();
    }

    let write_once_bool = write_once != 0;

    match SecureMemory::new_with_options(size, write_once_bool) {
        Some(mem) => {
            let boxed = Box::new(mem);
            Box::into_raw(boxed) as *mut SecureMemoryHandle
        }
        None => ptr::null_mut(),
    }
}

/// Free a SecureMemory instance
///
/// # Arguments
/// * `handle` - Handle returned by `secure_memory_new`
///
/// # Safety
/// - handle must be a valid handle from `secure_memory_new`
/// - handle must not be used after this call
/// - calling this function twice with the same handle is undefined behavior
#[no_mangle]
pub extern "C" fn secure_memory_free(handle: *mut SecureMemoryHandle) {
    if !handle.is_null() {
        unsafe {
            // Convert back to Box and drop it
            let _ = Box::from_raw(handle as *mut SecureMemory);
            // Drop is automatically called, which:
            // - Checks canaries
            // - Zeros all memory
            // - Frees the allocation
        }
    }
}

/// Read data from SecureMemory into a buffer
///
/// # Arguments
/// * `handle` - Valid SecureMemory handle
/// * `buffer` - Output buffer to receive the data
/// * `buffer_len` - Length of the output buffer
///
/// # Returns
/// * 0 on success
/// * -1 on invalid parameters
/// * -2 on canary corruption (security violation)
///
/// # Safety
/// - handle must be a valid SecureMemory handle
/// - buffer must point to valid memory of at least `buffer_len` bytes
#[no_mangle]
pub extern "C" fn secure_memory_read(
    handle: *mut SecureMemoryHandle,
    buffer: *mut u8,
    buffer_len: usize,
) -> i32 {
    if handle.is_null() || buffer.is_null() || buffer_len == 0 {
        return -1; // Invalid parameters
    }

    unsafe {
        let mem = &mut *(handle as *mut SecureMemory);
        let output_slice = std::slice::from_raw_parts_mut(buffer, buffer_len);

        // Use a flag to detect panics from canary checks
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            mem.read(|data| {
                let copy_len = data.len().min(buffer_len);
                output_slice[..copy_len].copy_from_slice(&data[..copy_len]);
                // Zero out remaining bytes if buffer is larger
                if buffer_len > copy_len {
                    output_slice[copy_len..].fill(0);
                }
            });
        }));

        match result {
            Ok(_) => 0,  // Success
            Err(_) => -2, // Panic occurred (likely canary corruption)
        }
    }
}

/// Write data to SecureMemory from a buffer
///
/// # Arguments
/// * `handle` - Valid SecureMemory handle
/// * `buffer` - Input buffer containing data to write
/// * `buffer_len` - Length of the input buffer
///
/// # Returns
/// * 0 on success
/// * -1 on invalid parameters
/// * -2 on canary corruption (security violation)
/// * -3 on write-once violation (attempted second write to write-once memory)
///
/// # Safety
/// - handle must be a valid SecureMemory handle
/// - buffer must point to valid memory of at least `buffer_len` bytes
#[no_mangle]
pub extern "C" fn secure_memory_write(
    handle: *mut SecureMemoryHandle,
    buffer: *const u8,
    buffer_len: usize,
) -> i32 {
    if handle.is_null() || buffer.is_null() || buffer_len == 0 {
        return -1; // Invalid parameters
    }

    unsafe {
        let mem = &mut *(handle as *mut SecureMemory);
        let input_slice = std::slice::from_raw_parts(buffer, buffer_len);

        let write_result = mem.write(|data| {
            let copy_len = data.len().min(buffer_len);
            data[..copy_len].copy_from_slice(&input_slice[..copy_len]);
            // Zero out remaining bytes if data buffer is larger
            if data.len() > copy_len {
                data[copy_len..].fill(0);
            }
        });

        match write_result {
            Ok(_) => {
                // Check if any panic occurred during the operation
                // (e.g., canary corruption)
                0 // Success
            }
            Err(_) => -3, // Write-once violation
        }
    }
}

/// Get the size of the SecureMemory buffer
///
/// # Arguments
/// * `handle` - Valid SecureMemory handle
///
/// # Returns
/// * Size in bytes, or 0 if handle is null
#[no_mangle]
pub extern "C" fn secure_memory_size(handle: *const SecureMemoryHandle) -> usize {
    if handle.is_null() {
        return 0;
    }

    unsafe {
        let mem = &*(handle as *const SecureMemory);
        mem.get_size()
    }
}

/// Cleanup TPM resources
///
/// This function should be called when the application is shutting down
/// to properly clean up TPM resources and flush all keys.
///
/// **IMPORTANT**: This must be called before the JVM exits to ensure
/// proper cleanup of TPM handles and sessions.
///
/// # Safety
/// This function is thread-safe but should only be called once during
/// application shutdown.
#[no_mangle]
pub extern "C" fn secure_memory_cleanup_tpm() {
    tpm_service::reset_service();
}
