use secure_memory::secure_memory::SecureMemory;
use secure_memory::secure_key::SecureKey;


#[test]
fn test_secure_memory_creation() {
    let key = SecureKey::new();
    let secure_mem = SecureMemory::new(1024, );
    assert!(secure_mem.is_some());
}

#[test]
fn test_secure_memory_read_write() {
    let key = SecureKey::new();
    let mut secure_mem = SecureMemory::new(64, ).unwrap();
    
    // Test write
    secure_mem.write(|buffer| {
        buffer[0] = 42;
        buffer[1] = 84;
    });
    
    // Test read
    secure_mem.read(|buffer| {
        assert_eq!(buffer[0], 42);
        assert_eq!(buffer[1], 84);
    });
}

#[test]
fn test_secure_memory_encryption() {
    let key = SecureKey::new();
    let mut secure_mem = SecureMemory::new(32).unwrap();
    
    // Write some test data
    let test_data = b"Hello, secure world!";
    secure_mem.write(|buffer| {
        buffer[..test_data.len()].copy_from_slice(test_data);
    });
    
    // Verify we can read it back
    secure_mem.read(|buffer| {
        assert_eq!(&buffer[..test_data.len()], test_data);
    });
}

#[test]
fn test_secure_memory_zero_size() {
    let key = SecureKey::new();
    let secure_mem = SecureMemory::new(0, );
    assert!(secure_mem.is_none());
}

#[test]
fn test_secure_memory_large_allocation() {
    let key = SecureKey::new();
    let size = 1024 * 1024; // 1MB
    let secure_mem = SecureMemory::new(size, );
    assert!(secure_mem.is_some());
}

#[test]
fn test_secure_memory_multiple_operations() {
    let key = SecureKey::new();
    let mut secure_mem = SecureMemory::new(256, ).unwrap();
    
    // Multiple write operations
    for i in 0..10 {
        secure_mem.write(|buffer| {
            buffer[i] = i as u8;
        });
    }
    
    // Verify all values
    secure_mem.read(|buffer| {
        for i in 0..10 {
            assert_eq!(buffer[i], i as u8);
        }
    });
}