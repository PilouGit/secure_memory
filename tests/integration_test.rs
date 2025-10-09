use secure_memory::{SecureBuffer, Error};

#[test]
fn test_buffer_creation() {
    let buffer = SecureBuffer::new(1024);
    assert_eq!(buffer.len(), 1024);
    assert!(!buffer.is_empty());
}

#[test]
fn test_buffer_operations() {
    let mut buffer = SecureBuffer::new(100);
    let test_data = b"Hello, World!";
    
    buffer.write_at(0, test_data).unwrap();
    let read_data = buffer.read_at(0, test_data.len()).unwrap();
    assert_eq!(read_data, test_data);
}

#[test]
fn test_buffer_overflow() {
    let mut buffer = SecureBuffer::new(10);
    let large_data = vec![0u8; 20];
    
    let result = buffer.write_at(0, &large_data);
    assert!(matches!(result, Err(Error::BufferOverflow)));
}

#[test]
fn test_read_overflow() {
    let buffer = SecureBuffer::new(10);
    
    let result = buffer.read_at(5, 10);
    assert!(matches!(result, Err(Error::BufferOverflow)));
}

#[test]
fn test_empty_buffer() {
    let buffer = SecureBuffer::new(0);
    assert!(buffer.is_empty());
    assert_eq!(buffer.len(), 0);
}