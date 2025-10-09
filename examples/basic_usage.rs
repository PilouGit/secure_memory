use secure_memory::{SecureBuffer, Result};

fn main() -> Result<()> {
    println!("Secure Memory - Basic Usage Example");
    
    let mut buffer = SecureBuffer::new(256);
    println!("Created secure buffer with {} bytes", buffer.len());
    
    let secret_data = b"This is sensitive information that should be wiped";
    buffer.write_at(0, secret_data)?;
    println!("Written {} bytes to buffer", secret_data.len());
    
    let read_data = buffer.read_at(0, secret_data.len())?;
    println!("Read data: {}", String::from_utf8_lossy(read_data));
    
    println!("Buffer will be automatically wiped when dropped");
    
    Ok(())
}