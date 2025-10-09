use secure_memory::{SecureBuffer, utils, Result};

fn main() -> Result<()> {
    println!("Secure Memory - Advanced Operations Example");
    
    let mut buffer1 = SecureBuffer::new(32);
    let mut buffer2 = SecureBuffer::new(32);
    
    let password = b"my_secret_password_123";
    let verify_password = b"my_secret_password_123";
    let wrong_password = b"wrong_password";
    
    buffer1.write_at(0, password)?;
    buffer2.write_at(0, verify_password)?;
    
    let data1 = buffer1.read_at(0, password.len())?;
    let data2 = buffer2.read_at(0, verify_password.len())?;
    
    if utils::constant_time_eq(data1, data2) {
        println!("✓ Passwords match (constant-time comparison)");
    } else {
        println!("✗ Passwords don't match");
    }
    
    if utils::constant_time_eq(data1, wrong_password) {
        println!("✓ Wrong password matches (this shouldn't happen)");
    } else {
        println!("✓ Wrong password correctly rejected");
    }
    
    println!("Manually wiping buffer1...");
    buffer1.wipe();
    
    println!("All buffers will be securely wiped on drop");
    
    Ok(())
}