use secure_memory::tpmcrypto::TpmCrypto;
use tss_esapi::Result;

fn main() -> Result<()> {
    let mut tpm = TpmCrypto::create()?;
    
    let mut buffer = vec![0u8; 32];
    tpm.random(&mut buffer)?;
    
    println!("Random bytes: {:02x?}", buffer);
    
    Ok(())
}