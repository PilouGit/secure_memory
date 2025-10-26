// Temporairement désactivé - nécessite correction du type TctiNameConf
// use secure_memory::tpm_service::TpmCrypto;
// use tss_esapi::Result;

fn main() {
    println!("Secure memory library - use `cargo test` to run tests");
    // let mut tpm = TpmCrypto::create(TctiNameConf::Device(...))?;
    // let mut buffer = vec![0u8; 32];
    // tpm.random(&mut buffer)?;
    // println!("Random bytes: {:02x?}", buffer);
}