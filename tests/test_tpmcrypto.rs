use secure_memory::tpm_service::TpmCrypto;
use tss_esapi::TctiNameConf;

#[test]
fn test_tpm_random_only() {
    // Créer une instance TPM sans passer par le singleton
    // Cela évite les problèmes d'initialisation des clés RSA
    let tpm = TpmCrypto::create(TctiNameConf::Mssim(Default::default()))
        .expect("Failed to create TPM context");

    // Test 1: Générer des données aléatoires
    let mut buffer1 = [0u8; 32];
    let mut buffer2 = [0u8; 32];

    tpm.random(&mut buffer1).expect("Failed to generate random data");
    tpm.random(&mut buffer2).expect("Failed to generate random data");

    // Vérifier que les buffers ne sont pas tous à zéro
    assert_ne!(
        buffer1,
        [0u8; 32],
        "Random buffer should not be all zeros"
    );

    assert_ne!(
        buffer2,
        [0u8; 32],
        "Random buffer should not be all zeros"
    );

    // Vérifier que deux générations successives donnent des résultats différents
    assert_ne!(
        buffer1,
        buffer2,
        "Two successive random generations should produce different results"
    );
    println!("✓ Test random generation passed");

    // Test 2: Random Different Sizes
    let sizes = [8, 16, 32, 64, 128, 256];

    for size in sizes.iter() {
        let mut buffer = vec![0u8; *size];
        tpm.random(&mut buffer).expect(&format!("Failed to generate {} random bytes", size));

        // Vérifier que le buffer n'est pas tout à zéro
        assert!(
            buffer.iter().any(|&b| b != 0),
            "Random buffer of size {} should contain non-zero bytes",
            size
        );
    }
    println!("✓ Test random different sizes passed");

    // Test 3: Random Entropy Check
    let mut buffer = vec![0u8; 1024];
    tpm.random(&mut buffer).expect("Failed to generate random data");

    // Compter les valeurs uniques
    let mut counts = [0u32; 256];
    for &byte in &buffer {
        counts[byte as usize] += 1;
    }

    // Vérifier qu'il y a une distribution raisonnable
    let unique_values = counts.iter().filter(|&&c| c > 0).count();

    // On devrait avoir au moins 100 valeurs différentes sur 256 possibles
    assert!(
        unique_values >= 100,
        "Random data should have good distribution of values (got {} unique values)",
        unique_values
    );
    println!("✓ Test random entropy check passed");

    println!("\n✅ All TPM random tests passed successfully!");
}

#[test]
fn test_tpm_concurrent_random() {
    use std::thread;

    // Test que plusieurs threads peuvent accéder au TPM
    let handles: Vec<_> = (0..4)
        .map(|i| {
            thread::spawn(move || {
                let tpm = TpmCrypto::create(TctiNameConf::Mssim(Default::default()))
                    .expect(&format!("Thread {} failed to create TPM context", i));

                let mut buffer = vec![0u8; 32];
                tpm.random(&mut buffer).expect(&format!("Thread {} failed to generate random", i));

                // Vérifier que le buffer n'est pas vide
                assert!(
                    buffer.iter().any(|&b| b != 0),
                    "Thread {} should have non-zero random data",
                    i
                );

                buffer
            })
        })
        .collect();

    // Collecter les résultats
    let results: Vec<_> = handles.into_iter()
        .map(|h| h.join().expect("Thread panicked"))
        .collect();

    // Vérifier que tous les threads ont obtenu des données différentes
    for i in 0..results.len() {
        for j in (i+1)..results.len() {
            assert_ne!(
                results[i],
                results[j],
                "Different threads should get different random data"
            );
        }
    }

    println!("✅ Concurrent random access test passed!");
}
