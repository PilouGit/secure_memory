use secure_memory::secure_memory::SecureMemory;

#[test]
fn test_write_once_allows_first_write() {
    let mut sm = SecureMemory::new_with_options(256, true).expect("Failed to create SecureMemory");

    // Première écriture devrait réussir
    sm.write(|buf| {
        buf[0] = 42;
        buf[1] = 24;
    }).expect("First write should succeed");

    // Vérifier que les données ont été écrites
    sm.read(|buf| {
        assert_eq!(buf[0], 42);
        assert_eq!(buf[1], 24);
    });
}

#[test]
fn test_write_once_prevents_second_write() {
    let mut sm = SecureMemory::new_with_options(256, true).expect("Failed to create SecureMemory");

    // Première écriture
    sm.write(|buf| {
        buf[0] = 42;
    }).expect("First write should succeed");

    // Deuxième écriture devrait échouer
    let result = sm.write(|buf| {
        buf[0] = 99;
    });

    assert!(result.is_err(), "Second write should fail for write-once memory");

    // Vérifier que la valeur originale n'a pas changé
    sm.read(|buf| {
        assert_eq!(buf[0], 42);
    });
}

#[test]
fn test_write_once_allows_multiple_reads() {
    let mut sm = SecureMemory::new_with_options(256, true).expect("Failed to create SecureMemory");

    // Écrire une fois
    sm.write(|buf| {
        buf[0] = 42;
        buf[1] = 24;
    }).expect("Write should succeed");

    // Plusieurs lectures devraient fonctionner
    sm.read(|buf| {
        assert_eq!(buf[0], 42);
        assert_eq!(buf[1], 24);
    });

    sm.read(|buf| {
        assert_eq!(buf[0], 42);
        assert_eq!(buf[1], 24);
    });

    sm.read(|buf| {
        assert_eq!(buf[0], 42);
        assert_eq!(buf[1], 24);
    });
}

#[test]
fn test_normal_memory_allows_multiple_writes() {
    let mut sm = SecureMemory::new(256).expect("Failed to create SecureMemory");

    // Première écriture
    sm.write(|buf| {
        buf[0] = 42;
    }).expect("First write should succeed");

    sm.read(|buf| {
        assert_eq!(buf[0], 42);
    });

    // Deuxième écriture (devrait fonctionner)
    sm.write(|buf| {
        buf[0] = 99;
    }).expect("Second write should succeed");

    sm.read(|buf| {
        assert_eq!(buf[0], 99);
    });

    // Troisième écriture (devrait aussi fonctionner)
    sm.write(|buf| {
        buf[0] = 123;
    }).expect("Third write should succeed");

    sm.read(|buf| {
        assert_eq!(buf[0], 123);
    });
}

#[test]
fn test_write_once_false_same_as_new() {
    let mut sm1 = SecureMemory::new(256).expect("Failed to create SecureMemory");
    let mut sm2 = SecureMemory::new_with_options(256, false).expect("Failed to create SecureMemory");

    // Les deux devraient permettre des écritures multiples
    sm1.write(|buf| { buf[0] = 1; }).expect("Write should succeed");
    sm1.write(|buf| { buf[0] = 2; }).expect("Write should succeed");
    sm1.read(|buf| { assert_eq!(buf[0], 2); });

    sm2.write(|buf| { buf[0] = 1; }).expect("Write should succeed");
    sm2.write(|buf| { buf[0] = 2; }).expect("Write should succeed");
    sm2.read(|buf| { assert_eq!(buf[0], 2); });
}
