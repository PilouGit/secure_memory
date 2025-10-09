/// Constant-time comparison of two byte slices
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    
    result == 0
}

/// Securely wipes a mutable byte slice
pub fn secure_wipe(data: &mut [u8]) {
    for byte in data {
        unsafe {
            // SAFETY: We're writing to a valid mutable reference within bounds
            // This volatile write prevents the compiler from optimizing away the wipe
            std::ptr::write_volatile(byte, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";
        
        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
        assert!(!constant_time_eq(a, b"hello world"));
    }

    #[test]
    fn test_secure_wipe() {
        let mut data = vec![1, 2, 3, 4, 5];
        secure_wipe(&mut data);
        assert_eq!(data, vec![0, 0, 0, 0, 0]);
    }
}