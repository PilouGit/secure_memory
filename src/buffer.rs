use crate::error::{Error, Result};

/// A secure buffer that automatically wipes its contents on drop
#[derive(Debug)]
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    /// Creates a new secure buffer with the specified size
    #[must_use]
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0; size],
        }
    }

    /// Returns the length of the buffer
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the buffer is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Writes data to the buffer at the specified offset
    ///
    /// # Errors
    ///
    /// Returns [`Error::BufferOverflow`] if the write would exceed buffer bounds.
    pub fn write_at(&mut self, offset: usize, data: &[u8]) -> Result<()> {
        if offset + data.len() > self.data.len() {
            return Err(Error::BufferOverflow);
        }
        
        self.data[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }

    /// Reads data from the buffer at the specified offset
    ///
    /// # Errors
    ///
    /// Returns [`Error::BufferOverflow`] if the read would exceed buffer bounds.
    pub fn read_at(&self, offset: usize, len: usize) -> Result<&[u8]> {
        if offset + len > self.data.len() {
            return Err(Error::BufferOverflow);
        }
        
        Ok(&self.data[offset..offset + len])
    }

    /// Securely wipes the buffer contents
    pub fn wipe(&mut self) {
        for byte in &mut self.data {
            unsafe {
                // SAFETY: We're writing to a valid mutable reference within bounds
                // This volatile write prevents the compiler from optimizing away the wipe
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.wipe();
    }
}