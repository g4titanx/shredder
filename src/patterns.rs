use rand::RngCore;

/// represents different patterns used for secure data wiping
#[derive(Debug, Clone)]
pub enum WipePattern {
    /// fill with zeros (0x00)
    /// used in various standards as part of multi-pass overwriting
    Zeros,

    /// fill with ones (0xFF)
    /// often used as a complement to zeros in multi-pass overwriting
    Ones,

    /// fill with cryptographically secure random data
    /// recommended by NIST 800-88 for single-pass overwrites
    Random,

    /// fill with a custom repeating pattern
    /// example: [0x55, 0xAA] creates alternating bits
    Custom(Vec<u8>),
}

impl WipePattern {
    /// fills a buffer with the specified pattern
    ///
    /// # Arguments
    /// * `buffer` - mutable slice to fill with the pattern
    ///
    /// # Examples
    /// ```
    /// use shredder::patterns::WipePattern;
    /// 
    /// let mut buffer = vec![0; 1024];
    /// WipePattern::Zeros.fill_buffer(&mut buffer);
    /// assert!(buffer.iter().all(|&b| b == 0x00));
    /// ```
    pub fn fill_buffer(&self, buffer: &mut [u8]) {
        match self {
            WipePattern::Zeros => buffer.fill(0x00),
            WipePattern::Ones => buffer.fill(0xFF),
            // fill buffer with cryptographically secure random data
            WipePattern::Random => rand::thread_rng().fill_bytes(buffer),
            // Fill buffer with repeating custom pattern
            WipePattern::Custom(pattern) => {
                // process buffer in chunks the size of our pattern
                for chunk in buffer.chunks_mut(pattern.len()) {
                    // handle partial chunks at the end of the buffer
                    let copy_size = std::cmp::min(chunk.len(), pattern.len());
                    // copy pattern into the chunk
                    chunk[..copy_size].copy_from_slice(&pattern[..copy_size]);
                }
            }
        }
    }

    /// verifies that a buffer contains the expected pattern
    ///
    /// # arguments
    /// * `buffer` - Slice to verify
    ///
    /// # returns
    /// * `bool` - True if buffer matches pattern, false otherwise
    ///
    /// # examples
    /// ```
    /// use shredder::patterns::WipePattern;
    /// 
    /// let mut buffer = vec![0x00; 1024];
    /// assert!(WipePattern::Zeros.verify_buffer(&buffer));
    /// ```
    pub fn verify_buffer(&self, buffer: &[u8]) -> bool {
        match self {
            // Check if all bytes are zero
            WipePattern::Zeros => buffer.iter().all(|&b| b == 0x00),
            
            // Check if all bytes are ones
            WipePattern::Ones => buffer.iter().all(|&b| b == 0xFF),
            
            // Random data can't be verified (always returns true)
            WipePattern::Random => true,
            
            // Verify custom pattern repeats correctly
            WipePattern::Custom(pattern) => {
                buffer.chunks(pattern.len()) // Split buffer into pattern-sized chunks
                    .all(|chunk| { // Check each chunk
                        let len = std::cmp::min(chunk.len(), pattern.len());
                        chunk[..len] == pattern[..len] // Compare chunk with pattern
                    })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// test zero-filling pattern
    #[test]
    fn test_zero_pattern() {
        let mut buffer = vec![0xFF; 1024]; // start with all ones
        WipePattern::Zeros.fill_buffer(&mut buffer);
        assert!(buffer.iter().all(|&b| b == 0)); // verify all bytes are zero
    }

    /// test custom alternating pattern
    #[test]
    fn test_custom_pattern() {
        let pattern = vec![0x55, 0xAA];  // alternating bits pattern
        let mut buffer = vec![0; 4];     // buffer for two pattern repetitions
        WipePattern::Custom(pattern).fill_buffer(&mut buffer);
        assert_eq!(buffer, vec![0x55, 0xAA, 0x55, 0xAA]); // verify pattern repeats
    }
}
