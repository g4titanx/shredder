use rand::RngCore;

#[derive(Debug, Clone)]
pub enum WipePattern {
    Zeros,
    Ones,
    Random,
    Custom(Vec<u8>),
}

impl WipePattern {
    pub fn fill_buffer(&self, buffer: &mut [u8]) {
        match self {
            WipePattern::Zeros => buffer.fill(0x00),
            WipePattern::Ones => buffer.fill(0xFF),
            WipePattern::Random => rand::thread_rng().fill_bytes(buffer),
            WipePattern::Custom(pattern) => {
                for chunk in buffer.chunks_mut(pattern.len()) {
                    let copy_size = std::cmp::min(chunk.len(), pattern.len());
                    chunk[..copy_size].copy_from_slice(&pattern[..copy_size]);
                }
            }
        }
    }

    pub fn verify_buffer(&self, buffer: &[u8]) -> bool {
        match self {
            WipePattern::Zeros => buffer.iter().all(|&b| b == 0x00),
            WipePattern::Ones => buffer.iter().all(|&b| b == 0xFF),
            WipePattern::Random => true, // Can't verify random data
            WipePattern::Custom(pattern) => {
                buffer.chunks(pattern.len())
                    .all(|chunk| {
                        let len = std::cmp::min(chunk.len(), pattern.len());
                        chunk[..len] == pattern[..len]
                    })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_pattern() {
        let mut buffer = vec![0xFF; 1024];
        WipePattern::Zeros.fill_buffer(&mut buffer);
        assert!(buffer.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_custom_pattern() {
        let pattern = vec![0x55, 0xAA];
        let mut buffer = vec![0; 4];
        WipePattern::Custom(pattern).fill_buffer(&mut buffer);
        assert_eq!(buffer, vec![0x55, 0xAA, 0x55, 0xAA]);
    }
}