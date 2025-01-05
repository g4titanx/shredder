use crate::patterns::WipePattern;

/// represents different data sanitization standards
#[derive(Debug, Clone)]
pub enum WipeStandard {
    /// NIST 800-88 modern standard
    /// focuses on storage-type specific methods and verification
    Modern(Nist80088Config),

    /// Legacy multi-pass overwrite standards
    /// includes DoD 5220.22-M, Gutmann, and VSITR
    Legacy(LegacyConfig),

    /// Custom user-defined wiping configuration
    Custom(WipeConfig),
}

/// configuration for NIST 800-88 sanitization
#[derive(Debug, Clone)]
pub struct Nist80088Config {
    /// method of sanitization (Clear or Purge)
    pub method: SanitizationMethod,
    /// level of verification after sanitization
    pub verify_level: VerificationLevel,
}

/// NIST 800-88 sanitization methods
#[derive(Debug, Clone)]
pub enum SanitizationMethod {
    /// for media reuse within organization
    /// simple overwrite, typically single-pass
    Clear,

    /// for media leaving organizational control
    /// more thorough sanitization, may use crypto erase
    Purge,
}

/// configuration for legacy wiping standards
#[derive(Debug, Clone)]
pub struct LegacyConfig {
    /// which legacy standard to follow
    pub standard: LegacyStandard,
    /// whether to perform additional verification
    pub extra_verification: bool,
}

/// legacy data sanitization standards
#[derive(Debug, Clone)]
pub enum LegacyStandard {
    /// DoD 5220.22-M (3 passes)
    Dod522022M,
    /// Gutmann 35-pass method
    Gutmann,
    /// German VSITR 7-pass standard
    VsitrStandard,
}

/// configuration for custom wiping patterns
#[derive(Debug, Clone)]
pub struct WipeConfig {
    /// sequence of patterns to apply
    pub passes: Vec<WipePattern>,
    /// whether to verify after each pass
    pub verify_each_pass: bool,
}

/// levels of verification after wiping
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum VerificationLevel {
    /// no verification
    None,
    /// basic sampling of wiped data
    Basic,
    /// complete verification of all data
    Full,
    /// multiple verification passes
    Enhanced,
}

impl LegacyStandard {
    /// returns the sequence of patterns for each legacy standard
    pub fn get_patterns(&self) -> Vec<WipePattern> {
        match self {
            // DoD 5220.22-M: 3-pass overwrite
            LegacyStandard::Dod522022M => {
                vec![
                    WipePattern::Zeros,    // Pass 1: All zeros
                    WipePattern::Ones,     // Pass 2: All ones
                    WipePattern::Random,   // Pass 3: Random data
                ]
            }
            // VSITR: 7-pass overwrite
            LegacyStandard::VsitrStandard => vec![
                WipePattern::Zeros,    // Pass 1: Zeros
                WipePattern::Ones,     // Pass 2: Ones
                WipePattern::Zeros,    // Pass 3: Zeros
                WipePattern::Ones,     // Pass 4: Ones
                WipePattern::Zeros,    // Pass 5: Zeros
                WipePattern::Ones,     // Pass 6: Ones
                WipePattern::Random,   // Pass 7: Random
            ],
            // Gutmann: 35-pass overwrite
            LegacyStandard::Gutmann => Self::gutmann_patterns(),
        }
    }

    /// returns the full Gutmann 35-pass pattern sequence
    ///
    /// the Gutmann method uses the following sequence:
    /// - Passes 1-4: Random data
    /// - Passes 5-31: Specific bit patterns designed to toggle magnetic domains
    /// - Passes 32-35: Random data
    fn gutmann_patterns() -> Vec<WipePattern> {
        let mut patterns = Vec::with_capacity(35);

        // passes 1-4: Random data
        for _ in 0..4 {
            patterns.push(WipePattern::Random);
        }

        // passes 5-31: Specific bit patterns
        patterns.extend_from_slice(&[
            // fixed patterns (hexadecimal representation)
            WipePattern::Custom(vec![0x55, 0x55, 0x55]), // 0b01010101
            WipePattern::Custom(vec![0xAA, 0xAA, 0xAA]), // 0b10101010
            WipePattern::Custom(vec![0x92, 0x49, 0x24]), // 0b10010010
            WipePattern::Custom(vec![0x49, 0x24, 0x92]), // 0b01001001
            WipePattern::Custom(vec![0x24, 0x92, 0x49]), // 0b00100100
            WipePattern::Custom(vec![0x00, 0x00, 0x00]), // all zeros
            WipePattern::Custom(vec![0x11, 0x11, 0x11]), // 0b00010001
            WipePattern::Custom(vec![0x22, 0x22, 0x22]), // 0b00100010
            WipePattern::Custom(vec![0x33, 0x33, 0x33]), // 0b00110011
            WipePattern::Custom(vec![0x44, 0x44, 0x44]), // 0b01000100
            WipePattern::Custom(vec![0x55, 0x55, 0x55]), // 0b01010101
            WipePattern::Custom(vec![0x66, 0x66, 0x66]), // 0b01100110
            WipePattern::Custom(vec![0x77, 0x77, 0x77]), // 0b01110111
            WipePattern::Custom(vec![0x88, 0x88, 0x88]), // 0b10001000
            WipePattern::Custom(vec![0x99, 0x99, 0x99]), // 0b10011001
            WipePattern::Custom(vec![0xAA, 0xAA, 0xAA]), // 0b10101010
            WipePattern::Custom(vec![0xBB, 0xBB, 0xBB]), // 0b10111011
            WipePattern::Custom(vec![0xCC, 0xCC, 0xCC]), // 0b11001100
            WipePattern::Custom(vec![0xDD, 0xDD, 0xDD]), // 0b11011101
            WipePattern::Custom(vec![0xEE, 0xEE, 0xEE]), // 0b11101110
            WipePattern::Custom(vec![0xFF, 0xFF, 0xFF]), // all ones
            WipePattern::Custom(vec![0x92, 0x49, 0x24]), // 0b10010010
            WipePattern::Custom(vec![0x49, 0x24, 0x92]), // 0b01001001
            WipePattern::Custom(vec![0x24, 0x92, 0x49]), // 0b00100100
            WipePattern::Custom(vec![0x6D, 0xB6, 0xDB]), // 0b01101101
            WipePattern::Custom(vec![0xB6, 0xDB, 0x6D]), // 0b10110110
            WipePattern::Custom(vec![0xDB, 0x6D, 0xB6]), // 0b11011011
        ]);

        // passes 32-35: Random data
        for _ in 0..4 {
            patterns.push(WipePattern::Random);
        }

        patterns
    }
}