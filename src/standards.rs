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
#[derive(Debug, Clone)]
pub enum VerificationLevel {
    /// No verification
    None,
    /// Basic sampling of wiped data
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

    /// Returns the full Gutmann 35-pass pattern sequence
    /// Note: Currently simplified to all random passes
    fn gutmann_patterns() -> Vec<WipePattern> {
        // TODO: Implement actual Gutmann pattern sequence:
        // - Passes 1-4: Random
        // - Passes 5-31: Specific bit patterns
        // - Passes 32-35: Random
        vec![WipePattern::Random; 35]
    }
}