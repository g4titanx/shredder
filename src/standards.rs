use crate::patterns::WipePattern;

#[derive(Debug, Clone)]
pub enum WipeStandard {
    Modern(Nist80088Config),
    Legacy(LegacyConfig),
    Custom(WipeConfig),
}

#[derive(Debug, Clone)]
pub struct Nist80088Config {
    pub method: SanitizationMethod,
    pub verify_level: VerificationLevel,
}

#[derive(Debug, Clone)]
pub enum SanitizationMethod {
    Clear,
    Purge,
}

#[derive(Debug, Clone)]
pub struct LegacyConfig {
    pub standard: LegacyStandard,
    pub extra_verification: bool,
}

#[derive(Debug, Clone)]
pub enum LegacyStandard {
    Dod522022M,
    Gutmann,
    VsitrStandard,
}

#[derive(Debug, Clone)]
pub struct WipeConfig {
    pub passes: Vec<WipePattern>,
    pub verify_each_pass: bool,
}

#[derive(Debug, Clone)]
pub enum VerificationLevel {
    None,
    Basic,
    Full,
    Enhanced,
}

impl LegacyStandard {
    pub fn get_patterns(&self) -> Vec<WipePattern> {
        match self {
            LegacyStandard::Dod522022M => vec![
                WipePattern::Zeros,
                WipePattern::Ones,
                WipePattern::Random,
            ],
            LegacyStandard::VsitrStandard => vec![
                WipePattern::Zeros,
                WipePattern::Ones,
                WipePattern::Zeros,
                WipePattern::Ones,
                WipePattern::Zeros,
                WipePattern::Ones,
                WipePattern::Random,
            ],
            LegacyStandard::Gutmann => Self::gutmann_patterns(),
        }
    }

    fn gutmann_patterns() -> Vec<WipePattern> {
        // Implement full 35-pass Gutmann pattern
        vec![WipePattern::Random; 35] // Simplified for brevity
    }
}