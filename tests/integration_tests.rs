use shredder::{
    standards::{
        LegacyConfig, LegacyStandard, Nist80088Config, SanitizationMethod, VerificationLevel,
        WipeStandard,
    },
    storage::{StorageCapabilities, StorageType},
    Shredder, WipeError,
};
use std::fs::File;
use std::io::{Read, Write};
use tempfile::tempdir;

mod common;

#[test]
fn test_secure_deletion_modern() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test_file.txt");

    // Create test file
    let mut file = File::create(&file_path).unwrap();
    file.write_all(b"sensitive data").unwrap();
    drop(file);

    // Configure secure deletion
    let wiper = Shredder::new(
        WipeStandard::Modern(Nist80088Config {
            method: SanitizationMethod::Clear,
            verify_level: VerificationLevel::Full,
        }),
        StorageType::Hdd(StorageCapabilities {
            supports_trim: false,
            supports_secure_erase: false,
            supports_nvme_sanitize: false,
            has_wear_leveling: false,
        }),
    );

    // Perform deletion
    wiper.wipe(&file_path).unwrap();

    // Verify file no longer exists
    assert!(!file_path.exists());
}

#[test]
fn test_secure_deletion_legacy_dod() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test_file_dod.txt");

    // Create and fill test file
    let mut file = File::create(&file_path).unwrap();
    let test_data = vec![0xAA; 1024]; // 1KB of test data
    file.write_all(&test_data).unwrap();
    drop(file);

    // Configure DoD secure deletion
    let wiper = Shredder::new(
        WipeStandard::Legacy(LegacyConfig {
            standard: LegacyStandard::Dod522022M,
            extra_verification: true,
        }),
        StorageType::Hdd(StorageCapabilities {
            supports_trim: false,
            supports_secure_erase: false,
            supports_nvme_sanitize: false,
            has_wear_leveling: false,
        }),
    );

    // Perform deletion
    wiper.wipe(&file_path).unwrap();

    // Verify file is completely gone
    assert!(!file_path.exists());
}

#[test]
fn test_ssd_specific_deletion() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test_file_ssd.txt");

    // Create test file
    let mut file = File::create(&file_path).unwrap();
    file.write_all(b"SSD test data").unwrap();
    drop(file);

    // Configure for SSD with TRIM support
    let wiper = Shredder::new(
        WipeStandard::Modern(Nist80088Config {
            method: SanitizationMethod::Purge,
            verify_level: VerificationLevel::Enhanced,
        }),
        StorageType::Ssd(StorageCapabilities {
            supports_trim: true,
            supports_secure_erase: true,
            supports_nvme_sanitize: true,
            has_wear_leveling: true,
        }),
    );

    // Perform deletion
    wiper.wipe(&file_path).unwrap();

    // Verify file no longer exists
    assert!(!file_path.exists());
}

#[test]
fn test_flash_wear_leveling_handling() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test_file_flash.txt");

    // Create test file
    let mut file = File::create(&file_path).unwrap();
    file.write_all(b"Flash drive test data").unwrap();
    drop(file);

    // Configure for Flash storage with wear leveling
    let wiper = Shredder::new(
        WipeStandard::Modern(Nist80088Config {
            method: SanitizationMethod::Clear,
            verify_level: VerificationLevel::Full,
        }),
        StorageType::Flash(StorageCapabilities {
            supports_trim: false,
            supports_secure_erase: false,
            supports_nvme_sanitize: false,
            has_wear_leveling: true,
        }),
    );

    // Perform deletion
    wiper.wipe(&file_path).unwrap();

    // Verify file no longer exists
    assert!(!file_path.exists());
}

#[test]
fn test_error_handling() {
    let dir = tempdir().unwrap();
    let nonexistent_path = dir.path().join("nonexistent.txt");

    let wiper = Shredder::new(
        WipeStandard::Modern(Nist80088Config {
            method: SanitizationMethod::Clear,
            verify_level: VerificationLevel::Basic,
        }),
        StorageType::Hdd(StorageCapabilities {
            supports_trim: false,
            supports_secure_erase: false,
            supports_nvme_sanitize: false,
            has_wear_leveling: false,
        }),
    );

    // Attempt to wipe non-existent file
    match wiper.wipe(&nonexistent_path) {
        Err(WipeError::Io(_)) => (), // Expected error
        other => panic!("Unexpected result: {:?}", other),
    }
}
