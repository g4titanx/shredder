use shredder::{
    Shredder,
    standards::{
        LegacyConfig, LegacyStandard, Nist80088Config, SanitizationMethod, VerificationLevel,
        WipeStandard, WipeConfig
    },
    patterns::WipePattern,
};
use std::fs::File;
use std::io::{Write, Read, Seek, SeekFrom};
use tempfile::tempdir;

mod common;
use common::*;

#[test]
fn test_basic_file_deletion() {
    let dir = tempdir().unwrap();
    let file_path = create_test_file(dir.path(), 1024).unwrap();

    let shredder = Shredder::new(
        WipeStandard::Modern(Nist80088Config {
            method: SanitizationMethod::Clear,
            verify_level: VerificationLevel::Full,
        }),
        mock_storage::mock_hdd().device_type,
    );

    assert!(shredder.wipe(&file_path).is_ok());
    assert!(!file_path.exists());
}

#[test]
fn test_large_file_deletion() {
    let dir = tempdir().unwrap();
    
    // Create a test pattern that's easy to verify
    let pattern = [0xAA, 0x55, 0xAA, 0x55];
    let file_size = 16 * 1024; // 16KB
    let file_path = dir.path().join("test_large_file.bin");

    // Create file with verifiable pattern
    {
        let mut file = File::create(&file_path).unwrap();
        let mut written = 0;
        while written < file_size {
            let write_size = std::cmp::min(pattern.len(), file_size - written);
            file.write_all(&pattern[..write_size]).unwrap();
            written += write_size;
        }
        file.sync_all().unwrap();
    }

    // Verify file was created correctly
    {
        let mut file = File::open(&file_path).unwrap();
        let mut buffer = vec![0u8; pattern.len()];
        let mut offset = 0;
        
        while let Ok(n) = file.read(&mut buffer) {
            if n == 0 { break; }
            assert_eq!(&buffer[..n], &pattern[..n], 
                "Initial pattern mismatch at offset {}", offset);
            offset += n;
        }
        assert_eq!(offset, file_size, "File size mismatch");
    }

    let shredder = Shredder::new(
        WipeStandard::Modern(Nist80088Config {
            method: SanitizationMethod::Clear,
            verify_level: VerificationLevel::Full, // Use full verification for better debugging
        }),
        mock_storage::mock_hdd().device_type,
    );

    match shredder.wipe(&file_path) {
        Ok(()) => {
            assert!(!file_path.exists(), "File should be deleted after wiping");
            if file_path.exists() {
                let content = std::fs::read(&file_path).unwrap_or_default();
                if !content.is_empty() {
                    panic!(
                        "File still contains {} bytes after wiping. First pattern: {:?}",
                        content.len(),
                        &content[..std::cmp::min(16, content.len())]
                    );
                }
            }
        },
        Err(e) => {
            let debug_info = if file_path.exists() {
                let content = std::fs::read(&file_path).unwrap_or_default();
                format!(
                    "File size: {}, First 16 bytes: {:?}, Permissions: {:?}",
                    content.len(),
                    &content[..std::cmp::min(16, content.len())],
                    std::fs::metadata(&file_path).unwrap().permissions()
                )
            } else {
                "File has been deleted despite error".to_string()
            };
            panic!("Wipe failed: {}. Debug info: {}", e, debug_info);
        }
    }
}

#[test]
fn test_dod_standard() {
    let dir = tempdir().unwrap();
    let file_path = create_test_file(dir.path(), 1024).unwrap();

    let shredder = Shredder::new(
        WipeStandard::Legacy(LegacyConfig {
            standard: LegacyStandard::Dod522022M,
            extra_verification: true,
        }),
        mock_storage::mock_hdd().device_type,
    );

    match shredder.wipe(&file_path) {
        Ok(()) => {
            assert!(!file_path.exists(), "File should be deleted after wiping");
        },
        Err(e) => panic!("Failed to wipe file with DoD standard: {}", e),
    }
}

#[test]
fn test_custom_pattern() {
    let dir = tempdir().unwrap();
    let file_path = create_test_file(dir.path(), 1024).unwrap();
    
    let pattern = vec![0xAA, 0x55, 0xAA, 0x55];
    let shredder = Shredder::new(
        WipeStandard::Custom(WipeConfig {
            passes: vec![WipePattern::Custom(pattern.clone())],
            verify_each_pass: true,
        }),
        mock_storage::mock_hdd().device_type,
    );

    assert!(shredder.wipe(&file_path).is_ok());
    assert!(!file_path.exists());
}

#[test]
fn test_ssd_handling() {
    let dir = tempdir().unwrap();
    let file_path = create_test_file(dir.path(), 4096).unwrap();

    let shredder = Shredder::new(
        WipeStandard::Modern(Nist80088Config {
            method: SanitizationMethod::Purge,
            verify_level: VerificationLevel::Enhanced,
        }),
        mock_storage::mock_ssd().device_type,
    );

    assert!(shredder.wipe(&file_path).is_ok());
    assert!(!file_path.exists());
}

#[test]
fn test_flash_wear_leveling() {
    let dir = tempdir().unwrap();
    let file_path = create_test_file(dir.path(), 4096).unwrap();

    let shredder = Shredder::new(
        WipeStandard::Modern(Nist80088Config {
            method: SanitizationMethod::Clear,
            verify_level: VerificationLevel::Full,
        }),
        mock_storage::mock_flash().device_type,
    );

    assert!(shredder.wipe(&file_path).is_ok());
    assert!(!file_path.exists());
}

#[test]
fn test_error_conditions() {
    let dir = tempdir().unwrap();
    
    // Test non-existent file
    let nonexistent = dir.path().join("nonexistent.txt");
    let shredder = Shredder::new(
        WipeStandard::Modern(Nist80088Config {
            method: SanitizationMethod::Clear,
            verify_level: VerificationLevel::None,
        }),
        mock_storage::mock_hdd().device_type,
    );

    assert!(shredder.wipe(&nonexistent).is_err());

    // Test file without write permissions
    let file_path = create_test_file(dir.path(), 1024).unwrap();
    let mut perms = std::fs::metadata(&file_path).unwrap().permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&file_path, perms).unwrap();
    
    assert!(shredder.wipe(&file_path).is_err());
}

#[test]
fn test_verification_levels() {
    let dir = tempdir().unwrap();
    
    for level in [
        VerificationLevel::None,
        VerificationLevel::Basic,
        VerificationLevel::Full,
        VerificationLevel::Enhanced,
    ] {
        let file_path = create_test_file(dir.path(), 4096).unwrap();
        
        let shredder = Shredder::new(
            WipeStandard::Modern(Nist80088Config {
                method: SanitizationMethod::Clear,
                verify_level: level,
            }),
            mock_storage::mock_hdd().device_type,
        );

        match shredder.wipe(&file_path) {
            Ok(()) => assert!(!file_path.exists(), "File should be deleted after wiping"),
            Err(e) => panic!("Failed to wipe file with verification level {:?}: {}", level, e),
        }
    }
}

#[test]
fn test_concurrent_operations() {
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let dir = tempdir().unwrap();
    let mut handles = vec![];
    let shredder = Arc::new(Shredder::new(
        WipeStandard::Modern(Nist80088Config {
            method: SanitizationMethod::Clear,
            verify_level: VerificationLevel::Basic,
        }),
        mock_storage::mock_hdd().device_type,
    ));

    // First create all files
    let mut file_paths = vec![];
    for i in 0..3 {
        let file_path = dir.path().join(format!("test_file_{}.bin", i));
        let mut file = File::create(&file_path).unwrap();
        file.write_all(&[0x55; 1024]).unwrap();
        file.sync_all().unwrap();
        file_paths.push(file_path);
    }

    // Ensure all files are created before starting threads
    thread::sleep(Duration::from_millis(100));

    for (i, file_path) in file_paths.into_iter().enumerate() {
        let shredder = Arc::clone(&shredder);
        let handle = thread::spawn(move || {
            if !file_path.exists() {
                panic!("File {} doesn't exist at start of thread", file_path.display());
            }

            match shredder.wipe(&file_path) {
                Ok(()) => {
                    assert!(!file_path.exists(), 
                        "File {} should be deleted after wiping", file_path.display());
                },
                Err(e) => panic!("Thread {} failed to wipe file {}: {}", 
                    i, file_path.display(), e),
            }
        });
        handles.push(handle);
        
        // Add small delay between thread spawns to reduce contention
        thread::sleep(Duration::from_millis(10));
    }

    for (i, handle) in handles.into_iter().enumerate() {
        if let Err(e) = handle.join() {
            panic!("Thread {} panicked: {:?}", i, e);
        }
    }
}

#[test]
fn test_small_file_deletion() {
    let dir = tempdir().unwrap();
    let file_path = create_test_file(dir.path(), 100).unwrap(); // 100 bytes

    let shredder = Shredder::new(
        WipeStandard::Modern(Nist80088Config {
            method: SanitizationMethod::Clear,
            verify_level: VerificationLevel::Full,
        }),
        mock_storage::mock_hdd().device_type,
    );

    assert!(shredder.wipe(&file_path).is_ok());
    assert!(!file_path.exists());
}

// Edge Cases
#[test]
fn test_empty_file() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("empty.txt");
    File::create(&file_path).unwrap();

    let shredder = Shredder::new(
        WipeStandard::Modern(Nist80088Config {
            method: SanitizationMethod::Clear,
            verify_level: VerificationLevel::Full,
        }),
        mock_storage::mock_hdd().device_type,
    );

    assert!(shredder.wipe(&file_path).is_ok());
    assert!(!file_path.exists());
}

#[test]
fn test_sparse_file() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("sparse.bin");
    
    // Create a sparse file
    let mut file = File::create(&file_path).unwrap();
    file.set_len(1024 * 1024).unwrap(); // 1MB sparse file
    file.write_all(b"Start").unwrap();
    file.seek(SeekFrom::End(-5)).unwrap();
    file.write_all(b"End").unwrap();
    file.sync_all().unwrap();

    let shredder = Shredder::new(
        WipeStandard::Modern(Nist80088Config {
            method: SanitizationMethod::Clear,
            verify_level: VerificationLevel::Full,
        }),
        mock_storage::mock_hdd().device_type,
    );

    assert!(shredder.wipe(&file_path).is_ok());
    assert!(!file_path.exists());
}

// Different Standards Tests
#[test]
fn test_all_standards() {
    let standards = vec![
        WipeStandard::Modern(Nist80088Config {
            method: SanitizationMethod::Clear,
            verify_level: VerificationLevel::Full,
        }),
        WipeStandard::Modern(Nist80088Config {
            method: SanitizationMethod::Purge,
            verify_level: VerificationLevel::Enhanced,
        }),
        WipeStandard::Legacy(LegacyConfig {
            standard: LegacyStandard::Dod522022M,
            extra_verification: true,
        }),
        WipeStandard::Legacy(LegacyConfig {
            standard: LegacyStandard::Gutmann,
            extra_verification: true,
        }),
        WipeStandard::Legacy(LegacyConfig {
            standard: LegacyStandard::VsitrStandard,
            extra_verification: true,
        }),
    ];

    for standard in standards {
        let dir = tempdir().unwrap();
        let file_path = create_test_file(dir.path(), 4096).unwrap();
        
        let shredder = Shredder::new(
            standard.clone(),
            mock_storage::mock_hdd().device_type,
        );

        assert!(shredder.wipe(&file_path).is_ok(), 
            "Failed with standard: {:?}", standard);
        assert!(!file_path.exists());
    }
}

// Custom Pattern Tests
#[test]
fn test_custom_patterns() {
    let patterns = vec![
        vec![0x55], // Single byte
        vec![0x55, 0xAA], // Alternating
        vec![0x00, 0xFF, 0x55, 0xAA], // Complex pattern
        vec![0x12; 1024], // Large pattern
    ];

    for pattern in patterns {
        let dir = tempdir().unwrap();
        let file_path = create_test_file(dir.path(), 4096).unwrap();
        
        let shredder = Shredder::new(
            WipeStandard::Custom(WipeConfig {
                passes: vec![WipePattern::Custom(pattern.clone())],
                verify_each_pass: true,
            }),
            mock_storage::mock_hdd().device_type,
        );

        assert!(shredder.wipe(&file_path).is_ok(),
            "Failed with pattern: {:?}", pattern);
        assert!(!file_path.exists());
    }
}

// Storage Type Tests
#[test]
fn test_different_storage_types() {
    let storage_types = vec![
        mock_storage::mock_hdd(),
        mock_storage::mock_ssd(),
        mock_storage::mock_flash(),
    ];

    for storage_info in storage_types {
        let dir = tempdir().unwrap();
        let file_path = create_test_file(dir.path(), 4096).unwrap();
        
        let shredder = Shredder::new(
            WipeStandard::Modern(Nist80088Config {
                method: SanitizationMethod::Clear,
                verify_level: VerificationLevel::Full,
            }),
            storage_info.device_type.clone(),
        );

        assert!(shredder.wipe(&file_path).is_ok(),
            "Failed with storage type: {:?}", storage_info.device_type);
        assert!(!file_path.exists());
    }
}

#[test]
fn test_buffer_size_configuration() {
    let dir = tempdir().unwrap();
    
    // Test with small buffer (using smaller test file)
    {
        let file_path = create_test_file(dir.path(), 64 * 1024).unwrap(); // 64KB file
        let small_buffer_size = 4 * 1024; // 4KB
        let shredder = Shredder::new(
            WipeStandard::Modern(Nist80088Config {
                method: SanitizationMethod::Clear,
                verify_level: VerificationLevel::Basic,
            }),
            mock_storage::mock_hdd().device_type,
        ).with_buffer_size(small_buffer_size);

        // Verify initial file content
        {
            let metadata = std::fs::metadata(&file_path).unwrap();
            println!("Initial file size: {}", metadata.len());
        }

        assert_eq!(shredder.get_buffer_size(), small_buffer_size);
        match shredder.wipe(&file_path) {
            Ok(()) => assert!(!file_path.exists(), "File should be deleted"),
            Err(e) => {
                if file_path.exists() {
                    let content = std::fs::read(&file_path).unwrap_or_default();
                    panic!("Failed to wipe with small buffer: {}. File size: {}, First few bytes: {:?}", 
                        e, content.len(), &content[..std::cmp::min(16, content.len())]);
                } else {
                    panic!("Failed to wipe with small buffer: {}. File no longer exists.", e);
                }
            }
        }
    }

    // Test with large buffer
    {
        let file_path = create_test_file(dir.path(), 64 * 1024).unwrap(); // 64KB file
        let large_buffer_size = 8 * 1024; // 8KB
        let shredder = Shredder::new(
            WipeStandard::Modern(Nist80088Config {
                method: SanitizationMethod::Clear,
                verify_level: VerificationLevel::Basic,
            }),
            mock_storage::mock_hdd().device_type,
        ).with_buffer_size(large_buffer_size);

        assert_eq!(shredder.get_buffer_size(), large_buffer_size);
        match shredder.wipe(&file_path) {
            Ok(()) => assert!(!file_path.exists(), "File should be deleted"),
            Err(e) => {
                if file_path.exists() {
                    let content = std::fs::read(&file_path).unwrap_or_default();
                    panic!("Failed to wipe with large buffer: {}. File size: {}, First few bytes: {:?}", 
                        e, content.len(), &content[..std::cmp::min(16, content.len())]);
                } else {
                    panic!("Failed to wipe with large buffer: {}. File no longer exists.", e);
                }
            }
        }
    }

    // Test buffer size clamping
    {
        let file_path = create_test_file(dir.path(), 4096).unwrap(); // 4KB file
        let shredder = Shredder::new(
            WipeStandard::Modern(Nist80088Config {
                method: SanitizationMethod::Clear,
                verify_level: VerificationLevel::Basic,
            }),
            mock_storage::mock_hdd().device_type,
        ).with_buffer_size(1024); // Too small, should be clamped to 4KB

        assert_eq!(shredder.get_buffer_size(), 4 * 1024);
        match shredder.wipe(&file_path) {
            Ok(()) => assert!(!file_path.exists(), "File should be deleted"),
            Err(e) => {
                if file_path.exists() {
                    let content = std::fs::read(&file_path).unwrap_or_default();
                    panic!("Failed to wipe with clamped buffer: {}. File size: {}, First few bytes: {:?}", 
                        e, content.len(), &content[..std::cmp::min(16, content.len())]);
                } else {
                    panic!("Failed to wipe with clamped buffer: {}. File no longer exists.", e);
                }
            }
        }
    }
}