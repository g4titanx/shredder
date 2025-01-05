use std::fs::{self, File};
use std::io::{self, Write, Read};
use std::path::{Path, PathBuf};
use tempfile::{tempdir, TempDir};
use rand::{thread_rng, RngCore};

/// creates a test file with specific content and size
pub fn create_test_file(dir: &Path, size: usize) -> io::Result<PathBuf> {
    let file_path = dir.join(format!("test_file_{}.bin", size));
    let mut file = File::create(&file_path)?;
    let mut buffer = vec![0u8; 1024]; // 1KB chunks
    let mut remaining = size;

    while remaining > 0 {
        thread_rng().fill_bytes(&mut buffer);
        let write_size = std::cmp::min(remaining, buffer.len());
        file.write_all(&buffer[..write_size])?;
        remaining -= write_size;
    }

    file.sync_all()?;
    Ok(file_path)
}

/// creates a test file with a specific pattern
#[allow(dead_code)]
pub fn create_pattern_file(dir: &Path, pattern: &[u8], size: usize) -> io::Result<PathBuf> {
    let file_path = dir.join(format!("pattern_file_{}.bin", size));
    let mut file = File::create(&file_path)?;
    let mut remaining = size;

    while remaining > 0 {
        let write_size = std::cmp::min(remaining, pattern.len());
        file.write_all(&pattern[..write_size])?;
        remaining -= write_size;
    }

    file.sync_all()?;
    Ok(file_path)
}

/// attempts to read file content after deletion
#[allow(dead_code)]
pub fn try_read_deleted_file(path: &Path) -> io::Result<bool> {
    match File::open(path) {
        Ok(mut file) => {
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            Ok(!buffer.is_empty())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// verifies that a file contains a specific pattern
#[allow(dead_code)]
pub fn verify_file_pattern(path: &Path, pattern: &[u8]) -> io::Result<bool> {
    let mut file = File::open(path)?;
    let mut buffer = vec![0u8; pattern.len()];

    while let Ok(n) = file.read(&mut buffer) {
        if n == 0 {
            break;
        }
        if &buffer[..n] != &pattern[..n] {
            return Ok(false);
        }
    }

    Ok(true)
}

/// creates a mock directory structure for testing
#[allow(dead_code)]
pub fn create_test_directory() -> io::Result<(TempDir, Vec<PathBuf>)> {
    let dir = tempdir()?;
    let mut files = Vec::new();

    // Create various test files
    files.push(create_test_file(&dir.path(), 1024)?); // 1KB
    files.push(create_test_file(&dir.path(), 1024 * 1024)?); // 1MB
    files.push(create_pattern_file(&dir.path(), &[0xAA; 1024], 4096)?); // 4KB pattern

    // Create a subdirectory with files
    let subdir = dir.path().join("subdir");
    fs::create_dir(&subdir)?;
    files.push(create_test_file(&subdir, 2048)?);

    Ok((dir, files))
}

/// simulates different storage types for testing
#[cfg(test)]
pub mod mock_storage {
    use shredder::storage::{StorageType, StorageCapabilities, StorageInfo};

    pub fn mock_hdd() -> StorageInfo {
        StorageInfo {
            device_type: StorageType::Hdd(StorageCapabilities {
                supports_trim: false,
                supports_secure_erase: true,
                supports_nvme_sanitize: false,
                has_wear_leveling: false,
            }),
            block_size: 512,
            total_size: 1024 * 1024 * 1024, // 1GB
        }
    }

    pub fn mock_ssd() -> StorageInfo {
        StorageInfo {
            device_type: StorageType::Ssd(StorageCapabilities {
                supports_trim: true,
                supports_secure_erase: true,
                supports_nvme_sanitize: true,
                has_wear_leveling: true,
            }),
            block_size: 4096,
            total_size: 1024 * 1024 * 1024, // 1GB
        }
    }

    pub fn mock_flash() -> StorageInfo {
        StorageInfo {
            device_type: StorageType::Flash(StorageCapabilities {
                supports_trim: false,
                supports_secure_erase: false,
                supports_nvme_sanitize: false,
                has_wear_leveling: true,
            }),
            block_size: 4096,
            total_size: 1024 * 1024 * 1024, // 1GB
        }
    }
}