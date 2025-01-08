pub mod patterns; // contains wiping patterns (Zeros, Ones, Random)
mod secure_erase;
pub mod standards; // contains wiping standards (DoD, NIST, etc.)
pub mod storage; // storage device type detection and handling
mod trim;

use log::{debug, info, warn};
use patterns::WipePattern;
use standards::{SanitizationMethod, VerificationLevel, WipeStandard};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use storage::StorageType;
use thiserror::Error;

/// represents various errors that can occur during secure deletion
#[derive(Error, Debug)]
pub enum WipeError {
    /// wraps standard I/O errors with automatic conversion
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// indicates data verification after wiping failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// indicates when an operation isn't supported (e.g., on certain platforms)
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),

    /// parsing error for numeric values
    #[error("Parse error: {0}")]
    Parse(#[from] std::num::ParseIntError),
}

/// type alias for Result with our custom WipeError
pub type Result<T> = std::result::Result<T, WipeError>;

/// main struct for secure file deletion operations
pub struct Shredder {
    /// the wiping standard to use (e.g., NIST 800-88, DoD 5220.22-M)
    standard: WipeStandard,

    /// type of storage device being written to
    storage_type: StorageType,

    /// size of the buffer used for writing operations (default: 1MB)
    buffer_size: usize,
}

impl Shredder {
    /// creates a new Shredder instance with specified standard and storage type
    ///
    /// # Arguments
    /// * `standard` - The wiping standard to use
    /// * `storage_type` - The type of storage device being written to
    pub fn new(standard: WipeStandard, storage_type: StorageType) -> Self {
        Self {
            standard,
            storage_type,
            buffer_size: 1024 * 1024, // 1MB default for optimal I/O performance
        }
    }

    /// securely wipes a file using the configured standard
    ///
    /// # Arguments
    /// * `path` - Path to the file to be wiped
    ///
    /// # Returns
    /// * `Result<()>` - Success or error status
    pub fn wipe<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        match &self.standard {
            WipeStandard::Modern(config) => self.perform_modern_wipe(path.as_ref(), config),
            WipeStandard::Legacy(config) => self.perform_legacy_wipe(path.as_ref(), config),
            WipeStandard::Custom(config) => self.perform_custom_wipe(path.as_ref(), config),
        }
    }

    /// implements NIST 800-88 compliant wiping
    fn perform_modern_wipe<P: AsRef<Path>>(
        &self,
        path: P,
        config: &standards::Nist80088Config,
    ) -> Result<()> {
        let path = path.as_ref();
        info!("Starting modern wipe for: {}", path.display());

        // open file with write permissions
        let mut file = OpenOptions::new().write(true).read(true).open(path)?;

        // Get file size for verification
        let file_size = file.metadata()?.len();
        debug!("File size: {} bytes", file_size);

        // create buffer sized according to storage characteristics
        let buffer_size = self.calculate_optimal_buffer_size(file_size);
        let mut buffer = vec![0u8; buffer_size];

        // if SSD/Flash, handle wear leveling
        if self.storage_type.requires_wear_leveling_handling() {
            debug!("Storage device requires wear leveling handling");
            self.handle_wear_leveling(&mut file)?;
        }

        match config.method {
            SanitizationMethod::Clear => {
                // single pass of random data for Clear method
                debug!("Performing Clear operation with random data");
                WipePattern::Random.fill_buffer(&mut buffer);
                self.overwrite_file_contents(&mut file, &buffer, file_size)?;
            }
            SanitizationMethod::Purge => {
                // for Purge, try hardware-based secure erase first
                if self.storage_type.supports_secure_erase() {
                    debug!("Attempting hardware-based secure erase");
                    if let Err(e) = self.perform_hardware_secure_erase(path) {
                        warn!(
                            "Hardware secure erase failed: {}, falling back to software method",
                            e
                        );
                        self.perform_purge_overwrite(&mut file, &mut buffer, file_size)?;
                    }
                } else {
                    debug!("No hardware secure erase support, using software method");
                    self.perform_purge_overwrite(&mut file, &mut buffer, file_size)?;
                }
            }
        }

        // verify wiping if required
        if config.verify_level != VerificationLevel::None {
            debug!(
                "Performing verification at level: {:?}",
                config.verify_level
            );
            self.verify_wiping(&mut file, &buffer, config.verify_level)?;
        }

        // ensure all writes are synced to disk
        file.sync_all()?;
        debug!("File contents synced to disk");

        // drop file handle before removal
        drop(file);

        // remove file after successful wiping
        std::fs::remove_file(path)?;
        info!("File successfully wiped and removed");

        Ok(())
    }

    /// implements legacy standard wiping (DoD, Gutmann, etc.)
    fn perform_legacy_wipe<P: AsRef<Path>>(
        &self,
        path: P,
        config: &standards::LegacyConfig,
    ) -> Result<()> {
        let path = path.as_ref();
        info!("Starting legacy wipe using standard: {:?}", config.standard);

        // get wiping patterns for the selected standard
        let patterns = config.standard.get_patterns();
        debug!("Using {} pass wiping pattern", patterns.len());

        // open file with write permissions
        let mut file = OpenOptions::new().write(true).read(true).open(path)?;

        let file_size = file.metadata()?.len();
        let buffer_size = self.calculate_optimal_buffer_size(file_size);
        let mut buffer = vec![0u8; buffer_size];

        // perform each pass
        for (i, pattern) in patterns.iter().enumerate() {
            debug!("Starting pass {}/{}", i + 1, patterns.len());
            pattern.fill_buffer(&mut buffer);
            self.overwrite_file_contents(&mut file, &buffer, file_size)?;

            // verify after each pass if requested
            if config.extra_verification {
                debug!("Performing verification after pass {}", i + 1);
                self.verify_wiping(&mut file, &buffer, VerificationLevel::Basic)?;
            }
        }

        // final verification if requested
        if config.extra_verification {
            debug!("Performing final full verification");
            self.verify_wiping(&mut file, &buffer, VerificationLevel::Full)?;
        }

        // sync and remove file
        file.sync_all()?;
        drop(file);
        std::fs::remove_file(path)?;
        info!("Legacy wipe completed successfully");

        Ok(())
    }

    /// implements custom wiping patterns
    fn perform_custom_wipe<P: AsRef<Path>>(
        &self,
        path: P,
        config: &standards::WipeConfig,
    ) -> Result<()> {
        let path = path.as_ref();
        info!("Starting custom wipe with {} passes", config.passes.len());

        let mut file = OpenOptions::new().write(true).read(true).open(path)?;

        let file_size = file.metadata()?.len();
        let buffer_size = self.calculate_optimal_buffer_size(file_size);
        let mut buffer = vec![0u8; buffer_size];

        // apply each custom pattern
        for (i, pattern) in config.passes.iter().enumerate() {
            debug!("Starting custom pass {}/{}", i + 1, config.passes.len());
            pattern.fill_buffer(&mut buffer);
            self.overwrite_file_contents(&mut file, &buffer, file_size)?;

            if config.verify_each_pass {
                debug!("Verifying pass {}", i + 1);
                self.verify_wiping(&mut file, &buffer, VerificationLevel::Full)?;
            }
        }

        file.sync_all()?;
        drop(file);
        std::fs::remove_file(path)?;
        info!("Custom wipe completed successfully");

        Ok(())
    }

    /// overwrites file contents with provided buffer
    fn overwrite_file_contents(
        &self,
        file: &mut File,
        pattern: &[u8],
        file_size: u64,
    ) -> Result<()> {
        // Create a buffer sized according to our buffer_size setting
        let mut write_buffer = vec![0u8; self.buffer_size];

        file.seek(SeekFrom::Start(0))?;
        let mut written = 0u64;

        while written < file_size {
            // Fill write buffer with pattern
            for chunk in write_buffer.chunks_mut(pattern.len()) {
                let len = std::cmp::min(chunk.len(), pattern.len());
                chunk[..len].copy_from_slice(&pattern[..len]);
            }

            let remaining = file_size - written;
            let write_size = std::cmp::min(remaining as usize, write_buffer.len());

            // Write and verify immediately
            file.write_all(&write_buffer[..write_size])?;
            file.flush()?;

            // Verify this chunk
            file.seek(SeekFrom::Start(written))?;
            let mut verify_buffer = vec![0u8; write_size];
            file.read_exact(&mut verify_buffer)?;

            if verify_buffer != write_buffer[..write_size] {
                return Err(WipeError::VerificationFailed(format!(
                    "Immediate verification failed at offset {}",
                    written
                )));
            }

            written += write_size as u64;
        }

        // Final flush and sync to ensure all writes are on disk
        file.flush()?;
        file.sync_all()?;

        Ok(())
    }

    /// performs the Purge-level overwrite sequence
    fn perform_purge_overwrite(
        &self,
        file: &mut File,
        buffer: &mut [u8],
        file_size: u64,
    ) -> Result<()> {
        // multiple passes for Purge method
        let patterns = [
            WipePattern::Random, // random data pass
            WipePattern::Zeros,  // zero pass
            WipePattern::Ones,   // ones pass
            WipePattern::Random, // final random pass
        ];

        for (i, pattern) in patterns.iter().enumerate() {
            debug!("Starting purge pass {}/{}", i + 1, patterns.len());
            pattern.fill_buffer(buffer);
            self.overwrite_file_contents(file, buffer, file_size)?;
        }

        Ok(())
    }

    /// calculates optimal buffer size based on file size and system memory
    fn calculate_optimal_buffer_size(&self, file_size: u64) -> usize {
        let max_buffer = 8 * 1024 * 1024; // 8MB max
        let min_buffer = 4 * 1024; // 4KB min (typical page size)

        // use smaller buffer for small files
        if file_size < min_buffer as u64 {
            return file_size as usize;
        }

        // scale buffer with file size, but cap at max_buffer
        std::cmp::min(
            max_buffer,
            std::cmp::max(
                min_buffer,
                (file_size / 100) as usize, // Use ~1% of file size
            ),
        )
    }

    /// verifies the wiping operation
    fn verify_wiping(
        &self,
        file: &mut File,
        expected_pattern: &[u8],
        level: VerificationLevel,
    ) -> Result<()> {
        match level {
            VerificationLevel::None => Ok(()),
            VerificationLevel::Basic => {
                // sample ~1% of file at random locations
                let file_size = file.metadata()?.len();
                if file_size == 0 {
                    return Ok(()); // Empty file is considered verified
                }

                let mut verify_buf = vec![0u8; expected_pattern.len()];
                let samples = std::cmp::max((file_size / 100) as usize, 1); // At least 1 sample

                for _ in 0..samples {
                    // ensure we don't exceed file size - pattern length
                    let max_offset = file_size.saturating_sub(expected_pattern.len() as u64);
                    if max_offset == 0 {
                        break; // File is too small for pattern verification
                    }

                    let offset = rand::random::<u64>() % max_offset;
                    file.seek(SeekFrom::Start(offset))?;
                    file.read_exact(&mut verify_buf)?;

                    if verify_buf != expected_pattern {
                        return Err(WipeError::VerificationFailed(format!(
                            "Pattern mismatch at offset {}",
                            offset
                        )));
                    }
                }
                Ok(())
            }
            VerificationLevel::Full | VerificationLevel::Enhanced => {
                // verify entire file
                file.seek(SeekFrom::Start(0))?;
                let mut verify_buf = vec![0u8; expected_pattern.len()];

                if file.metadata()?.len() == 0 {
                    return Ok(()); // empty file is considered verified
                }

                loop {
                    match file.read_exact(&mut verify_buf) {
                        Ok(_) => {
                            if verify_buf != expected_pattern {
                                return Err(WipeError::VerificationFailed(
                                    "Pattern mismatch during full verification".into(),
                                ));
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                        Err(e) => return Err(e.into()),
                    }
                }
                Ok(())
            }
        }
    }

    /// attempts to perform hardware-based secure erase
    fn perform_hardware_secure_erase<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        secure_erase::perform_secure_erase(path.as_ref())
    }

    /// performs TRIM operation for SSDs
    fn perform_trim_operation(&self, file: &mut File) -> Result<()> {
        trim::perform_trim(file)
    }

    /// handles wear leveling for SSDs and Flash storage
    fn handle_wear_leveling(&self, file: &mut File) -> Result<()> {
        // for SSDs/Flash, first try TRIM if available
        if let StorageType::Ssd(caps) | StorageType::Flash(caps) = &self.storage_type {
            if caps.supports_trim {
                debug!("Attempting TRIM operation");
                self.perform_trim_operation(file)?;
            }
        }
        Ok(())
    }

    /// sets the buffer size for I/O operations
    ///
    /// # Arguments
    /// * `size` - The new buffer size in bytes (minimum 4KB, maximum 16MB)
    ///
    /// # Returns
    /// the shredder instance for method chaining
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        const MIN_BUFFER: usize = 4 * 1024; // 4KB
        const MAX_BUFFER: usize = 16 * 1024 * 1024; // 16MB

        self.buffer_size = size.clamp(MIN_BUFFER, MAX_BUFFER);
        self
    }

    /// gets the current buffer size
    pub fn get_buffer_size(&self) -> usize {
        self.buffer_size
    }
}
