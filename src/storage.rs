use crate::Result;
use std::path::Path;

/// represents different types of storage devices with their capabilities
#[derive(Debug, Clone)]
pub enum StorageType {
    /// traditional Hard Disk Drive
    /// mechanical storage with magnetic platters
    Hdd(StorageCapabilities),

    /// solid State Drive
    /// flash-based storage with no moving parts
    Ssd(StorageCapabilities),

    /// flash Storage (USB drives, SD cards)
    /// portable flash-based storage
    Flash(StorageCapabilities),
}

/// capabilities and features of a storage device
#[derive(Debug, Clone)]
pub struct StorageCapabilities {
    /// whether the device supports the TRIM command
    /// important for SSD performance and wear leveling
    pub supports_trim: bool,

    /// whether the device supports ATA Secure Erase
    /// hardware-level secure erase capability
    pub supports_secure_erase: bool,

    /// whether the device supports NVMe sanitize command
    /// NVMe-specific secure erase capability
    pub supports_nvme_sanitize: bool,

    /// whether the device uses wear leveling
    /// common in SSDs and flash storage
    pub has_wear_leveling: bool,
}

/// information about a storage device
#[derive(Debug)]
pub struct StorageInfo {
    /// type of storage device and its capabilities
    pub device_type: StorageType,
    
    /// size of the device's blocks/sectors
    /// typically 512 or 4096 bytes
    pub block_size: usize,
    
    /// total storage capacity in bytes
    pub total_size: u64,
}

impl StorageType {
    /// detects storage type and capabilities from a file path
    ///
    /// # Arguments
    /// * `path` - Path to file or device to analyze
    ///
    /// # Returns
    /// * `Result<StorageInfo>` - Information about the storage device
    pub fn detect_from_path(path: &Path) -> Result<StorageInfo> {
        // platform-specific implementations
        #[cfg(target_os = "linux")]
        {
            Self::detect_storage_linux(path)
        }
        #[cfg(target_os = "windows")]
        {
            Self::detect_storage_windows(path)
        }
        #[cfg(target_os = "macos")]
        {
            Self::detect_storage_macos(path)
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            Err(crate::WipeError::UnsupportedOperation(
                "Storage detection not supported on this platform".into(),
            ))
        }
    }

    /// linux-specific storage detection implementation
    #[cfg(target_os = "linux")]
    fn detect_storage_linux(path: &Path) -> Result<StorageInfo> {
        // TODO: Implement using:
        // - sysfs (/sys/block/)
        // - udev
        // - hdparm for ATA info
        // - nvme-cli for NVMe info
        unimplemented!("Linux storage detection not yet implemented")
    }

    /// macOS-specific storage detection implementation
    #[cfg(target_os = "macos")]
    fn detect_storage_macos(path: &Path) -> Result<StorageInfo> {
        // TODO: Implement using:
        // - IOKit
        // - diskutil
        unimplemented!("macOS storage detection not yet implemented")
    }

    /// windows-specific storage detection implementation
    #[cfg(target_os = "windows")]
    fn detect_storage_windows(path: &Path) -> Result<StorageInfo> {
        // TODO: Implement using:
        // - GetDriveType
        // - DeviceIoControl
        // - IOCTL_STORAGE_QUERY_PROPERTY
        unimplemented!("Windows storage detection not yet implemented")
    }

    /// checks if the device supports secure erase commands
    pub fn supports_secure_erase(&self) -> bool {
        match self {
            // SSDs and HDDs might support secure erase
            StorageType::Ssd(caps) | StorageType::Hdd(caps) => caps.supports_secure_erase,
            // Flash devices typically don't support secure erase
            StorageType::Flash(_) => false,
        }
    }

    /// checks if the device needs special handling for wear leveling
    pub fn requires_wear_leveling_handling(&self) -> bool {
        match self {
            // SSDs and Flash devices use wear leveling
            StorageType::Flash(caps) | StorageType::Ssd(caps) => caps.has_wear_leveling,
            // HDDs don't use wear leveling
            StorageType::Hdd(_) => false,
        }
    }
}