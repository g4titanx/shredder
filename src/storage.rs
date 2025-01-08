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
        use std::fs::read_to_string;
        use std::path::PathBuf;

        // Get canonical path to resolve symlinks
        let canonical_path = std::fs::canonicalize(path)?;

        // Extract device name from path (e.g., /dev/sda1 -> sda)
        let device_name = canonical_path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| {
                if name.starts_with("nvme") {
                    Some(name.split('p').next().unwrap_or(name))
                } else {
                    Some(name.trim_end_matches(char::is_numeric))
                }
            })
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::Other, "Unable to determine device name")
            })?;

        // Construct sysfs path
        let sysfs_path = PathBuf::from("/sys/block").join(device_name);

        // Read rotational status (0 for SSD, 1 for HDD)
        let rotational_str = read_to_string(sysfs_path.join("queue/rotational"))?;
        let rotational = rotational_str.trim().parse::<u8>()?;

        // Read device identifier
        let device_id = read_to_string(sysfs_path.join("device/model"))
            .unwrap_or_else(|_| String::from("Unknown"));

        // Determine if NVMe
        let is_nvme = device_name.starts_with("nvme");

        // Read block size
        let block_size_str = read_to_string(sysfs_path.join("queue/logical_block_size"))?;
        let block_size = block_size_str.trim().parse::<usize>()?;

        // Read device size in bytes
        let size_str = read_to_string(sysfs_path.join("size"))?;
        let total_size = size_str.trim().parse::<u64>()? * 512; // size is in 512-byte sectors

        // Create appropriate StorageCapabilities based on device type
        let storage_type = if rotational == 1 {
            StorageType::Hdd(StorageCapabilities {
                supports_trim: false,
                supports_secure_erase: true,
                supports_nvme_sanitize: false,
                has_wear_leveling: false,
            })
        } else if is_nvme {
            StorageType::Ssd(StorageCapabilities {
                supports_trim: true,
                supports_secure_erase: true,
                supports_nvme_sanitize: true,
                has_wear_leveling: true,
            })
        } else {
            StorageType::Ssd(StorageCapabilities {
                supports_trim: true,
                supports_secure_erase: true,
                supports_nvme_sanitize: false,
                has_wear_leveling: true,
            })
        };

        Ok(StorageInfo {
            device_type: storage_type,
            block_size,
            total_size,
        })
    }

    /// macOS-specific storage detection implementation
    #[cfg(target_os = "macos")]
    fn detect_storage_macos(path: &Path) -> Result<StorageInfo> {
        use std::process::Command;
        use std::str;

        // get the volume name from path
        let canonical_path = std::fs::canonicalize(path)?;
        let volume_name = canonical_path
            .components()
            .find(|c| {
                if let std::path::Component::Normal(name) = c {
                    name.to_str().map_or(false, |s| s.starts_with("/Volumes/"))
                } else {
                    false
                }
            })
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::Other, "Unable to determine volume")
            })?;

        // run diskutil info command
        let output = Command::new("diskutil")
            .arg("info")
            .arg(volume_name)
            .output()?;

        let info = str::from_utf8(&output.stdout)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // parse diskutil output
        let is_solid_state = info.contains("Solid State: Yes");
        let is_removable = info.contains("Removable Media: Yes");

        // get block size
        let block_size = info
            .lines()
            .find(|line| line.contains("Device Block Size"))
            .and_then(|line| line.split(':').nth(1))
            .and_then(|size| size.trim().split_whitespace().next())
            .and_then(|num| num.parse().ok())
            .unwrap_or(4096);

        // get total size
        let total_size = info
            .lines()
            .find(|line| line.contains("Total Size"))
            .and_then(|line| line.split(':').nth(1))
            .and_then(|size| size.trim().split_whitespace().next())
            .and_then(|num| num.parse().ok())
            .unwrap_or(0);

        // determine storage type
        let storage_type = if is_removable {
            StorageType::Flash(StorageCapabilities {
                supports_trim: false,
                supports_secure_erase: false,
                supports_nvme_sanitize: false,
                has_wear_leveling: true,
            })
        } else if is_solid_state {
            StorageType::Ssd(StorageCapabilities {
                supports_trim: true,
                supports_secure_erase: true,
                supports_nvme_sanitize: false,
                has_wear_leveling: true,
            })
        } else {
            StorageType::Hdd(StorageCapabilities {
                supports_trim: false,
                supports_secure_erase: true,
                supports_nvme_sanitize: false,
                has_wear_leveling: false,
            })
        };

        Ok(StorageInfo {
            device_type: storage_type,
            block_size,
            total_size,
        })
    }

    /// windows-specific storage detection implementation
    #[cfg(target_os = "windows")]
    fn detect_storage_windows(path: &Path) -> Result<StorageInfo> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::fs::OpenOptionsExt;
        use std::ptr;
        use winapi::um::fileapi::{CreateFileW, GetDriveTypeW};
        use winapi::um::handleapi::INVALID_HANDLE_VALUE;
        use winapi::um::winioctl::{
            PropertyStandardQuery, StorageDeviceProperty, STORAGE_DEVICE_DESCRIPTOR,
            STORAGE_PROPERTY_QUERY, STORAGE_QUERY_TYPE,
        };
        use winapi::um::winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE};

        // get the root path (e.g., C:\ from C:\path\to\file)
        let root_path = path
            .ancestors()
            .find(|p| p.parent().is_none())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::Other, "Unable to determine root path")
            })?;

        // convert path to wide string for Windows API
        let root_path_str = root_path.to_str().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "Invalid path encoding")
        })?;
        let wide_path: Vec<u16> = OsStr::new(root_path_str)
            .encode_wide()
            .chain(Some(0))
            .collect();

        // get drive type
        let drive_type = unsafe { GetDriveTypeW(wide_path.as_ptr()) };

        // open the volume
        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null_mut(),
                3, // OPEN_EXISTING
                0,
                ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error().into());
        }

        // query storage device descriptor
        let mut query = STORAGE_PROPERTY_QUERY {
            PropertyId: StorageDeviceProperty,
            QueryType: PropertyStandardQuery,
            AdditionalParameters: [0u8; 1],
        };

        let mut descriptor: STORAGE_DEVICE_DESCRIPTOR = unsafe { std::mem::zeroed() };
        let mut bytes_returned = 0u32;

        // based on the drive type and device descriptor, determine storage type
        let storage_type = match drive_type {
            2 /* DRIVE_REMOVABLE */ => StorageType::Flash(StorageCapabilities {
                supports_trim: false,
                supports_secure_erase: false,
                supports_nvme_sanitize: false,
                has_wear_leveling: true,
            }),
            3 /* DRIVE_FIXED */ => {
                // Default to SSD with modern capabilities
                StorageType::Ssd(StorageCapabilities {
                    supports_trim: true,
                    supports_secure_erase: true,
                    supports_nvme_sanitize: false,
                    has_wear_leveling: true,
                })
            },
            _ => StorageType::Hdd(StorageCapabilities {
                supports_trim: false,
                supports_secure_erase: true,
                supports_nvme_sanitize: false,
                has_wear_leveling: false,
            }),
        };

        Ok(StorageInfo {
            device_type: storage_type,
            block_size: 4096, // default to 4K sectors for modern drives
            total_size: 0,    // would need additional API calls to determine
        })
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
