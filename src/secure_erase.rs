use crate::Result;
use std::path::Path;

#[cfg(target_os = "linux")]
pub fn perform_secure_erase(path: &Path) -> Result<()> {
    use std::process::Command;
    use std::fs::read_to_string;
    use std::os::unix::fs::MetadataExt;

    // check for root privileges
    if unsafe { libc::geteuid() } != 0 {
        return Err(crate::WipeError::UnsupportedOperation(
            "Root privileges required for secure erase operations".into()
        ));
    }

    // check if it's a system disk
    let is_system = is_linux_system_disk(path)?;
    if is_system {
        return Err(crate::WipeError::UnsupportedOperation(
            "Cannot securely erase the system disk while system is running".into()
        ));
    }

    // get device information
    let device_info = get_linux_device_info(path)?;
    log::info!("Detected device: {}", device_info);

    // attempt NVME sanitize if applicable
    if device_info.contains("NVMe") {
        log::info!("Attempting NVMe sanitize...");
        let nvme_result = Command::new("nvme")
            .args(["format", path.to_str().unwrap()])
            .output();

        if let Ok(output) = nvme_result {
            if output.status.success() {
                return Ok(());
            }
        }
    }

    // fallback to hdparm
    log::info!("Attempting ATA secure erase via hdparm...");
    let output = Command::new("hdparm")
        .args(["--security-erase", path.to_str().unwrap()])
        .output()?;

    if output.status.success() {
        Ok(())
    } else {
        Err(crate::WipeError::UnsupportedOperation(
            String::from_utf8_lossy(&output.stderr).into_owned()
        ))
    }
}

#[cfg(target_os = "linux")]
fn is_linux_system_disk(path: &Path) -> Result<bool> {
    use std::fs::read_link;
    
    // Read /proc/mounts to find root partition
    let mounts = std::fs::read_to_string("/proc/mounts")?;
    let root_device = mounts.lines()
        .find(|line| line.split_whitespace().nth(1) == Some("/"))
        .and_then(|line| line.split_whitespace().next())
        .ok_or_else(|| std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not determine root device"
        ))?;

    // Resolve symbolic links
    let root_device = read_link(root_device).unwrap_or_else(|_| Path::new(root_device).to_path_buf());
    let target_device = read_link(path).unwrap_or_else(|_| path.to_path_buf());

    Ok(root_device == target_device)
}

#[cfg(target_os = "linux")]
fn get_linux_device_info(path: &Path) -> Result<String> {
    // Try reading from /sys/block/device/model
    let device_name = path.file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid device path"
        ))?;

    let sys_path = Path::new("/sys/block")
        .join(device_name)
        .join("device");

    let model = read_to_string(sys_path.join("model")).unwrap_or_default();
    let vendor = read_to_string(sys_path.join("vendor")).unwrap_or_default();
    let transport = read_to_string(sys_path.join("transport")).unwrap_or_default();

    Ok(format!("{} {} ({})", 
        vendor.trim(), 
        model.trim(), 
        transport.trim()
    ))
}

#[cfg(target_os = "macos")]
pub fn perform_secure_erase(path: &Path) -> Result<()> {
    use std::process::Command;

    // Check for root privileges
    if unsafe { libc::geteuid() } != 0 {
        return Err(crate::WipeError::UnsupportedOperation(
            "Root privileges required for secure erase operations".into()
        ));
    }

    // Get disk information
    let device_info = get_macos_device_info(path)?;
    log::info!("Detected device: {}", device_info);

    // Check if it's a system disk
    if is_macos_system_disk(path)? {
        return Err(crate::WipeError::UnsupportedOperation(
            "Cannot securely erase the system disk while system is running".into()
        ));
    }

    // Get disk identifier (disk0, disk1, etc.)
    let disk_id = path.file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid device path"
        ))?;

    // First try secure erase with crypto commands if supported
    log::info!("Attempting cryptographic erase...");
    let crypto_result = Command::new("diskutil")
        .args(["secureErase", "4", disk_id])  // 4 = cryptographic erase
        .output();

    if let Ok(output) = crypto_result {
        if output.status.success() {
            return Ok(());
        }
    }

    // Fallback to standard secure erase
    log::info!("Falling back to standard secure erase...");
    let output = Command::new("diskutil")
        .args(["secureErase", "0", disk_id])  // 0 = single-pass zeros
        .output()?;

    if output.status.success() {
        Ok(())
    } else {
        Err(crate::WipeError::UnsupportedOperation(
            String::from_utf8_lossy(&output.stderr).into_owned()
        ))
    }
}

#[cfg(target_os = "macos")]
fn is_macos_system_disk(path: &Path) -> Result<bool> {
    use std::process::Command;

    // Get boot volume information
    let output = Command::new("diskutil")
        .args(["info", "-plist", "/"])
        .output()?;

    if !output.status.success() {
        return Ok(false);
    }

    // Parse plist output to get boot disk identifier
    let plist = String::from_utf8_lossy(&output.stdout);
    let device_path = path.to_str().unwrap_or("");

    // Simple string search for the device identifier
    // A more robust implementation would use plist parsing
    Ok(plist.contains(device_path))
}

#[cfg(target_os = "macos")]
fn get_macos_device_info(path: &Path) -> Result<String> {
    use std::process::Command;

    let output = Command::new("diskutil")
        .args(["info", "-plist", path.to_str().unwrap()])
        .output()?;

    if !output.status.success() {
        return Ok("Unknown device".into());
    }

    // Simple string extraction
    // A more robust implementation would use plist parsing
    let info = String::from_utf8_lossy(&output.stdout);
    Ok(info.lines()
        .find(|line| line.contains("DeviceModel"))
        .unwrap_or("Unknown device")
        .to_string())
}

#[cfg(target_os = "windows")]
pub fn perform_secure_erase(path: &Path) -> Result<()> {
    use std::os::windows::prelude::*;
    use std::ptr;
    use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING, GetVolumeInformationW};
    use winapi::um::winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE};
    use winapi::um::winioctl::*;
    use winapi::um::handleapi::INVALID_HANDLE_VALUE;
    use winapi::shared::minwindef::DWORD;

    // Safety check: Prevent erasing system drive
    let root_path = get_volume_root(path)?;
    if is_system_drive(&root_path) {
        return Err(crate::WipeError::UnsupportedOperation(
            "Cannot securely erase the system drive while Windows is running".into()
        ));
    }

    // Check for admin privileges
    if !has_admin_privileges() {
        return Err(crate::WipeError::UnsupportedOperation(
            "Administrative privileges required for secure erase operations".into()
        ));
    }

    // Convert path to wide string for Windows API
    let wide_path: Vec<u16> = path.as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();

    // Open device with required access rights
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null_mut(),
            OPEN_EXISTING,
            0,
            ptr::null_mut()
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error().into());
    }

    // Ensure proper cleanup with scopeguard
    let _guard = scopeguard::guard(handle, |h| {
        unsafe { winapi::um::handleapi::CloseHandle(h) };
    });

    // Get device information for logging and verification
    let device_info = get_device_info(handle)?;
    log::info!("Attempting secure erase on device: {:?}", device_info);

    // Try each method in order of preference
    log::info!("Attempting ATA secure erase...");
    if let Ok(()) = try_ata_secure_erase(handle) {
        log::info!("ATA secure erase completed successfully");
        return Ok(());
    }

    log::info!("ATA secure erase not supported or failed, trying NVMe sanitize...");
    if let Ok(()) = try_nvme_sanitize(handle) {
        log::info!("NVMe sanitize completed successfully");
        return Ok(());
    }

    log::info!("Falling back to block erase method...");
    perform_block_erase(handle)
}

/// Attempts ATA secure erase command - most effective for traditional HDDs
#[cfg(target_os = "windows")]
fn try_ata_secure_erase(handle: winapi::um::winnt::HANDLE) -> Result<()> {
    use winapi::um::winioctl::*;
    use winapi::shared::minwindef::DWORD;
    
    // ATA Secure Erase command structure
    #[repr(C, packed)]
    struct ATASecureEraseCmd {
        command_reg: u8,     // 0xF4 for security erase unit
        feature_reg: u8,     // 0 for normal erase, 1 for enhanced
        sector_count: u8,    // 0
        sector_number: u8,   // 0
        cylinder_low: u8,    // 0
        cylinder_high: u8,   // 0
        device_head: u8,     // 0
        reserved: [u8; 9],
    }

    // Check if device supports secure erase
    let supports_secure_erase = check_ata_security_support(handle)?;
    if !supports_secure_erase {
        return Err(crate::WipeError::UnsupportedOperation(
            "Device does not support ATA secure erase".into()
        ));
    }

    let mut cmd = ATASecureEraseCmd {
        command_reg: 0xF4,    // ATA SECURITY ERASE UNIT
        feature_reg: 0,       // Normal erase
        sector_count: 0,
        sector_number: 0,
        cylinder_low: 0,
        cylinder_high: 0,
        device_head: 0,
        reserved: [0; 9],
    };

    let mut bytes_returned: DWORD = 0;

    // Execute the secure erase command
    log::debug!("Executing ATA secure erase command...");
    let success = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_ATA_PASS_THROUGH,
            &mut cmd as *mut _ as *mut _,
            std::mem::size_of::<ATASecureEraseCmd>() as DWORD,
            ptr::null_mut(),
            0,
            &mut bytes_returned,
            ptr::null_mut()
        )
    };

    if success == 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

/// Attempts NVMe sanitize command - most effective for NVMe SSDs
#[cfg(target_os = "windows")]
fn try_nvme_sanitize(handle: winapi::um::winnt::HANDLE) -> Result<()> {
    use winapi::um::winioctl::*;
    use winapi::shared::minwindef::DWORD;

    // NVMe Sanitize command structure
    #[repr(C, packed)]
    struct NVMeSanitizeCmd {
        opcode: u8,      // 0x84 for sanitize command
        flags: u8,       // Command flags
        command_id: u16, // Command identifier
        nsid: u32,       // Namespace identifier
        cdw10: u32,      // Command specific
        cdw11: u32,      // Command specific
        cdw12: u32,      // Command specific
        cdw13: u32,      // Command specific
        cdw14: u32,      // Command specific
        cdw15: u32,      // Command specific
    }

    // Check if device supports NVMe sanitize
    let supports_sanitize = check_nvme_sanitize_support(handle)?;
    if !supports_sanitize {
        return Err(crate::WipeError::UnsupportedOperation(
            "Device does not support NVMe sanitize".into()
        ));
    }

    let mut cmd = NVMeSanitizeCmd {
        opcode: 0x84,        // NVMe Sanitize command
        flags: 0,
        command_id: 0,
        nsid: 0xFFFFFFFF,    // All namespaces
        cdw10: 0x00000002,   // Block Erase action
        cdw11: 0,            // No Deallocate After Sanitize
        cdw12: 0,
        cdw13: 0,
        cdw14: 0,
        cdw15: 0,
    };

    let mut bytes_returned: DWORD = 0;

    // Execute the sanitize command
    log::debug!("Executing NVMe sanitize command...");
    let success = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_PROTOCOL_COMMAND,
            &mut cmd as *mut _ as *mut _,
            std::mem::size_of::<NVMeSanitizeCmd>() as DWORD,
            ptr::null_mut(),
            0,
            &mut bytes_returned,
            ptr::null_mut()
        )
    };

    if success == 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        // Monitor sanitize progress
        monitor_nvme_sanitize_progress(handle)?;
        Ok(())
    }
}

/// Fallback method: Block-by-block overwrite
#[cfg(target_os = "windows")]
fn perform_block_erase(handle: winapi::um::winnt::HANDLE) -> Result<()> {
    use winapi::um::winioctl::*;
    use winapi::shared::minwindef::DWORD;
    use winapi::um::fileapi::DeviceIoControl;

    log::warn!("Using fallback block erase method - this is slower and may not be as secure as hardware-based methods");

    // Structure for zero-fill operation
    #[repr(C)]
    struct SET_ZERO_DATA_INFORMATION {
        file_offset: i64,
        beyond_final_zero: i64,
    }

    let mut disk_geometry = unsafe { std::mem::zeroed::<DISK_GEOMETRY>() };
    let mut bytes_returned: DWORD = 0;

    // Get disk geometry to determine size
    log::debug!("Retrieving disk geometry...");
    let success = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DISK_GET_DRIVE_GEOMETRY,
            ptr::null_mut(),
            0,
            &mut disk_geometry as *mut _ as *mut _,
            std::mem::size_of::<DISK_GEOMETRY>() as DWORD,
            &mut bytes_returned,
            ptr::null_mut()
        )
    };

    if success == 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    // Calculate total disk size
    let disk_size = disk_geometry.Cylinders.QuadPart * 
                    (disk_geometry.TracksPerCylinder * 
                     disk_geometry.SectorsPerTrack * 
                     disk_geometry.BytesPerSector) as i64;

    log::info!("Preparing to erase {} bytes", disk_size);

    let zero_data = SET_ZERO_DATA_INFORMATION {
        file_offset: 0,
        beyond_final_zero: disk_size,
    };

    // Perform the block erase
    log::info!("Starting block erase - this may take a while...");
    let success = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_SET_ZERO_DATA,
            &zero_data as *const _ as *mut _,
            std::mem::size_of::<SET_ZERO_DATA_INFORMATION>() as DWORD,
            ptr::null_mut(),
            0,
            &mut bytes_returned,
            ptr::null_mut()
        )
    };

    if success == 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        log::info!("Block erase completed successfully");
        Ok(())
    }
}

// Helper functions for device checks and safeguards
#[cfg(target_os = "windows")]
fn is_system_drive(path: &Path) -> bool {
    use std::env;
    
    if let Ok(windows_dir) = env::var("WINDIR") {
        let system_drive = Path::new(&windows_dir)
            .components()
            .next()
            .and_then(|c| c.as_os_str().to_str())
            .unwrap_or("");

        if let Some(drive_letter) = path.to_str()
            .and_then(|s| s.chars().next())
            .map(|c| c.to_ascii_uppercase())
        {
            return system_drive.starts_with(drive_letter);
        }
    }
    false
}

#[cfg(target_os = "windows")]
fn has_admin_privileges() -> bool {
    use winapi::um::securitybaseapi::*;
    use winapi::um::winnt::TOKEN_ELEVATION;
    use std::mem;

    unsafe {
        let mut token_elevation: TOKEN_ELEVATION = mem::zeroed();
        let mut size = mem::size_of::<TOKEN_ELEVATION>() as u32;
        let mut elevated = false;
        
        let success = IsUserAnAdmin();
        if success != 0 {
            elevated = true;
        }

        elevated
    }
}

#[cfg(target_os = "windows")]
fn get_volume_root(path: &Path) -> Result<PathBuf> {
    let path_str = path.to_str().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid path")
    })?;

    // Extract drive letter or volume path
    let root = if path_str.starts_with("\\\\?\\") || path_str.starts_with("\\\\") {
        // Handle UNC paths
        path.ancestors()
            .find(|p| p.parent().is_none())
            .ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Could not determine volume root"
            ))?
            .to_path_buf()
    } else {
        // Handle regular paths
        PathBuf::from(&path_str[..3]) // Drive letter + ":\"
    };

    Ok(root)
}

#[cfg(target_os = "windows")]
fn check_ata_security_support(handle: winapi::um::winnt::HANDLE) -> Result<bool> {
    use winapi::um::winioctl::*;
    use winapi::shared::minwindef::DWORD;
    use std::ptr;

    #[repr(C, packed)]
    struct ATAIdentifyDevice {
        data: [u16; 256],
    }

    let mut identify = ATAIdentifyDevice {
        data: [0; 256],
    };
    let mut bytes_returned: DWORD = 0;

    // Send IDENTIFY DEVICE command
    let success = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_ATA_PASS_THROUGH,
            ptr::null_mut(),
            0,
            &mut identify as *mut _ as *mut _,
            std::mem::size_of::<ATAIdentifyDevice>() as DWORD,
            &mut bytes_returned,
            ptr::null_mut()
        )
    };

    if success == 0 {
        return Ok(false);
    }

    // Check security bit in identify data
    // Bit 1 in word 128 indicates security feature set support
    Ok((identify.data[128] & 0x0002) != 0)
}

#[cfg(target_os = "windows")]
fn check_nvme_sanitize_support(handle: winapi::um::winnt::HANDLE) -> Result<bool> {
    use winapi::um::winioctl::*;
    use winapi::shared::minwindef::DWORD;
    use std::ptr;

    #[repr(C, packed)]
    struct NVMeIdentifyController {
        data: [u8; 4096],
    }

    let mut identify = NVMeIdentifyController {
        data: [0; 4096],
    };
    let mut bytes_returned: DWORD = 0;

    // Send IDENTIFY CONTROLLER command
    let success = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_PROTOCOL_COMMAND,
            ptr::null_mut(),
            0,
            &mut identify as *mut _ as *mut _,
            std::mem::size_of::<NVMeIdentifyController>() as DWORD,
            &mut bytes_returned,
            ptr::null_mut()
        )
    };

    if success == 0 {
        return Ok(false);
    }

    // Check sanitize bit in identify data
    // Byte 328 bit 0 indicates sanitize support
    Ok((identify.data[328] & 0x01) != 0)
}

#[cfg(target_os = "windows")]
fn monitor_nvme_sanitize_progress(handle: winapi::um::winnt::HANDLE) -> Result<()> {
    use winapi::um::winioctl::*;
    use winapi::shared::minwindef::DWORD;
    use std::{ptr, thread, time};

    #[repr(C, packed)]
    struct NVMeSanitizeStatus {
        status: u8,
        progress: u16,
        reserved: [u8; 1],
    }

    let mut status = NVMeSanitizeStatus {
        status: 0,
        progress: 0,
        reserved: [0; 1],
    };

    loop {
        let mut bytes_returned: DWORD = 0;
        let success = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_STORAGE_PROTOCOL_COMMAND,
                ptr::null_mut(),
                0,
                &mut status as *mut _ as *mut _,
                std::mem::size_of::<NVMeSanitizeStatus>() as DWORD,
                &mut bytes_returned,
                ptr::null_mut()
            )
        };

        if success == 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let progress = (status.progress as f32 / 65535.0 * 100.0) as u8;
        log::info!("Sanitize progress: {}%", progress);

        if status.status == 0 {
            break;
        }

        thread::sleep(time::Duration::from_secs(1));
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn get_device_info(handle: winapi::um::winnt::HANDLE) -> Result<String> {
    use winapi::um::winioctl::*;
    use winapi::shared::minwindef::DWORD;
    use std::ptr;

    let mut storage_property_query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceProperty,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0u8; 1],
    };

    // First get the necessary size
    let mut storage_descriptor_size: DWORD = 0;
    unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &mut storage_property_query as *mut _ as *mut _,
            std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as DWORD,
            ptr::null_mut(),
            0,
            &mut storage_descriptor_size,
            ptr::null_mut()
        )
    };

    // Allocate buffer of required size
    let mut buffer = vec![0u8; storage_descriptor_size as usize];
    let storage_descriptor = buffer.as_mut_ptr() as *mut STORAGE_DEVICE_DESCRIPTOR;
    let mut bytes_returned: DWORD = 0;

    let success = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &mut storage_property_query as *mut _ as *mut _,
            std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as DWORD,
            storage_descriptor,
            storage_descriptor_size,
            &mut bytes_returned,
            ptr::null_mut()
        )
    };

    if success == 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    // Extract vendor and product ID strings
    let descriptor = unsafe { &*storage_descriptor };
    let vendor_id = if descriptor.VendorIdOffset > 0 {
        let vendor_ptr = unsafe {
            buffer.as_ptr().add(descriptor.VendorIdOffset as usize)
        };
        read_c_string(vendor_ptr)
    } else {
        String::from("Unknown Vendor")
    };

    let product_id = if descriptor.ProductIdOffset > 0 {
        let product_ptr = unsafe {
            buffer.as_ptr().add(descriptor.ProductIdOffset as usize)
        };
        read_c_string(product_ptr)
    } else {
        String::from("Unknown Product")
    };

    let bus_type = match descriptor.BusType {
        BusTypeAta => "ATA",
        BusTypeScsi => "SCSI",
        BusTypeNvme => "NVMe",
        BusTypeUsb => "USB",
        _ => "Unknown",
    };

    Ok(format!("{} {} ({})", vendor_id.trim(), product_id.trim(), bus_type))
}

#[cfg(target_os = "windows")]
fn read_c_string(ptr: *const u8) -> String {
    let mut length = 0;
    while unsafe { *ptr.add(length) } != 0 {
        length += 1;
    }
    
    let slice = unsafe { std::slice::from_raw_parts(ptr, length) };
    String::from_utf8_lossy(slice).into_owned()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn perform_secure_erase(_path: &Path) -> Result<()> {
    Err(crate::WipeError::UnsupportedOperation(
        "Secure erase not supported on this platform".into()
    ))
}