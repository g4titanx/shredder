use crate::Result;
use std::fs::File;

#[cfg(target_os = "linux")]
pub fn perform_trim(file: &mut File) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    unsafe {
        // FITRIM ioctl command
        let FITRIM: u64 = 0x40086601;

        #[repr(C)]
        struct FtrimRange {
            start: u64,
            len: u64,
            min_len: u64,
        }

        let range = FtrimRange {
            start: 0,
            len: u64::MAX,
            min_len: 0,
        };

        let result = libc::ioctl(file.as_raw_fd(), FITRIM, &range);
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().into())
        }
    }
}

#[cfg(target_os = "macos")]
pub fn perform_trim(file: &mut File) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    unsafe {
        // F_FULLFSYNC fcntl command
        const F_FULLFSYNC: i32 = 51;

        let result = libc::fcntl(file.as_raw_fd(), F_FULLFSYNC);
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().into())
        }
    }
}

#[cfg(target_os = "windows")]
pub fn perform_trim(file: &mut File) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use winapi::shared::minwindef::DWORD;
    use winapi::um::fileapi::DeviceIoControl;
    use winapi::um::winioctl::*;

    #[repr(C)]
    struct DEVICE_MANAGE_DATA_SET_ATTRIBUTES {
        size: DWORD,
        action: DWORD,
        flags: DWORD,
        parameter_block_offset: DWORD,
        parameter_block_length: DWORD,
        data_set_ranges_offset: DWORD,
        data_set_ranges_length: DWORD,
    }

    #[repr(C)]
    struct DEVICE_DATA_SET_RANGE {
        starting_offset: i64,
        length_in_bytes: u64,
    }

    // get file size
    let file_size = file.metadata()?.len();

    // create the parameter block
    let range = DEVICE_DATA_SET_RANGE {
        starting_offset: 0,
        length_in_bytes: file_size,
    };

    let attrs = DEVICE_MANAGE_DATA_SET_ATTRIBUTES {
        size: std::mem::size_of::<DEVICE_MANAGE_DATA_SET_ATTRIBUTES>() as DWORD,
        action: DEVICEDSMACTION_TRIM as DWORD,
        flags: DEVICEDSMFLAGS_TRIM_SKIP_MAPPED_RANGES,
        parameter_block_offset: 0,
        parameter_block_length: 0,
        data_set_ranges_offset: std::mem::size_of::<DEVICE_MANAGE_DATA_SET_ATTRIBUTES>() as DWORD,
        data_set_ranges_length: std::mem::size_of::<DEVICE_DATA_SET_RANGE>() as DWORD,
    };

    // create buffer that contains both structures
    let total_size = std::mem::size_of::<DEVICE_MANAGE_DATA_SET_ATTRIBUTES>()
        + std::mem::size_of::<DEVICE_DATA_SET_RANGE>();
    let mut buffer = vec![0u8; total_size];

    // copy structures to buffer
    unsafe {
        let attrs_ptr = buffer.as_mut_ptr() as *mut DEVICE_MANAGE_DATA_SET_ATTRIBUTES;
        ptr::write(attrs_ptr, attrs);

        let range_ptr = buffer
            .as_mut_ptr()
            .add(std::mem::size_of::<DEVICE_MANAGE_DATA_SET_ATTRIBUTES>())
            as *mut DEVICE_DATA_SET_RANGE;
        ptr::write(range_ptr, range);
    }

    let mut bytes_returned: DWORD = 0;

    let success = unsafe {
        DeviceIoControl(
            file.as_raw_handle() as *mut _,
            FSCTL_FILE_LEVEL_TRIM,
            buffer.as_mut_ptr() as *mut _,
            total_size as DWORD,
            ptr::null_mut(),
            0,
            &mut bytes_returned,
            ptr::null_mut(),
        )
    };

    if success == 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn perform_trim(_file: &mut File) -> Result<()> {
    Err(crate::WipeError::UnsupportedOperation(
        "TRIM not supported on this platform".into(),
    ))
}
