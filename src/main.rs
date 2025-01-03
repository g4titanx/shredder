use std::env;
use std::path::PathBuf;
use std::process;

use shredder::{
    Shredder,
    storage::StorageType,
    standards::{WipeStandard, Nist80088Config, SanitizationMethod, VerificationLevel},
};

fn check_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        // On Windows, we'll need to check for admin privileges
        // This is a placeholder - needs proper implementation
        true
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 2 {
        eprintln!("Usage: sudo shred <path_to_file>");
        process::exit(1);
    }

    if !check_root() {
        eprintln!("Error: This program needs root privileges.");
        eprintln!("Please run with sudo: sudo shred <path_to_file>");
        process::exit(1);
    }

    let path = PathBuf::from(&args[1]);
    
    // check if file exists
    if !path.exists() {
        eprintln!("Error: File not found: {}", path.display());
        process::exit(1);
    }
    
    println!("🔥 Preparing to shred: {}", path.display());
    println!("Type 'Auf Wiedersen' to confirm:");

    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();

    if input.trim() != "Auf Wiedersen" {
        println!("Operation cancelled. Your file lives another day.");
        process::exit(0);
    }

    println!("☠️  Initiating secure deletion...");
    
    // detect storage type
    let storage_info = match StorageType::detect_from_path(&path) {
        Ok(info) => info,
        Err(e) => {
            eprintln!("Error detecting storage type: {}", e);
            println!("Falling back to HDD mode for maximum compatibility.");
            // Fallback to HDD with no special capabilities
            StorageType::Hdd(shredder::storage::StorageCapabilities {
                supports_trim: false,
                supports_secure_erase: false,
                supports_nvme_sanitize: false,
                has_wear_leveling: false,
            })
        }
    };

    // create shredder with NIST 800-88 Clear method
    let shredder = Shredder::new(
        WipeStandard::Modern(Nist80088Config {
            method: SanitizationMethod::Clear,
            verify_level: VerificationLevel::Full,
        }),
        storage_info,
    );

    // Perform secure deletion
    match shredder.wipe(&path) {
        Ok(()) => {
            println!("✨ File has been securely shredded!");
            process::exit(0);
        }
        Err(e) => {
            eprintln!("Error during secure deletion: {}", e);
            eprintln!("The file may not have been completely shredded.");
            process::exit(1);
        }
    }
}