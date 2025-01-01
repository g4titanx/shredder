use secure_wipe::{
    SecureWipe,
    standards::{WipeStandard, Nist80088Config, SanitizationMethod, VerificationLevel},
    storage::StorageType,
};
use std::path::PathBuf;
use std::process;

fn main() {
    // Initialize logging
    env_logger::init();

    // Parse command line arguments (simplified example)
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <file>", args[0]);
        process::exit(1);
    }

    let path = PathBuf::from(&args[1]);
    
    // Detect storage type
    let storage_info = match StorageType::detect_from_path(&path) {
        Ok(info) => info,
        Err(e) => {
            eprintln!("Failed to detect storage type: {}", e);
            process::exit(1);
        }
    };

    // Create secure wipe instance with NIST 800-88 Clear method
    let wiper = SecureWipe::new(
        WipeStandard::Modern(Nist80088Config {
            method: SanitizationMethod::Clear,
            verify_level: VerificationLevel::Full,
        }),
        storage_info.device_type,
    );

    // Perform secure deletion
    if let Err(e) = wiper.wipe(&path) {
        eprintln!("Failed to securely delete file: {}", e);
        process::exit(1);
    }

    println!("File securely deleted");
}