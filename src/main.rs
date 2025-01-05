use std::path::PathBuf;
use std::process;

use shredder::{
    Shredder,
    storage::{StorageType, StorageInfo, StorageCapabilities},
    standards::{WipeStandard, Nist80088Config, SanitizationMethod, VerificationLevel},
};
use clap::{CommandFactory, Parser, Subcommand};

/// A secure file deletion tool that says Auf Wiedersen to your files
#[derive(Parser)]
#[command(name = "shred")]
#[command(author = "alake <g4titan1@gmail.com>")]
#[command(version)]
#[command(about = "Securely erases files and storage devices", long_about = None)]
struct Cli {
    /// path to file or device to securely erase
    path: PathBuf,

    /// wiping standard to use (nist, dod, gutmann, vsitr)
    #[arg(short, long, default_value = "nist")]
    standard: String,

    /// verification level (none, basic, full, enhanced)
    #[arg(short, long, default_value = "full")]
    verify: String,

    /// force operation without confirmation
    #[arg(short, long)]
    force: bool,

    /// skip root/admin check (use with caution)
    #[arg(long)]
    no_root_check: bool,
}

fn check_privileges() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        use winapi::um::securitybaseapi::IsUserAnAdmin;
        unsafe { IsUserAnAdmin() != 0 }
    }
}

fn confirm_operation(path: &PathBuf, force: bool) -> bool {
    if force {
        return true;
    }

    println!("🔥 Preparing to securely erase: {}", path.display());
    println!("⚠️  WARNING: This operation is irreversible!");
    println!("Type 'Auf Wiedersen' to confirm:");

    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }

    input.trim() == "Auf Wiedersen"
}

fn parse_standard(standard: &str) -> WipeStandard {
    use shredder::standards::{LegacyConfig, LegacyStandard};

    match standard.to_lowercase().as_str() {
        "nist" => WipeStandard::Modern(Nist80088Config {
            method: SanitizationMethod::Purge,
            verify_level: VerificationLevel::Full,
        }),
        "dod" => WipeStandard::Legacy(LegacyConfig {
            standard: LegacyStandard::Dod522022M,
            extra_verification: true,
        }),
        "gutmann" => WipeStandard::Legacy(LegacyConfig {
            standard: LegacyStandard::Gutmann,
            extra_verification: true,
        }),
        "vsitr" => WipeStandard::Legacy(LegacyConfig {
            standard: LegacyStandard::VsitrStandard,
            extra_verification: true,
        }),
        _ => {
            eprintln!("Warning: Unknown standard '{}', defaulting to NIST", standard);
            WipeStandard::Modern(Nist80088Config {
                method: SanitizationMethod::Purge,
                verify_level: VerificationLevel::Full,
            })
        }
    }
}

fn parse_verification_level(level: &str) -> VerificationLevel {
    match level.to_lowercase().as_str() {
        "none" => VerificationLevel::None,
        "basic" => VerificationLevel::Basic,
        "full" => VerificationLevel::Full,
        "enhanced" => VerificationLevel::Enhanced,
        _ => {
            eprintln!("Warning: Unknown verification level '{}', defaulting to Full", level);
            VerificationLevel::Full
        }
    }
}

fn main() {
    // initialize logger
    env_logger::init();
    
    // parse command line arguments
    let cli = Cli::parse();

    // check for root/admin privileges if not explicitly skipped
    if !cli.no_root_check && !check_privileges() {
        eprintln!("Error: This program needs root/administrator privileges.");
        #[cfg(unix)]
        eprintln!("Please run with sudo: sudo shred <path>");
        #[cfg(windows)]
        eprintln!("Please run as administrator");
        process::exit(1);
    }

    // validate path
    if !cli.path.exists() {
        eprintln!("Error: File not found: {}", cli.path.display());
        process::exit(1);
    }

    // get confirmation unless --force is used
    if !confirm_operation(&cli.path, cli.force) {
        println!("Operation cancelled. Your file lives another day.");
        process::exit(0);
    }

    println!("☠️  Initiating secure deletion...");
    
    // detect storage type with progress indication
    println!("Detecting storage type...");
    let storage_info = match StorageType::detect_from_path(&cli.path) {
        Ok(info) => {
            println!("✓ Detected storage type");
            info
        }
        Err(e) => {
            eprintln!("Warning: Error detecting storage type: {}", e);
            println!("Falling back to HDD mode for maximum compatibility");
            StorageInfo {
                device_type: StorageType::Hdd(StorageCapabilities {
                    supports_trim: false,
                    supports_secure_erase: false,
                    supports_nvme_sanitize: false,
                    has_wear_leveling: false,
                }),
                block_size: 4096,
                total_size: 0,
            }
        }
    };

    // create shredder with selected standard and verification level
    let mut standard = parse_standard(&cli.standard);
    // update verification level if specified
    match &mut standard {
        WipeStandard::Modern(config) => {
            config.verify_level = parse_verification_level(&cli.verify);
        },
        WipeStandard::Legacy(config) => {
            config.extra_verification = cli.verify.to_lowercase() != "none";
        },
        WipeStandard::Custom(config) => {
            config.verify_each_pass = cli.verify.to_lowercase() != "none";
        }
    }

    let shredder = Shredder::new(standard, storage_info.device_type);

    // perform secure deletion
    println!("Starting secure deletion...");
    match shredder.wipe(&cli.path) {
        Ok(()) => {
            println!("✨ File has been securely shredded!");
            process::exit(0);
        }
        Err(e) => {
            eprintln!("Error during secure deletion: {}", e);
            eprintln!("⚠️  WARNING: The file may not have been completely shredded!");
            process::exit(1);
        }
    }
}