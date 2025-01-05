# shredder (PoC)
shredder is a secure file deletion tool

⚠️ **Warning**: not ready for use

## features
- Multiple secure deletion standards (NIST 800-88, DoD 5220.22-M, Gutmann, VSITR)
- Storage-aware operation (HDD, SSD, Flash)
- Hardware-based secure erase when available
- Multiple verification levels
- Cross-platform support (Linux, Windows, macOS)

## usage
```bash
# install cargo using `https://rustup.rs/`
cargo install shredder

# Or build from source

git clone https://github.com/g4titanx/shredder
cd shred
cargo build --release
```
shred {path_to_file}
(enter password and say `Auf Wiedersen` to your file`)


## usage

### basic command
```bash
shred 
```

### options
```bash
shred [OPTIONS] 

Options:
  -s, --standard     wiping standard to use [default: nist] [possible values: nist, dod, gutmann, vsitr]
  -v, --verify         verification level [default: full] [possible values: none, basic, full, enhanced]
  -f, --force                 force operation without confirmation
      --no-root-check        skip root/admin check (use with caution)
  -h, --help                 print help
  -V, --version              print version
```

### important notes
the tool requires administrative privileges to ensure complete secure deletion
you can run it either:
   - Using `sudo` on Unix systems
   - From an administrator prompt on Windows
   - With `--no-root-check` (not recommended, may fail)
using `sudo` with `--no-root-check` is redundant as the privilege check will pass with sudo

⚠️ **Warning**: Operations might fail when run without proper privileges

### Security Standards
- **NIST** (default): NIST 800-88 compliant, modern approach
- **DoD**: DoD 5220.22-M standard (3 passes)
- **Gutmann**: Peter Gutmann's 35-pass method
- **VSITR**: German VSITR 7-pass standard
