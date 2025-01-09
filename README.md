# shredder
shredder is a secure file deletion tool

## features
- multiple secure deletion standards (NIST 800-88, DoD 5220.22-M, Gutmann, VSITR)
- storage-aware operation (HDD, SSD, Flash)
- hardware-based secure erase when available
- multiple verification levels
- cross-platform support (Linux, Windows, macOS)

## security standards
- **NIST** (default): NIST 800-88 compliant, modern approach
- **DoD**: DoD 5220.22-M standard (3 passes)
- **Gutmann**: Peter Gutmann's 35-pass method
- **VSITR**: German VSITR 7-pass standard

## installation

### from source
```bash
# clone the repository
git clone https://github.com/g4titanx/shredder
cd shred

# build and install
cargo build --release     # just build
cargo install --path .    # install to ~/.cargo/bin/shred
```

### running with different installation methods

1. if installed via `cargo install`:
```bash
sudo shred file.txt             # If ~/.cargo/bin is in PATH
sudo ~/.cargo/bin/shred file.txt # Full path
```

2. running from the repository:
```bash
sudo ./target/release/shred file.txt
```

## usage

```bash
# basic usage
sudo shred file.txt

# using DoD standard
sudo shred --standard dod file.txt

# enhanced verification
sudo shred --verify enhanced file.txt

# force deletion without confirmation
sudo shred --force file.txt
```

### options
```bash
shred [OPTIONS] 

Options:
  -s, --standard            wiping standard to use [default: nist] [possible values: nist, dod, gutmann, vsitr]
  -v, --verify              verification level [default: full] [possible values: none, basic, full, enhanced]
  -f, --force               force operation without confirmation
      --no-root-check       skip root/admin check (use with caution)
  -h, --help                print help
  -V, --version             print version
```

### important notes
the tool requires administrative privileges to ensure complete secure deletion
you can run it either:
   - Using `sudo` on Unix systems
   - From an administrator prompt on Windows
   - With `--no-root-check` (not recommended, may fail)
using `sudo` with `--no-root-check` is redundant as the privilege check will pass with sudo

⚠️ **Warning**: Operations might fail when run without proper privileges

## TODO

### planned Features
1. directory Support
   - [ ] Recursive directory wiping and directory traversal options
   - [ ] Configurable file inclusion/exclusion patterns

2. enhanced progress reporting
   - [ ] Progress tracking for multiple files
   - [ ] ETA calculation
   - [ ] Detailed operation statistics
