# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

matchy-wireshark-plugin is a Wireshark plugin written in Rust that provides real-time threat intelligence matching for packet analysis. The plugin acts as a postdissector, processing packets after normal Wireshark dissection to match IPs and domains against threat databases.

## Build and Development Commands

### Building
```bash
# Debug build
cargo build

# Release build (optimized for performance)
cargo build --release
```

The compiled plugin will be located at:
- **macOS**: `target/release/libmatchy_wireshark_plugin.dylib`
- **Linux**: `target/release/libmatchy_wireshark_plugin.so`
- **Windows**: `target/release/matchy_wireshark_plugin.dll`

### Testing
```bash
# Run all unit tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test module
cargo test threats::tests
```

### Code Quality
```bash
# Check for common issues
cargo clippy -- -D warnings

# Format code
cargo fmt

# Check formatting without applying
cargo fmt -- --check
```

### Installation
Use the provided installer scripts which handle version detection and path setup:

**macOS/Linux:**
```bash
./install.sh
```

**Windows:**
```cmd
install.bat
```

The installers automatically detect your Wireshark version and install to the correct plugin directory.

## Architecture

### Plugin Flow
1. **Plugin Loading**: `plugin_register()` is called by Wireshark when the plugin loads
2. **Postdissector Registration**: Registers the postdissector to process every packet
3. **Database Loading**: User loads a `.mxy` threat database via Wireshark preferences
4. **Packet Processing**: For each packet:
   - Extract source/destination IPs and domain names
   - Query the matchy database for threat intelligence
   - Add custom fields to Wireshark's packet tree
   - Apply threat-level coloring (red=critical, orange=high, yellow=medium)

### Module Organization

- **`lib.rs`**: Plugin entry point, FFI exports, global database management
  - FFI functions exported for Wireshark C API
  - Global `THREAT_DB` mutex holding the loaded threat database
  - Version and plugin metadata constants
  - Protocol and field registration with Wireshark
  - Preferences registration (database path setting)

- **`postdissector.rs`**: Wireshark postdissector implementation
  - Registers the postdissector with Wireshark
  - Main packet processing logic - extracts IPs and queries database
  - Adds threat info to Wireshark's protocol tree

- **`threats.rs`**: Threat data structures
  - `ThreatLevel` enum: Critical, High, Medium, Low, Unknown
  - `ThreatData` struct: Parsed threat intelligence data
  - JSON parsing from matchy database results

- **`wireshark_ffi.rs`**: Wireshark C API bindings
  - Hand-written minimal FFI bindings for Wireshark functions
  - Type definitions matching Wireshark's C structures
  - Address extraction helpers for IPv4/IPv6

### FFI Layer

The plugin uses Rust FFI to interface with Wireshark's C API:
- `#[no_mangle]` exports for C visibility
- `extern "C"` functions for C calling convention
- Uses `libc` types (`c_char`, `c_int`, `c_void`)
- Compiled as `cdylib` for dynamic loading
- On Windows, uses `raw-dylib` linking to avoid needing import libraries
- FFI functions are split into separate `extern` blocks based on which DLL exports them:
  - `libwireshark.dll`: protocol registration, tree functions, preferences
  - `libwsutil.dll`: logging functions (`ws_log_full`)

### Thread Safety

The threat database is stored in a `static Mutex<Option<Arc<matchy::Database>>>`:
- Thread-safe access across Wireshark's multi-threaded packet processing
- `Arc` allows shared ownership without copying the large database
- Database loaded once, read many times

## Dependencies

### External Libraries
- **matchy**: Core threat database library (from GitHub, main branch)
  - Provides `.mxy` database format reading
  - IP trie for CIDR matching
  - Glob pattern matching for domains
  - Sub-millisecond lookups

- **libc**: C FFI types and functions
- **serde_json**: JSON parsing for threat metadata

### Build Configuration
- **crate-type**: `cdylib` (C-compatible dynamic library)
- **LTO enabled**: For maximum performance in release builds
- **Debug symbols included**: Even in release builds for profiling

## Development Status

**Current State**: Functional plugin with cross-platform support

**Implemented**:
- Full Wireshark plugin structure with FFI bindings
- Protocol and field registration (matchy.threat_detected, matchy.level, etc.)
- Database loading via preferences or environment variable
- IP extraction from packets (IPv4 and IPv6)
- Threat lookups using matchy database
- Protocol tree display of threat information
- Cross-platform builds (macOS, Linux, Windows)
- Installer scripts for all platforms

**TODO**:
- Domain name extraction from DNS packets
- Packet coloring based on threat level
- Performance optimization for high-throughput captures

## Wireshark Plugin Development

### Key Concepts
- **Postdissector**: Runs after normal packet dissection, can add custom fields
- **Display Filters**: Custom filter expressions like `matchy.threat_detected`
- **Packet Tree**: Hierarchical display of packet data in Wireshark UI
- **TVB**: Wireshark's "Testy Virtual Buffer" for packet data access

### Display Filters
Analysts can filter packets using:
```
matchy.threat_detected                 # Any threat match
matchy.level == "critical"             # Specific threat level
matchy.category == "malware"           # Specific category
matchy.level == "high" && tcp.port == 443  # Combined filters
```

### Performance Requirements
- **Lookup time**: <1ms per packet (no capture degradation)
- **Memory usage**: <50MB per Wireshark process
- **Zero-copy**: Memory-mapped threat database, no data copying

## Testing Strategy

### Unit Tests
Each module has inline tests:
- `threats.rs`: ThreatLevel conversions, JSON parsing, color mappings
- Test with: `cargo test`

### Integration Testing
The integration test (`cargo test --test integration`) is self-contained:
- Automatically detects Wireshark version from `tshark --version`
- Creates temp plugin directory with correct structure (`X.Y/epan/`)
- Copies freshly-built plugin to temp dir
- Uses `WIRESHARK_PLUGIN_DIR` env var to load plugin
- Runs tshark against test pcap with test threat database
- No manual installation required

### Test Database Creation
Use the matchy CLI to build test databases:
```bash
# Create from CSV
matchy build threats.csv -o test.mxy --format csv

# Example CSV format:
# entry,threat_level,category,source
# 1.2.3.4,high,malware,abuse.ch
# *.evil.com,critical,phishing,urlhaus
```

## Code Style

- Follow standard Rust conventions (enforced by `cargo fmt`)
- Use meaningful variable names (not single letters except in small scopes)
- Add doc comments (`///`) for public items
- Use `TODO:` comments for incomplete implementations
- Prefer explicit error handling over `unwrap()`

## Related Resources

- [Matchy Core Library](https://github.com/matchylabs/matchy)
- [Wireshark Plugin Development](https://www.wireshark.org/docs/wsdg_html_chunked/)
- [Wireshark FFI in Rust](https://doc.rust-lang.org/nomicon/ffi.html)
