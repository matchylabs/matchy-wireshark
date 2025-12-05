# Matchy Wireshark Plugin

Real-time threat intelligence matching for Wireshark packet analysis.

## Features

- **Real-time threat enrichment**: Match source/destination IPs and domains against threat databases during packet capture
- **Custom display filters**: Query threats using display filters like `matchy.threat_detected` and `matchy.level == "high"`
- **Packet colorization**: Automatically color packets by threat level (red=critical, orange=high, yellow=medium)
- **Zero-copy performance**: Sub-millisecond lookups on 100K+ indicators
- **Local threat databases**: Use prebuilt .mxy threat feeds or create custom databases

## Installation

### Requirements

- Wireshark 4.0+ (macOS, Linux)
- Rust 1.70+
- libwireshark development headers

> **Note:** Windows builds are currently not supported due to Wireshark not shipping development libraries (.lib files) with their Windows installers. Windows support requires building Wireshark from source.

### Build

```bash
cargo build --release
# Plugin will be at: target/release/libmatchy_wireshark.so (Linux) or .dylib (macOS)

# macOS only: Fix library paths for portability
./fix-dylib-paths.sh target/release/libmatchy_wireshark.dylib
```

### Install

**From source** (after building):
```bash
# Use the install script (handles version detection and paths)
./install.sh

# Or install manually:
# Detect Wireshark version
WS_VERSION=$(tshark --version | head -1 | sed -E 's/.*([0-9]+\.[0-9]+)\..*/\1/' | tr '.' '-')
PLUGIN_DIR="$HOME/.local/lib/wireshark/plugins/${WS_VERSION}/epan"
mkdir -p "$PLUGIN_DIR"

# macOS
cp target/release/libmatchy_wireshark.dylib "$PLUGIN_DIR/matchy.so"

# Linux  
cp target/release/libmatchy_wireshark.so "$PLUGIN_DIR/matchy.so"
```

**From pre-built release**:
```bash
# Download from GitHub releases
tar -xzf matchy-wireshark-*.tar.gz
cd matchy-wireshark-*/
./install.sh
```

## Usage

### 1. Load a threat database

In Wireshark, go to **Edit → Preferences → Protocols → Matchy**:
1. Click the **Browse** button next to "Database Path"
2. Select your `.mxy` threat intelligence database file
3. Click **OK** to apply
4. The database will load immediately (no restart required)

The database path is saved in your Wireshark preferences and will be loaded automatically on startup.

### 2. Use display filters

Filter packets by threat intelligence:

```
# Show all threat matches
matchy.threat_detected

# Filter by threat level
matchy.level == "critical"
matchy.level == "high"
matchy.level == "medium"

# Filter by category
matchy.category == "malware"
matchy.category == "phishing"
matchy.category == "c2"

# Combine with standard filters
(matchy.threat_detected) && tcp.port == 443
matchy.level == "critical" && ip.src == 1.2.3.4
```

### 3. View threat details

Click on a packet with threat matches to see:
- Threat level
- Category
- Source (feed)
- Custom metadata

## Building Threat Databases

Convert CSV/JSONL threat feeds to .mxy format using the matchy CLI:

```bash
# Create from CSV (entry, threat_level, category, source)
matchy build threats.csv -o threats.mxy --format csv

# Create from JSONL
matchy build threats.jsonl -o threats.mxy --format jsonl
```

Example CSV:
```
entry,threat_level,category,source
1.2.3.4,high,malware,abuse.ch
10.0.0.0/8,low,internal,rfc1918
*.evil.com,critical,phishing,urlhaus
```

## Performance

- **Lookup time**: <1ms per packet (100K indicator database)
- **Memory usage**: <50MB per process
- **Throughput**: No degradation to capture speed (sub-millisecond overhead)

## Architecture

```
┌──────────────────────┐
│  Wireshark (C API)   │
└──────────┬───────────┘
           │
┌──────────▼───────────────────────┐
│  matchy-wireshark (Rust FFI)      │
│  ├─ Wireshark postdissector       │
│  ├─ IP/domain extraction          │
│  ├─ Threat lookup (matchy API)    │
│  └─ Display filter expressions    │
└──────────┬───────────────────────┘
           │
┌──────────▼───────────────────────┐
│  matchy (Rust library)            │
│  ├─ .mxy database loading         │
│  ├─ IP trie (CIDR matching)       │
│  ├─ Glob patterns (domain matches)│
│  └─ Sub-ms lookups                │
└──────────────────────────────────┘
```

## Development

### Project structure

```
matchy-wireshark/
├── src/
│   ├── lib.rs              # Plugin entry point, FFI
│   ├── postdissector.rs    # Wireshark postdissector logic
│   ├── display_filter.rs   # Display filter expressions
│   └── threats.rs          # Threat matching + coloring
├── include/
│   └── wireshark/          # Wireshark C API headers
├── Cargo.toml
└── README.md
```

### Testing

```bash
# Unit tests
cargo test

# Build release
cargo build --release

# Check for issues
cargo clippy -- -D warnings
```

### Running locally

Copy the compiled plugin to your Wireshark plugins directory, restart Wireshark, and load a threat database via preferences.

## License

Apache-2.0

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) in the main MatchyLabs repository.

## Resources

- [Matchy Documentation](https://matchylabs.github.io/matchy/)
- [Wireshark Plugin Development](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_gui.html)
- [Threat Feed Formats](../matchy/docs/FORMATS.md)
