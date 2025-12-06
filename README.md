# Matchy Wireshark Plugin

A Wireshark plugin written in Rust that provides real-time threat intelligence matching during packet capture. Match IPs and domains against threat databases with sub-millisecond performance.

![Wireshark showing threat detection](docs/wireshark-screenshot.png)

## Features

- **Real-time threat enrichment**: Matches source/destination IPs and domains against threat databases during packet capture
- **Custom display filters**: Filter packets using expressions like `matchy.threat_detected` and `matchy.level == "critical"`
- **Automatic packet colorization**: Color-codes packets by threat level (red=critical, orange=high, yellow=medium)
- **High performance**: Sub-millisecond lookups on databases with 100K+ indicators using memory-mapped .mxy format
- **Flexible databases**: Use prebuilt threat feeds or build custom databases from CSV/JSON sources

## Installation

### Requirements

- **Wireshark**: 4.0 or later
- **Rust**: 1.70 or later (for building from source)

### Build from Source

```bash
# Build optimized release version
cargo build --release

# Output locations:
# - macOS: target/release/libmatchy_wireshark_plugin.dylib
# - Linux: target/release/libmatchy_wireshark_plugin.so
# - Windows: target/release/matchy_wireshark_plugin.dll
```

### Install

**Option 1: Use the install script**:
```bash
# After building, run the installer
./install.sh

# The script automatically:
# - Detects your Wireshark version
# - Finds the correct plugin directory
# - Copies the plugin to the right location
```

**Option 2: Manual installation**:
```bash
# Detect Wireshark version
WS_VERSION=$(tshark --version | head -1 | sed -E 's/.*([0-9]+\.[0-9]+)\..*/\1/')

# macOS uses dashes in version directory (4-6), Linux uses dots (4.6)
# macOS
PLUGIN_DIR="$HOME/.local/lib/wireshark/plugins/$(echo $WS_VERSION | tr '.' '-')/epan"
mkdir -p "$PLUGIN_DIR"
cp target/release/libmatchy_wireshark_plugin.dylib "$PLUGIN_DIR/matchy.so"

# Linux
PLUGIN_DIR="$HOME/.local/lib/wireshark/plugins/${WS_VERSION}/epan"
mkdir -p "$PLUGIN_DIR"
cp target/release/libmatchy_wireshark_plugin.so "$PLUGIN_DIR/matchy.so"
```

**Option 3: From pre-built release** (recommended):

Download the appropriate package from [GitHub Releases](https://github.com/matchylabs/matchy-wireshark-plugin/releases):
- macOS: `matchy-wireshark-plugin-*-macos-arm64.tar.gz`
- Linux x86_64: `matchy-wireshark-plugin-*-linux-x86_64.tar.gz`
- Linux ARM64: `matchy-wireshark-plugin-*-linux-aarch64.tar.gz`
- Windows: `matchy-wireshark-plugin-*-windows-x86_64.zip`

```bash
# macOS/Linux
tar -xzf matchy-wireshark-plugin-*.tar.gz
cd matchy-wireshark-plugin-*/
./install.sh

# Windows
# Extract zip and run install.bat
```

## Usage

### 1. Load a Threat Database

Configure the plugin in Wireshark:

1. Open **Edit → Preferences → Protocols → Matchy**
2. Click **Browse** next to "Database Path"
3. Select your `.mxy` threat intelligence database file
4. Click **OK**

The database loads immediately (no restart needed) and the path is saved for future sessions.

### 2. Filter Packets by Threat

Use Wireshark display filters to find threats:

```
# Show any packet with a threat match
matchy.threat_detected

# Filter by threat level
matchy.level == "critical"
matchy.level == "high"
matchy.level == "medium"
matchy.level == "low"

# Filter by threat category
matchy.category == "malware"
matchy.category == "phishing"
matchy.category == "c2"
matchy.category == "botnet"

# Combine with standard Wireshark filters
matchy.threat_detected && tcp.port == 443
matchy.level == "critical" && ip.src == 1.2.3.4
(matchy.category == "malware" || matchy.category == "c2") && http
```

### 3. View Threat Details

Select any packet with a threat match to view:
- **Threat level**: Critical, High, Medium, Low
- **Category**: Malware, phishing, C2, botnet, etc.
- **Source**: Which threat feed flagged this indicator
- **Metadata**: Additional context from the threat database

## Creating Threat Databases

Build `.mxy` databases from CSV or JSON threat feeds using the [matchy CLI](https://github.com/matchylabs/matchy):

```bash
# From CSV format
matchy build threats.csv -o threats.mxy --format csv

# From JSON Lines format
matchy build threats.jsonl -o threats.mxy --format jsonl
```

**Example CSV format**:
```csv
entry,threat_level,category,source
1.2.3.4,high,malware,abuse.ch
192.0.2.0/24,medium,scanner,shodan
10.0.0.0/8,low,internal,rfc1918
*.evil.com,critical,phishing,urlhaus
example.net,medium,suspicious,custom
```

The `.mxy` format uses memory-mapping for fast lookups with minimal memory overhead.

## Performance

- **Lookup time**: Sub-millisecond per packet (tested with 100K+ indicator databases)
- **Memory footprint**: <50MB per Wireshark instance - depending on database size
- **Capture overhead**: Negligible impact on packet capture throughput
- **Database format**: Memory-mapped .mxy files for zero-copy performance

## Architecture Overview

The plugin operates as a Wireshark postdissector, processing packets after standard protocol dissection:

```
┌─────────────────────────────────┐
│     Wireshark (C/C++)           │
│     ├─ Packet capture           │
│     ├─ Protocol dissectors      │
│     └─ Postdissector chain      │
└─────────────┬───────────────────┘
              │ FFI boundary
┌─────────────▼───────────────────┐
│  matchy-wireshark-plugin (Rust) │
│  ├─ Extract IPs & domains       │
│  ├─ Query threat database       │
│  ├─ Add custom packet fields    │
│  ├─ Apply threat colorization   │
│  └─ Register display filters    │
└─────────────┬───────────────────┘
              │
┌─────────────▼───────────────────┐
│  matchy-core (Rust)             │
│  ├─ Memory-mapped .mxy files    │
│  ├─ IP prefix trie (CIDR)       │
│  ├─ Glob pattern matching       │
│  └─ Sub-millisecond lookups     │
└─────────────────────────────────┘
```

**Key components**:
- **Postdissector**: Runs after normal packet dissection, extracts IPs/domains
- **FFI layer**: Safe Rust-to-C bridge for Wireshark integration
- **Threat matching**: Fast lookups against memory-mapped threat database
- **Display filters**: Custom filter expressions for threat-based packet filtering

## Development

### Testing and Development

```bash
# Run unit tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Build for development
cargo build

# Build optimized release
cargo build --release

# Check code quality
cargo clippy -- -D warnings

# Format code
cargo fmt
```

### Local Testing

1. Build the plugin: `cargo build --release`
2. Install to Wireshark: `./install.sh`
3. Restart Wireshark (if already running)
4. Load a test `.mxy` database in preferences
5. Capture traffic and verify threat matching works


## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
