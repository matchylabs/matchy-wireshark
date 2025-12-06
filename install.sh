#!/bin/sh
# Install matchy-wireshark-plugin
#
# This script installs the matchy Wireshark plugin to the user's plugin directory.
# It supports both macOS and Linux systems.
#
# POSIX-compliant - works with /bin/sh, dash, bash, zsh, etc.

set -e

# Get script directory (POSIX-compatible)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Detect OS type
detect_os() {
    case "$(uname -s)" in
        Darwin*) echo "darwin" ;;
        Linux*)  echo "linux" ;;
        *)       echo "unknown" ;;
    esac
}

OS_TYPE="$(detect_os)"

info() { printf "${GREEN}%s${NC}\n" "$1"; }
error() { printf "${RED}%s${NC}\n" "$1"; }

# Extract major.minor version from Wireshark version string
extract_version() {
    echo "$1" | sed -E 's/.*([0-9]+\.[0-9]+)\..*/\1/' | head -1
}

# Detect Wireshark version from config file
detect_version_from_config() {
    # Check both possible config locations
    for recent_file in "$HOME/.config/wireshark/recent" "$HOME/.wireshark/recent"; do
        if [ -f "$recent_file" ]; then
            version=$(head -1 "$recent_file" | sed -E 's/.*Wireshark ([0-9]+\.[0-9]+)\..*/\1/')
            if [ -n "$version" ] && echo "$version" | grep -qE '^[0-9]+\.[0-9]+$'; then
                echo "$version"
                return
            fi
        fi
    done
}

# Detect Wireshark version from binary
detect_version_from_binary() {
    # Try wireshark, then tshark
    for bin in wireshark tshark; do
        if command -v "$bin" >/dev/null 2>&1; then
            version=$("$bin" --version 2>/dev/null | head -1)
            extract_version "$version"
            return
        fi
    done
    
    # macOS: check Wireshark.app
    if [ "$OS_TYPE" = "darwin" ] && [ -d "/Applications/Wireshark.app" ]; then
        version=$(/Applications/Wireshark.app/Contents/MacOS/Wireshark --version 2>/dev/null | head -1)
        extract_version "$version"
        return
    fi
}

# Detect Wireshark version - prefer config file, fall back to binary
detect_wireshark_version() {
    # Config file is most reliable (works even if binary not in PATH)
    version=$(detect_version_from_config)
    if [ -n "$version" ]; then
        echo "$version"
        return
    fi
    
    # Fall back to binary detection
    detect_version_from_binary
}

# Get the minimum Wireshark version required (binary packages only)
get_min_version() {
    if [ -f "$SCRIPT_DIR/MIN_WIRESHARK_VERSION" ]; then
        tr -d '\n' < "$SCRIPT_DIR/MIN_WIRESHARK_VERSION"
    fi
}

# Compare versions (returns 0 if v1 >= v2, 1 otherwise)
version_gte() {
    v1="$1"
    v2="$2"
    # Simple major.minor comparison
    v1_major=$(echo "$v1" | cut -d. -f1)
    v1_minor=$(echo "$v1" | cut -d. -f2)
    v2_major=$(echo "$v2" | cut -d. -f1)
    v2_minor=$(echo "$v2" | cut -d. -f2)
    
    if [ "$v1_major" -gt "$v2_major" ]; then
        return 0
    elif [ "$v1_major" -eq "$v2_major" ] && [ "$v1_minor" -ge "$v2_minor" ]; then
        return 0
    else
        return 1
    fi
}

# Build the plugin
build_plugin() {
    echo "Building plugin..."
    (cd "$SCRIPT_DIR" && cargo build --release)
}

# Install plugin to user directory
install_plugin() {
    version="$1"
    
    # macOS uses dashes (4-6), Linux uses dots (4.6)
    if [ "$OS_TYPE" = "darwin" ]; then
        version_dir=$(echo "$version" | tr '.' '-')
    else
        version_dir="$version"
    fi
    plugin_dir="$HOME/.local/lib/wireshark/plugins/${version_dir}/epan"
    plugin_name="matchy.so"
    
    echo
    info "Installing for Wireshark $version"
    echo "  Plugin directory: $plugin_dir"
    
    mkdir -p "$plugin_dir"
    
    # Find source binary (check binary package first, then source tree)
    plugin_src=""
    if [ -f "$SCRIPT_DIR/matchy.so" ]; then
        # Binary package
        plugin_src="$SCRIPT_DIR/matchy.so"
    elif [ -f "$SCRIPT_DIR/target/release/libmatchy_wireshark_plugin.dylib" ]; then
        plugin_src="$SCRIPT_DIR/target/release/libmatchy_wireshark_plugin.dylib"
    elif [ -f "$SCRIPT_DIR/target/release/libmatchy_wireshark_plugin.so" ]; then
        plugin_src="$SCRIPT_DIR/target/release/libmatchy_wireshark_plugin.so"
    else
        error "Error: Plugin binary not found. Run: cargo build --release"
        return 1
    fi
    
    cp "$plugin_src" "$plugin_dir/$plugin_name"
    
    # macOS: Remove quarantine attribute (for downloaded binaries)
    if [ "$OS_TYPE" = "darwin" ]; then
        xattr -d com.apple.quarantine "$plugin_dir/$plugin_name" 2>/dev/null || true
    fi
    
    # macOS: Fix library paths to use @rpath
    if [ "$OS_TYPE" = "darwin" ]; then
        install_name_tool -id "$plugin_name" "$plugin_dir/$plugin_name" 2>/dev/null || true
        
        # Fix wireshark/wsutil/glib to use @rpath
        for lib in libwireshark libwsutil libglib-2.0; do
            old_path=$(otool -L "$plugin_dir/$plugin_name" | grep "$lib" | awk '{print $1}' | head -1)
            if [ -n "$old_path" ]; then
                case "$old_path" in
                    @rpath/*) ;;  # Already using @rpath, skip
                    *)
                        lib_name=$(basename "$old_path")
                        install_name_tool -change "$old_path" "@rpath/$lib_name" "$plugin_dir/$plugin_name" 2>/dev/null || true
                        ;;
                esac
            fi
        done
        
        # Re-sign after modifying library paths (required on modern macOS)
        codesign -f -s - "$plugin_dir/$plugin_name" 2>/dev/null || true
    fi
    
    info "  Installed successfully"
}

# Show usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    if [ -f "$SCRIPT_DIR/Cargo.toml" ]; then
        echo "  --build       Force rebuild before installing"
    fi
    echo "  --help        Show this help message"
}

# Main
main() {
    force_build=false
    
    while [ $# -gt 0 ]; do
        case "$1" in
            --build) force_build=true; shift ;;
            --help) usage; exit 0 ;;
            *) error "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
    
    echo "Matchy Wireshark Plugin Installer"
    echo "================================="
    
    # Detect Wireshark version
    installed_version=$(detect_wireshark_version)
    min_version=$(get_min_version)
    
    if [ -z "$installed_version" ]; then
        error "Error: No Wireshark installation found"
        echo
        echo "Please install Wireshark:"
        echo "  macOS:  brew install wireshark  OR  https://www.wireshark.org/download.html"
        echo "  Linux:  apt install wireshark / dnf install wireshark"
        exit 1
    fi
    
    # Check minimum version compatibility for binary packages
    if [ -n "$min_version" ]; then
        if ! version_gte "$installed_version" "$min_version"; then
            error "Error: Wireshark version too old"
            echo "  This plugin requires Wireshark $min_version or later"
            echo "  You have Wireshark $installed_version installed"
            echo
            echo "Please upgrade Wireshark or download an older plugin version from:"
            echo "  https://github.com/matchylabs/matchy-wireshark-plugin/releases"
            exit 1
        fi
        info "Detected Wireshark $installed_version (requires $min_version+)"
    fi
    
    version="$installed_version"
    
    # Build if needed (only in source tree, not binary packages)
    if [ -f "$SCRIPT_DIR/Cargo.toml" ]; then
    if [ "$force_build" = true ] || { [ ! -f "$SCRIPT_DIR/target/release/libmatchy_wireshark_plugin.dylib" ] && \
                                           [ ! -f "$SCRIPT_DIR/target/release/libmatchy_wireshark_plugin.so" ]; }; then
            build_plugin
        fi
    fi
    
    install_plugin "$version"
    
    echo
    info "Installation complete!"
    echo
    echo "Verify installation:"
    echo "  tshark -G plugins | grep matchy"
    echo
    echo "Configuration:"
    echo "  1. Open Wireshark"
    echo "  2. Go to Edit → Preferences → Protocols → Matchy"
    echo "  3. Browse to select your .mxy threat database file"
}

# Pause if running interactively (e.g., double-clicked from file manager)
# This keeps the terminal window open so the user can read the output
pause_if_interactive() {
    # Only pause if stdin is a terminal and we're not being piped
    if [ -t 0 ] && [ -t 1 ]; then
        # Check if we're likely launched from a GUI (no parent shell)
        # ppid=1 or parent is a GUI app typically means double-clicked
        case "$(ps -o comm= -p $PPID 2>/dev/null)" in
            # Common terminal emulators - don't pause
            bash|zsh|sh|dash|fish|ksh|tcsh|csh) ;;
            # Everything else (Finder, Nautilus, etc.) - pause
            *)
                printf "Press Enter to close..."
                read -r _
                ;;
        esac
    fi
}

main "$@"
pause_if_interactive
