#!/bin/sh
# Install matchy-wireshark plugin
#
# This script installs the matchy Wireshark plugin for the current user.
# It supports both macOS and Linux systems, and handles multiple Wireshark
# installations (Homebrew, Wireshark.app, system packages).
#
# POSIX-compliant - works with /bin/sh, dash, bash, zsh, etc.

set -e

# Get script directory (POSIX-compatible)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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
warn() { printf "${YELLOW}%s${NC}\n" "$1"; }
error() { printf "${RED}%s${NC}\n" "$1"; }

# Extract major.minor version from Wireshark version string
extract_version() {
    echo "$1" | sed -E 's/.*([0-9]+\.[0-9]+)\..*/\1/' | head -1
}

# Detect all Wireshark installations on the system
# Output: newline-separated "type:version:prefix" entries
detect_installations() {
    # macOS: Check for Wireshark.app
    if [ "$OS_TYPE" = "darwin" ]; then
        if [ -d "/Applications/Wireshark.app" ]; then
            app_version=$(/Applications/Wireshark.app/Contents/MacOS/Wireshark --version 2>/dev/null | head -1)
            app_version=$(extract_version "$app_version")
            if [ -n "$app_version" ]; then
                echo "app:$app_version:/Applications/Wireshark.app"
            fi
        fi
        
        # Homebrew (ARM)
        if [ -x "/opt/homebrew/bin/tshark" ]; then
            brew_version=$(/opt/homebrew/bin/tshark --version 2>/dev/null | head -1)
            brew_version=$(extract_version "$brew_version")
            if [ -n "$brew_version" ]; then
                echo "homebrew-arm:$brew_version:/opt/homebrew"
            fi
        fi
        
        # Homebrew (Intel)
        if [ -x "/usr/local/bin/tshark" ]; then
            brew_version=$(/usr/local/bin/tshark --version 2>/dev/null | head -1)
            brew_version=$(extract_version "$brew_version")
            if [ -n "$brew_version" ]; then
                echo "homebrew-intel:$brew_version:/usr/local"
            fi
        fi
    fi
    
    # Linux: Check common locations
    if [ "$OS_TYPE" = "linux" ]; then
        if command -v tshark >/dev/null 2>&1; then
            sys_version=$(tshark --version 2>/dev/null | head -1)
            sys_version=$(extract_version "$sys_version")
            if [ -n "$sys_version" ]; then
                echo "system:$sys_version:"
            fi
        fi
    fi
}

# Get glib path for a specific installation
get_glib_path() {
    install_type="$1"
    
    case "$install_type" in
        app)
            # Wireshark.app bundles its own frameworks, use @rpath
            echo "@rpath/libglib-2.0.0.dylib"
            ;;
        homebrew-arm)
            echo "/opt/homebrew/opt/glib/lib/libglib-2.0.0.dylib"
            ;;
        homebrew-intel)
            echo "/usr/local/opt/glib/lib/libglib-2.0.0.dylib"
            ;;
        *)
            # Try to find it
            find /opt/homebrew /usr/local /usr -name "libglib-2.0.so*" -o -name "libglib-2.0*.dylib" 2>/dev/null | head -1
            ;;
    esac
}

# Build the plugin
build_plugin() {
    echo "Building plugin..."
    (cd "$SCRIPT_DIR" && cargo build --release)
}

# Install for a specific Wireshark installation
# Args: type version prefix
install_for() {
    install_type="$1"
    version="$2"
    prefix="$3"
    
    version_dir=$(echo "$version" | tr '.' '-')
    plugin_dir="$HOME/.local/lib/wireshark/plugins/${version_dir}/epan"
    plugin_name="matchy.so"
    
    echo
    info "Installing for: $install_type (Wireshark $version)"
    echo "  Plugin directory: $plugin_dir"
    
    mkdir -p "$plugin_dir"
    
    # Find source binary (check binary package first, then source tree)
    plugin_src=""
    if [ -f "$SCRIPT_DIR/matchy.so" ]; then
        # Binary package
        plugin_src="$SCRIPT_DIR/matchy.so"
    elif [ -f "$SCRIPT_DIR/target/release/libmatchy_wireshark.dylib" ]; then
        plugin_src="$SCRIPT_DIR/target/release/libmatchy_wireshark.dylib"
    elif [ -f "$SCRIPT_DIR/target/release/libmatchy_wireshark.so" ]; then
        plugin_src="$SCRIPT_DIR/target/release/libmatchy_wireshark.so"
    else
        error "Error: Plugin binary not found. Run: cargo build --release"
        return 1
    fi
    
    cp "$plugin_src" "$plugin_dir/$plugin_name"
    
    # macOS: Remove quarantine attribute (for downloaded binaries)
    if [ "$OS_TYPE" = "darwin" ]; then
        xattr -d com.apple.quarantine "$plugin_dir/$plugin_name" 2>/dev/null || true
    fi
    
    # macOS: Fix library paths
    if [ "$OS_TYPE" = "darwin" ]; then
        install_name_tool -id "$plugin_name" "$plugin_dir/$plugin_name" 2>/dev/null || true
        
        # Fix wireshark/wsutil to use @rpath
        for lib in libwireshark libwsutil; do
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
        
        # Fix glib path based on installation type
        glib_target=$(get_glib_path "$install_type")
        if [ -n "$glib_target" ]; then
            old_glib=$(otool -L "$plugin_dir/$plugin_name" | grep "libglib-2.0" | awk '{print $1}' | head -1)
            if [ -n "$old_glib" ] && [ "$old_glib" != "$glib_target" ]; then
                install_name_tool -change "$old_glib" "$glib_target" "$plugin_dir/$plugin_name" 2>/dev/null || true
            fi
        fi
    fi
    
    info "  Installed successfully"
}

# Show usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  --all         Install for all detected Wireshark installations"
    echo "  --list        List detected Wireshark installations"
    echo "  --build       Force rebuild before installing"
    echo "  --help        Show this help message"
    echo
    echo "Without options, installs for the first detected installation."
}

# Main
main() {
    install_all=false
    list_only=false
    force_build=false
    
    while [ $# -gt 0 ]; do
        case "$1" in
            --all) install_all=true; shift ;;
            --list) list_only=true; shift ;;
            --build) force_build=true; shift ;;
            --help) usage; exit 0 ;;
            *) error "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
    
    echo "Matchy Wireshark Plugin Installer"
    echo "================================="
    
    # Detect installations (newline-separated)
    installations=$(detect_installations)
    
    if [ -z "$installations" ]; then
        error "Error: No Wireshark installation found"
        echo
        echo "Please install Wireshark:"
        echo "  macOS:  brew install wireshark  OR  https://www.wireshark.org/download.html"
        echo "  Linux:  apt install wireshark / dnf install wireshark"
        exit 1
    fi
    
    echo
    echo "Detected Wireshark installations:"
    echo "$installations" | while IFS=: read -r type version prefix; do
        echo "  - $type: version $version"
    done
    
    if [ "$list_only" = true ]; then
        exit 0
    fi
    
    # Build if needed (only in source tree, not binary packages)
    if [ -f "$SCRIPT_DIR/Cargo.toml" ]; then
        if [ "$force_build" = true ] || { [ ! -f "$SCRIPT_DIR/target/release/libmatchy_wireshark.dylib" ] && \
                                           [ ! -f "$SCRIPT_DIR/target/release/libmatchy_wireshark.so" ]; }; then
            build_plugin
        fi
    fi
    
    # Install
    if [ "$install_all" = true ]; then
        echo "$installations" | while IFS=: read -r type version prefix; do
            install_for "$type" "$version" "$prefix"
        done
    else
        # Install for first (preferred) installation
        first=$(echo "$installations" | head -1)
        type=$(echo "$first" | cut -d: -f1)
        version=$(echo "$first" | cut -d: -f2)
        prefix=$(echo "$first" | cut -d: -f3)
        install_for "$type" "$version" "$prefix"
        
        install_count=$(echo "$installations" | wc -l | tr -d ' ')
        if [ "$install_count" -gt 1 ]; then
            echo
            warn "Note: Multiple Wireshark installations detected."
            echo "Run with --all to install for all of them."
        fi
    fi
    
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
    echo
    echo "Or use environment variable:"
    echo "  MATCHY_DATABASE=/path/to/threats.mxy wireshark"
    echo
}

main "$@"
