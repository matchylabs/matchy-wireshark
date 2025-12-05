#!/bin/bash
# Install matchy-wireshark plugin
#
# This script installs the matchy Wireshark plugin for the current user.
# It supports both macOS and Linux systems, and handles multiple Wireshark
# installations (Homebrew, Wireshark.app, system packages).

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}$1${NC}"; }
warn() { echo -e "${YELLOW}$1${NC}"; }
error() { echo -e "${RED}$1${NC}"; }

# Detect all Wireshark installations on the system
detect_installations() {
    local installs=()
    
    # macOS: Check for Wireshark.app
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if [[ -d "/Applications/Wireshark.app" ]]; then
            local app_version=$(/Applications/Wireshark.app/Contents/MacOS/Wireshark --version 2>/dev/null | head -1 | sed -E 's/.*([0-9]+\.[0-9]+)\..*/\1/')
            if [[ -n "$app_version" ]]; then
                installs+=("app:$app_version:/Applications/Wireshark.app")
            fi
        fi
        
        # Homebrew (ARM)
        if [[ -x "/opt/homebrew/bin/tshark" ]]; then
            local brew_version=$(/opt/homebrew/bin/tshark --version 2>/dev/null | head -1 | sed -E 's/.*([0-9]+\.[0-9]+)\..*/\1/')
            if [[ -n "$brew_version" ]]; then
                installs+=("homebrew-arm:$brew_version:/opt/homebrew")
            fi
        fi
        
        # Homebrew (Intel)
        if [[ -x "/usr/local/bin/tshark" ]]; then
            local brew_version=$(/usr/local/bin/tshark --version 2>/dev/null | head -1 | sed -E 's/.*([0-9]+\.[0-9]+)\..*/\1/')
            if [[ -n "$brew_version" ]]; then
                installs+=("homebrew-intel:$brew_version:/usr/local")
            fi
        fi
    fi
    
    # Linux: Check common locations
    if [[ "$OSTYPE" == "linux"* ]]; then
        if command -v tshark &> /dev/null; then
            local sys_version=$(tshark --version 2>/dev/null | head -1 | sed -E 's/.*([0-9]+\.[0-9]+)\..*/\1/')
            if [[ -n "$sys_version" ]]; then
                installs+=("system:$sys_version:")
            fi
        fi
    fi
    
    # Fallback: check PATH
    if [[ ${#installs[@]} -eq 0 ]]; then
        if command -v tshark &> /dev/null; then
            local path_version=$(tshark --version 2>/dev/null | head -1 | sed -E 's/.*([0-9]+\.[0-9]+)\..*/\1/')
            if [[ -n "$path_version" ]]; then
                installs+=("path:$path_version:")
            fi
        fi
    fi
    
    printf '%s\n' "${installs[@]}"
}

# Get glib path for a specific installation
get_glib_path() {
    local install_type="$1"
    local install_prefix="$2"
    
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
            local glib_path=$(find /opt/homebrew /usr/local /usr -name "libglib-2.0.so*" -o -name "libglib-2.0*.dylib" 2>/dev/null | head -1)
            echo "$glib_path"
            ;;
    esac
}

# Build the plugin
build_plugin() {
    echo "Building plugin..."
    (cd "$SCRIPT_DIR" && cargo build --release)
}

# Install for a specific Wireshark installation
install_for() {
    local install_type="$1"
    local version="$2"
    local prefix="$3"
    
    local version_dir="${version//./-}"
    local plugin_dir="$HOME/.local/lib/wireshark/plugins/${version_dir}/epan"
    local plugin_name="matchy.so"
    
    echo
    info "Installing for: $install_type (Wireshark $version)"
    echo "  Plugin directory: $plugin_dir"
    
    mkdir -p "$plugin_dir"
    
    # Find source binary
    local plugin_src=""
    if [[ -f "$SCRIPT_DIR/target/release/libmatchy_wireshark.dylib" ]]; then
        plugin_src="$SCRIPT_DIR/target/release/libmatchy_wireshark.dylib"
    elif [[ -f "$SCRIPT_DIR/target/release/libmatchy_wireshark.so" ]]; then
        plugin_src="$SCRIPT_DIR/target/release/libmatchy_wireshark.so"
    else
        error "Error: Plugin binary not found. Run: cargo build --release"
        return 1
    fi
    
    cp "$plugin_src" "$plugin_dir/$plugin_name"
    
    # macOS: Remove quarantine attribute (for downloaded binaries)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        xattr -d com.apple.quarantine "$plugin_dir/$plugin_name" 2>/dev/null || true
    fi
    
    # macOS: Fix library paths
    if [[ "$OSTYPE" == "darwin"* ]]; then
        install_name_tool -id "$plugin_name" "$plugin_dir/$plugin_name" 2>/dev/null || true
        
        # Fix wireshark/wsutil to use @rpath
        for lib in libwireshark libwsutil; do
            old_path=$(otool -L "$plugin_dir/$plugin_name" | grep "$lib" | awk '{print $1}' | head -1)
            if [[ -n "$old_path" && "$old_path" != @rpath/* ]]; then
                lib_name=$(basename "$old_path")
                install_name_tool -change "$old_path" "@rpath/$lib_name" "$plugin_dir/$plugin_name" 2>/dev/null || true
            fi
        done
        
        # Fix glib path based on installation type
        local glib_target=$(get_glib_path "$install_type" "$prefix")
        if [[ -n "$glib_target" ]]; then
            old_glib=$(otool -L "$plugin_dir/$plugin_name" | grep "libglib-2.0" | awk '{print $1}' | head -1)
            if [[ -n "$old_glib" && "$old_glib" != "$glib_target" ]]; then
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
    local install_all=false
    local list_only=false
    local force_build=false
    
    while [[ $# -gt 0 ]]; do
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
    
    # Detect installations
    installations=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && installations+=("$line")
    done < <(detect_installations)
    
    if [[ ${#installations[@]} -eq 0 ]]; then
        error "Error: No Wireshark installation found"
        echo
        echo "Please install Wireshark:"
        echo "  macOS:  brew install wireshark  OR  https://www.wireshark.org/download.html"
        echo "  Linux:  apt install wireshark / dnf install wireshark"
        exit 1
    fi
    
    echo
    echo "Detected Wireshark installations:"
    for install in "${installations[@]}"; do
        IFS=: read -r type version prefix <<< "$install"
        echo "  - $type: version $version"
    done
    
    if $list_only; then
        exit 0
    fi
    
    # Build if needed
    if $force_build || { [[ ! -f "$SCRIPT_DIR/target/release/libmatchy_wireshark.dylib" ]] && \
                         [[ ! -f "$SCRIPT_DIR/target/release/libmatchy_wireshark.so" ]]; }; then
        build_plugin
    fi
    
    # Install
    if $install_all; then
        for install in "${installations[@]}"; do
            IFS=: read -r type version prefix <<< "$install"
            install_for "$type" "$version" "$prefix"
        done
    else
        # Install for first (preferred) installation
        IFS=: read -r type version prefix <<< "${installations[0]}"
        install_for "$type" "$version" "$prefix"
        
        if [[ ${#installations[@]} -gt 1 ]]; then
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
