#!/bin/bash
# Post-build script to fix dynamic library paths for Wireshark plugin
# This makes the plugin compatible with both Homebrew and standalone Wireshark.app installations

set -e

PLUGIN_PATH="$1"

if [ -z "$PLUGIN_PATH" ]; then
    echo "Usage: $0 <path-to-plugin.dylib>"
    exit 1
fi

if [ ! -f "$PLUGIN_PATH" ]; then
    echo "Error: Plugin file not found: $PLUGIN_PATH"
    exit 1
fi

echo "Fixing dylib paths for: $PLUGIN_PATH"

# Fix the install name to be just the filename
PLUGIN_NAME=$(basename "$PLUGIN_PATH")
install_name_tool -id "$PLUGIN_NAME" "$PLUGIN_PATH"
echo "  ✓ Set install name to: $PLUGIN_NAME"

# Change absolute Homebrew paths to @rpath for compatibility
if otool -L "$PLUGIN_PATH" | grep -q "/opt/homebrew/opt/wireshark/lib/libwireshark"; then
    install_name_tool -change /opt/homebrew/opt/wireshark/lib/libwireshark.19.dylib @rpath/libwireshark.19.dylib "$PLUGIN_PATH"
    echo "  ✓ Changed libwireshark to @rpath"
fi

if otool -L "$PLUGIN_PATH" | grep -q "/opt/homebrew/opt/wireshark/lib/libwsutil"; then
    install_name_tool -change /opt/homebrew/opt/wireshark/lib/libwsutil.17.dylib @rpath/libwsutil.17.dylib "$PLUGIN_PATH"
    echo "  ✓ Changed libwsutil to @rpath"
fi

if otool -L "$PLUGIN_PATH" | grep -q "/opt/homebrew/opt/glib/lib/libglib"; then
    install_name_tool -change /opt/homebrew/opt/glib/lib/libglib-2.0.0.dylib @rpath/libglib-2.0.0.dylib "$PLUGIN_PATH"
    echo "  ✓ Changed libglib to @rpath"
fi

echo "✓ Done! Plugin is now compatible with both Homebrew and Wireshark.app"
