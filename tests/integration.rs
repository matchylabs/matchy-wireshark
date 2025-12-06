//! Integration tests for matchy-wireshark-plugin
//!
//! These tests verify the plugin correctly detects threats by running tshark
//! with the built plugin against test fixtures.
//!
//! The test automatically sets up a temporary plugin directory pointing to
//! the freshly-built plugin, so no manual installation is required.
//!
//! Prerequisites:
//! - tshark must be in PATH
//!
//! Run with: cargo test --test integration

use std::path::PathBuf;
use std::process::Command;

/// Get the path to the test fixtures directory
fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

/// Check if tshark is available and return its version (major.minor)
fn get_tshark_version() -> Option<String> {
    let output = Command::new("tshark").arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    // Parse "TShark (Wireshark) 4.6.1" or similar
    for line in text.lines() {
        if line.contains("Wireshark") || line.contains("TShark") {
            for part in line.split_whitespace() {
                if part
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_digit())
                    .unwrap_or(false)
                {
                    let parts: Vec<&str> = part.split('.').collect();
                    if parts.len() >= 2 {
                        return Some(format!("{}.{}", parts[0], parts[1]));
                    }
                }
            }
        }
    }
    None
}

/// Set up a temporary plugin directory structure for testing.
/// Copies all available plugin versions, just like the real install.
/// Returns the path to the temp plugin dir (set WIRESHARK_PLUGIN_DIR to this).
fn setup_test_plugin_dir() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp_dir = std::env::temp_dir().join("matchy-wireshark-test");
    
    // Clean up any previous test directory
    let _ = std::fs::remove_dir_all(&temp_dir);
    
    #[cfg(target_os = "windows")]
    let (plugin_name, dest_name) = ("matchy_wireshark_plugin.dll", "matchy.dll");
    #[cfg(target_os = "macos")]
    let (plugin_name, dest_name) = ("libmatchy_wireshark_plugin.dylib", "matchy.so");
    #[cfg(target_os = "linux")]
    let (plugin_name, dest_name) = ("libmatchy_wireshark_plugin.so", "matchy.so");
    
    let mut installed_count = 0;
    
    // First, try to copy from plugins/ directory (CI builds with multiple versions)
    let plugins_dir = manifest_dir.join("plugins");
    if plugins_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&plugins_dir) {
            for entry in entries.flatten() {
                let version_dir = entry.path();
                if version_dir.is_dir() {
                    if let Some(version) = version_dir.file_name().and_then(|s| s.to_str()) {
                        // Look for matchy.so or matchy.dll in the version directory
                        let src = version_dir.join(dest_name);
                        if src.exists() {
                            let dest_dir = temp_dir.join(version).join("epan");
                            std::fs::create_dir_all(&dest_dir)
                                .expect("Failed to create temp plugin directory");
                            let dest = dest_dir.join(dest_name);
                            std::fs::copy(&src, &dest)
                                .expect("Failed to copy plugin to temp directory");
                            eprintln!("Installed plugin for version {} from plugins/", version);
                            installed_count += 1;
                        }
                    }
                }
            }
        }
    }
    
    // If no plugins/ directory (local dev), copy from target/ to common versions
    if installed_count == 0 {
        let candidates = [
            manifest_dir.join("target/release").join(plugin_name),
            manifest_dir.join("target/debug").join(plugin_name),
        ];
        
        let plugin_path = candidates
            .into_iter()
            .find(|p| p.exists())
            .expect("Built plugin not found - run 'cargo build' first");
        
        // Install to common Wireshark versions for local testing
        for version in ["4.0", "4.2", "4.4", "4.6"] {
            let dest_dir = temp_dir.join(version).join("epan");
            std::fs::create_dir_all(&dest_dir)
                .expect("Failed to create temp plugin directory");
            let dest = dest_dir.join(dest_name);
            std::fs::copy(&plugin_path, &dest)
                .expect("Failed to copy plugin to temp directory");
        }
        eprintln!("Installed plugin from target/ to all versions");
    }
    
    temp_dir
}

/// Check if the matchy plugin is loaded by Wireshark (with custom plugin dir)
fn plugin_loaded_with_dir(plugin_dir: &PathBuf) -> bool {
    let output = Command::new("tshark")
        .env("WIRESHARK_PLUGIN_DIR", plugin_dir)
        .args(["-G", "plugins"])
        .output();

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let stderr = String::from_utf8_lossy(&o.stderr);
            // Check stdout for plugin listing and stderr for load errors
            let found = stdout.to_lowercase().contains("matchy");
            let has_error = stderr.to_lowercase().contains("couldn't load plugin");
            if has_error {
                eprintln!("Plugin load error (stderr): {}", stderr);
            }
            if !found {
                eprintln!("Plugin not found in tshark output. Looking for 'matchy' in:");
                eprintln!("{}", stdout);
            }
            found && !has_error
        }
        Err(e) => {
            eprintln!("Failed to run tshark: {}", e);
            false
        }
    }
}

/// Run tshark with the matchy plugin and return parsed output
fn run_tshark_test(plugin_dir: &PathBuf) -> Result<Vec<PacketResult>, String> {
    let fixtures = fixtures_dir();
    let pcap_path = fixtures.join("test.pcap");
    let mxy_path = fixtures.join("test.mxy");

    if !pcap_path.exists() {
        return Err(format!("Test pcap not found: {}", pcap_path.display()));
    }
    if !mxy_path.exists() {
        return Err(format!("Test database not found: {}", mxy_path.display()));
    }

    // Use -o to set the database path, avoiding conflicts with saved preferences
    let db_pref = format!("matchy.database_path:{}", mxy_path.display());

    let output = Command::new("tshark")
        .env("WIRESHARK_PLUGIN_DIR", plugin_dir)
        .args([
            "-o",
            &db_pref,
            "-r",
            pcap_path.to_str().unwrap(),
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "matchy.threat_detected",
            "-e",
            "matchy.level",
            "-e",
            "matchy.category",
        ])
        .output()
        .map_err(|e| format!("Failed to run tshark: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("tshark failed: {}", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_tshark_output(&stdout)
}

/// Parsed result for a single packet
#[derive(Debug)]
struct PacketResult {
    frame_number: u32,
    src_ip: String,
    dst_ip: String,
    threat_detected: bool,
    threat_level: Option<String>,
    category: Option<String>,
}

/// Parse tab-separated tshark output into PacketResults
fn parse_tshark_output(output: &str) -> Result<Vec<PacketResult>, String> {
    let mut results = Vec::new();

    for line in output.lines() {
        if line.trim().is_empty() {
            continue;
        }

        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 3 {
            continue;
        }

        let frame_number = fields[0]
            .parse()
            .map_err(|_| format!("Invalid frame number: {}", fields[0]))?;

        let threat_detected = fields.get(3).map(|s| !s.is_empty()).unwrap_or(false);

        results.push(PacketResult {
            frame_number,
            src_ip: fields[1].to_string(),
            dst_ip: fields[2].to_string(),
            threat_detected,
            threat_level: fields
                .get(4)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
            category: fields
                .get(5)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
        });
    }

    Ok(results)
}

#[test]
fn test_plugin_integration() {
    // Verify tshark is available
    let ws_version =
        get_tshark_version().expect("tshark not found in PATH - install Wireshark/tshark first");
    eprintln!("Detected Wireshark version: {}", ws_version);

    // Set up temp plugin directory with all built plugin versions
    let plugin_dir = setup_test_plugin_dir();
    eprintln!("Using plugin directory: {}", plugin_dir.display());

    // Verify plugin loads correctly
    assert!(
        plugin_loaded_with_dir(&plugin_dir),
        "matchy plugin failed to load - check build output"
    );

    let results = run_tshark_test(&plugin_dir).expect("Failed to run tshark test");

    assert_eq!(results.len(), 4, "Expected 4 packets in test pcap");

    // Frame 1: dst=192.168.1.1 (exact match) -> high threat, malware
    let pkt1 = &results[0];
    assert_eq!(pkt1.frame_number, 1);
    assert_eq!(pkt1.dst_ip, "192.168.1.1");
    assert!(
        pkt1.threat_detected,
        "Frame 1 should detect threat on dst IP"
    );
    assert_eq!(
        pkt1.threat_level.as_deref(),
        Some("High"),
        "Frame 1 threat level"
    );
    assert_eq!(
        pkt1.category.as_deref(),
        Some("malware"),
        "Frame 1 category"
    );

    // Frame 2: dst=10.1.2.3 (matches 10.0.0.0/8 CIDR) -> medium threat, internal
    let pkt2 = &results[1];
    assert_eq!(pkt2.frame_number, 2);
    assert_eq!(pkt2.dst_ip, "10.1.2.3");
    assert!(
        pkt2.threat_detected,
        "Frame 2 should detect threat via CIDR match"
    );
    assert_eq!(
        pkt2.threat_level.as_deref(),
        Some("Medium"),
        "Frame 2 threat level"
    );
    assert_eq!(
        pkt2.category.as_deref(),
        Some("internal"),
        "Frame 2 category"
    );

    // Frame 3: src=192.168.1.1 (threat as source) -> high threat, malware
    let pkt3 = &results[2];
    assert_eq!(pkt3.frame_number, 3);
    assert_eq!(pkt3.src_ip, "192.168.1.1");
    assert!(
        pkt3.threat_detected,
        "Frame 3 should detect threat on src IP"
    );
    assert_eq!(
        pkt3.threat_level.as_deref(),
        Some("High"),
        "Frame 3 threat level"
    );
    assert_eq!(
        pkt3.category.as_deref(),
        Some("malware"),
        "Frame 3 category"
    );

    // Frame 4: clean packet (8.8.8.8 -> 1.1.1.1) -> no threat
    let pkt4 = &results[3];
    assert_eq!(pkt4.frame_number, 4);
    assert!(
        !pkt4.threat_detected,
        "Frame 4 should NOT detect any threat"
    );
    assert!(pkt4.threat_level.is_none(), "Frame 4 should have no level");
    assert!(pkt4.category.is_none(), "Frame 4 should have no category");

    eprintln!("All integration tests passed!");
}
