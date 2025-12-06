//! Integration tests for matchy-wireshark-plugin
//!
//! These tests verify the plugin correctly detects threats by running tshark
//! with the built plugin against test fixtures.
//!
//! Prerequisites:
//! - Plugin must be installed (run install.sh/install.bat first)
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

/// Check if tshark is available
fn tshark_available() -> bool {
    Command::new("tshark")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if the matchy plugin is loaded by Wireshark
fn plugin_loaded() -> bool {
    Command::new("tshark")
        .args(["-G", "plugins"])
        .output()
        .map(|o| {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.to_lowercase().contains("matchy")
        })
        .unwrap_or(false)
}

/// Run tshark with the matchy plugin and return parsed output
fn run_tshark_test() -> Result<Vec<PacketResult>, String> {
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
            threat_level: fields.get(4).filter(|s| !s.is_empty()).map(|s| s.to_string()),
            category: fields.get(5).filter(|s| !s.is_empty()).map(|s| s.to_string()),
        });
    }

    Ok(results)
}

#[test]
fn test_plugin_integration() {
    // Skip if tshark not available (e.g., in some CI environments)
    if !tshark_available() {
        eprintln!("SKIP: tshark not found in PATH");
        return;
    }

    // Skip if plugin not installed
    if !plugin_loaded() {
        eprintln!("SKIP: matchy plugin not loaded (run install.sh first)");
        return;
    }

    let results = run_tshark_test().expect("Failed to run tshark test");

    assert_eq!(results.len(), 4, "Expected 4 packets in test pcap");

    // Frame 1: dst=192.168.1.1 (exact match) -> high threat, malware
    let pkt1 = &results[0];
    assert_eq!(pkt1.frame_number, 1);
    assert_eq!(pkt1.dst_ip, "192.168.1.1");
    assert!(pkt1.threat_detected, "Frame 1 should detect threat on dst IP");
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
