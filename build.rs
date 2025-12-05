// build.rs - Wireshark plugin build configuration

use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Try to find Wireshark installation
    let wireshark_include = find_wireshark_include();
    let wireshark_lib = find_wireshark_lib();

    println!("cargo:rerun-if-changed=build.rs");

    // Detect Wireshark version and export for the installer
    let wireshark_version = detect_wireshark_version().unwrap_or_else(|| "4.6".to_string());
    println!("cargo:rustc-env=WIRESHARK_VERSION={}", wireshark_version);
    eprintln!("Detected Wireshark version: {}", wireshark_version);

    if let Some(include_path) = &wireshark_include {
        println!(
            "cargo:rustc-env=WIRESHARK_INCLUDE={}",
            include_path.display()
        );
    }

    if let Some(lib_path) = &wireshark_lib {
        println!("cargo:rustc-link-search=native={}", lib_path.display());
    }

    // Link against Wireshark libraries
    // These are required for calling Wireshark's C API
    #[cfg(target_os = "windows")]
    {
        // Windows uses .lib files for linking
        println!("cargo:rustc-link-lib=wireshark");
        println!("cargo:rustc-link-lib=wsutil");
        println!("cargo:rustc-link-lib=glib-2.0");
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Unix-like systems use dynamic linking
        println!("cargo:rustc-link-lib=dylib=wireshark");
        println!("cargo:rustc-link-lib=dylib=wsutil");
    }

    // On macOS with Homebrew, we also need glib
    #[cfg(target_os = "macos")]
    {
        if let Some(glib_lib) = find_glib_lib() {
            println!("cargo:rustc-link-search=native={}", glib_lib.display());
        }
        println!("cargo:rustc-link-lib=dylib=glib-2.0");

        // Tell the linker to use @rpath for these libraries to make
        // the plugin compatible with both Homebrew and Wireshark.app
        println!("cargo:rustc-link-arg=-Wl,-install_name,libmatchy_wireshark.dylib");
    }

    // On Linux, glib is usually linked via pkg-config or system paths
    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-lib=dylib=glib-2.0");
    }

    // Print configuration for debugging
    eprintln!("Wireshark include: {:?}", wireshark_include);
    eprintln!("Wireshark lib: {:?}", wireshark_lib);
}

fn detect_wireshark_version() -> Option<String> {
    // Try tshark --version
    let output = Command::new("tshark").arg("--version").output().ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);

    // Parse "TShark (Wireshark) 4.6.1" or similar
    for line in text.lines() {
        if line.contains("Wireshark") || line.contains("TShark") {
            for part in line.split_whitespace() {
                // Look for version number like "4.6.1"
                if part
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_digit())
                    .unwrap_or(false)
                {
                    let version_parts: Vec<&str> = part.split('.').collect();
                    if version_parts.len() >= 2 {
                        return Some(format!("{}.{}", version_parts[0], version_parts[1]));
                    }
                }
            }
        }
    }

    None
}

fn find_wireshark_include() -> Option<PathBuf> {
    // On Windows, check WIRESHARK_DIR environment variable first
    #[cfg(target_os = "windows")]
    {
        if let Ok(wireshark_dir) = std::env::var("WIRESHARK_DIR") {
            let include_path = PathBuf::from(&wireshark_dir).join("include");
            if include_path.exists() {
                return Some(include_path);
            }
        }
    }

    // Try pkg-config first (Unix-like systems)
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(output) = Command::new("pkg-config")
            .args(["--cflags-only-I", "wireshark"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for part in stdout.split_whitespace() {
                    if let Some(path) = part.strip_prefix("-I") {
                        return Some(PathBuf::from(path));
                    }
                }
            }
        }
    }

    // Try common locations based on platform
    #[cfg(target_os = "windows")]
    let candidates = [
        r"C:\Wireshark\include",
        r"C:\Program Files\Wireshark\include",
        r"C:\Program Files (x86)\Wireshark\include",
    ];

    #[cfg(not(target_os = "windows"))]
    let candidates = [
        "/opt/homebrew/include/wireshark",
        "/usr/local/include/wireshark",
        "/usr/include/wireshark",
    ];

    for candidate in candidates {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Some(path);
        }
    }

    None
}

fn find_wireshark_lib() -> Option<PathBuf> {
    // On Windows, check WIRESHARK_DIR environment variable first
    #[cfg(target_os = "windows")]
    {
        if let Ok(wireshark_dir) = std::env::var("WIRESHARK_DIR") {
            let lib_path = PathBuf::from(&wireshark_dir);
            // Check both root dir and lib subdirectory
            let check_paths = [lib_path.clone(), lib_path.join("lib")];
            for path in &check_paths {
                let wireshark_lib = path.join("wireshark.lib");
                if wireshark_lib.exists() {
                    return Some(path.clone());
                }
            }
        }
    }

    // Try pkg-config first (Unix-like systems)
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(output) = Command::new("pkg-config")
            .args(["--libs-only-L", "wireshark"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for part in stdout.split_whitespace() {
                    if let Some(path) = part.strip_prefix("-L") {
                        return Some(PathBuf::from(path));
                    }
                }
            }
        }
    }

    // Try common locations based on platform
    #[cfg(target_os = "windows")]
    let candidates: Vec<PathBuf> = vec![
        PathBuf::from(r"C:\Wireshark"),
        PathBuf::from(r"C:\Wireshark\lib"),
        PathBuf::from(r"C:\Program Files\Wireshark"),
        PathBuf::from(r"C:\Program Files (x86)\Wireshark"),
    ];

    #[cfg(not(target_os = "windows"))]
    let candidates: Vec<PathBuf> = vec![
        PathBuf::from("/opt/homebrew/lib"),
        PathBuf::from("/usr/local/lib"),
        PathBuf::from("/usr/lib"),
        PathBuf::from("/usr/lib/x86_64-linux-gnu"),
    ];

    for candidate in &candidates {
        #[cfg(target_os = "windows")]
        let wireshark_exists = candidate.join("wireshark.lib").exists();

        #[cfg(not(target_os = "windows"))]
        let wireshark_exists = {
            let wireshark_lib = candidate.join("libwireshark.dylib");
            let wireshark_so = candidate.join("libwireshark.so");
            wireshark_lib.exists() || wireshark_so.exists()
        };

        if wireshark_exists {
            return Some(candidate.clone());
        }
    }

    None
}

#[cfg(target_os = "macos")]
fn find_glib_lib() -> Option<PathBuf> {
    // Try pkg-config first
    if let Ok(output) = Command::new("pkg-config")
        .args(["--libs-only-L", "glib-2.0"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for part in stdout.split_whitespace() {
                if let Some(path) = part.strip_prefix("-L") {
                    return Some(PathBuf::from(path));
                }
            }
        }
    }

    // Common Homebrew location
    let homebrew_glib = PathBuf::from("/opt/homebrew/opt/glib/lib");
    if homebrew_glib.exists() {
        return Some(homebrew_glib);
    }

    None
}
