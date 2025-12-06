//! Matchy Wireshark Plugin
//!
//! Real-time threat intelligence matching for packet analysis.
//! Integrates matchy threat databases into Wireshark as a postdissector plugin.

// Wireshark's plugin API requires mutable statics for field registration.
// This is safe because Wireshark initializes plugins single-threaded.
#![allow(static_mut_refs)]

mod postdissector;
mod threats;
mod wireshark_ffi;

use libc::{c_char, c_int};
use std::ffi::CStr;
use std::sync::Mutex;

/// Global threat database handle
static THREAT_DB: Mutex<Option<matchy::Database>> = Mutex::new(None);

/// Database path preference (pointer to C string)
static mut DATABASE_PATH: *const c_char = std::ptr::null();

/// Our logging domain
const LOG_DOMAIN: &[u8] = b"Matchy\0";

/// Log a debug message using Wireshark's logging framework
/// Usage: `wireshark --log-level=debug --log-domain=Matchy`
macro_rules! ws_debug {
    ($msg:expr) => {{
        use wireshark_ffi::ws_log_level;
        unsafe {
            wireshark_ffi::ws_log_full(
                LOG_DOMAIN.as_ptr() as *const c_char,
                ws_log_level::LOG_LEVEL_DEBUG,
                std::ptr::null(), // file
                0,                // line
                std::ptr::null(), // func
                $msg.as_ptr() as *const c_char,
            );
        }
    }};
}

/// Global protocol ID (set during registration)
static mut PROTO_MATCHY: c_int = -1;

/// Header field IDs
static mut HF_THREAT_DETECTED: c_int = -1;
static mut HF_THREAT_LEVEL: c_int = -1;
static mut HF_THREAT_CATEGORY: c_int = -1;
static mut HF_THREAT_SOURCE: c_int = -1;
static mut HF_THREAT_INDICATOR: c_int = -1;

/// Subtree index
static mut ETT_MATCHY: c_int = -1;

// ============================================================================
// Plugin Version Information
// ============================================================================

// Plugin version and Wireshark compatibility version - auto-generated from Cargo.toml
include!(concat!(env!("OUT_DIR"), "/version.rs"));

// ============================================================================
// Proto Plugin Structure
// ============================================================================

/// Proto plugin structure - tells Wireshark which functions to call
#[repr(C)]
struct ProtoPlugin {
    register_protoinfo: Option<unsafe extern "C" fn()>,
    register_handoff: Option<unsafe extern "C" fn()>,
}

/// Static plugin descriptor
static PROTO_PLUGIN: ProtoPlugin = ProtoPlugin {
    register_protoinfo: Some(proto_register_matchy),
    register_handoff: Some(proto_reg_handoff_matchy),
};

// ============================================================================
// Plugin Entry Point
// ============================================================================

#[cfg_attr(target_os = "windows", link(name = "libwireshark", kind = "raw-dylib"))]
extern "C" {
    fn proto_register_plugin(plugin: *const ProtoPlugin);
}

/// Plugin registration - called by Wireshark at startup
///
/// This registers our plugin with Wireshark's plugin system.
/// Wireshark will then call our register_protoinfo and register_handoff
/// functions at the appropriate times during initialization.
#[no_mangle]
pub extern "C" fn plugin_register() {
    unsafe {
        proto_register_plugin(&PROTO_PLUGIN);
    }
}

// ============================================================================
// Protocol Registration (called by Wireshark during protocol init)
// ============================================================================

/// Called by Wireshark to register our protocol and fields
#[no_mangle]
unsafe extern "C" fn proto_register_matchy() {
    use wireshark_ffi::*;

    // Register the protocol
    static NAME: &[u8] = b"Matchy Threat Intelligence\0";
    static SHORT_NAME: &[u8] = b"Matchy\0";
    static FILTER_NAME: &[u8] = b"matchy\0";

    PROTO_MATCHY = proto_register_protocol(
        NAME.as_ptr() as *const c_char,
        SHORT_NAME.as_ptr() as *const c_char,
        FILTER_NAME.as_ptr() as *const c_char,
    );

    // Register header fields
    register_fields();

    // Register preferences
    register_preferences();
}

/// Static storage for header field registration info
/// These MUST be static because Wireshark keeps pointers to them
static mut HF_ARRAY: [wireshark_ffi::hf_register_info; 5] = {
    use wireshark_ffi::*;
    [
        hf_register_info {
            p_id: std::ptr::null_mut(), // Will be set at runtime
            hfinfo: header_field_info {
                name: c"Threat Detected".as_ptr(),
                abbrev: c"matchy.threat_detected".as_ptr(),
                type_: FT_BOOLEAN,
                display: BASE_NONE,
                strings: std::ptr::null(),
                bitmask: 0,
                blurb: c"Whether this packet matches a threat indicator".as_ptr(),
                id: -1,
                parent: 0,
                ref_type: 0,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
            },
        },
        hf_register_info {
            p_id: std::ptr::null_mut(),
            hfinfo: header_field_info {
                name: c"Threat Level".as_ptr(),
                abbrev: c"matchy.level".as_ptr(),
                type_: FT_STRINGZ,
                display: BASE_NONE,
                strings: std::ptr::null(),
                bitmask: 0,
                blurb: c"Severity level of the threat".as_ptr(),
                id: -1,
                parent: 0,
                ref_type: 0,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
            },
        },
        hf_register_info {
            p_id: std::ptr::null_mut(),
            hfinfo: header_field_info {
                name: c"Category".as_ptr(),
                abbrev: c"matchy.category".as_ptr(),
                type_: FT_STRINGZ,
                display: BASE_NONE,
                strings: std::ptr::null(),
                bitmask: 0,
                blurb: c"Type of threat (malware, phishing, c2, etc.)".as_ptr(),
                id: -1,
                parent: 0,
                ref_type: 0,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
            },
        },
        hf_register_info {
            p_id: std::ptr::null_mut(),
            hfinfo: header_field_info {
                name: c"Source".as_ptr(),
                abbrev: c"matchy.source".as_ptr(),
                type_: FT_STRINGZ,
                display: BASE_NONE,
                strings: std::ptr::null(),
                bitmask: 0,
                blurb: c"Threat intelligence feed source".as_ptr(),
                id: -1,
                parent: 0,
                ref_type: 0,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
            },
        },
        hf_register_info {
            p_id: std::ptr::null_mut(),
            hfinfo: header_field_info {
                name: c"Indicator".as_ptr(),
                abbrev: c"matchy.indicator".as_ptr(),
                type_: FT_STRINGZ,
                display: BASE_NONE,
                strings: std::ptr::null(),
                bitmask: 0,
                blurb: c"The matched threat indicator".as_ptr(),
                id: -1,
                parent: 0,
                ref_type: 0,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
            },
        },
    ]
};

/// Static storage for subtree indices
static mut ETT_ARRAY: [*mut c_int; 1] = [std::ptr::null_mut()];

/// Callback invoked when preferences are updated
/// This is called when the user changes the database path in preferences
unsafe extern "C" fn preferences_apply() {
    ws_debug!(b"preferences_apply called\0");

    // Check if a database path was set
    if DATABASE_PATH.is_null() {
        ws_debug!(b"no database path configured\0");
        return;
    }

    // Try to load the database from the configured path
    let path = std::ffi::CStr::from_ptr(DATABASE_PATH);
    if let Ok(path_str) = path.to_str() {
        if !path_str.is_empty() {
            ws_debug!(b"loading database from preference\0");
            if matchy_load_database(DATABASE_PATH) == 0 {
                ws_debug!(b"database loaded successfully\0");
            } else {
                ws_debug!(b"failed to load database\0");
            }
        }
    }
}

/// Register preferences for the protocol
unsafe fn register_preferences() {
    use wireshark_ffi::*;

    // Register preferences module for the Matchy protocol
    // This will appear under Edit -> Preferences -> Protocols -> Matchy
    let prefs_module = prefs_register_protocol(PROTO_MATCHY, Some(preferences_apply));

    if prefs_module.is_null() {
        return;
    }

    // Register filename preference for database path
    static DB_NAME: &[u8] = b"database_path\0";
    static DB_TITLE: &[u8] = b"Database Path\0";
    static DB_DESC: &[u8] = b"Path to the .mxy threat database file\0";

    prefs_register_filename_preference(
        prefs_module,
        DB_NAME.as_ptr() as *const c_char,
        DB_TITLE.as_ptr() as *const c_char,
        DB_DESC.as_ptr() as *const c_char,
        std::ptr::addr_of_mut!(DATABASE_PATH),
        0, // for_writing = false (we're reading the database)
    );
}

/// Register header fields for display and filtering
unsafe fn register_fields() {
    use wireshark_ffi::*;

    // Set up the p_id pointers to point to our static field ID variables
    HF_ARRAY[0].p_id = std::ptr::addr_of_mut!(HF_THREAT_DETECTED);
    HF_ARRAY[1].p_id = std::ptr::addr_of_mut!(HF_THREAT_LEVEL);
    HF_ARRAY[2].p_id = std::ptr::addr_of_mut!(HF_THREAT_CATEGORY);
    HF_ARRAY[3].p_id = std::ptr::addr_of_mut!(HF_THREAT_SOURCE);
    HF_ARRAY[4].p_id = std::ptr::addr_of_mut!(HF_THREAT_INDICATOR);

    proto_register_field_array(PROTO_MATCHY, HF_ARRAY.as_mut_ptr(), HF_ARRAY.len() as c_int);

    // Register subtree
    ETT_ARRAY[0] = std::ptr::addr_of_mut!(ETT_MATCHY);
    proto_register_subtree_array(ETT_ARRAY.as_ptr(), ETT_ARRAY.len() as c_int);
}

// ============================================================================
// Handoff Registration (called by Wireshark after all protocols registered)
// ============================================================================

/// Called by Wireshark to register our postdissector
/// This is called after all protocols are registered, so we can safely
/// create our dissector handle and register it.
#[no_mangle]
unsafe extern "C" fn proto_reg_handoff_matchy() {
    use wireshark_ffi::*;

    // Try to load database from environment variable
    if let Ok(db_path) = std::env::var("MATCHY_DATABASE") {
        ws_debug!(b"loading database from MATCHY_DATABASE\0");
        let path_c = std::ffi::CString::new(db_path).unwrap();
        if matchy_load_database(path_c.as_ptr()) == 0 {
            ws_debug!(b"database loaded successfully\0");
        } else {
            ws_debug!(b"failed to load database\0");
        }
    }

    let handle = create_dissector_handle(postdissector::dissect_matchy, PROTO_MATCHY);
    register_postdissector(handle);
}

// ============================================================================
// Public API for database management
// ============================================================================

/// Load a matchy threat database
///
/// # Safety
/// Caller must ensure `path` is a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn matchy_load_database(path: *const c_char) -> c_int {
    if path.is_null() {
        return -1;
    }

    let path_str = match CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    match matchy::Database::from(path_str).open() {
        Ok(db) => {
            if let Ok(mut guard) = THREAT_DB.lock() {
                *guard = Some(db);
                0
            } else {
                -1
            }
        }
        Err(_) => -1,
    }
}

/// Check if a database is loaded
#[no_mangle]
pub extern "C" fn matchy_database_loaded() -> c_int {
    match THREAT_DB.lock() {
        Ok(guard) => {
            if guard.is_some() {
                1
            } else {
                0
            }
        }
        Err(_) => 0,
    }
}

/// Unload the current database
#[no_mangle]
pub extern "C" fn matchy_unload_database() {
    if let Ok(mut guard) = THREAT_DB.lock() {
        *guard = None;
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

pub(crate) fn get_database() -> Option<std::sync::MutexGuard<'static, Option<matchy::Database>>> {
    THREAT_DB.lock().ok()
}

pub(crate) fn get_hf_ids() -> (c_int, c_int, c_int, c_int, c_int) {
    unsafe {
        (
            HF_THREAT_DETECTED,
            HF_THREAT_LEVEL,
            HF_THREAT_CATEGORY,
            HF_THREAT_SOURCE,
            HF_THREAT_INDICATOR,
        )
    }
}

pub(crate) fn get_ett_matchy() -> c_int {
    unsafe { ETT_MATCHY }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_version() {
        // Version should be null-terminated
        let last = plugin_version[plugin_version.len() - 1];
        assert_eq!(last, 0, "plugin_version must be null-terminated");

        // Version should match Cargo.toml
        let version_str = std::ffi::CStr::from_bytes_until_nul(unsafe {
            std::slice::from_raw_parts(plugin_version.as_ptr() as *const u8, plugin_version.len())
        })
        .unwrap()
        .to_str()
        .unwrap();
        assert_eq!(version_str, env!("CARGO_PKG_VERSION"));
    }
}
