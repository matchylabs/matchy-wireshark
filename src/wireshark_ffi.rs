//! FFI bindings for Wireshark C API
//!
//! Minimal hand-written bindings for the Wireshark plugin API.
//! We only define what we actually need to avoid complex header dependencies.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use libc::{c_char, c_int, c_uint, c_void};

/// Wireshark's boolean type (actually c_int)
pub type gboolean = c_int;

// ============================================================================
// Logging
// ============================================================================

/// Log levels from ws_log_defs.h
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ws_log_level {
    LOG_LEVEL_NONE = 0,
    LOG_LEVEL_NOISY = 1,
    LOG_LEVEL_DEBUG = 2,
    LOG_LEVEL_INFO = 3,
    LOG_LEVEL_MESSAGE = 4,
    LOG_LEVEL_WARNING = 5,
    LOG_LEVEL_CRITICAL = 6,
    LOG_LEVEL_ERROR = 7,
    LOG_LEVEL_ECHO = 8,
}

// ============================================================================
// Opaque Types (pointers to Wireshark internal structures)
// ============================================================================

/// Packet info - contains addresses, ports, timestamps, etc.
/// We treat this as opaque and use accessor functions.
#[repr(C)]
pub struct packet_info {
    _opaque: [u8; 0],
}

/// Tree Value Buffer - packet data buffer
#[repr(C)]
pub struct tvbuff_t {
    _opaque: [u8; 0],
}

/// Protocol tree - hierarchical packet display
#[repr(C)]
pub struct proto_tree {
    _opaque: [u8; 0],
}

/// Protocol item - single field in the tree
#[repr(C)]
pub struct proto_item {
    _opaque: [u8; 0],
}

/// Dissector handle - returned by create_dissector_handle
#[repr(C)]
pub struct dissector_handle {
    _opaque: [u8; 0],
}

pub type dissector_handle_t = *mut dissector_handle;

/// Address structure - matches Wireshark's address type
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct address {
    pub type_: c_int, // address_type enum
    pub len: c_int,   // length of data
    pub data: *const c_void,
    pub priv_: *mut c_void,
}

// ============================================================================
// Address Types
// ============================================================================

pub const AT_NONE: c_int = 0;
pub const AT_ETHER: c_int = 1;
pub const AT_IPV4: c_int = 2;
pub const AT_IPV6: c_int = 3;

// ============================================================================
// Field Types (from epan/ftypes/ftypes.h)
// ============================================================================

pub const FT_NONE: c_int = 0;
pub const FT_PROTOCOL: c_int = 1;
pub const FT_BOOLEAN: c_int = 2;
pub const FT_CHAR: c_int = 3;
pub const FT_UINT8: c_int = 4;
pub const FT_UINT16: c_int = 5;
pub const FT_UINT24: c_int = 6;
pub const FT_UINT32: c_int = 7;
pub const FT_STRING: c_int = 26;
pub const FT_STRINGZ: c_int = 27;

// ============================================================================
// Field Display
// ============================================================================

pub const BASE_NONE: c_int = 0;
pub const BASE_DEC: c_int = 1;
pub const BASE_HEX: c_int = 2;

// ============================================================================
// Encoding
// ============================================================================

pub const ENC_BIG_ENDIAN: c_uint = 0x00000000;
pub const ENC_LITTLE_ENDIAN: c_uint = 0x80000000;
pub const ENC_NA: c_uint = 0x00000000;

// ============================================================================
// Dissector function type
// ============================================================================

/// Dissector callback signature
pub type dissector_t = unsafe extern "C" fn(
    tvb: *mut tvbuff_t,
    pinfo: *mut packet_info,
    tree: *mut proto_tree,
    data: *mut c_void,
) -> c_int;

// ============================================================================
// Header field info structure
// ============================================================================

/// Header field info for registration
/// This must match Wireshark's hf_register_info structure layout
#[repr(C)]
pub struct hf_register_info {
    pub p_id: *mut c_int, // pointer to field ID variable
    pub hfinfo: header_field_info,
}

#[repr(C)]
pub struct header_field_info {
    pub name: *const c_char,
    pub abbrev: *const c_char,
    pub type_: c_int,           // ftenum
    pub display: c_int,         // field_display_e
    pub strings: *const c_void, // value_string or similar
    pub bitmask: u64,           // uint64_t
    pub blurb: *const c_char,
    // Internal fields - Wireshark fills these in (HFILL macro sets these)
    pub id: c_int,                              // -1
    pub parent: c_int,                          // 0
    pub ref_type: c_int,                        // HF_REF_TYPE_NONE = 0
    pub same_name_prev_id: c_int,               // -1
    pub same_name_next: *mut header_field_info, // NULL
}

// ============================================================================
// External Wireshark Functions
// ============================================================================

// ============================================================================
// Preferences Module
// ============================================================================

/// Opaque preferences module pointer
#[repr(C)]
pub struct module_t {
    _opaque: [u8; 0],
}

/// Preference update callback
pub type pref_cb = unsafe extern "C" fn();

// On Windows, use raw-dylib to link directly against DLLs without needing import libraries.
// This eliminates the need to generate .lib files from .dll in CI.
// Note: Windows DLLs are named libwireshark.dll and libwsutil.dll (with lib prefix).
#[cfg_attr(target_os = "windows", link(name = "libwireshark", kind = "raw-dylib"))]
#[cfg_attr(target_os = "windows", link(name = "libwsutil", kind = "raw-dylib"))]
#[cfg_attr(not(target_os = "windows"), link(name = "wireshark"))]
#[cfg_attr(not(target_os = "windows"), link(name = "wsutil"))]
extern "C" {
    // Protocol registration
    pub fn proto_register_protocol(
        name: *const c_char,
        short_name: *const c_char,
        filter_name: *const c_char,
    ) -> c_int;

    pub fn proto_register_field_array(parent: c_int, hf: *mut hf_register_info, num_records: c_int);

    pub fn proto_register_subtree_array(indices: *const *mut c_int, num_indices: c_int);

    // Preferences registration
    pub fn prefs_register_protocol(proto: c_int, apply_cb: Option<pref_cb>) -> *mut module_t;

    pub fn prefs_register_module(
        parent: *mut module_t,
        name: *const c_char,
        title: *const c_char,
        description: *const c_char,
        apply_cb: Option<pref_cb>,
    ) -> *mut module_t;

    pub fn prefs_register_subtree(
        parent: *mut module_t,
        name: *const c_char,
        title: *const c_char,
        apply_cb: Option<pref_cb>,
    ) -> *mut module_t;

    pub fn prefs_register_filename_preference(
        module: *mut module_t,
        name: *const c_char,
        title: *const c_char,
        description: *const c_char,
        var: *mut *const c_char,
        for_writing: c_int,
    );

    pub fn prefs_register_bool_preference(
        module: *mut module_t,
        name: *const c_char,
        title: *const c_char,
        description: *const c_char,
        var: *mut gboolean,
    );

    // Logging
    pub fn ws_log_full(
        domain: *const c_char,
        level: ws_log_level,
        file: *const c_char,
        line: libc::c_long,
        func: *const c_char,
        format: *const c_char,
        ...
    );

    // Dissector handle creation and registration
    pub fn create_dissector_handle(dissector: dissector_t, proto: c_int) -> dissector_handle_t;

    pub fn register_postdissector(handle: dissector_handle_t);

    // Tree item creation
    pub fn proto_tree_add_item(
        tree: *mut proto_tree,
        hfindex: c_int,
        tvb: *mut tvbuff_t,
        start: c_int,
        length: c_int,
        encoding: c_uint,
    ) -> *mut proto_item;

    pub fn proto_tree_add_string(
        tree: *mut proto_tree,
        hfindex: c_int,
        tvb: *mut tvbuff_t,
        start: c_int,
        length: c_int,
        value: *const c_char,
    ) -> *mut proto_item;

    pub fn proto_tree_add_boolean(
        tree: *mut proto_tree,
        hfindex: c_int,
        tvb: *mut tvbuff_t,
        start: c_int,
        length: c_int,
        value: c_uint,
    ) -> *mut proto_item;

    pub fn proto_item_add_subtree(pi: *mut proto_item, idx: c_int) -> *mut proto_tree;

    // TVB accessors
    pub fn tvb_captured_length(tvb: *mut tvbuff_t) -> c_uint;
    pub fn tvb_reported_length(tvb: *mut tvbuff_t) -> c_uint;
}

// ============================================================================
// packet_info struct definition
//
// This is a partial definition of Wireshark's packet_info struct.
// We define the exact layout up to and including the src/dst fields,
// which is more defensive than using hardcoded byte offsets.
//
// Based on Wireshark 4.6.x epan/packet_info.h
// If Wireshark changes the struct layout, this will need updating,
// but at least the compiler will enforce correct field access.
// ============================================================================

/// Wireshark's nstime_t (from wsutil/nstime.h)
/// A time value with seconds and nanoseconds
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nstime_t {
    pub secs: i64,  // time_t is typically i64
    pub nsecs: i32,
}

/// Flags struct embedded in packet_info
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct pinfo_flags {
    bitfield: u32, // in_error_pkt:1, in_gre_pkt:1
}

/// Full packet_info struct definition (Wireshark 4.6.x)
/// This must match the C struct layout exactly!
#[repr(C)]
pub struct packet_info_full {
    pub current_proto: *const c_char,           // const char*
    pub cinfo: *mut c_void,                     // struct epan_column_info*
    pub presence_flags: u32,                    // uint32_t
    pub num: u32,                               // uint32_t (frame number)
    pub abs_ts: nstime_t,                       // nstime_t
    pub rel_ts: nstime_t,                       // nstime_t
    pub rel_cap_ts: nstime_t,                   // nstime_t
    pub rel_cap_ts_present: bool,               // bool
    // Padding for alignment (bool is 1 byte, next is pointer)
    _pad1: [u8; 7],
    pub fd: *mut c_void,                        // frame_data*
    pub pseudo_header: *mut c_void,             // union wtap_pseudo_header*
    pub rec: *mut c_void,                       // wtap_rec*
    pub data_src: *mut c_void,                  // GSList*
    pub dl_src: address,                        // address (link-layer source)
    pub dl_dst: address,                        // address (link-layer dest)
    pub net_src: address,                       // address (network-layer source)
    pub net_dst: address,                       // address (network-layer dest)
    pub src: address,                           // address (source - net if present, DL otherwise)
    pub dst: address,                           // address (dest - net if present, DL otherwise)
    // We don't need fields beyond this point
}

/// Get source address from packet_info
///
/// # Safety
/// Caller must ensure pinfo is valid and points to a valid packet_info struct
pub unsafe fn pinfo_get_src(pinfo: *const packet_info) -> *const address {
    if pinfo.is_null() {
        return std::ptr::null();
    }
    // Cast to our full struct definition to access the field properly
    let pinfo_full = pinfo as *const packet_info_full;
    &(*pinfo_full).src as *const address
}

/// Get destination address from packet_info
///
/// # Safety
/// Caller must ensure pinfo is valid and points to a valid packet_info struct
pub unsafe fn pinfo_get_dst(pinfo: *const packet_info) -> *const address {
    if pinfo.is_null() {
        return std::ptr::null();
    }
    // Cast to our full struct definition to access the field properly
    let pinfo_full = pinfo as *const packet_info_full;
    &(*pinfo_full).dst as *const address
}

/// Extract IPv4 address bytes from Wireshark address struct
/// Returns None if not an IPv4 address or if validation fails
pub unsafe fn address_to_ipv4(addr: *const address) -> Option<[u8; 4]> {
    if addr.is_null() {
        return None;
    }
    let addr_ref = &*addr;
    
    // Defensive checks:
    // 1. Type must be AT_IPV4 (value 2)
    // 2. Length must be exactly 4 bytes
    // 3. Data pointer must be non-null
    if addr_ref.type_ != AT_IPV4 {
        return None;
    }
    if addr_ref.len != 4 {
        return None;
    }
    if addr_ref.data.is_null() {
        return None;
    }
    
    let data = addr_ref.data as *const u8;
    Some([*data, *data.add(1), *data.add(2), *data.add(3)])
}

/// Extract IPv6 address bytes from Wireshark address struct
/// Returns None if not an IPv6 address or if validation fails
pub unsafe fn address_to_ipv6(addr: *const address) -> Option<[u8; 16]> {
    if addr.is_null() {
        return None;
    }
    let addr_ref = &*addr;
    
    // Defensive checks:
    // 1. Type must be AT_IPV6 (value 3)
    // 2. Length must be exactly 16 bytes
    // 3. Data pointer must be non-null
    if addr_ref.type_ != AT_IPV6 {
        return None;
    }
    if addr_ref.len != 16 {
        return None;
    }
    if addr_ref.data.is_null() {
        return None;
    }
    
    let data = addr_ref.data as *const [u8; 16];
    Some(*data)
}

// ============================================================================
// Helper functions
// ============================================================================

/// Create a null-terminated C string from a Rust string slice.
/// The returned CString must be kept alive while the pointer is in use.
pub fn to_c_string(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s).expect("String contains null byte")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    /// Verify our struct layout matches expected Wireshark offsets.
    /// These offsets were verified against Wireshark 4.6.x.
    /// If this test fails after a Wireshark update, the struct definition needs updating.
    #[test]
    fn test_packet_info_struct_layout() {
        // Verify address struct size (should be 24 bytes on 64-bit: int + int + ptr + ptr)
        assert_eq!(
            mem::size_of::<address>(),
            24,
            "address struct size mismatch - Wireshark headers may have changed"
        );

        // Verify nstime_t size (should be 16 bytes: i64 + i32 + padding)
        assert_eq!(
            mem::size_of::<nstime_t>(),
            16,
            "nstime_t struct size mismatch"
        );

        // Calculate offset to src field in our packet_info_full struct
        let src_offset = mem::offset_of!(packet_info_full, src);
        let dst_offset = mem::offset_of!(packet_info_full, dst);

        // The original hardcoded offsets were 208 and 232 for Wireshark 4.6
        // Our struct-based approach should produce the same offsets
        // If these don't match, our struct definition is wrong
        assert_eq!(
            src_offset, 208,
            "packet_info.src offset mismatch (expected 208, got {}). \
             The packet_info_full struct layout needs to be updated for this Wireshark version.",
            src_offset
        );
        assert_eq!(
            dst_offset, 232,
            "packet_info.dst offset mismatch (expected 232, got {}). \
             The packet_info_full struct layout needs to be updated for this Wireshark version.",
            dst_offset
        );
    }

    #[test]
    fn test_address_type_constants() {
        // Verify our address type constants match Wireshark's enum values
        assert_eq!(AT_NONE, 0);
        assert_eq!(AT_ETHER, 1);
        assert_eq!(AT_IPV4, 2);
        assert_eq!(AT_IPV6, 3);
    }
}
