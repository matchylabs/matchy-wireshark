//! FFI bindings for Wireshark C API
//!
//! Minimal hand-written bindings for the Wireshark plugin API.
//! We only define what we actually need to avoid complex header dependencies.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use libc::{c_char, c_int, c_uint, c_void};

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
// packet_info field accessors
//
// Since packet_info is a large struct with many fields, we access
// src/dst addresses by calculating offsets. This is fragile but
// avoids needing the full struct definition.
//
// Alternative: use Wireshark's exported accessor functions if available.
// ============================================================================

/// Offset to 'src' address in packet_info (Wireshark 4.6)
/// This is calculated from the packet_info struct definition.
/// WARNING: This offset may change between Wireshark versions!
const PINFO_SRC_OFFSET: usize = 208; // Verified for Wireshark 4.6
const PINFO_DST_OFFSET: usize = 232; // Verified for Wireshark 4.6

/// Get source address from packet_info
///
/// # Safety
/// Caller must ensure pinfo is valid
pub unsafe fn pinfo_get_src(pinfo: *const packet_info) -> *const address {
    (pinfo as *const u8).add(PINFO_SRC_OFFSET) as *const address
}

/// Get destination address from packet_info
///
/// # Safety
/// Caller must ensure pinfo is valid
pub unsafe fn pinfo_get_dst(pinfo: *const packet_info) -> *const address {
    (pinfo as *const u8).add(PINFO_DST_OFFSET) as *const address
}

/// Extract IPv4 address bytes from Wireshark address struct
/// Returns None if not an IPv4 address
pub unsafe fn address_to_ipv4(addr: *const address) -> Option<[u8; 4]> {
    if addr.is_null() {
        return None;
    }
    let addr_ref = &*addr;
    if addr_ref.type_ != AT_IPV4 || addr_ref.len != 4 || addr_ref.data.is_null() {
        return None;
    }
    let data = addr_ref.data as *const u8;
    Some([*data, *data.add(1), *data.add(2), *data.add(3)])
}

/// Extract IPv6 address bytes from Wireshark address struct
/// Returns None if not an IPv6 address
pub unsafe fn address_to_ipv6(addr: *const address) -> Option<[u8; 16]> {
    if addr.is_null() {
        return None;
    }
    let addr_ref = &*addr;
    if addr_ref.type_ != AT_IPV6 || addr_ref.len != 16 || addr_ref.data.is_null() {
        return None;
    }
    let mut result = [0u8; 16];
    let data = addr_ref.data as *const u8;
    for i in 0..16 {
        result[i] = *data.add(i);
    }
    Some(result)
}

// ============================================================================
// Helper functions
// ============================================================================

/// Create a null-terminated C string from a Rust string slice.
/// The returned CString must be kept alive while the pointer is in use.
pub fn to_c_string(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s).expect("String contains null byte")
}
