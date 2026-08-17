use std::collections::HashMap;
use std::ffi::c_char;
use std::ptr;
use std::sync::OnceLock;

use crate::client::{parse_preset_name, preset_bundle};
use crate::error::FfiError;
use crate::panic::catch_status;

fn preset_names() -> &'static [&'static str] {
    &[
        "chrome_131",
        "chrome_144",
        "chrome_145",
        "chrome_146",
        "chrome_147",
        "chrome_148",
        "chrome_149",
        "chrome_150",
        "chrome_151",
        "firefox_133",
        "firefox_147",
        "safari_18",
        "safari_26",
    ]
}

fn preset_list_json_bytes() -> &'static Vec<u8> {
    static LIST: OnceLock<Vec<u8>> = OnceLock::new();
    LIST.get_or_init(|| {
        let mut bytes = serde_json::to_vec(preset_names()).expect("serialize preset list");
        bytes.push(0);
        bytes
    })
}

fn preset_details_map() -> &'static HashMap<&'static str, Vec<u8>> {
    static DETAILS: OnceLock<HashMap<&'static str, Vec<u8>>> = OnceLock::new();
    DETAILS.get_or_init(|| {
        let mut map = HashMap::new();
        for &name in preset_names() {
            let preset = parse_preset_name(name).expect("known preset");
            let preset = preset_bundle(preset);
            let header_order = preset.header_order_strings();
            let h3_header_order = preset.h3_header_order.as_ref().map(|order| {
                order
                    .iter()
                    .map(|header| header.as_str().to_string())
                    .collect::<Vec<_>>()
            });
            let lkrequest::preset::ClientPreset {
                tls_profile,
                h2_profile,
                quic_profile,
                ..
            } = preset;
            let value = serde_json::json!({
                "name": name,
                "tls_profile": tls_profile,
                "h2_profile": h2_profile,
                "quic_profile": quic_profile,
                "header_order": header_order,
                "h3_header_order": h3_header_order,
            });
            let mut bytes = serde_json::to_vec(&value).expect("serialize preset detail");
            bytes.push(0);
            map.insert(name, bytes);
        }
        map
    })
}

#[no_mangle]
pub extern "C" fn lk_preset_list_json(out_json_ptr: *mut *const c_char) -> crate::abi::lk_status_t {
    catch_status(ptr::null_mut(), || unsafe {
        if out_json_ptr.is_null() {
            return Err(FfiError::invalid_argument("out_json_ptr is null"));
        }
        let bytes = preset_list_json_bytes();
        *out_json_ptr = bytes.as_ptr().cast::<c_char>();
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn lk_preset_get_detail_json(
    name_ptr: *const c_char,
    name_len: usize,
    out_json_ptr: *mut *const c_char,
    out_err: *mut *mut crate::handles::lk_error_t,
) -> crate::abi::lk_status_t {
    catch_status(out_err, || unsafe {
        if out_json_ptr.is_null() {
            return Err(FfiError::invalid_argument("out_json_ptr is null"));
        }
        *out_json_ptr = ptr::null();
        let name = crate::conv::read_string_parts(name_ptr, name_len, "preset name")?;
        let bytes = preset_details_map()
            .get(name.as_str())
            .ok_or_else(|| FfiError::not_found(format!("preset not found: {name}")))?;
        *out_json_ptr = bytes.as_ptr().cast::<c_char>();
        Ok(())
    })
}
