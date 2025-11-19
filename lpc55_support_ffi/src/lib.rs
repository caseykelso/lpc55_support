use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::ptr;
use std::sync::{Mutex, OnceLock};

use lpc55_areas::{CFPAPage, CMPAPage};
use lpc55_sign::cert::{read_certs, read_rsa_private_key};
use lpc55_sign::crc_image;
use lpc55_sign::signed_image::{sign_image, stamp_image, CertConfig};
use lpc55_sign::verify;

static LAST_ERROR: OnceLock<Mutex<Option<String>>> = OnceLock::new();

fn error_slot() -> &'static Mutex<Option<String>> {
    LAST_ERROR.get_or_init(|| Mutex::new(None))
}

fn store_error(err: impl ToString) -> i32 {
    let mut slot = error_slot().lock().unwrap();
    *slot = Some(err.to_string());
    -1
}

fn clear_error() {
    let mut slot = error_slot().lock().unwrap();
    *slot = None;
}

unsafe fn cstr_from_ptr(ptr: *const c_char) -> Result<&'static CStr, i32> {
    if ptr.is_null() {
        return Err(store_error("null pointer"));
    }
    Ok(CStr::from_ptr(ptr))
}

fn path_from_cstr(cstr: &CStr) -> Result<PathBuf, i32> {
    let s = cstr.to_str().map_err(|e| store_error(e))?;
    Ok(PathBuf::from(s))
}

fn read_cert_config(path: &PathBuf) -> Result<CertConfig, i32> {
    let contents = std::fs::read_to_string(path).map_err(|e| store_error(e))?;
    toml::from_str(&contents).map_err(|e| store_error(e))
}

fn read_cmpa(path: &PathBuf) -> Result<CMPAPage, i32> {
    let bytes = std::fs::read(path).map_err(|e| store_error(e))?;
    let arr: [u8; 512] = bytes.as_slice().try_into().map_err(|_| store_error("CMPA file must be 512 bytes"))?;
    CMPAPage::from_bytes(&arr).map_err(|e| store_error(e))
}

fn read_cfpa(path: &PathBuf) -> Result<CFPAPage, i32> {
    let bytes = std::fs::read(path).map_err(|e| store_error(e))?;
    let arr: [u8; 512] = bytes.as_slice().try_into().map_err(|_| store_error("CFPA file must be 512 bytes"))?;
    CFPAPage::from_bytes(&arr).map_err(|e| store_error(e))
}

#[no_mangle]
pub unsafe extern "C" fn lpc55_support_generate_crc(
    src: *const c_char,
    dest: *const c_char,
    address: u32,
) -> i32 {
    let src = match cstr_from_ptr(src) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let dest = match cstr_from_ptr(dest) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let src = match path_from_cstr(src) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let dest = match path_from_cstr(dest) {
        Ok(p) => p,
        Err(code) => return code,
    };
    match crc_image::update_crc(&src, &dest, address) {
        Ok(_) => {
            clear_error();
            0
        }
        Err(e) => store_error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lpc55_support_sign_image(
    src: *const c_char,
    dest: *const c_char,
    cert_cfg: *const c_char,
    private_key: *const c_char,
    address: u32,
) -> i32 {
    let src = match cstr_from_ptr(src) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let dest = match cstr_from_ptr(dest) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let cert_cfg = match cstr_from_ptr(cert_cfg) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let private_key = match cstr_from_ptr(private_key) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let src = match path_from_cstr(src) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let dest = match path_from_cstr(dest) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let cfg_path = match path_from_cstr(cert_cfg) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let key_path = match path_from_cstr(private_key) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let cfg = match read_cert_config(&cfg_path) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let private_key = match read_rsa_private_key(&key_path) {
        Ok(k) => k,
        Err(e) => return store_error(e),
    };
    let image = match std::fs::read(&src) {
        Ok(v) => v,
        Err(e) => return store_error(e),
    };
    let signing_certs = match read_certs(&cfg.signing_certs) {
        Ok(v) => v,
        Err(e) => return store_error(e),
    };
    let root_certs = match read_certs(&cfg.root_certs) {
        Ok(v) => v,
        Err(e) => return store_error(e),
    };
    let stamped = match stamp_image(image, signing_certs, root_certs, address) {
        Ok(v) => v,
        Err(e) => return store_error(e),
    };
    let signed = match sign_image(&stamped, &private_key) {
        Ok(v) => v,
        Err(e) => return store_error(e),
    };
    if let Err(e) = std::fs::write(&dest, signed) {
        return store_error(e);
    }
    clear_error();
    0
}

#[no_mangle]
pub unsafe extern "C" fn lpc55_support_verify_signed_image(
    cmpa_path: *const c_char,
    cfpa_path: *const c_char,
    image_path: *const c_char,
) -> i32 {
    let cmpa_path = match cstr_from_ptr(cmpa_path) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let cfpa_path = match cstr_from_ptr(cfpa_path) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let image_path = match cstr_from_ptr(image_path) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let cmpa_path = match path_from_cstr(cmpa_path) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let cfpa_path = match path_from_cstr(cfpa_path) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let image_path = match path_from_cstr(image_path) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let cmpa = match read_cmpa(&cmpa_path) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let cfpa = match read_cfpa(&cfpa_path) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let image = match std::fs::read(&image_path) {
        Ok(v) => v,
        Err(e) => return store_error(e),
    };
    match verify::verify_image(&image, cmpa, cfpa) {
        Ok(_) => {
            clear_error();
            0
        }
        Err(e) => store_error(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lpc55_support_last_error(
    buffer: *mut c_char,
    len: usize,
) -> usize {
    let slot = error_slot().lock().unwrap();
    let Some(message) = slot.as_ref() else {
        if !buffer.is_null() && len > 0 {
            ptr::write(buffer, 0);
        }
        return 0;
    };
    let bytes = message.as_bytes();
    let needed = bytes.len() + 1;
    if !buffer.is_null() && len > 0 {
        let slice = std::slice::from_raw_parts_mut(buffer as *mut u8, len.min(needed));
        if !slice.is_empty() {
            let to_copy = slice.len().saturating_sub(1);
            slice[..to_copy].copy_from_slice(&bytes[..to_copy]);
            slice[to_copy] = 0;
        }
    }
    needed
}
