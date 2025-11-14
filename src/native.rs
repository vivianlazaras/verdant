use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;

use serde_json;

use tokio::runtime::Runtime;

use keycast::discovery::Discovery; // for type references in comments
use crate::services::{VerdantCmd, VerdantUiCmd, VerdantService, LoginRequest}; // adjust paths if needed

/// Opaque C handle
#[repr(C)]
pub struct VerdantServiceHandle {
    inner: *mut VerdantService,
}

/// Tag values for the C-visible event type
#[repr(C)]
pub enum VerdantEventTag {
    None = 0,
    LoginResult = 1,
    ServerDiscovered = 2,
    LkToken = 3,
    Error = 0xFFFFisize,
}

#[repr(C)]
pub enum LoginResultTag {
    Success,
    PasswordReset,
    Unauthorized,
    UnknownServer,
}

#[repr(C)]
pub struct LoginResultFFI {
    pub tag: u32,
    pub payload: *mut c_char,
}

/// A simple FFI-safe event result. `payload` is a JSON string whose ownership is transferred
/// to the caller. The caller must call `verdant_free_cstring(payload)` when done.
#[repr(C)]
pub struct VerdantEventFFI {
    pub tag: u32,          // VerdantEventTag as u32
    pub payload: *mut c_char, // JSON string or null
}

#[repr(C)]
pub struct TokenResponseFFI {
    room: *mut c_char,
    token: *mut c_char,
}

#[repr(C)]
pub struct IpAddrFFI {
    version: u8,
    ipaddr: [u8; 16],
}

#[repr(C)]
pub struct DiscoveryFFI {
    version: *mut c_char,
    addrs: *mut *mut IpAddrFFI,
    protocol: *mut c_char,
    port: u16,
    name: *mut c_char,
    host: *mut c_char,
    pubkey_hash: *mut c_char,
}

/// Create a new VerdantService.
/// - `start_discovery`: if non-zero, discovery is enabled
/// - `rt_ptr`: optional pointer to a tokio::runtime::Runtime (if you have one).
///      If null, a new Runtime will be created internally.
/// Returns a pointer to `VerdantServiceHandle` (null on failure).
#[unsafe(no_mangle)]
pub extern "C" fn verdant_service_new(
    start_discovery: c_int,
    rt_ptr: *mut Runtime,
) -> *mut VerdantServiceHandle {
    // obtain runtime reference
    let runtime = if rt_ptr.is_null() {
        // return null bc this should be created externally
        return std::ptr::null_mut();
    } else {
        rt_ptr
    };

    // SAFETY: runtime pointer is valid if non-null (caller responsibility)
    let runtime_ref = unsafe { &*runtime };

    // call VerdantService::new; map discovery arg
    match VerdantService::new(runtime_ref, start_discovery != 0) {
        Ok(svc) => {
            let boxed = Box::new(svc);
            let svc_ptr = Box::into_raw(boxed);
            let handle = Box::new(VerdantServiceHandle { inner: svc_ptr });
            Box::into_raw(handle)
        }
        Err(_e) => {
            // On error, if we created the runtime locally, free it.
            if rt_ptr.is_null() {
                unsafe { drop(Box::from_raw(runtime)) };
            }
            ptr::null_mut()
        }
    }
}

/// Free the service and all associated resources. Safe to call with null.
#[unsafe(no_mangle)]
pub extern "C" fn verdant_service_free(h: *mut VerdantServiceHandle) {
    if h.is_null() {
        return;
    }
    // take ownership and drop
    let handle = unsafe { Box::from_raw(h) };
    if !handle.inner.is_null() {
        unsafe { drop(Box::from_raw(handle.inner)) };
    }
}

/// Send a login command. Returns 0 on success, non-zero on failure (e.g., bad args or send error).
#[unsafe(no_mangle)]
pub extern "C" fn verdant_service_login(
    h: *mut VerdantServiceHandle,
    url: *const c_char,
    username: *const c_char,
    password: *const c_char,
) -> c_int {
    if h.is_null() || url.is_null() || username.is_null() || password.is_null() {
        return -1;
    }
    let handle = unsafe { &*h };
    if handle.inner.is_null() {
        return -1;
    }
    let svc = unsafe { &*handle.inner };

    // safely copy strings
    let url = unsafe { CStr::from_ptr(url) }.to_string_lossy().into_owned();
    let username = unsafe { CStr::from_ptr(username) }.to_string_lossy().into_owned();
    let password = unsafe { CStr::from_ptr(password) }.to_string_lossy().into_owned();

    // clone sender and send using VerdantService::login helper
    // tx() returns &UnboundedSender<VerdantCmd>, so clone it
    let tx = svc.tx().clone();
    match VerdantService::login(&tx, url, username, password) {
        Ok(_) => 0,
        Err(_send_err) => -2,
    }
}

/// Try to receive an UI event without blocking. Returns a VerdantEventFFIby value.
/// If no event is available, returns an event with tag = None and payload = NULL.
/// Caller is responsible for freeing `payload` if non-null by calling `verdant_free_cstring`.
#[unsafe(no_mangle)]
pub extern "C" fn verdant_service_try_recv(h: *mut VerdantServiceHandle) -> VerdantEventFFI{
    if h.is_null() {
        return VerdantEventFFI{
            tag: VerdantEventTag::None as u32,
            payload: ptr::null_mut(),
        };
    }
    let handle = unsafe { &mut *h };
    if handle.inner.is_null() {
        return VerdantEventFFI{
            tag: VerdantEventTag::None as u32,
            payload: ptr::null_mut(),
        };
    }
    let svc = unsafe { &mut *handle.inner };

    match svc.try_recv() {
        Some(evt) => {
            // Serialize the inner payload to JSON so C can parse it easily.
            match evt {
                VerdantUiCmd::LoginResult(login_res) => {
                    // login_res is serde-serializable
                    match serde_json::to_string(&login_res) {
                        Ok(json) => {
                            let c = CString::new(json).unwrap_or_default().into_raw();
                            VerdantEventFFI{ tag: VerdantEventTag::LoginResult as u32, payload: c }
                        }
                        Err(_) => VerdantEventFFI{ tag: VerdantEventTag::Error as u32, payload: ptr::null_mut() },
                    }
                }
                VerdantUiCmd::ServerDiscovered(discovery) => {
                    // serialize discovery (Discovery must be serde serializable)
                    match serde_json::to_string(&discovery) {
                        Ok(json) => {
                            let c = CString::new(json).unwrap_or_default().into_raw();
                            VerdantEventFFI{ tag: VerdantEventTag::ServerDiscovered as u32, payload: c }
                        }
                        Err(_) => VerdantEventFFI{ tag: VerdantEventTag::Error as u32, payload: ptr::null_mut() },
                    }
                }
                VerdantUiCmd::LkToken(_, token) => {
                    match serde_json::to_string(&token) {
                        Ok(json) => {
                            let c = CString::new(json).unwrap_or_default().into_raw();
                            VerdantEventFFI{ tag: VerdantEventTag::LkToken as u32, payload: c }
                        }
                        Err(_) => VerdantEventFFI{ tag: VerdantEventTag::Error as u32, payload: ptr::null_mut() },
                    }
                }
                _ => unimplemented!(),
            }
        }
        None => VerdantEventFFI{ tag: VerdantEventTag::None as u32, payload: ptr::null_mut() },
    }
}

/// Free a C string returned by the above APIs (or any CString you create via `into_raw()`).
#[unsafe(no_mangle)]
pub extern "C" fn verdant_free_cstring(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(s));
    }
}

#[repr(C)]
pub struct RuntimeHandle {
    ptr: *mut Runtime,
}
/// Create a new Tokio runtime and return a raw pointer to it.
/// Returns NULL on failure. Caller must later call `verdant_runtime_free()`.
#[unsafe(no_mangle)]
pub extern "C" fn verdant_runtime_new() -> RuntimeHandle {
    let ptr = match Runtime::new() {
        Ok(rt) => Box::into_raw(Box::new(rt)),
        Err(_) => ptr::null_mut(),
    };
    RuntimeHandle {
        ptr
    }
}

/// Free a Tokio runtime created with `verdant_runtime_new()`.
/// Safe to call with NULL.
#[unsafe(no_mangle)]
pub extern "C" fn verdant_runtime_free(rt: *mut RuntimeHandle) {
    if rt.is_null() {
        return;
    }
    unsafe {
        if (*rt).ptr.is_null() {
            return;
        }
        drop(Box::from_raw((*rt).ptr));
    }
}