use jni::JNIEnv;
use jni::objects::JString;
use jni::sys::jint;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;
use jni_sys::*;
use crate::services::VerdantErr;

use serde_json;
use tokio::runtime::Runtime;

use keycast::discovery::Discovery;
use crate::services::{VerdantCmd, VerdantUiCmd, VerdantService, LoginRequest};

pub const VERDANT_SERVER_DISCOVERED: i64 = 1;
pub const VERDANT_LOGIN_RESULT: i64 = 2;
pub const VERDANT_LK_RESPONSE: i64 = 3;

#[repr(C)]
struct VerdantEventFFI<'r> {
    tag: jlong,
    payload: JString<'r>,
}

impl<'r> VerdantEventFFI<'r> {
    pub fn new(env: &mut JNIEnv<'r>, msg: &str, tag: jlong) -> Self {
        let payload = env.new_string(msg).expect("failed to create payload");
        Self {
            tag,
            payload
        }
    }

    pub fn empty(env: &mut JNIEnv<'r>) -> Self {
        Self {
            payload: env.new_string("").expect("failed to create string"),
            tag: 0
        }
    }
}

unsafe fn jstring_to_rust(env: &mut JNIEnv, jstr: JString) -> String {
    

    env.get_string(&jstr).expect("failed to get string").into()
}

/// Create a new Tokio runtime
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_qrespite_verdant_VerdantService_VerdantRuntimeNew(
    _env: *mut JNIEnv,
    _class: jni_sys::jclass,
) -> jlong {
    let ptr = match Runtime::new() {
        Ok(rt) => Box::into_raw(Box::new(rt)),
        Err(_) => std::ptr::null_mut(),
    };
    ptr as jlong
}

/// Free a Tokio runtime
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_qrespite_verdant_VerdantService_VerdantRuntimeFree(
    _env: *mut JNIEnv,
    _class: jni_sys::jclass,
    rt_ptr: jlong,
) {
    if rt_ptr == 0 {
        return;
    }
    unsafe {
        let rt = rt_ptr as *mut Runtime;
        drop(Box::from_raw(rt));
    }
}

/// Create a new VerdantService
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_qrespite_verdant_VerdantService_VerdantServiceNew(
    _env: *mut JNIEnv,
    _class: jni_sys::jclass,
    start_discovery: jboolean,
    rt_ptr: jlong,
) -> jlong {
    if rt_ptr == 0 {
        return 0;
    }
    let runtime = rt_ptr as *mut Runtime;
    let runtime_ref = unsafe { &*runtime };

    match VerdantService::new(runtime_ref, start_discovery) {
        Ok(svc) => {
            let boxed = Box::new(svc);
            Box::into_raw(boxed) as jlong
        }
        Err(_) => 0,
    }
}

/// Free a VerdantService
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_qrespite_verdant_VerdantService_VerdantServiceFree(
    _env: *mut JNIEnv,
    _class: jni_sys::jclass,
    svc_ptr: jlong,
) {
    if svc_ptr == 0 {
        return;
    }
    unsafe {
        drop(Box::from_raw(svc_ptr as *mut VerdantService));
    }
}

/// Login
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_qrespite_verdant_VerdantService_login(
    mut env: JNIEnv,
    _class: jni_sys::jclass,
    svc_ptr: jlong,
    jurl: JString,
    jusername: JString,
    jpassword: JString,
) -> jint {
    if svc_ptr == 0 {
        return -1;
    }

    let svc = unsafe { &*(svc_ptr as *mut VerdantService) };

    // Convert Java strings to Rust
    let url = unsafe { jstring_to_rust(&mut env, jurl) };
    let username =
        unsafe { jstring_to_rust(&mut env, jusername) };
    let password =
        unsafe { jstring_to_rust(&mut env, jpassword) };

    let tx = svc.tx().clone();
    match VerdantService::login(&tx, url, username, password) {
        Ok(_) => 0,
        Err(_) => -2,
    }
}

/// Try receive event
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_qrespite_verdant_VerdantService_TryRecv<'r>(
    mut env: JNIEnv<'r>,
    _class: jni_sys::jclass,
    svc_ptr: jlong,
) -> JString<'r> {
    if svc_ptr == 0 {
        return env.new_string("").expect("failed to create empty JString");
    }
    let svc = unsafe { &mut *(svc_ptr as *mut VerdantService) };

    match svc.try_recv() {
        Some(evt) => {
            let event = serde_json::to_string(&evt).unwrap();
            env.new_string(event).expect("failed to create event JString")
        }
        None => {
            let noop = VerdantUiCmd::Error(VerdantErr::noop());
            let noop_str = serde_json::to_string(&noop).unwrap();
            env.new_string(&noop_str).expect("failed to create empty JString") 
        },
    }
}