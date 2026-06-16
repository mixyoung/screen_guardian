//! Screen Guardian Hook DLL
//!
//! This DLL is loaded into target processes to call SetWindowDisplayAffinity.

use windows::Win32::{
    Foundation::{GetLastError, HWND},
    UI::WindowsAndMessaging::{SetWindowDisplayAffinity, WINDOW_DISPLAY_AFFINITY},
};

/// Direct call function to set window protection
/// This function can be called after loading the DLL
#[no_mangle]
pub extern "C" fn SetWindowProtection(hwnd: isize, affinity: u32) -> i32 {
    let hwnd_obj = HWND(hwnd as *mut _);
    let affinity_obj = WINDOW_DISPLAY_AFFINITY(affinity);

    unsafe {
        match SetWindowDisplayAffinity(hwnd_obj, affinity_obj) {
            Ok(()) => 0,
            Err(_) => GetLastError().0 as i32,
        }
    }
}

/// DLL entry point
#[no_mangle]
pub extern "system" fn DllMain(
    _hmodule: windows::Win32::Foundation::HINSTANCE,
    reason: u32,
    _reserved: *mut std::ffi::c_void,
) -> i32 {
    match reason {
        1 => 1, // DLL_PROCESS_ATTACH
        0 => 1, // DLL_PROCESS_DETACH
        _ => 1,
    }
}
