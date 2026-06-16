use std::ffi::c_void;

use windows::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, HWND},
    System::Memory::{
        MapViewOfFile, OpenFileMappingW, UnmapViewOfFile,
        FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS,
    },
    UI::WindowsAndMessaging::{SetWindowDisplayAffinity, WINDOW_DISPLAY_AFFINITY},
};

const SHARED_MEM_SIZE: usize = 16;

fn log_dll(msg: &str) {
    // DLL runs inside target process — use absolute path to log alongside GUI
    let log_path = "E:\\33_dev_env\\screen_guardian\\gui-debug.log";
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(log_path) {
        use std::io::Write;
        let _ = writeln!(f, "[inject-dll] {}", msg);
    }
}

/// Exported function called by the injector via CreateRemoteThread.
/// The LPVOID parameter points to [hwnd: isize(8), affinity: u32(4)] in remote memory.
#[no_mangle]
pub unsafe extern "system" fn SetAffinityFromInjector(lp_param: *mut c_void) -> u32 {
    if lp_param.is_null() {
        log_dll("ERROR: lp_param is null");
        write_result_to_shared_mem(9901);
        return 9901;
    }

    let base = lp_param as *const u8;
    let hwnd_raw: isize =
        isize::from_ne_bytes(core::slice::from_raw_parts(base, 8).try_into().unwrap());
    let affinity_raw: u32 =
        u32::from_ne_bytes(core::slice::from_raw_parts(base.add(8), 4).try_into().unwrap());

    log_dll(&format!("called: hwnd={:#x}, affinity={}", hwnd_raw, affinity_raw));

    let hwnd = HWND(hwnd_raw as *mut _);

    // Try the requested affinity first
    let result = SetWindowDisplayAffinity(hwnd, WINDOW_DISPLAY_AFFINITY(affinity_raw));
    if result.is_ok() {
        log_dll(&format!("OK: affinity={} set successfully", affinity_raw));
        write_result_to_shared_mem(0);
        return 0;
    }

    let err1 = GetLastError().0 as u32;
    log_dll(&format!("FAIL: affinity={}, error={}", affinity_raw, err1));

    // Fallback: if EXCLUDEFROMCAPTURE(17) failed, try MONITOR(1)
    if affinity_raw == 17 {
        log_dll("fallback: trying WDA_MONITOR(1)...");
        let result2 = SetWindowDisplayAffinity(hwnd, WINDOW_DISPLAY_AFFINITY(1));
        if result2.is_ok() {
            log_dll("OK: fallback WDA_MONITOR(1) succeeded");
            write_result_to_shared_mem(0);
            return 0;
        }
        let err2 = GetLastError().0 as u32;
        log_dll(&format!("FAIL: fallback WDA_MONITOR(1) also failed, error={}", err2));
    }

    // Fallback: if NONE(0) failed, that's unusual but report it
    write_result_to_shared_mem(err1 as i32);
    err1
}

unsafe fn write_result_to_shared_mem(result: i32) {
    let mapping_name = windows::core::w!("Local\\SG_AFFINITY");

    let mapping_handle: HANDLE = match OpenFileMappingW(
        (FILE_MAP_READ | FILE_MAP_WRITE).0,
        false,
        mapping_name,
    ) {
        Ok(h) => h,
        Err(e) => {
            log_dll(&format!("write_result: OpenFileMappingW failed: {}", e));
            return;
        }
    };

    let view: MEMORY_MAPPED_VIEW_ADDRESS =
        MapViewOfFile(mapping_handle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, SHARED_MEM_SIZE);

    if !view.Value.is_null() {
        let write_ptr = view.Value as *mut u8;
        core::ptr::copy_nonoverlapping(result.to_ne_bytes().as_ptr(), write_ptr.add(12), 4);
        let _ = UnmapViewOfFile(view);
    } else {
        log_dll("write_result: MapViewOfFile returned null");
    }

    let _ = CloseHandle(mapping_handle);
}

#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _hinst_dll: *mut c_void,
    fdw_reason: u32,
    _lpv_reserved: *mut c_void,
) -> i32 {
    // DllMain is a no-op. The injector calls SetAffinityFromInjector directly.
    let _ = fdw_reason;
    1
}
