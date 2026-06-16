use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowDisplayAffinity, IsWindowVisible, SetWindowDisplayAffinity,
    WINDOW_DISPLAY_AFFINITY,
};

fn main() {
    println!("Testing SetWindowDisplayAffinity...");
    println!("WDA_NONE = 0, WDA_MONITOR = 1, WDA_EXCLUDEFROMCAPTURE = 17");

    let mut found = 0;
    unsafe {
        let _ = EnumWindows(Some(enum_proc), &mut found as *mut i32 as isize);
    }
    println!("Total windows tested: {}", found);
}

unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: isize) -> windows::core::BOOL {
    let count = &mut *(lparam as *mut i32);
    if *count >= 5 {
        return windows::core::BOOL(1); // stop after 5
    }

    if !IsWindowVisible(hwnd).as_bool() {
        return windows::core::BOOL(1);
    }

    *count += 1;
    let hwnd_val = hwnd.0 as isize;

    // Try to get current affinity
    let mut affinity: u32 = 0;
    let get_result = GetWindowDisplayAffinity(hwnd, &mut affinity as *mut u32);
    println!("[{}] HWND={:?}, GetResult={:?}, current_affinity={}", count, hwnd, get_result, affinity);

    // Try WDA_NONE (0)
    let r0 = SetWindowDisplayAffinity(hwnd, WINDOW_DISPLAY_AFFINITY(0));
    println!("  SetAffinity(0/WDA_NONE) => {:?}", r0);

    // Try WDA_MONITOR (1)
    let r1 = SetWindowDisplayAffinity(hwnd, WINDOW_DISPLAY_AFFINITY(1));
    println!("  SetAffinity(1/WDA_MONITOR) => {:?}", r1);

    // Get error code if failed
    if r1.is_err() {
        let err = unsafe { windows::Win32::Foundation::GetLastError() };
        println!("  GetLastError after WDA_MONITOR: {:?}", err);
    }

    // Try WDA_EXCLUDEFROMCAPTURE (17)
    let r17 = SetWindowDisplayAffinity(hwnd, WINDOW_DISPLAY_AFFINITY(17));
    println!("  SetAffinity(17/WDA_EXCLUDEFROMCAPTURE) => {:?}", r17);

    if r17.is_err() {
        let err = unsafe { windows::Win32::Foundation::GetLastError() };
        println!("  GetLastError after WDA_EXCLUDEFROMCAPTURE: {:?}", err);
    }

    // Reset to none
    let _ = SetWindowDisplayAffinity(hwnd, WINDOW_DISPLAY_AFFINITY(0));

    windows::core::BOOL(1) // continue
}
