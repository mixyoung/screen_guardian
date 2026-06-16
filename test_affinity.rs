use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::{
    FindWindowW, GetWindowDisplayAffinity, SetWindowDisplayAffinity, WINDOW_DISPLAY_AFFINITY,
};

fn main() {
    // Test with Notepad or any visible window
    unsafe {
        // Try to find a window
        let hwnd = FindWindowW(None, None).unwrap();
        println!("Found HWND: {:?}", hwnd);

        // Get current affinity
        let mut affinity: u32 = 0;
        let result = GetWindowDisplayAffinity(hwnd, &mut affinity as *mut u32);
        println!("GetWindowDisplayAffinity result: {:?}, affinity: {}", result, affinity);

        // Try to set WDA_EXCLUDEFROMCAPTURE (17)
        let set_result = SetWindowDisplayAffinity(hwnd, WINDOW_DISPLAY_AFFINITY(17));
        println!("SetWindowDisplayAffinity(17) result: {:?}", set_result);

        // Try to set WDA_MONITOR (1)
        let set_result2 = SetWindowDisplayAffinity(hwnd, WINDOW_DISPLAY_AFFINITY(1));
        println!("SetWindowDisplayAffinity(1) result: {:?}", set_result2);

        // Try to set WDA_NONE (0)
        let set_result3 = SetWindowDisplayAffinity(hwnd, WINDOW_DISPLAY_AFFINITY(0));
        println!("SetWindowDisplayAffinity(0) result: {:?}", set_result3);
    }
}
