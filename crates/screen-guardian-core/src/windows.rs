#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessArchitecture {
    X86,
    X64,
    Arm64,
    Unknown,
}

#[cfg(not(windows))]
pub fn enumerate_windows() -> anyhow::Result<Vec<WindowInfo>> {
    Ok(Vec::new())
}

#[cfg(not(windows))]
pub fn audit_protected_windows() -> anyhow::Result<Vec<WindowInfo>> {
    Ok(Vec::new())
}

#[cfg(not(windows))]
pub fn detect_process_architecture(_pid: u32) -> anyhow::Result<ProcessArchitecture> {
    Ok(ProcessArchitecture::Unknown)
}

#[cfg(windows)]
mod imp {
    use anyhow::Context;
    use windows::{
        core::PWSTR,
        Win32::{
            Foundation::{CloseHandle, BOOL, HANDLE, HWND, LPARAM},
            System::Threading::{
                OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
                PROCESS_QUERY_LIMITED_INFORMATION,
            },
            UI::WindowsAndMessaging::{
                EnumWindows, GetWindowDisplayAffinity, GetWindowTextLengthW, GetWindowTextW,
                GetWindowThreadProcessId, IsWindowVisible, WDA_NONE,
            },
        },
    };

    use super::ProcessArchitecture;
    use crate::models::WindowInfo;

    struct HandleGuard(HANDLE);

    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    pub fn enumerate_windows() -> anyhow::Result<Vec<WindowInfo>> {
        let mut windows = Vec::<WindowInfo>::new();
        unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
            if !unsafe { IsWindowVisible(hwnd).as_bool() } {
                return true.into();
            }

            let mut pid = 0u32;
            unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };

            let title_len = unsafe { GetWindowTextLengthW(hwnd) };
            let mut title_buf = vec![0u16; title_len as usize + 1];
            unsafe {
                let _ = GetWindowTextW(hwnd, &mut title_buf);
            }
            let title = String::from_utf16_lossy(
                &title_buf
                    .iter()
                    .copied()
                    .take_while(|ch| *ch != 0)
                    .collect::<Vec<u16>>(),
            );

            if title.trim().is_empty() {
                return true.into();
            }

            let executable_path =
                process_image_path(pid).unwrap_or_else(|_| "<unknown>".to_string());
            let app_name = executable_path
                .rsplit(['\\', '/'])
                .next()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "<unknown>".to_string());

            let mut affinity: u32 = 0;
            let protected = unsafe {
                GetWindowDisplayAffinity(hwnd, &mut affinity).is_ok() && affinity != WDA_NONE.0
            };

            let out = unsafe { &mut *(lparam.0 as *mut Vec<WindowInfo>) };
            let window_type = detect_window_type(&app_name, &executable_path, hwnd);
            out.push(WindowInfo {
                index: out.len() + 1,
                app_name,
                pid,
                hwnd: hwnd.0 as isize,
                title,
                executable_path,
                is_protected: protected,
                window_type,
            });
            true.into()
        }

        unsafe {
            EnumWindows(
                Some(enum_proc),
                LPARAM((&mut windows as *mut Vec<WindowInfo>) as isize),
            )
            .ok()
            .context("EnumWindows failed")?;
        }
        Ok(windows)
    }

    pub fn audit_protected_windows() -> anyhow::Result<Vec<WindowInfo>> {
        let all = enumerate_windows()?;
        Ok(all.into_iter().filter(|w| w.is_protected).collect())
    }

    fn detect_window_type(app_name: &str, exe_path: &str, hwnd: HWND) -> String {
        let name_lower = app_name.to_lowercase();
        let path_lower = exe_path.to_lowercase();

        // System / elevated processes
        let system_names = [
            "svchost", "csrss", "smss", "wininit", "winlogon", "services",
            "lsass", "lsm", "dwm", "taskhostw", "taskhost", "sihost",
            "runtimebroker", "searchui", "shellexperiencehost", "startmenuexperiencehost",
            "ctfmon", "fontdrvhost", "msdtc", "spoolsv", "wlanext",
            "consent", "trustedinstaller", "tiworker",
        ];
        for s in &system_names {
            if name_lower.contains(s) {
                return "系统进程".to_string();
            }
        }

        // UWP / packaged apps
        if path_lower.contains("\\windowsapps\\") || path_lower.contains("\\microsoft.windowsapps.") {
            return "UWP应用".to_string();
        }

        // Check for immersive / modern app class names
        unsafe {
            let mut class_buf = [0u16; 256];
            let len = windows::Win32::UI::WindowsAndMessaging::GetClassNameW(hwnd, &mut class_buf);
            if len > 0 {
                let class_name = String::from_utf16_lossy(&class_buf[..len as usize]);
                let class_lower = class_name.to_lowercase();
                if class_lower.contains("applicationframe") || class_lower.contains("windows.ui.core") {
                    return "UWP应用".to_string();
                }
                if class_lower.contains("shell_traywnd") || class_lower.contains("shell_secondary") {
                    return "系统窗口".to_string();
                }
            }
        }

        // System32 processes
        if path_lower.contains("\\system32\\") || path_lower.contains("\\syswow64\\") {
            return "系统组件".to_string();
        }

        // Electron / Chromium-based
        if name_lower.contains("electron") || path_lower.contains("\\electron") {
            return "Electron应用".to_string();
        }

        // Common known apps
        if name_lower.contains("chrome") || name_lower.contains("msedge") || name_lower.contains("firefox") {
            return "浏览器".to_string();
        }
        if name_lower.contains("explorer") {
            return "文件管理器".to_string();
        }
        if name_lower.contains("code") || name_lower.contains("notepad") || name_lower.contains("idea64") {
            return "编辑器".to_string();
        }

        "桌面应用".to_string()
    }

    fn process_image_path(pid: u32) -> anyhow::Result<String> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?;
            let _guard = HandleGuard(handle);
            let mut size = 32768u32;
            let mut buffer = vec![0u16; size as usize];
            QueryFullProcessImageNameW(handle, PROCESS_NAME_FORMAT(0), PWSTR(buffer.as_mut_ptr()), &mut size)?;
            buffer.truncate(size as usize);
            Ok(String::from_utf16_lossy(&buffer))
        }
    }

    pub fn detect_process_architecture(pid: u32) -> anyhow::Result<ProcessArchitecture> {
        use windows::Win32::System::{
            SystemInformation::{
                IMAGE_FILE_MACHINE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64,
                IMAGE_FILE_MACHINE_I386,
            },
            Threading::IsWow64Process2,
        };

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?;
            let _guard = HandleGuard(handle);

            let mut process_machine = IMAGE_FILE_MACHINE(0);
            let mut native_machine = IMAGE_FILE_MACHINE(0);
            IsWow64Process2(handle, &mut process_machine, Some(&mut native_machine))?;

            let arch = if process_machine == IMAGE_FILE_MACHINE_I386 {
                ProcessArchitecture::X86
            } else if native_machine == IMAGE_FILE_MACHINE_AMD64 {
                ProcessArchitecture::X64
            } else if native_machine == IMAGE_FILE_MACHINE_ARM64 {
                ProcessArchitecture::Arm64
            } else {
                ProcessArchitecture::Unknown
            };
            Ok(arch)
        }
    }
}

#[cfg(windows)]
pub use imp::*;
