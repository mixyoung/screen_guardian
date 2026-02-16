use crate::models::WindowInfo;

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
    use std::{mem::size_of, ptr::null_mut};

    use anyhow::Context;
    use windows::{
        core::PWSTR,
        Win32::{
            Foundation::{CloseHandle, BOOL, HANDLE, HWND, LPARAM},
            System::Threading::{
                GetCurrentProcess, OpenProcess, QueryFullProcessImageNameW,
                PROCESS_QUERY_LIMITED_INFORMATION,
            },
            UI::WindowsAndMessaging::{
                EnumWindows, GetWindowDisplayAffinity, GetWindowTextLengthW, GetWindowTextW,
                GetWindowThreadProcessId, IsWindowVisible, WDA_EXCLUDEFROMCAPTURE, WDA_MONITOR,
                WDA_NONE,
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

            let mut affinity = 0u32;
            let protected = unsafe {
                GetWindowDisplayAffinity(hwnd, &mut affinity).as_bool() && affinity != WDA_NONE.0
            };

            let out = unsafe { &mut *(lparam.0 as *mut Vec<WindowInfo>) };
            out.push(WindowInfo {
                index: out.len() + 1,
                app_name,
                pid,
                hwnd: hwnd.0,
                title,
                executable_path,
                is_protected: protected,
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

    fn process_image_path(pid: u32) -> anyhow::Result<String> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?;
            let _guard = HandleGuard(handle);
            let mut size = 32768u32;
            let mut buffer = vec![0u16; size as usize];
            QueryFullProcessImageNameW(handle, 0, PWSTR(buffer.as_mut_ptr()), &mut size)?;
            buffer.truncate(size as usize);
            Ok(String::from_utf16_lossy(&buffer))
        }
    }

    pub fn detect_process_architecture(pid: u32) -> anyhow::Result<ProcessArchitecture> {
        use windows::Win32::System::Threading::{
            IsWow64Process2, PROCESS_MACHINE_AMD64, PROCESS_MACHINE_ARM64, PROCESS_MACHINE_I386,
        };

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?;
            let _guard = HandleGuard(handle);

            let mut process_machine = 0u16;
            let mut native_machine = 0u16;
            IsWow64Process2(handle, &mut process_machine, &mut native_machine)?;

            let arch = if process_machine == PROCESS_MACHINE_I386 {
                ProcessArchitecture::X86
            } else if native_machine == PROCESS_MACHINE_AMD64 {
                ProcessArchitecture::X64
            } else if native_machine == PROCESS_MACHINE_ARM64 {
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
