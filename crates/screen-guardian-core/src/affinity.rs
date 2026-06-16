#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AffinityValue {
    None = 0,
    Monitor = 1,
    ExcludeFromCapture = 17,
}

impl AffinityValue {
    pub fn from_bool(protected: bool) -> Self {
        if protected {
            Self::ExcludeFromCapture
        } else {
            Self::None
        }
    }

    pub fn from_visibility(visible: bool) -> Self {
        if visible {
            Self::None
        } else {
            Self::ExcludeFromCapture
        }
    }
}

fn log_affinity(msg: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("./gui-debug.log") {
        let _ = std::io::Write::write_fmt(&mut f, format_args!("[{}] [affinity] {}\n", crate::timefmt::format_now(), msg));
    }
}

#[derive(Debug, Clone)]
pub struct AffinityOrchestrator {
}

impl AffinityOrchestrator {
    pub fn new(_helper_32_path: impl Into<std::path::PathBuf>) -> Self {
        Self {}
    }

    pub fn apply(&self, hwnd: isize, pid: u32, affinity: AffinityValue) -> anyhow::Result<()> {
        #[cfg(windows)]
        {
            let self_pid = std::process::id();
            if pid == self_pid {
                return self.apply_native(hwnd, affinity);
            }

            // Check if process has user32.dll (GUI capability)
            if !crate::inject::has_user32(pid) {
                log_affinity(&format!(
                    "skip: pid={} has no user32.dll (non-GUI process)",
                    pid
                ));
                return Ok(()); // Skip non-GUI processes silently
            }

            log_affinity(&format!(
                "inject_set_affinity: pid={}, hwnd={:#x}, affinity={}",
                pid, hwnd, affinity as u32
            ));

            // Try shellcode injection
            match crate::inject::inject_set_affinity(pid, hwnd, affinity as u32) {
                Ok(()) => {
                    log_affinity(&format!("inject success: pid={}", pid));
                    Ok(())
                }
                Err(e) => {
                    log_affinity(&format!("inject failed: pid={}, error={}", pid, e));
                    Err(e)
                }
            }
        }

        #[cfg(not(windows))]
        {
            let _ = (hwnd, pid, affinity);
            Ok(())
        }
    }

    #[cfg(windows)]
    fn apply_native(&self, hwnd: isize, affinity: AffinityValue) -> anyhow::Result<()> {
        use windows::Win32::{
            Foundation::{GetLastError, HWND},
            UI::WindowsAndMessaging::{SetWindowDisplayAffinity, WINDOW_DISPLAY_AFFINITY},
        };

        let hwnd_obj = HWND(hwnd as *mut _);
        let affinity_u32 = affinity as u32;

        unsafe {
            let result = SetWindowDisplayAffinity(hwnd_obj, WINDOW_DISPLAY_AFFINITY(affinity_u32));
            if result.is_ok() {
                log_affinity(&format!("native OK: hwnd={:?}, affinity={}", hwnd_obj, affinity_u32));
                return Ok(());
            }

            let err = GetLastError();
            log_affinity(&format!("native FAIL: hwnd={:?}, affinity={}, error={}", hwnd_obj, affinity_u32, err.0));

            // 如果 EXCLUDEFROMCAPTURE 失败，回退到 Monitor
            if affinity_u32 == 17 {
                log_affinity("fallback to WDA_MONITOR(1)...");
                let result2 = SetWindowDisplayAffinity(hwnd_obj, WINDOW_DISPLAY_AFFINITY(1));
                if result2.is_ok() {
                    return Ok(());
                }
            }

            anyhow::bail!("SetWindowDisplayAffinity failed (error={})", err.0);
        }
    }
}
