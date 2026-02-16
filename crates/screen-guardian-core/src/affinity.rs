use std::path::PathBuf;

use anyhow::Context;

use crate::windows::{detect_process_architecture, ProcessArchitecture};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AffinityValue {
    None = 0,
    Monitor = 1,
    ExcludeFromCapture = 17,
}

impl AffinityValue {
    pub fn from_bool(protected: bool) -> Self {
        if protected {
            Self::Monitor
        } else {
            Self::None
        }
    }
}

#[derive(Debug, Clone)]
pub struct AffinityOrchestrator {
    helper_32_path: PathBuf,
}

impl AffinityOrchestrator {
    pub fn new(helper_32_path: impl Into<PathBuf>) -> Self {
        Self {
            helper_32_path: helper_32_path.into(),
        }
    }

    pub fn apply(&self, hwnd: isize, pid: u32, affinity: AffinityValue) -> anyhow::Result<()> {
        #[cfg(windows)]
        {
            if matches!(detect_process_architecture(pid)?, ProcessArchitecture::X86) {
                return self.apply_with_helper(hwnd, affinity);
            }
            return self.apply_native(hwnd, affinity);
        }

        #[cfg(not(windows))]
        {
            let _ = (hwnd, pid, affinity);
            Ok(())
        }
    }

    fn apply_with_helper(&self, hwnd: isize, affinity: AffinityValue) -> anyhow::Result<()> {
        let output = std::process::Command::new(&self.helper_32_path)
            .arg(hwnd.to_string())
            .arg((affinity as u32).to_string())
            .output()
            .with_context(|| {
                format!("failed to launch helper {}", self.helper_32_path.display())
            })?;

        if output.status.success() {
            Ok(())
        } else {
            anyhow::bail!(
                "helper exited with {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            )
        }
    }

    #[cfg(windows)]
    fn apply_native(&self, hwnd: isize, affinity: AffinityValue) -> anyhow::Result<()> {
        use windows::Win32::{Foundation::HWND, UI::WindowsAndMessaging::SetWindowDisplayAffinity};

        unsafe {
            SetWindowDisplayAffinity(HWND(hwnd), affinity as u32)
                .ok()
                .context("SetWindowDisplayAffinity failed")?;
        }
        Ok(())
    }
}
