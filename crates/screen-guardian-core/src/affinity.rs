use serde::{Deserialize, Serialize};
use std::os::windows::ffi::OsStrExt;

/// Affinity value for SetWindowDisplayAffinity
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

/// Protection method enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtectionMethod {
    /// SetWindowsHookEx + DLL (safest, Windows official)
    HookEx,
    /// Shellcode injection (no extra files needed)
    Shellcode,
    /// DLL injection (classic approach)
    DllInjection,
    /// Native call (same process)
    Native,
}

impl std::fmt::Display for ProtectionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HookEx => write!(f, "HookEx"),
            Self::Shellcode => write!(f, "Shellcode"),
            Self::DllInjection => write!(f, "DLL"),
            Self::Native => write!(f, "Native"),
        }
    }
}

/// Protection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionResult {
    pub method: ProtectionMethod,
    pub success: bool,
    pub error: Option<String>,
}

/// Protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionConfig {
    pub enable_hook_ex: bool,
    pub enable_shellcode: bool,
    pub enable_dll_injection: bool,
    pub preferred_method: Option<ProtectionMethod>,
}

impl Default for ProtectionConfig {
    fn default() -> Self {
        Self {
            enable_hook_ex: true,
            enable_shellcode: true,
            enable_dll_injection: false, // Disabled by default (higher risk)
            preferred_method: None,
        }
    }
}

/// Protection statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtectionStats {
    pub hook_ex_count: u32,
    pub shellcode_count: u32,
    pub dll_injection_count: u32,
    pub native_count: u32,
    pub failure_count: u32,
    pub skip_count: u32,
}

/// Shared memory structure for hook communication
#[repr(C)]
pub struct HookParams {
    pub hwnd: isize,
    pub affinity: u32,
    pub result: i32,
    pub completed: u32,
}

/// Find the hook DLL path
#[cfg(windows)]
fn find_hook_dll() -> anyhow::Result<Vec<u16>> {
    // Try to find the DLL in the same directory as the executable
    let exe_path = std::env::current_exe()?;
    let exe_dir = exe_path.parent().unwrap_or(std::path::Path::new("."));

    let dll_names = [
        "screen_guardian_hook.dll",
        "screen-guardian-hook-dll.dll",
    ];

    for dll_name in &dll_names {
        let dll_path = exe_dir.join(dll_name);
        if dll_path.exists() {
            let wide: Vec<u16> = dll_path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            return Ok(wide);
        }
    }

    // Try bin subdirectory
    let bin_dir = exe_dir.join("bin");
    for dll_name in &dll_names {
        let dll_path = bin_dir.join(dll_name);
        if dll_path.exists() {
            let wide: Vec<u16> = dll_path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            return Ok(wide);
        }
    }

    anyhow::bail!("hook DLL not found")
}

/// Get thread ID for a window
#[cfg(windows)]
fn get_window_thread_id(hwnd: isize) -> u32 {
    use windows::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId;
    use windows::Win32::Foundation::HWND;

    let hwnd_obj = HWND(hwnd as *mut _);
    unsafe {
        GetWindowThreadProcessId(hwnd_obj, None)
    }
}

fn log_affinity(msg: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("./gui-debug.log")
    {
        let _ = std::io::Write::write_fmt(
            &mut f,
            format_args!("[{}] [affinity] {}\n", crate::timefmt::format_now(), msg),
        );
    }
}

/// Layered protection orchestrator
#[derive(Debug, Clone)]
pub struct AffinityOrchestrator {
    config: ProtectionConfig,
    stats: ProtectionStats,
}

impl AffinityOrchestrator {
    pub fn new(_helper_32_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            config: ProtectionConfig::default(),
            stats: ProtectionStats::default(),
        }
    }

    pub fn with_config(config: ProtectionConfig) -> Self {
        Self {
            config,
            stats: ProtectionStats::default(),
        }
    }

    /// Get protection statistics
    pub fn get_stats(&self) -> &ProtectionStats {
        &self.stats
    }

    /// Get protection config
    pub fn get_config(&self) -> &ProtectionConfig {
        &self.config
    }

    /// Update protection config
    pub fn set_config(&mut self, config: ProtectionConfig) {
        self.config = config;
    }

    /// Apply protection with layered fallback
    pub fn apply(
        &mut self,
        hwnd: isize,
        pid: u32,
        affinity: AffinityValue,
    ) -> anyhow::Result<ProtectionResult> {
        #[cfg(windows)]
        {
            let self_pid = std::process::id();
            if pid == self_pid {
                self.apply_native(hwnd, affinity)?;
                return Ok(ProtectionResult {
                    method: ProtectionMethod::Native,
                    success: true,
                    error: None,
                });
            }

            // Check if process has user32.dll (GUI capability)
            if !crate::inject::has_user32(pid) {
                log_affinity(&format!(
                    "skip: pid={} has no user32.dll (non-GUI process)",
                    pid
                ));
                self.stats.skip_count += 1;
                return Ok(ProtectionResult {
                    method: ProtectionMethod::Shellcode,
                    success: true,
                    error: None,
                });
            }

            log_affinity(&format!(
                "apply_with_fallback: pid={}, hwnd={:#x}, affinity={}",
                pid, hwnd, affinity as u32
            ));

            // Try methods in order based on config
            let methods = self.get_method_order();

            for method in methods {
                let result = match method {
                    ProtectionMethod::HookEx => self.apply_with_hook_ex(hwnd, pid, affinity),
                    ProtectionMethod::Shellcode => self.apply_with_shellcode(hwnd, pid, affinity),
                    ProtectionMethod::DllInjection => {
                        self.apply_with_dll_injection(hwnd, pid, affinity)
                    }
                    ProtectionMethod::Native => self.apply_native(hwnd, affinity),
                };

                match result {
                    Ok(()) => {
                        log_affinity(&format!(
                            "success: method={}, pid={}",
                            method, pid
                        ));
                        self.increment_stats(method);
                        return Ok(ProtectionResult {
                            method,
                            success: true,
                            error: None,
                        });
                    }
                    Err(e) => {
                        log_affinity(&format!(
                            "failed: method={}, pid={}, error={}",
                            method, pid, e
                        ));
                        // Continue to next method
                    }
                }
            }

            // All methods failed
            self.stats.failure_count += 1;
            anyhow::bail!("all protection methods failed for pid={}", pid)
        }

        #[cfg(not(windows))]
        {
            let _ = (hwnd, pid, affinity);
            Ok(ProtectionResult {
                method: ProtectionMethod::Native,
                success: true,
                error: None,
            })
        }
    }

    /// Get method order based on config and preferred method
    fn get_method_order(&self) -> Vec<ProtectionMethod> {
        let mut methods = Vec::new();

        // Add preferred method first if specified
        if let Some(preferred) = self.config.preferred_method {
            methods.push(preferred);
        }

        // Add other enabled methods in default order
        if self.config.enable_hook_ex && !methods.contains(&ProtectionMethod::HookEx) {
            methods.push(ProtectionMethod::HookEx);
        }
        if self.config.enable_shellcode && !methods.contains(&ProtectionMethod::Shellcode) {
            methods.push(ProtectionMethod::Shellcode);
        }
        if self.config.enable_dll_injection && !methods.contains(&ProtectionMethod::DllInjection) {
            methods.push(ProtectionMethod::DllInjection);
        }

        methods
    }

    /// Increment statistics for successful method
    fn increment_stats(&mut self, method: ProtectionMethod) {
        match method {
            ProtectionMethod::HookEx => self.stats.hook_ex_count += 1,
            ProtectionMethod::Shellcode => self.stats.shellcode_count += 1,
            ProtectionMethod::DllInjection => self.stats.dll_injection_count += 1,
            ProtectionMethod::Native => self.stats.native_count += 1,
        }
    }

    /// Layer 1: Load DLL and call SetWindowProtection
    #[cfg(windows)]
    fn apply_with_hook_ex(
        &self,
        hwnd: isize,
        _pid: u32,
        affinity: AffinityValue,
    ) -> anyhow::Result<()> {
        use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

        // Find the hook DLL path
        let dll_path = find_hook_dll()?;
        log_affinity(&format!("hook_ex: loading DLL from {:?}", std::path::Path::new(
            &String::from_utf16_lossy(&dll_path[..dll_path.len()-1])
        )));

        unsafe {
            // Load DLL
            let dll_module = LoadLibraryW(windows::core::PCWSTR(dll_path.as_ptr()))?;

            if dll_module.is_invalid() {
                anyhow::bail!("failed to load hook DLL");
            }

            // Get the SetWindowProtection function
            let proc_addr = GetProcAddress(
                dll_module,
                windows::core::s!("SetWindowProtection"),
            );

            if let Some(proc) = proc_addr {
                // Call the function
                let set_protection: extern "C" fn(isize, u32) -> i32 =
                    std::mem::transmute(proc);
                let result = set_protection(hwnd, affinity as u32);

                if result == 0 {
                    log_affinity("hook_ex: success");
                    return Ok(());
                } else {
                    anyhow::bail!("SetWindowProtection failed with error {}", result);
                }
            } else {
                anyhow::bail!("SetWindowProtection function not found in DLL");
            }
        }
    }

    /// Layer 2: Shellcode injection
    #[cfg(windows)]
    fn apply_with_shellcode(
        &self,
        hwnd: isize,
        pid: u32,
        affinity: AffinityValue,
    ) -> anyhow::Result<()> {
        crate::inject::inject_set_affinity(pid, hwnd, affinity as u32)
    }

    /// Layer 3: DLL injection
    #[cfg(windows)]
    fn apply_with_dll_injection(
        &self,
        _hwnd: isize,
        _pid: u32,
        _affinity: AffinityValue,
    ) -> anyhow::Result<()> {
        // TODO: Implement DLL injection
        anyhow::bail!("DLL injection not implemented yet")
    }

    /// Native call (same process)
    #[cfg(windows)]
    fn apply_native(
        &self,
        hwnd: isize,
        affinity: AffinityValue,
    ) -> anyhow::Result<()> {
        use windows::Win32::{
            Foundation::{GetLastError, HWND},
            UI::WindowsAndMessaging::{SetWindowDisplayAffinity, WINDOW_DISPLAY_AFFINITY},
        };

        let hwnd_obj = HWND(hwnd as *mut _);
        let affinity_u32 = affinity as u32;

        unsafe {
            let result =
                SetWindowDisplayAffinity(hwnd_obj, WINDOW_DISPLAY_AFFINITY(affinity_u32));
            if result.is_ok() {
                log_affinity(&format!(
                    "native OK: hwnd={:?}, affinity={}",
                    hwnd_obj, affinity_u32
                ));
                return Ok(());
            }

            let err = GetLastError();
            log_affinity(&format!(
                "native FAIL: hwnd={:?}, affinity={}, error={}",
                hwnd_obj, affinity_u32, err.0
            ));

            // Fallback to WDA_MONITOR if EXCLUDEFROMCAPTURE fails
            if affinity_u32 == 17 {
                log_affinity("fallback to WDA_MONITOR(1)...");
                let result2 = SetWindowDisplayAffinity(hwnd_obj, WINDOW_DISPLAY_AFFINITY(1));
                if result2.is_ok() {
                    return Ok(());
                }
            }

            anyhow::bail!("SetWindowDisplayAffinity failed (error={})", err.0)
        }
    }
}
