//! GPU Screenshot Protection Module
//!
//! This module provides protection against GPU-based screen capture methods:
//! - DXGI Desktop Duplication API
//! - Windows Graphics Capture API
//! - Direct3D/Vulkan Game Capture

use serde::{Deserialize, Serialize};

/// GPU capture technology type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuCaptureType {
    /// Traditional GDI capture (BitBlt, GetDIBits)
    Gdi,
    /// DXGI Desktop Duplication API
    Dxgi,
    /// Windows Graphics Capture API (Win10 1903+)
    WindowsGraphicsCapture,
    /// Direct3D/Vulkan Hook (OBS Game Capture)
    GameCapture,
}

impl std::fmt::Display for GpuCaptureType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gdi => write!(f, "GDI"),
            Self::Dxgi => write!(f, "DXGI"),
            Self::WindowsGraphicsCapture => write!(f, "WGC"),
            Self::GameCapture => write!(f, "Game"),
        }
    }
}

/// GPU protection method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuProtectionMethod {
    /// Hook DXGI Present to return black frames
    DxgiPresentHook,
    /// Hook Direct3D Present
    D3dPresentHook,
    /// Use Windows Graphics Capture protection
    WgcProtection,
    /// Overlay-based protection
    OverlayProtection,
}

impl std::fmt::Display for GpuProtectionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DxgiPresentHook => write!(f, "DXGI Hook"),
            Self::D3dPresentHook => write!(f, "D3D Hook"),
            Self::WgcProtection => write!(f, "WGC Protection"),
            Self::OverlayProtection => write!(f, "Overlay"),
        }
    }
}

/// GPU protection level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuProtectionLevel {
    /// Basic: Only GDI protection (SetWindowDisplayAffinity)
    Basic,
    /// Standard: GDI + DXGI protection
    Standard,
    /// Advanced: GDI + DXGI + D3D protection
    Advanced,
    /// Maximum: All protections (high performance impact)
    Maximum,
}

impl std::fmt::Display for GpuProtectionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Basic => write!(f, "Basic"),
            Self::Standard => write!(f, "Standard"),
            Self::Advanced => write!(f, "Advanced"),
            Self::Maximum => write!(f, "Maximum"),
        }
    }
}

/// GPU protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuProtectionConfig {
    pub enabled: bool,
    pub level: GpuProtectionLevel,
    pub enable_dxgi_hook: bool,
    pub enable_d3d_hook: bool,
    pub enable_wgc_protection: bool,
    pub enable_overlay: bool,
}

impl Default for GpuProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            level: GpuProtectionLevel::Basic,
            enable_dxgi_hook: false,
            enable_d3d_hook: false,
            enable_wgc_protection: true,
            enable_overlay: false,
        }
    }
}

/// GPU protection status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuProtectionStatus {
    pub enabled: bool,
    pub level: GpuProtectionLevel,
    pub active_methods: Vec<GpuProtectionMethod>,
    pub protected_windows: usize,
}

/// Known screenshot/recording applications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotApp {
    pub name: String,
    pub process_name: String,
    pub capture_type: GpuCaptureType,
    pub threat_level: ThreatLevel,
}

/// Threat level for screenshot apps
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
        }
    }
}

/// Get list of known screenshot/recording applications
pub fn get_known_screenshot_apps() -> Vec<ScreenshotApp> {
    vec![
        ScreenshotApp {
            name: "OBS Studio".to_string(),
            process_name: "obs64.exe".to_string(),
            capture_type: GpuCaptureType::Dxgi,
            threat_level: ThreatLevel::High,
        },
        ScreenshotApp {
            name: "OBS Studio (32-bit)".to_string(),
            process_name: "obs32.exe".to_string(),
            capture_type: GpuCaptureType::Dxgi,
            threat_level: ThreatLevel::High,
        },
        ScreenshotApp {
            name: "XSplit".to_string(),
            process_name: "XSplit.Core.exe".to_string(),
            capture_type: GpuCaptureType::Dxgi,
            threat_level: ThreatLevel::High,
        },
        ScreenshotApp {
            name: "Bandicam".to_string(),
            process_name: "bdcam.exe".to_string(),
            capture_type: GpuCaptureType::Dxgi,
            threat_level: ThreatLevel::High,
        },
        ScreenshotApp {
            name: "Fraps".to_string(),
            process_name: "fraps.exe".to_string(),
            capture_type: GpuCaptureType::Dxgi,
            threat_level: ThreatLevel::Medium,
        },
        ScreenshotApp {
            name: "ShareX".to_string(),
            process_name: "ShareX.exe".to_string(),
            capture_type: GpuCaptureType::Gdi,
            threat_level: ThreatLevel::Medium,
        },
        ScreenshotApp {
            name: "Greenshot".to_string(),
            process_name: "Greenshot.exe".to_string(),
            capture_type: GpuCaptureType::Gdi,
            threat_level: ThreatLevel::Low,
        },
        ScreenshotApp {
            name: "Lightshot".to_string(),
            process_name: "lightshot.exe".to_string(),
            capture_type: GpuCaptureType::Gdi,
            threat_level: ThreatLevel::Low,
        },
        ScreenshotApp {
            name: "Snipping Tool".to_string(),
            process_name: "SnippingTool.exe".to_string(),
            capture_type: GpuCaptureType::Gdi,
            threat_level: ThreatLevel::Low,
        },
        ScreenshotApp {
            name: "Windows Game Bar".to_string(),
            process_name: "GameBar.exe".to_string(),
            capture_type: GpuCaptureType::Dxgi,
            threat_level: ThreatLevel::High,
        },
        ScreenshotApp {
            name: "NVIDIA ShadowPlay".to_string(),
            process_name: "NVIDIA Share.exe".to_string(),
            capture_type: GpuCaptureType::Dxgi,
            threat_level: ThreatLevel::High,
        },
        ScreenshotApp {
            name: "AMD ReLive".to_string(),
            process_name: "AMDExternalEvents.exe".to_string(),
            capture_type: GpuCaptureType::Dxgi,
            threat_level: ThreatLevel::High,
        },
    ]
}

/// GPU protection manager
pub struct GpuProtectionManager {
    config: GpuProtectionConfig,
    active_methods: Vec<GpuProtectionMethod>,
}

impl GpuProtectionManager {
    pub fn new(config: GpuProtectionConfig) -> Self {
        Self {
            config,
            active_methods: Vec::new(),
        }
    }

    /// Enable GPU protection
    pub fn enable(&mut self) -> anyhow::Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Enable methods based on config
        if self.config.enable_dxgi_hook {
            self.active_methods.push(GpuProtectionMethod::DxgiPresentHook);
        }
        if self.config.enable_d3d_hook {
            self.active_methods.push(GpuProtectionMethod::D3dPresentHook);
        }
        if self.config.enable_wgc_protection {
            self.active_methods.push(GpuProtectionMethod::WgcProtection);
        }
        if self.config.enable_overlay {
            self.active_methods.push(GpuProtectionMethod::OverlayProtection);
        }

        Ok(())
    }

    /// Disable GPU protection
    pub fn disable(&mut self) {
        self.active_methods.clear();
    }

    /// Get active protection methods
    pub fn get_active_methods(&self) -> &[GpuProtectionMethod] {
        &self.active_methods
    }

    /// Get protection status
    pub fn get_status(&self) -> GpuProtectionStatus {
        GpuProtectionStatus {
            enabled: self.config.enabled,
            level: self.config.level,
            active_methods: self.active_methods.clone(),
            protected_windows: 0, // TODO: Track protected windows
        }
    }

    /// Detect capture type for a process
    pub fn detect_capture_type(&self, process_name: &str) -> Option<GpuCaptureType> {
        let known_apps = get_known_screenshot_apps();
        known_apps
            .iter()
            .find(|app| process_name.to_lowercase().contains(&app.process_name.to_lowercase()))
            .map(|app| app.capture_type)
    }

    /// Check if a process is a known screenshot app
    pub fn is_screenshot_app(&self, process_name: &str) -> Option<ScreenshotApp> {
        let known_apps = get_known_screenshot_apps();
        known_apps
            .into_iter()
            .find(|app| process_name.to_lowercase().contains(&app.process_name.to_lowercase()))
    }

    /// Apply WGC protection to a window
    /// This uses Windows.Graphics.Capture API protection
    #[cfg(windows)]
    pub fn apply_wgc_protection(&self, hwnd: isize) -> anyhow::Result<()> {
        use windows::Win32::{
            Foundation::HWND,
            UI::WindowsAndMessaging::{
                SetWindowDisplayAffinity, WINDOW_DISPLAY_AFFINITY,
            },
        };

        if !self.config.enable_wgc_protection {
            return Ok(());
        }

        let hwnd_obj = HWND(hwnd as *mut _);

        // WDA_EXCLUDEFROMCAPTURE (0x11) works with Windows Graphics Capture API
        // This makes the window invisible to WGC-based capture tools
        unsafe {
            let result = SetWindowDisplayAffinity(
                hwnd_obj,
                WINDOW_DISPLAY_AFFINITY(0x11), // WDA_EXCLUDEFROMCAPTURE
            );

            if result.is_ok() {
                return Ok(());
            }

            // Fallback to WDA_MONITOR
            let result2 = SetWindowDisplayAffinity(
                hwnd_obj,
                WINDOW_DISPLAY_AFFINITY(0x01), // WDA_MONITOR
            );

            if result2.is_ok() {
                return Ok(());
            }

            anyhow::bail!("WGC protection failed")
        }
    }

    /// Get WGC protection status for a window
    #[cfg(windows)]
    pub fn get_wgc_status(&self, hwnd: isize) -> bool {
        use windows::Win32::{
            Foundation::HWND,
            UI::WindowsAndMessaging::GetWindowDisplayAffinity,
        };

        let hwnd_obj = HWND(hwnd as *mut _);

        unsafe {
            let mut affinity: u32 = 0;
            let result = GetWindowDisplayAffinity(hwnd_obj, &mut affinity);

            if result.is_ok() {
                // Check if WDA_EXCLUDEFROMCAPTURE (0x11) or WDA_MONITOR (0x01) is set
                return affinity == 0x11 || affinity == 0x01;
            }

            false
        }
    }

    /// Apply Game Capture protection to a process
    /// This hooks DirectX/Vulkan Present calls
    ///
    /// NOTE: This is a complex operation that requires:
    /// 1. Injecting a hook DLL into the target process
    /// 2. Hooking DirectX 9/11/12 or Vulkan Present functions
    /// 3. Modifying frame buffers before presentation
    ///
    /// This is currently a placeholder for future implementation
    pub fn apply_game_capture_protection(&self, _pid: u32) -> anyhow::Result<()> {
        if !self.config.enable_d3d_hook {
            return Ok(());
        }

        // TODO: Implement Game Capture protection
        // This would require:
        // 1. A separate hook DLL with DirectX/Vulkan hooks
        // 2. DLL injection into the target process
        // 3. Hooking IDXGISwapChain::Present, IDirect3DDevice9::Present, etc.
        // 4. Clearing or encrypting frame buffers before presentation

        anyhow::bail!("Game Capture protection not yet implemented")
    }

    /// Check if a process uses DirectX/Vulkan
    pub fn detect_graphics_api(&self, process_name: &str) -> Option<String> {
        let lower = process_name.to_lowercase();

        // Common game/graphics process names
        let dx_patterns = [
            "d3d", "direct3d", "dxgi", "vulkan", "opengl",
            "game", "unity", "unreal", "godot",
        ];

        for pattern in &dx_patterns {
            if lower.contains(pattern) {
                return Some(pattern.to_string());
            }
        }

        None
    }
}
