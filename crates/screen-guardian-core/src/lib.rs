pub mod affinity;
pub mod config;
pub mod daemon;
pub mod gpu_protection;
pub mod inject;
pub mod models;
pub mod policy;
pub mod process_monitor;
pub mod rules;
pub mod screenshot_apps;
pub mod timefmt;
pub mod windows;

pub use affinity::{AffinityOrchestrator, AffinityValue};
pub use config::AppConfig;
pub use daemon::{Daemon, DaemonStatus};
pub use gpu_protection::{
    GpuCaptureType, GpuProtectionConfig, GpuProtectionLevel, GpuProtectionManager,
    GpuProtectionMethod, GpuProtectionStatus, ScreenshotApp, ThreatLevel,
};
pub use models::{SortBy, SortOrder, WindowInfo};
pub use policy::{PolicyChange, PolicyStore};
pub use process_monitor::{DetectedApp, ProcessMonitor, ThreatSnapshot};
pub use rules::{ApplyResult, Rule, RuleEngine, RuleGroup};
pub use timefmt::format_now;
pub use windows::{audit_protected_windows, detect_process_architecture, enumerate_windows};
