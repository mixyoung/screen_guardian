use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::screenshot_apps::{known_screenshot_apps, ScreenshotApp};

/// A detected screenshot/recording application currently running
#[derive(Debug, Clone, Serialize)]
pub struct DetectedApp {
    pub display_name: String,
    pub process_name: String,
    pub pid: u32,
    pub threat_level: String,
    pub threat_label: String,
    pub description: String,
    pub detected_at: String,
}

/// Snapshot of all detected threats at a point in time
#[derive(Debug, Clone, Serialize)]
pub struct ThreatSnapshot {
    pub detected: Vec<DetectedApp>,
    pub total_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub scan_time_ms: u64,
}

/// Callback type for when threats change
pub type ThreatCallback = Box<dyn Fn(&ThreatSnapshot) + Send + 'static>;

/// Fast process monitor that scans for known screenshot/recording software
pub struct ProcessMonitor {
    known_apps: Vec<ScreenshotApp>,
    scan_interval: Duration,
    callbacks: Vec<ThreatCallback>,
    running: Arc<AtomicBool>,
}

impl ProcessMonitor {
    pub fn new() -> Self {
        Self {
            known_apps: known_screenshot_apps(),
            scan_interval: Duration::from_secs(1),
            callbacks: Vec::new(),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.scan_interval = interval;
        self
    }

    /// Register a callback that fires when the threat list changes
    pub fn on_threat_change(&mut self, cb: ThreatCallback) {
        self.callbacks.push(cb);
    }

    /// Perform a single scan of all running processes
    pub fn scan(&self) -> ThreatSnapshot {
        let start = Instant::now();
        let mut detected = Vec::new();

        if let Ok(processes) = enumerate_process_names() {
            for (process_name, pid) in &processes {
                let lower = process_name.to_lowercase();
                for app in &self.known_apps {
                    let matched = app.process_names.iter().any(|known| {
                        known.to_lowercase() == lower
                    });
                    if matched {
                        detected.push(DetectedApp {
                            display_name: app.display_name.to_string(),
                            process_name: process_name.clone(),
                            pid: *pid,
                            threat_level: app.threat_level.as_str().to_string(),
                            threat_label: app.threat_level.label().to_string(),
                            description: app.description.to_string(),
                            detected_at: crate::timefmt::format_now(),
                        });
                    }
                }
            }
        }

        let high_count = detected.iter()
            .filter(|d| d.threat_level == "high")
            .count();
        let medium_count = detected.iter()
            .filter(|d| d.threat_level == "medium")
            .count();

        let total_count = detected.len();

        ThreatSnapshot {
            detected,
            total_count,
            high_count,
            medium_count,
            scan_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// Start background monitoring thread
    /// Returns a handle and a shared snapshot that updates automatically
    pub fn start_background(
        self,
    ) -> (thread::JoinHandle<()>, Arc<std::sync::Mutex<ThreatSnapshot>>) {
        let snapshot = Arc::new(std::sync::Mutex::new(ThreatSnapshot {
            detected: Vec::new(),
            total_count: 0,
            high_count: 0,
            medium_count: 0,
            scan_time_ms: 0,
        }));
        let snapshot_clone = snapshot.clone();
        let running = self.running.clone();
        running.store(true, Ordering::SeqCst);

        let interval = self.scan_interval;
        let known_apps = self.known_apps.clone();
        let callbacks: Vec<ThreatCallback> = self.callbacks.into();

        let handle = thread::spawn(move || {
            log_monitor("[process-monitor] background thread started");

            while running.load(Ordering::SeqCst) {
                let result = scan_once(&known_apps);

                // Update shared snapshot
                if let Ok(mut snap) = snapshot_clone.lock() {
                    *snap = result.clone();
                }

                // Fire callbacks if threats changed
                for cb in &callbacks {
                    cb(&result);
                }

                thread::sleep(interval);
            }

            log_monitor("[process-monitor] background thread exited");
        });

        (handle, snapshot)
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// One-shot scan (used by background thread)
fn scan_once(known_apps: &[ScreenshotApp]) -> ThreatSnapshot {
    let start = Instant::now();
    let mut detected = Vec::new();

    if let Ok(processes) = enumerate_process_names() {
        for (process_name, pid) in &processes {
            let lower = process_name.to_lowercase();
            for app in known_apps {
                let matched = app.process_names.iter().any(|known| {
                    known.to_lowercase() == lower
                });
                if matched {
                    detected.push(DetectedApp {
                        display_name: app.display_name.to_string(),
                        process_name: process_name.clone(),
                        pid: *pid,
                        threat_level: app.threat_level.as_str().to_string(),
                        threat_label: app.threat_level.label().to_string(),
                        description: app.description.to_string(),
                        detected_at: crate::timefmt::format_now(),
                    });
                }
            }
        }
    }

    let high_count = detected.iter()
        .filter(|d| d.threat_level == "high")
        .count();
    let medium_count = detected.iter()
        .filter(|d| d.threat_level == "medium")
        .count();
    let total_count = detected.len();

    ThreatSnapshot {
        detected,
        total_count,
        high_count,
        medium_count,
        scan_time_ms: start.elapsed().as_millis() as u64,
    }
}

/// Enumerate all running process names and PIDs using CreateToolhelp32Snapshot
fn enumerate_process_names() -> anyhow::Result<Vec<(String, u32)>> {
    #[cfg(windows)]
    {
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        let mut result = Vec::new();

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                .map_err(|e| anyhow::anyhow!("CreateToolhelp32Snapshot failed: {}", e))?;

            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..std::mem::zeroed()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let name_raw = &entry.szExeFile;
                    let name_len = name_raw.iter().position(|&c| c == 0).unwrap_or(name_raw.len());
                    let name = String::from_utf16_lossy(&name_raw[..name_len]);
                    result.push((name, entry.th32ProcessID));

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = windows::Win32::Foundation::CloseHandle(snapshot);
        }

        Ok(result)
    }

    #[cfg(not(windows))]
    {
        Ok(Vec::new())
    }
}

fn log_monitor(msg: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("./gui-debug.log")
    {
        let _ = std::io::Write::write_fmt(
            &mut f,
            format_args!("[{}] [monitor] {}\n", crate::timefmt::format_now(), msg),
        );
    }
}
