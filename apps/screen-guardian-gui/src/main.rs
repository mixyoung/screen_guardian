#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::Write;
use std::sync::Mutex;

use serde::Serialize;
use tauri::Manager;

use screen_guardian_core::{
    AppConfig, Daemon, ProcessMonitor, Rule, RuleEngine, RuleGroup, ThreatSnapshot, WindowInfo,
};

fn gui_log(msg: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("./gui-debug.log")
    {
        let _ = writeln!(f, "[{}] {}", screen_guardian_core::format_now(), msg);
    }
}

struct AppState {
    config: Mutex<AppConfig>,
    daemon: Mutex<Daemon>,
    rule_engine: Mutex<RuleEngine>,
    orchestrator: Mutex<screen_guardian_core::AffinityOrchestrator>,
    monitor_running: Mutex<bool>,
    threat_snapshot: Mutex<ThreatSnapshot>,
    threat_monitor_running: Mutex<bool>,
}

#[tauri::command]
fn list_windows(state: tauri::State<AppState>) -> Result<Vec<WindowInfo>, String> {
    gui_log("list_windows called");
    let _ = state;
    let result = screen_guardian_core::enumerate_windows().map_err(|e| e.to_string());
    match &result {
        Ok(wins) => gui_log(&format!("list_windows ok, {} windows", wins.len())),
        Err(e) => gui_log(&format!("list_windows error: {}", e)),
    }
    result
}

#[tauri::command]
fn set_protection(
    state: tauri::State<AppState>,
    hwnd: isize,
    pid: u32,
    protect: bool,
) -> Result<(), String> {
    gui_log(&format!("set_protection called: hwnd={}, pid={}, protect={}", hwnd, pid, protect));
    let mut orchestrator = state.orchestrator.lock().map_err(|e| e.to_string())?;
    let affinity = screen_guardian_core::AffinityValue::from_bool(protect);
    gui_log(&format!("set_protection affinity={:?}", affinity));
    match orchestrator.apply(hwnd, pid, affinity) {
        Ok(result) => {
            gui_log(&format!("set_protection ok: method={}", result.method));
            Ok(())
        }
        Err(e) => {
            gui_log(&format!("set_protection error: {}", e));
            Err(e.to_string())
        }
    }
}

#[tauri::command]
fn list_rules(state: tauri::State<AppState>) -> Result<Vec<Rule>, String> {
    let engine = state.rule_engine.lock().map_err(|e| e.to_string())?;
    Ok(engine.rules().to_vec())
}

#[tauri::command]
fn list_rules_by_group(state: tauri::State<AppState>, group_id: String) -> Result<Vec<Rule>, String> {
    let engine = state.rule_engine.lock().map_err(|e| e.to_string())?;
    Ok(engine.rules_by_group(&group_id).into_iter().cloned().collect())
}

#[tauri::command]
fn list_groups(state: tauri::State<AppState>) -> Result<Vec<RuleGroup>, String> {
    let engine = state.rule_engine.lock().map_err(|e| e.to_string())?;
    Ok(engine.groups().to_vec())
}

#[tauri::command]
fn add_group(state: tauri::State<AppState>, group: RuleGroup) -> Result<(), String> {
    let mut engine = state.rule_engine.lock().map_err(|e| e.to_string())?;
    engine.add_group(group).map_err(|e| e.to_string())?;
    engine.save().map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn remove_group(state: tauri::State<AppState>, id: String) -> Result<bool, String> {
    let mut engine = state.rule_engine.lock().map_err(|e| e.to_string())?;
    let removed = engine.remove_group(&id);
    if removed {
        engine.save().map_err(|e| e.to_string())?;
    }
    Ok(removed)
}

#[tauri::command]
fn toggle_group(state: tauri::State<AppState>, id: String, enabled: bool) -> Result<bool, String> {
    let mut engine = state.rule_engine.lock().map_err(|e| e.to_string())?;
    let found = engine.toggle_group(&id, enabled);
    if found {
        engine.save().map_err(|e| e.to_string())?;
    }
    Ok(found)
}

#[tauri::command]
fn add_rule(state: tauri::State<AppState>, rule: Rule) -> Result<(), String> {
    let mut engine = state.rule_engine.lock().map_err(|e| e.to_string())?;
    engine.add(rule).map_err(|e| e.to_string())?;
    engine.save().map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn remove_rule(state: tauri::State<AppState>, id: String) -> Result<bool, String> {
    let mut engine = state.rule_engine.lock().map_err(|e| e.to_string())?;
    let removed = engine.remove(&id);
    if removed {
        engine.save().map_err(|e| e.to_string())?;
    }
    Ok(removed)
}

#[tauri::command]
fn toggle_rule(state: tauri::State<AppState>, id: String, enabled: bool) -> Result<bool, String> {
    let mut engine = state.rule_engine.lock().map_err(|e| e.to_string())?;
    let found = engine.enable(&id, enabled);
    if found {
        engine.save().map_err(|e| e.to_string())?;
    }
    Ok(found)
}

#[derive(Serialize)]
struct MonitorStatus {
    running: bool,
    protected_count: usize,
    rule_count: usize,
    last_scan_secs_ago: u64,
}

#[tauri::command]
fn get_daemon_status(state: tauri::State<AppState>) -> Result<MonitorStatus, String> {
    gui_log("get_daemon_status called");
    let daemon = state.daemon.lock().map_err(|e| e.to_string())?;
    let running = *state.monitor_running.lock().map_err(|e| e.to_string())?;
    let status = daemon.status();
    gui_log(&format!("get_daemon_status ok: running={}, protected={}, rules={}", running, status.protected_count, status.rule_count));
    Ok(MonitorStatus {
        running,
        protected_count: status.protected_count,
        rule_count: status.rule_count,
        last_scan_secs_ago: status.last_scan_secs_ago,
    })
}

#[tauri::command]
fn run_scan(state: tauri::State<AppState>) -> Result<usize, String> {
    gui_log("run_scan called");
    let mut daemon = state.daemon.lock().map_err(|e| e.to_string())?;
    daemon.tick().map_err(|e| {
        let msg = format!("tick error: {}", e);
        gui_log(&msg);
        msg
    })?;
    let status = daemon.status();
    gui_log(&format!("run_scan ok: protected={}", status.protected_count));
    Ok(status.protected_count)
}

#[tauri::command]
fn start_monitor(_app: tauri::AppHandle, state: tauri::State<AppState>) -> Result<(), String> {
    gui_log("start_monitor called");
    {
        let mut running = state.monitor_running.lock().map_err(|e| e.to_string())?;
        if *running {
            gui_log("start_monitor: already running");
            return Ok(());
        }
        *running = true;
    }
    gui_log("start_monitor: spawning background thread");

    std::thread::spawn(move || {
        gui_log("[monitor] thread started");
        loop {
            // Check if we should stop
            // We can't hold the lock across tick(), so we read it, drop, then act
            let should_run = {
                // Try to access the monitor_running state via a global
                // Since we can't easily access tauri::State from a thread, use a file flag
                std::fs::read_to_string("./data/monitor-running.flag")
                    .map(|s| s.trim() == "1")
                    .unwrap_or(true)
            };
            if !should_run {
                gui_log("[monitor] stop flag detected, exiting loop");
                break;
            }

            // Do one tick via the daemon - but we can't access AppState from here
            // So we call the CLI-style approach: enumerate windows, apply rules
            match screen_guardian_core::enumerate_windows() {
                Ok(windows) => {
                    gui_log(&format!("[monitor] tick: {} windows", windows.len()));
                    // Load rules and apply
                    let config = screen_guardian_core::AppConfig::load("./data/config.json").unwrap_or_default();
                    if let Ok(engine) = screen_guardian_core::RuleEngine::load(&config.rules_path) {
                        let mut orchestrator = screen_guardian_core::AffinityOrchestrator::new(&config.helper_path);
                        if let Ok(mut store) = screen_guardian_core::PolicyStore::load(&config.policy_path) {
                            match engine.apply_to_windows(&mut orchestrator, &mut store) {
                                Ok(results) => {
                                    gui_log(&format!("[monitor] applied {} changes", results.len()));
                                }
                                Err(e) => {
                                    gui_log(&format!("[monitor] apply error: {}", e));
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    gui_log(&format!("[monitor] enumerate error: {}", e));
                }
            }

            let interval = {
                screen_guardian_core::AppConfig::load("./data/config.json")
                    .unwrap_or_default()
                    .poll_interval_ms
            };
            std::thread::sleep(std::time::Duration::from_millis(interval));
        }
        gui_log("[monitor] thread exited");
        let _ = std::fs::write("./data/monitor-running.flag", "0");
    });

    let _ = std::fs::write("./data/monitor-running.flag", "1");
    gui_log("start_monitor: done");
    Ok(())
}

#[tauri::command]
fn stop_monitor(state: tauri::State<AppState>) -> Result<(), String> {
    gui_log("stop_monitor called");
    let _ = std::fs::write("./data/monitor-running.flag", "0");
    let mut running = state.monitor_running.lock().map_err(|e| e.to_string())?;
    *running = false;
    gui_log("stop_monitor: flag set to 0");
    Ok(())
}

#[tauri::command]
fn scan_threats(state: tauri::State<AppState>) -> Result<ThreatSnapshot, String> {
    gui_log("scan_threats called");
    let monitor = ProcessMonitor::new();
    let snapshot = monitor.scan();
    if let Ok(mut snap) = state.threat_snapshot.lock() {
        *snap = snapshot.clone();
    }
    gui_log(&format!("scan_threats ok: {} detected", snapshot.total_count));
    Ok(snapshot)
}

#[tauri::command]
fn get_threat_snapshot(state: tauri::State<AppState>) -> Result<ThreatSnapshot, String> {
    let snap = state.threat_snapshot.lock().map_err(|e| e.to_string())?;
    Ok(snap.clone())
}

#[tauri::command]
fn start_threat_monitor(state: tauri::State<AppState>) -> Result<(), String> {
    gui_log("start_threat_monitor called");
    {
        let mut running = state.threat_monitor_running.lock().map_err(|e| e.to_string())?;
        if *running {
            gui_log("start_threat_monitor: already running");
            return Ok(());
        }
        *running = true;
    }

    std::thread::spawn(move || {
        gui_log("[threat-monitor] background thread started");
        let monitor = ProcessMonitor::new();

        loop {
            let should_run = std::fs::read_to_string("./data/threat-monitor-running.flag")
                .map(|s| s.trim() == "1")
                .unwrap_or(true);
            if !should_run {
                gui_log("[threat-monitor] stop flag detected, exiting");
                break;
            }

            let _ = monitor.scan();
            std::thread::sleep(std::time::Duration::from_secs(1));
        }

        gui_log("[threat-monitor] thread exited");
        let _ = std::fs::write("./data/threat-monitor-running.flag", "0");
    });

    let _ = std::fs::write("./data/threat-monitor-running.flag", "1");
    gui_log("start_threat_monitor: done");
    Ok(())
}

#[tauri::command]
fn stop_threat_monitor(state: tauri::State<AppState>) -> Result<(), String> {
    gui_log("stop_threat_monitor called");
    let _ = std::fs::write("./data/threat-monitor-running.flag", "0");
    let mut running = state.threat_monitor_running.lock().map_err(|e| e.to_string())?;
    *running = false;
    Ok(())
}

#[tauri::command]
fn read_log() -> Result<String, String> {
    std::fs::read_to_string("./gui-debug.log").or_else(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Ok(String::new())
        } else {
            Err(e.to_string())
        }
    })
}

#[tauri::command]
fn clear_log() -> Result<(), String> {
    std::fs::write("./gui-debug.log", "").map_err(|e| e.to_string())
}

#[tauri::command]
fn get_config(state: tauri::State<AppState>) -> Result<AppConfig, String> {
    let config = state.config.lock().map_err(|e| e.to_string())?;
    Ok(config.clone())
}

#[tauri::command]
fn update_config(state: tauri::State<AppState>, new_config: AppConfig) -> Result<(), String> {
    let mut config = state.config.lock().map_err(|e| e.to_string())?;
    *config = new_config.clone();
    config
        .save("./data/config.json")
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn main() {
    // Reset monitor flag on startup
    let _ = std::fs::create_dir_all("./data");
    let _ = std::fs::write("./data/monitor-running.flag", "0");
    let _ = std::fs::write("./data/threat-monitor-running.flag", "0");

    let config = AppConfig::load("./data/config.json").unwrap_or_default();
    let rule_engine = RuleEngine::load(&config.rules_path).unwrap_or_else(|_| {
        RuleEngine::load("/dev/null").unwrap_or_else(|_| {
            // Create empty engine
            let rules: Vec<Rule> = Vec::new();
            let json = serde_json::to_string(&rules).unwrap_or_default();
            let _ = std::fs::write(&config.rules_path, &json);
            RuleEngine::load(&config.rules_path).unwrap()
        })
    });
    let daemon = Daemon::new(config.clone()).unwrap();
    let orchestrator = screen_guardian_core::AffinityOrchestrator::new(&config.helper_path);

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState {
            config: Mutex::new(config),
            daemon: Mutex::new(daemon),
            rule_engine: Mutex::new(rule_engine),
            orchestrator: Mutex::new(orchestrator),
            monitor_running: Mutex::new(false),
            threat_snapshot: Mutex::new(ThreatSnapshot {
                detected: Vec::new(),
                total_count: 0,
                high_count: 0,
                medium_count: 0,
                scan_time_ms: 0,
            }),
            threat_monitor_running: Mutex::new(false),
        })
        .setup(|app| {
            gui_log("=== GUI SETUP STARTED ===");
            // Build tray menu
            let show = tauri::menu::MenuItemBuilder::new("Show Window")
                .id("show")
                .build(app)?;
            let pause = tauri::menu::MenuItemBuilder::new("Pause Monitor")
                .id("pause")
                .build(app)?;
            let quit = tauri::menu::MenuItemBuilder::new("Quit")
                .id("quit")
                .build(app)?;

            let menu = tauri::menu::MenuBuilder::new(app)
                .item(&show)
                .item(&pause)
                .separator()
                .item(&quit)
                .build()?;

            let tray_icon = app.default_window_icon().cloned();
            let mut tray_builder = tauri::tray::TrayIconBuilder::new()
                .menu(&menu)
                .tooltip("Screen Guardian")
                .icon_as_template(true);
            if let Some(icon) = tray_icon {
                tray_builder = tray_builder.icon(icon);
            }
            let _tray = tray_builder
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "pause" => {
                        // Toggle monitoring
                    }
                    "quit" => {
                        app.exit(0);
                    }
                    _ => {}
                })
                .build(app)?;

            // Handle window close: minimize to tray or actually close
            if let Some(window) = app.get_webview_window("main") {
                let app_handle = app.handle().clone();
                window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        let config = app_handle.state::<AppState>()
                            .config
                            .lock()
                            .map(|c| c.clone())
                            .unwrap_or_default();
                        if config.close_to_tray {
                            api.prevent_close();
                            if let Some(win) = app_handle.get_webview_window("main") {
                                let _ = win.hide();
                            }
                            gui_log("window hidden to tray");
                        }
                    }
                });
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_windows,
            set_protection,
            list_rules,
            list_rules_by_group,
            list_groups,
            add_group,
            remove_group,
            toggle_group,
            add_rule,
            remove_rule,
            toggle_rule,
            get_daemon_status,
            run_scan,
            start_monitor,
            stop_monitor,
            get_config,
            update_config,
            read_log,
            clear_log,
            scan_threats,
            get_threat_snapshot,
            start_threat_monitor,
            stop_threat_monitor,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
