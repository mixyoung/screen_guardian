# Architecture: Screen Guardian 功能扩展

## 1. 系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        Tauri v2 GUI                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐│
│  │ 窗口列表  │ │ 规则管理  │ │ 审计中心  │ │ 威胁检测  │ │ 日志   ││
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └───┬────┘│
│       │            │            │            │           │      │
│  ┌────┴─────┐ ┌────┴─────┐ ┌────┴─────┐                     │
│  │ 系统设置  │ │ 关于      │ │ 底部状态栏│                     │
│  └──────────┘ └──────────┘ └──────────┘                     │
├─────────────────────────────────────────────────────────────────┤
│                      Tauri IPC Commands                         │
├─────────────────────────────────────────────────────────────────┤
│                      screen-guardian-core                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐│
│  │ windows   │ │ affinity │ │ policy   │ │ rules    │ │ daemon ││
│  │ 枚举/监控 │ │ 保护控制 │ │ 历史记录 │ │ 规则引擎 │ │ 守护进程││
│  ├──────────┤ ├──────────┤ ├──────────┤ ├──────────┤ ├────────┤│
│  │ process   │ │ screenshot│ │ config  │ │ inject   │ │ timefmt││
│  │ 进程监控  │ │ 截屏检测  │ │ 配置管理│ │ DLL注入  │ │ 时间格式││
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └────────┘│
├─────────────────────────────────────────────────────────────────┤
│  screen-guardian-cli  │  screen-guardian-helper                  │
│  (CLI 工具)           │  (32位辅助进程)                          │
└─────────────────────────────────────────────────────────────────┘
```

## 2. Workspace 结构（扩展后）

```
screen_guardian/
├── Cargo.toml                          # workspace root
├── apps/
│   ├── screen-guardian-cli/            # 已有 — CLI 工具
│   ├── screen-guardian-helper/         # 已有 — 32位 helper
│   └── screen-guardian-gui/            # 新增 — Tauri GUI 应用
│       ├── Cargo.toml
│       ├── tauri.conf.json
│       ├── src/
│       │   └── main.rs                # Tauri 入口 + IPC 命令
│       └── ui/                        # 前端资源（HTML/JS/CSS）
│           ├── index.html
│           ├── main.js
│           └── style.css
├── crates/
│   └── screen-guardian-core/           # 已有 — 核心库扩展
│       └── src/
│           ├── lib.rs                  # 模块导出
│           ├── rules.rs               # 规则模型 + 匹配引擎
│           ├── daemon.rs              # 监控守护逻辑
│           ├── config.rs              # 统一配置
│           ├── process_monitor.rs     # 进程监控
│           ├── screenshot_apps.rs     # 截屏应用检测
│           ├── inject.rs              # DLL 注入（可选）
│           ├── timefmt.rs             # 时间格式化
│           ├── affinity.rs            # 窗口保护控制
│           ├── models.rs              # 数据模型
│           ├── policy.rs              # 策略历史记录
│           └── windows.rs             # 窗口枚举
├── data/
│   ├── rules.json                     # 规则持久化
│   └── policy-history.json            # 策略历史（已有）
└── output/                            # Super Dev 文档
```

## 3. 模块设计

### 3.1 rules.rs — 规则引擎

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub group_id: String,          // 规则组 ID
    pub name: String,
    pub process_pattern: String,   // 正则表达式
    pub protect: bool,
    pub enabled: bool,
    pub priority: u32,             // 越小越优先
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleGroup {
    pub id: String,
    pub name: String,
}

pub struct RuleEngine {
    groups: Vec<RuleGroup>,
    rules: Vec<Rule>,
    compiled: Vec<CompiledRule>,   // 编译后的 regex
}

impl RuleEngine {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self>;
    pub fn save(&self) -> anyhow::Result<()>;

    // 规则组操作
    pub fn add_group(&mut self, group: RuleGroup) -> anyhow::Result<()>;
    pub fn remove_group(&mut self, id: &str) -> bool;
    pub fn update_group(&mut self, group: RuleGroup) -> anyhow::Result<()>;
    pub fn list_groups(&self) -> &[RuleGroup];

    // 规则操作
    pub fn add(&mut self, rule: Rule) -> anyhow::Result<()>;
    pub fn remove(&mut self, id: &str) -> bool;
    pub fn enable(&mut self, id: &str, enabled: bool) -> bool;
    pub fn match_window(&self, process_name: &str) -> Option<&Rule>;
    pub fn apply_to_windows(&self, orchestrator: &AffinityOrchestrator) -> anyhow::Result<Vec<ApplyResult>>;
}
```

### 3.2 daemon.rs — 监控守护

```rust
pub struct DaemonConfig {
    pub poll_interval_ms: u64,     // 默认 3000
    pub auto_start: bool,
    pub rules_path: PathBuf,
    pub policy_path: PathBuf,
    pub helper_path: PathBuf,
}

pub struct Daemon {
    config: DaemonConfig,
    rule_engine: RuleEngine,
    orchestrator: AffinityOrchestrator,
    store: PolicyStore,
    protected_windows: HashSet<isize>,  // 已保护的 HWND
}

impl Daemon {
    pub fn new(config: DaemonConfig) -> anyhow::Result<Self>;
    pub fn tick(&mut self) -> anyhow::Result<()>;  // 单次扫描
    pub fn run(&mut self) -> anyhow::Result<()>;    // 循环运行
}
```

`tick()` 逻辑：
1. `enumerate_windows()` 获取当前所有窗口
2. 对每个窗口调用 `rule_engine.match_window()`
3. 匹配到规则且未保护 → 调用 `orchestrator.apply()` + 记录到 `store`
4. 已保护但窗口已关闭 → 从 `protected_windows` 移除

### 3.3 process_monitor.rs — 进程监控

```rust
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
}

pub struct ProcessMonitor {
    // 进程监控状态
}

impl ProcessMonitor {
    pub fn new() -> Self;
    pub fn scan(&self) -> anyhow::Result<Vec<ProcessInfo>>;
    pub fn get_process_details(&self, pid: u32) -> Option<ProcessInfo>;
}
```

### 3.4 screenshot_apps.rs — 截屏应用检测

```rust
pub struct ScreenshotApp {
    pub name: String,
    pub process_name: String,
    pub threat_level: ThreatLevel,  // 高危/中危/低危
}

pub enum ThreatLevel {
    High,
    Medium,
    Low,
}

pub struct ScreenshotDetector {
    known_apps: Vec<ScreenshotApp>,
}

impl ScreenshotDetector {
    pub fn new() -> Self;
    pub fn detect_running(&self, processes: &[ProcessInfo]) -> Vec<ScreenshotApp>;
    pub fn is_screenshot_app(&self, process_name: &str) -> Option<&ScreenshotApp>;
}
```

### 3.5 config.rs — 统一配置

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub poll_interval_ms: u64,
    pub auto_start_monitoring: bool,
    pub boot_auto_start: bool,
    pub rules_path: PathBuf,
    pub policy_path: PathBuf,
    pub helper_path: PathBuf,
}

impl AppConfig {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self>;
    pub fn save(&self) -> anyhow::Result<()>;
    pub fn default() -> Self;
}
```

### 3.6 GUI — Tauri IPC 命令

```rust
// 窗口管理
#[tauri::command]
fn list_windows() -> Result<Vec<WindowInfo>, String>;

#[tauri::command]
fn set_protection(hwnd: isize, pid: u32, protect: bool) -> Result<(), String>;

#[tauri::command]
fn run_scan() -> Result<(), String>;

// 规则管理
#[tauri::command]
fn list_rules() -> Result<Vec<Rule>, String>;

#[tauri::command]
fn add_rule(rule: Rule) -> Result<(), String>;

#[tauri::command]
fn remove_rule(id: String) -> Result<bool, String>;

#[tauri::command]
fn toggle_rule(id: String, enabled: bool) -> Result<bool, String>;

#[tauri::command]
fn list_rule_groups() -> Result<Vec<RuleGroup>, String>;

#[tauri::command]
fn add_rule_group(group: RuleGroup) -> Result<(), String>;

#[tauri::command]
fn remove_rule_group(id: String) -> Result<bool, String>;

// 监控管理
#[tauri::command]
fn get_daemon_status() -> Result<DaemonStatus, String>;

#[tauri::command]
fn start_monitor() -> Result<(), String>;

#[tauri::command]
fn stop_monitor() -> Result<(), String>;

// 威胁检测
#[tauri::command]
fn scan_threats() -> Result<Vec<ThreatInfo>, String>;

// 配置管理
#[tauri::command]
fn get_config() -> Result<AppConfig, String>;

#[tauri::command]
fn update_config(config: AppConfig) -> Result<(), String>;
```

## 4. 依赖扩展

### workspace Cargo.toml 新增
```toml
regex = "1"
sysinfo = "0.33"
tauri = { version = "2", features = ["tray-icon"] }
serde = { version = "1", features = ["derive"] }  # 已有
serde_json = "1"  # 已有
uuid = { version = "1", features = ["v4"] }  # 生成规则 ID
```

### screen-guardian-core 新增
```toml
regex.workspace = true
uuid.workspace = true
```

### screen-guardian-gui 新增
```toml
tauri.workspace = true
screen-guardian-core = { path = "../../crates/screen-guardian-core" }
uuid.workspace = true
```

## 5. 数据流

```
[窗口事件] → Daemon.tick() → RuleEngine.match_window()
                                    ↓ 匹配成功
                              AffinityOrchestrator.apply()
                                    ↓
                              PolicyStore.record()
                                    ↓
                              GUI 实时刷新 ← Tauri IPC 轮询

[进程扫描] → ProcessMonitor.scan() → ScreenshotDetector.detect_running()
                                              ↓ 检测到威胁
                                        ThreatInfo 返回到 GUI

[规则变更] → RuleEngine.add/remove/toggle() → JSON 持久化
```

## 6. 关键决策

| 决策 | 选择 | 原因 |
|------|------|------|
| GUI 框架 | Tauri v2 | 内置托盘支持，WebView2 免安装 |
| 规则引擎 | regex 线性扫描 | 10-50 条规则无需复杂引擎 |
| 监控方式 | 轮询（3秒） | 比 WinEventHook 更简单可控 |
| 配置格式 | JSON | 与现有 PolicyStore 一致 |
| 规则组 | 支持规则组管理 | 便于分类管理规则 |
| 威胁检测 | 内置截屏应用列表 | 提供实时威胁感知 |
| 底部状态栏 | 固定显示 | 提供全局状态概览 |
| 自动刷新 | 可配置间隔 | 提升实时监控体验 |
