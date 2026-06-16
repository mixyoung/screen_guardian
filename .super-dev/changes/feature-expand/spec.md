# Spec: Screen Guardian 功能扩展

## 概述
为 screen_guardian 新增规则自动匹配、托盘常驻/自动监控、GUI 界面三项能力。

## 技术栈
- Rust 2021 edition
- windows 0.58（已有）
- regex 1（新增 — 规则匹配）
- tauri 2（新增 — GUI + 托盘）
- serde/serde_json（已有）
- chrono（已有）
- clap 4（已有）

## 新增模块

### config.rs
- `AppConfig`: 监控间隔、路径配置、自启设置
- JSON 持久化到 `data/config.json`

### rules.rs
- `Rule`: id, name, process_pattern (regex), protect, enabled, priority
- `RuleEngine`: 编译 regex，按优先级匹配，短路返回
- JSON 持久化到 `data/rules.json`

### daemon.rs
- `Daemon`: 持有 RuleEngine + AffinityOrchestrator + PolicyStore
- `tick()`: 枚举窗口 → 匹配规则 → 应用保护 → 记录变更
- `run()`: 循环调用 tick，间隔可配置

## 新增应用

### screen-guardian-gui
- Tauri v2 应用
- IPC 命令桥接 core 模块
- 前端：HTML + JS + CSS（无框架依赖）
- 四页面：窗口列表、规则管理、监控状态、设置
- 系统托盘：图标 + 右键菜单

## 数据流
```
[新窗口出现] → Daemon.tick() → RuleEngine.match()
                                      ↓ 匹配
                                AffinityOrchestrator.apply()
                                      ↓
                                PolicyStore.record()
                                      ↓
                                GUI 通过 IPC 刷新显示
```
