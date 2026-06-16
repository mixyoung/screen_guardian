# Tasks: Screen Guardian 功能扩展

## 执行顺序

### Phase 1: Core 扩展（screen-guardian-core）

- [ ] **T1.1** 新增 `config.rs` — 统一配置模块
  - `AppConfig` 结构体（监控间隔、路径配置、自启设置）
  - `load()` / `save()` / `default()` 方法

- [ ] **T1.2** 新增 `rules.rs` — 规则引擎
  - `Rule` 结构体（id, name, process_pattern, protect, enabled, priority）
  - `RuleEngine` — load/save/add/remove/enable/match_window/apply_to_windows
  - 正则编译 + 优先级排序 + 短路匹配

- [ ] **T1.3** 新增 `daemon.rs` — 监控守护逻辑
  - `DaemonConfig` 结构体
  - `Daemon` — new/tick/run
  - tick: enumerate → match → apply → record
  - 已关闭窗口清理

- [ ] **T1.4** 更新 `lib.rs` — 导出新模块

- [ ] **T1.5** 更新 workspace `Cargo.toml` — 添加 regex 依赖

### Phase 2: CLI 扩展（screen-guardian-cli）

- [ ] **T2.1** 添加 `rule` 子命令组
  - `rule list` — 列出规则
  - `rule add` — 添加规则
  - `rule remove` — 删除规则
  - `rule enable/disable` — 启用/禁用

- [ ] **T2.2** 添加 `monitor` 子命令
  - `monitor start` — 启动监控
  - `monitor status` — 查看状态

- [ ] **T2.3** 更新 CLI 依赖（引用新模块）

### Phase 3: GUI 应用（screen-guardian-gui）

- [ ] **T3.1** 初始化 Tauri v2 项目结构
  - `apps/screen-guardian-gui/Cargo.toml`
  - `apps/screen-guardian-gui/tauri.conf.json`
  - `apps/screen-guardian-gui/src/main.rs`

- [ ] **T3.2** Tauri IPC 命令层
  - list_windows / set_protection
  - list_rules / add_rule / remove_rule / toggle_rule
  - get_daemon_status / set_monitoring
  - get_config / update_config

- [ ] **T3.3** 前端 UI — 窗口列表页
  - 表格展示、排序、搜索、保护状态切换

- [ ] **T3.4** 前端 UI — 规则管理页
  - 规则列表、添加/编辑/删除表单

- [ ] **T3.5** 前端 UI — 监控状态页
  - 状态卡片、变更日志

- [ ] **T3.6** 前端 UI — 设置页
  - 配置表单、保存/重置

- [ ] **T3.7** 系统托盘集成
  - 托盘图标、右键菜单、显示/隐藏窗口

### Phase 4: 构建验证

- [ ] **T4.1** cargo build 全 workspace
- [ ] **T4.2** CLI 功能验证
- [ ] **T4.3** GUI 功能验证

## 依赖关系

```
T1.1 → T1.2 → T1.3 → T1.4 → T1.5
                                ↓
                    T2.1, T2.2, T2.3
                                ↓
                    T3.1 → T3.2 → T3.3~T3.7
                                ↓
                    T4.1 → T4.2 → T4.3
```
