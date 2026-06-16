# Research: Screen Guardian 功能扩展

## 调研日期
2026-06-15（更新）

## 调研目标
为 screen_guardian 项目规划三项新功能：规则自动匹配、托盘常驻/自动监控、GUI 界面。

---

## 1. 现有项目状态

### 已完成
- 窗口枚举（`enumerate_windows`）
- 进程架构检测（`detect_process_architecture`）
- `SetWindowDisplayAffinity` 调用（含 32 位 helper 路由）
- 策略变更历史记录（`PolicyStore`）
- CLI 手动操作（list/audit/set/save/history）

### 现有依赖
- `windows 0.58` — Win32 API
- `clap 4` — CLI 参数解析
- `serde/serde_json` — 序列化
- `chrono` — 时间处理
- `tabled` — 表格输出
- `anyhow/thiserror` — 错误处理

---

## 2. 技术选型调研

### 2.1 GUI 框架

| 框架 | 成熟度 | 系统托盘 | 适用场景 |
|------|--------|----------|----------|
| **Tauri v2** | 高 | 内置支持 | 托盘工具 + 配置界面 |
| **egui** | 高 | 需 `tray-icon` crate | 调试/工具 UI |
| **iced** | 中 | 无原生支持 | 纯 Rust 自定义 UI |
| **Slint** | 中高 | 无原生支持 | 嵌入式/原生风格 |

**推荐: Tauri v2** — WebView2 内置于 Win10/11，二进制小（~5-10MB），系统托盘一等公民支持。

### 2.2 系统托盘
- `tray-icon`（tauri-apps 出品）+ `muda`（上下文菜单）
- 底层使用 Win32 `Shell_NotifyIcon`
- Tauri v2 内部已封装

### 2.3 窗口事件监控
- 使用 `SetWinEventHook` 监听 `EVENT_OBJECT_CREATE`（0x8000）和 `EVENT_SYSTEM_FOREGROUND`（0x0003）
- `WINEVENT_OUTOFCONTEXT` 模式，事件驱动非轮询，高效
- 回调中用 `GetWindowThreadProcessId` + `GetWindowTextW` 识别窗口

### 2.4 规则引擎
- `regex` crate 做进程名匹配
- `Vec<Rule>` 线性扫描，10-50 条规则性能无问题
- 简单直接，无需引入重量级引擎

---

## 3. 推荐技术栈

```
tauri v2          — GUI + 系统托盘
regex             — 规则匹配
windows 0.58      — Win32 API（已有）
sysinfo           — 进程信息查询
serde/serde_json  — 配置/规则持久化（已有）
```

---

## 4. 竞品深度分析

### 4.1 NoScreenCap（GitHub 开源项目）
- **实现方式**: DLL 注入 + `SetWindowDisplayAffinity`
- **风险**: 高风险机制，可能触发安全软件告警
- **优点**: 直接调用 Windows API，效果立竿见影
- **本项目改进**: 采用更安全的 helper EXE 模式，避免 DLL 注入

### 4.2 SpyShelter（商业软件）
- **核心功能**: 反键盘记录 + 截屏保护 + 剪贴板保护
- **截屏保护**: 全局启用，使截屏工具获取黑色图像
- **特点**: 
  - 实时监控所有进程行为
  - 应用程序控制（白名单/黑名单）
  - 终端命令行支持
  - 资源占用低
- **局限**: 全局保护，无法按窗口/应用单独配置

### 4.3 ScreenWings（免费工具）
- **实现方式**: 检测截屏行为时黑屏
- **特点**: 轻量级、易于安装
- **局限**: 功能单一，无规则引擎

### 4.4 Windows 信息保护（WIP）/ Azure Virtual Desktop
- **类型**: 企业级方案
- **实现**: 组策略 + 远程桌面服务
- **特点**: 集中管理、策略下发
- **局限**: 过于重量级，不适合单机工具场景

### 4.5 VeraCrypt（加密软件）
- **近期更新**: 添加反截屏功能
- **实现**: 使用 `SetWindowDisplayAffinity` + `WDA_EXCLUDEFROMCAPTURE`
- **特点**: 仅保护自身窗口，安全性高

---

## 5. Windows API 技术细节

### 5.1 SetWindowDisplayAffinity 详解

```c
BOOL SetWindowDisplayAffinity(
  HWND hWnd,
  DWORD dwAffinity
);
```

**Affinity 值**:
| 值 | 常量 | 效果 |
|----|------|------|
| 0x00 | `WDA_NONE` | 无保护 |
| 0x01 | `WDA_MONITOR` | 截屏时显示黑色 |
| 0x11 | `WDA_EXCLUDEFROMCAPTURE` | 完全从截屏中移除（Win10 2004+） |

**限制**:
- 仅对顶级窗口有效
- 窗口必须属于调用进程
- 需要 Windows 7+（`WDA_EXCLUDEFROMCAPTURE` 需要 Win10 2004+）

### 5.2 本项目实现优势

| 特性 | NoScreenCap | Screen Guardian |
|------|-------------|-----------------|
| 注入方式 | DLL 注入 | Helper EXE（安全） |
| 架构支持 | x64 only | x64 + x86（通过 helper） |
| 规则引擎 | 无 | 正则匹配 + 优先级 |
| GUI | 无 | Tauri v2 完整界面 |
| 托盘常驻 | 无 | 内置支持 |
| 威胁检测 | 无 | 进程监控 + 截屏应用识别 |

---

## 6. 差异化方向

### 6.1 核心差异化
1. **窗口级精细控制**: 按进程名/窗口标题单独配置保护策略
2. **规则引擎**: 支持正则表达式、优先级排序、规则组管理
3. **安全模式**: Helper EXE 避免 DLL 注入风险
4. **完整 GUI**: 图形化管理 + 系统托盘常驻

### 6.2 目标用户画像
- **开发者**: 保护代码窗口、API 密钥、终端输出
- **远程办公**: 保护会议窗口、聊天记录、邮件内容
- **内容创作者**: 保护未发布内容、创作素材
- **隐私意识用户**: 保护敏感信息、个人数据

### 6.3 未来扩展方向
- **进程行为监控**: 实时检测截屏/录屏软件活动
- **窗口水印**: 在保护窗口上添加隐形/显性水印
- **云端策略同步**: 多设备策略同步（可选）
- **API 开放**: 提供 SDK 供第三方应用集成
