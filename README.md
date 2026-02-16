# Screen Guardian (Rust)

Windows 截屏录屏行为审计与管控系统（Rust 实现），参考 NoScreenCap 的核心思路并做了工程化拆分：

- `screen-guardian-core`：窗口枚举、状态识别、策略记录、跨架构编排。
- `screen-guardian-cli`：命令行管理工具（列表、审计、设置、保存、历史）。
- `screen-guardian-helper`：32 位极简辅助进程，接收 `HWND` + `affinity` 参数并调用 `SetWindowDisplayAffinity`。

## Why helper EXE instead of injection

本实现采用 “x64 主程序 + x86 helper EXE” 模式：

1. 避免 DLL 注入/APC/远程线程等高风险机制。
2. 提升稳定性和可维护性。
3. 通过命令行参数传递 `HWND` 与 affinity，helper 完成调用后立即退出。

## CLI 示例

```bash
# 列出全部可见窗口
screen-guardian list --sort-by title --order asc

# 审计全部已启用防截屏窗口
screen-guardian audit

# 切换某窗口状态
screen-guardian set --hwnd 123456 --pid 1000 --protect true

# 查看策略历史
screen-guardian history
```

## Build

```bash
cargo build -p screen-guardian-cli

# 在 Windows 上构建 32-bit helper
cargo build -p screen-guardian-helper --target i686-pc-windows-msvc
```

