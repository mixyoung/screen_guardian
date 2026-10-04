# Screen Guardian

Windows 截屏录屏行为审计与管控系统

## 功能特性

- 🛡️ 窗口截屏保护（SetWindowDisplayAffinity）
- 📋 规则引擎（正则表达式匹配）
- 🖥️ GUI 管理界面（Tauri v2）
- ⌨️ CLI 命令行工具（`sgcli`）
- 🔔 系统托盘常驻
- 📊 审计日志
- 🔐 许可证管理

## 快速开始

### 下载

从本仓库下载最新版本。

### 使用方法

1. 下载并解压本仓库，得到 `screen-guardian/` 目录
2. 双击 `screen-guardian.exe` 启动图形界面
3. 命令行：把 `bin/` 加入 PATH 后，在任意终端使用 `sgcli`

```powershell
# 以 PowerShell 为例，把 bin/ 加入当前用户的 PATH（只需一次）
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";" + "D:\解压路径\screen-guardian\bin", "User")
```

加好 PATH 后，三种终端（cmd / PowerShell / Git Bash）都可以直接使用：

```bash
sgcli --help            # 查看帮助
sgcli list              # 列出所有窗口
sgcli license status    # 查看许可证状态
sgcli rule list         # 管理规则
```

> 不加 PATH 也可以用：直接运行 `bin\screen-guardian-cli.exe`（建议在程序根目录下运行，保证读写同一份 `data/` 配置）。

### 目录结构

```
screen-guardian/
├── screen-guardian.exe            # 主程序，双击打开图形界面
├── bin/                           # 组件目录（加入 PATH 即可用 sgcli）
│   ├── sgcli.cmd                  # sgcli 命令入口（cmd / PowerShell）
│   ├── sgcli                      # sgcli 命令入口（Git Bash / WSL）
│   ├── screen-guardian-cli.exe    # 命令行工具本体
│   ├── screen-guardian-helper.exe # 32 位辅助进程
│   └── screen_guardian_hook.dll   # Hook DLL
├── data/                          # 配置与运行数据
│   └── config.json                # 配置文件（rules/license 等运行时自动生成）
├── screen-guardian-gui/           # GUI 前端资源与 Tauri 配置
├── LICENSE.md                     # 授权协议
└── README.md                      # 本文件
```

## 系统要求

- Windows 10 1809+ 或 Windows 11
- x64 架构
- 管理员权限（用于窗口保护）

## 许可证

本软件采用个人免费授权 - 详见 [LICENSE.md](LICENSE.md) 文件

**注意**: 本仓库仅包含编译后的文件，不包含源代码。

## 联系方式

- **开发者**: mixyoung
- **联系邮箱**: mixyoung@88.com
