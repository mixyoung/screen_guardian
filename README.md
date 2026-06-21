# Screen Guardian

Windows 截屏录屏行为审计与管控系统

## 功能特性

- 🛡️ 窗口截屏保护（SetWindowDisplayAffinity）
- 📋 规则引擎（正则表达式匹配）
- 🖥️ GUI 管理界面（Tauri v2）
- ⌨️ CLI 命令行工具
- 🔔 系统托盘常驻
- 📊 审计日志
- 🔐 许可证管理

## 快速开始

### 下载

从本仓库下载最新版本。

### 使用方法

1. 下载并解压本仓库
2. 运行 `bin/screen-guardian-gui.exe` 启动图形界面
3. 或运行 `bin/screen-guardian-cli.exe` 使用命令行工具

### 目录结构

```
screen_guardian/
├── bin/                           # 编译后的可执行文件
│   ├── screen-guardian-gui.exe    # GUI 应用程序
│   ├── screen-guardian-cli.exe    # CLI 命令行工具
│   ├── screen-guardian-helper.exe # 32 位辅助进程
│   ├── screen_guardian_hook.dll   # Hook DLL
│   └── screen_guardian_inject_dll.dll # 注入 DLL
├── screen-guardian-gui/           # GUI 前端资源
│   ├── ui/                        # HTML/JS/CSS 文件
│   └── icons/                     # 应用图标
├── data/                          # 数据文件
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