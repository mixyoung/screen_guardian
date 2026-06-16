/// Known screenshot/recording software database
/// Used by ProcessMonitor to detect potential screen capture threats

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ThreatLevel {
    /// System built-in screenshot tool (Snipping Tool, Win+Shift+S)
    High,
    /// Third-party screenshot/recording tool (ShareX, OBS, etc.)
    High2,
    /// Remote desktop / meeting software with screen sharing
    Medium,
    /// Browser with potential screenshot extensions
    Low,
}

impl ThreatLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "high",
            Self::High2 => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::High => "系统截图工具",
            Self::High2 => "第三方截录屏",
            Self::Medium => "远程/会议共享",
            Self::Low => "浏览器",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScreenshotApp {
    pub display_name: &'static str,
    pub process_names: &'static [&'static str],
    pub threat_level: ThreatLevel,
    pub description: &'static str,
}

/// Built-in database of known screenshot/recording software
pub fn known_screenshot_apps() -> Vec<ScreenshotApp> {
    vec![
        // --- System built-in ---
        ScreenshotApp {
            display_name: "截图工具 (Snipping Tool)",
            process_names: &["SnippingTool.exe", "ScreenSketch.exe"],
            threat_level: ThreatLevel::High,
            description: "Windows 内置截图工具，支持 Win+Shift+S 快捷截图",
        },
        ScreenshotApp {
            display_name: "步骤记录器 (Steps Recorder)",
            process_names: &["psr.exe"],
            threat_level: ThreatLevel::High,
            description: "Windows 步骤记录器，自动截取每一步操作",
        },
        ScreenshotApp {
            display_name: "Xbox Game Bar",
            process_names: &["GameBar.exe", "GameBarFTServer.exe"],
            threat_level: ThreatLevel::High,
            description: "Win+G 游戏栏，支持截图和录屏",
        },
        ScreenshotApp {
            display_name: "Windows Media Player 录制",
            process_names: &["wmprph.exe"],
            threat_level: ThreatLevel::High,
            description: "Windows 媒体录制",
        },

        // --- Third-party screenshot tools ---
        ScreenshotApp {
            display_name: "ShareX",
            process_names: &["ShareX.exe"],
            threat_level: ThreatLevel::High2,
            description: "开源截图/录屏工具，支持自动上传",
        },
        ScreenshotApp {
            display_name: "Greenshot",
            process_names: &["Greenshot.exe"],
            threat_level: ThreatLevel::High2,
            description: "轻量级截图工具",
        },
        ScreenshotApp {
            display_name: "Lightshot",
            process_names: &["lightshot.exe", "prntscr.exe"],
            threat_level: ThreatLevel::High2,
            description: "快速截图工具",
        },
        ScreenshotApp {
            display_name: "FastStone Capture",
            process_names: &["FSCapture.exe"],
            threat_level: ThreatLevel::High2,
            description: "老牌截图工具",
        },
        ScreenshotApp {
            display_name: "Snipaste",
            process_names: &["Snipaste.exe"],
            threat_level: ThreatLevel::High2,
            description: "截图贴图工具",
        },
        ScreenshotApp {
            display_name: "PicPick",
            process_names: &["picpick.exe"],
            threat_level: ThreatLevel::High2,
            description: "截图+图片编辑工具",
        },
        ScreenshotApp {
            display_name: "Flameshot",
            process_names: &["flameshot.exe"],
            threat_level: ThreatLevel::High2,
            description: "开源跨平台截图工具",
        },

        // --- Recording tools ---
        ScreenshotApp {
            display_name: "OBS Studio",
            process_names: &["obs64.exe", "obs32.exe"],
            threat_level: ThreatLevel::High2,
            description: "开源录屏/直播软件",
        },
        ScreenshotApp {
            display_name: "Bandicam",
            process_names: &["bdcam.exe", "BDCam.exe"],
            threat_level: ThreatLevel::High2,
            description: "专业录屏软件",
        },
        ScreenshotApp {
            display_name: "Camtasia",
            process_names: &["CamtasiaStudio.exe", "CamRecorder.exe"],
            threat_level: ThreatLevel::High2,
            description: "专业录屏+视频编辑",
        },
        ScreenshotApp {
            display_name: "CamStudio",
            process_names: &["CamStudio.exe", "CamStudio_Recorder.exe"],
            threat_level: ThreatLevel::High2,
            description: "开源录屏软件",
        },
        ScreenshotApp {
            display_name: "FRAPS",
            process_names: &["fraps.exe", "FRAPS.exe"],
            threat_level: ThreatLevel::High2,
            description: "游戏截图/录屏",
        },
        ScreenshotApp {
            display_name: "Action!",
            process_names: &["Action.exe"],
            threat_level: ThreatLevel::High2,
            description: "游戏录屏软件",
        },
        ScreenshotApp {
            display_name: "oCam",
            process_names: &["oCam.exe"],
            threat_level: ThreatLevel::High2,
            description: "屏幕录制软件",
        },
        ScreenshotApp {
            display_name: "EV 录屏",
            process_names: &["EVCapture.exe"],
            threat_level: ThreatLevel::High2,
            description: "国产录屏软件",
        },
        ScreenshotApp {
            display_name: "嗨格式录屏",
            process_names: &["HgRecorder.exe"],
            threat_level: ThreatLevel::High2,
            description: "国产录屏软件",
        },

        // --- Remote desktop / Meeting software ---
        ScreenshotApp {
            display_name: "腾讯会议",
            process_names: &["wemeetapp.exe", "WeMeetApp.exe", "Meeting.exe"],
            threat_level: ThreatLevel::Medium,
            description: "支持屏幕共享的会议软件",
        },
        ScreenshotApp {
            display_name: "钉钉",
            process_names: &["DingTalk.exe", "dingtalk.exe"],
            threat_level: ThreatLevel::Medium,
            description: "支持屏幕共享的办公软件",
        },
        ScreenshotApp {
            display_name: "飞书",
            process_names: &["Lark.exe", "Feishu.exe"],
            threat_level: ThreatLevel::Medium,
            description: "支持屏幕共享的办公软件",
        },
        ScreenshotApp {
            display_name: "Zoom",
            process_names: &["Zoom.exe", "zoom.exe"],
            threat_level: ThreatLevel::Medium,
            description: "视频会议软件，支持屏幕共享",
        },
        ScreenshotApp {
            display_name: "Teams",
            process_names: &["Teams.exe", "ms-teams.exe"],
            threat_level: ThreatLevel::Medium,
            description: "Microsoft Teams，支持屏幕共享",
        },
        ScreenshotApp {
            display_name: "企业微信",
            process_names: &["WXWork.exe"],
            threat_level: ThreatLevel::Medium,
            description: "企业微信，支持屏幕共享",
        },
        ScreenshotApp {
            display_name: "TeamViewer",
            process_names: &["TeamViewer.exe", "TeamViewer_Service.exe"],
            threat_level: ThreatLevel::Medium,
            description: "远程桌面控制软件",
        },
        ScreenshotApp {
            display_name: "AnyDesk",
            process_names: &["AnyDesk.exe"],
            threat_level: ThreatLevel::Medium,
            description: "远程桌面软件",
        },
        ScreenshotApp {
            display_name: "向日葵远程",
            process_names: &["SunloginClient.exe", "sunloginclient.exe"],
            threat_level: ThreatLevel::Medium,
            description: "国产远程桌面软件",
        },
        ScreenshotApp {
            display_name: "ToDesk",
            process_names: &["ToDesk.exe"],
            threat_level: ThreatLevel::Medium,
            description: "远程桌面软件",
        },
        ScreenshotApp {
            display_name: "RustDesk",
            process_names: &["rustdesk.exe"],
            threat_level: ThreatLevel::Medium,
            description: "开源远程桌面软件",
        },

        // --- Communication with screen share ---
        ScreenshotApp {
            display_name: "Discord",
            process_names: &["Discord.exe", "discord.exe", "DiscordPTB.exe", "DiscordCanary.exe"],
            threat_level: ThreatLevel::Medium,
            description: "支持屏幕共享的通讯软件",
        },
        ScreenshotApp {
            display_name: "QQ",
            process_names: &["QQ.exe", "QQProtect.exe"],
            threat_level: ThreatLevel::Medium,
            description: "支持屏幕分享的即时通讯",
        },
        ScreenshotApp {
            display_name: "Skype",
            process_names: &["Skype.exe", "skype.exe"],
            threat_level: ThreatLevel::Medium,
            description: "支持屏幕共享的通讯软件",
        },
    ]
}
