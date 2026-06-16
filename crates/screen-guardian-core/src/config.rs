use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub poll_interval_ms: u64,
    pub auto_start_monitoring: bool,
    pub boot_auto_start: bool,
    pub close_to_tray: bool,
    pub rules_path: PathBuf,
    pub policy_path: PathBuf,
    pub helper_path: PathBuf,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 3000,
            auto_start_monitoring: false,
            boot_auto_start: false,
            close_to_tray: true,
            rules_path: PathBuf::from("./data/rules.json"),
            policy_path: PathBuf::from("./data/policy-history.json"),
            helper_path: PathBuf::from("./target/debug/screen-guardian-helper.exe"),
        }
    }
}

impl AppConfig {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if path.exists() {
            let content = std::fs::read(path)?;
            Ok(serde_json::from_slice(&content)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }
}
