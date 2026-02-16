use std::{
    fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyChange {
    pub timestamp: DateTime<Utc>,
    pub hwnd: isize,
    pub pid: u32,
    pub title: String,
    pub executable_path: String,
    pub previous_protected: bool,
    pub current_protected: bool,
    pub actor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PolicySnapshot {
    changes: Vec<PolicyChange>,
}

#[derive(Debug, Clone)]
pub struct PolicyStore {
    path: PathBuf,
    snapshot: PolicySnapshot,
}

impl PolicyStore {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let snapshot = if path.exists() {
            serde_json::from_slice(&fs::read(&path)?)?
        } else {
            PolicySnapshot::default()
        };
        Ok(Self { path, snapshot })
    }

    pub fn record(&mut self, change: PolicyChange) {
        self.snapshot.changes.push(change);
    }

    pub fn history(&self) -> &[PolicyChange] {
        &self.snapshot.changes
    }

    pub fn save(&self) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.path, serde_json::to_vec_pretty(&self.snapshot)?)?;
        Ok(())
    }
}
