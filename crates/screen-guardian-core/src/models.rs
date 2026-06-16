use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SortBy {
    Index,
    AppName,
    Pid,
    Hwnd,
    Title,
    ExecutablePath,
    Protected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SortOrder {
    Asc,
    Desc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowInfo {
    pub index: usize,
    pub app_name: String,
    pub pid: u32,
    pub hwnd: isize,
    pub title: String,
    pub executable_path: String,
    pub is_protected: bool,
    #[serde(default)]
    pub window_type: String,
}

impl WindowInfo {
    pub fn sort(items: &mut [Self], by: &SortBy, order: &SortOrder) {
        items.sort_by(|a, b| {
            let ord = match by {
                SortBy::Index => a.index.cmp(&b.index),
                SortBy::AppName => a.app_name.cmp(&b.app_name),
                SortBy::Pid => a.pid.cmp(&b.pid),
                SortBy::Hwnd => a.hwnd.cmp(&b.hwnd),
                SortBy::Title => a.title.cmp(&b.title),
                SortBy::ExecutablePath => a.executable_path.cmp(&b.executable_path),
                SortBy::Protected => a.is_protected.cmp(&b.is_protected),
            };
            match order {
                SortOrder::Asc => ord,
                SortOrder::Desc => ord.reverse(),
            }
        });
    }
}
