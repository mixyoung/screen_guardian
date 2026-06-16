use std::path::{Path, PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::affinity::{AffinityOrchestrator, AffinityValue};
use crate::policy::{PolicyChange, PolicyStore};
use crate::windows::enumerate_windows;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleGroup {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    #[serde(default = "default_group_id")]
    pub group_id: String,
    pub name: String,
    pub process_pattern: String,
    pub protect: bool,
    pub enabled: bool,
    pub priority: u32,
}

fn default_group_id() -> String {
    "default".to_string()
}

struct CompiledRule {
    rule: Rule,
    regex: Regex,
}

pub struct ApplyResult {
    pub hwnd: isize,
    pub pid: u32,
    pub title: String,
    pub rule_id: String,
    pub protect: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RulesData {
    groups: Vec<RuleGroup>,
    rules: Vec<Rule>,
}

pub struct RuleEngine {
    path: PathBuf,
    groups: Vec<RuleGroup>,
    rules: Vec<Rule>,
    compiled: Vec<CompiledRule>,
}

impl RuleEngine {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let (groups, rules) = if path.exists() {
            let content = std::fs::read(&path)?;
            // Try new format first, fall back to old format (rules-only array)
            if let Ok(data) = serde_json::from_slice::<RulesData>(&content) {
                (data.groups, data.rules)
            } else if let Ok(rules) = serde_json::from_slice::<Vec<Rule>>(&content) {
                // Old format: just a rules array, create default group
                let default_group = RuleGroup {
                    id: "default".to_string(),
                    name: "默认规则".to_string(),
                    description: "系统默认规则组".to_string(),
                    enabled: true,
                };
                (vec![default_group], rules)
            } else {
                (Vec::new(), Vec::new())
            }
        } else {
            (Vec::new(), Vec::new())
        };
        let compiled = compile_rules(&rules)?;
        Ok(Self {
            path,
            groups,
            rules,
            compiled,
        })
    }

    pub fn save(&self) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = RulesData {
            groups: self.groups.clone(),
            rules: self.rules.clone(),
        };
        std::fs::write(&self.path, serde_json::to_vec_pretty(&data)?)?;
        Ok(())
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn groups(&self) -> &[RuleGroup] {
        &self.groups
    }

    pub fn add_group(&mut self, group: RuleGroup) -> anyhow::Result<()> {
        if self.groups.iter().any(|g| g.id == group.id) {
            anyhow::bail!("Group with id '{}' already exists", group.id);
        }
        self.groups.push(group);
        Ok(())
    }

    pub fn remove_group(&mut self, id: &str) -> bool {
        let before = self.groups.len();
        self.groups.retain(|g| g.id != id);
        // Also remove all rules in this group
        self.rules.retain(|r| r.group_id != id);
        self.compiled.retain(|c| c.rule.group_id != id);
        self.groups.len() < before
    }

    pub fn toggle_group(&mut self, id: &str, enabled: bool) -> bool {
        let mut found = false;
        for g in &mut self.groups {
            if g.id == id {
                g.enabled = enabled;
                found = true;
            }
        }
        // Also toggle all rules in this group
        for r in &mut self.rules {
            if r.group_id == id {
                r.enabled = enabled;
            }
        }
        for c in &mut self.compiled {
            if c.rule.group_id == id {
                c.rule.enabled = enabled;
            }
        }
        found
    }

    pub fn rules_by_group(&self, group_id: &str) -> Vec<&Rule> {
        self.rules.iter().filter(|r| r.group_id == group_id).collect()
    }

    pub fn add(&mut self, rule: Rule) -> anyhow::Result<()> {
        let regex = Regex::new(&rule.process_pattern)?;
        self.compiled.push(CompiledRule {
            rule: rule.clone(),
            regex,
        });
        self.rules.push(rule);
        self.sort_compiled();
        Ok(())
    }

    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != id);
        self.compiled.retain(|c| c.rule.id != id);
        self.rules.len() < before
    }

    pub fn enable(&mut self, id: &str, enabled: bool) -> bool {
        let mut found = false;
        for r in &mut self.rules {
            if r.id == id {
                r.enabled = enabled;
                found = true;
            }
        }
        for c in &mut self.compiled {
            if c.rule.id == id {
                c.rule.enabled = enabled;
                found = true;
            }
        }
        found
    }

    pub fn match_window(&self, process_name: &str) -> Option<&Rule> {
        self.compiled
            .iter()
            .filter(|c| c.rule.enabled)
            .find(|c| c.regex.is_match(process_name))
            .map(|c| &c.rule)
    }

    pub fn apply_to_windows(
        &self,
        orchestrator: &mut AffinityOrchestrator,
        store: &mut PolicyStore,
    ) -> anyhow::Result<Vec<ApplyResult>> {
        let windows = enumerate_windows()?;
        let mut results = Vec::new();

        for win in windows {
            if let Some(rule) = self.match_window(&win.app_name) {
                let affinity = AffinityValue::from_bool(rule.protect);
                if win.is_protected != rule.protect {
                    match orchestrator.apply(win.hwnd, win.pid, affinity) {
                        Ok(_result) => {
                            store.record(PolicyChange {
                                timestamp: chrono::Utc::now(),
                                hwnd: win.hwnd,
                                pid: win.pid,
                                title: win.title.clone(),
                                executable_path: win.executable_path.clone(),
                                previous_protected: win.is_protected,
                                current_protected: rule.protect,
                                actor: format!("rule:{}", rule.id),
                            });

                            results.push(ApplyResult {
                                hwnd: win.hwnd,
                                pid: win.pid,
                                title: win.title,
                                rule_id: rule.id.clone(),
                                protect: rule.protect,
                            });
                        }
                        Err(e) => {
                            // Log error but continue with other windows
                            eprintln!("[rules] failed to apply rule '{}' to window {}: {}", rule.id, win.hwnd, e);
                        }
                    }
                }
            }
        }

        store.save()?;
        Ok(results)
    }

    fn sort_compiled(&mut self) {
        self.compiled.sort_by_key(|c| c.rule.priority);
    }
}

fn compile_rules(rules: &[Rule]) -> anyhow::Result<Vec<CompiledRule>> {
    let mut compiled = Vec::new();
    for rule in rules {
        let regex = Regex::new(&rule.process_pattern)?;
        compiled.push(CompiledRule {
            rule: rule.clone(),
            regex,
        });
    }
    compiled.sort_by_key(|c| c.rule.priority);
    Ok(compiled)
}
