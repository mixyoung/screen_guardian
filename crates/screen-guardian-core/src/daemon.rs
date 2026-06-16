use std::collections::HashSet;

use crate::affinity::AffinityOrchestrator;
use crate::config::AppConfig;
use crate::policy::PolicyStore;
use crate::rules::RuleEngine;

pub struct DaemonStatus {
    pub running: bool,
    pub protected_count: usize,
    pub rule_count: usize,
    pub last_scan_secs_ago: u64,
}

pub struct Daemon {
    config: AppConfig,
    rule_engine: RuleEngine,
    orchestrator: AffinityOrchestrator,
    store: PolicyStore,
    protected_windows: HashSet<isize>,
    last_scan: Option<std::time::Instant>,
    running: bool,
}

impl Daemon {
    pub fn new(config: AppConfig) -> anyhow::Result<Self> {
        let rule_engine = RuleEngine::load(&config.rules_path)?;
        let orchestrator = AffinityOrchestrator::new(&config.helper_path);
        let store = PolicyStore::load(&config.policy_path)?;

        Ok(Self {
            config,
            rule_engine,
            orchestrator,
            store,
            protected_windows: HashSet::new(),
            last_scan: None,
            running: false,
        })
    }

    pub fn tick(&mut self) -> anyhow::Result<()> {
        let results = self
            .rule_engine
            .apply_to_windows(&self.orchestrator, &mut self.store)?;

        for r in &results {
            if r.protect {
                self.protected_windows.insert(r.hwnd);
            } else {
                self.protected_windows.remove(&r.hwnd);
            }
        }

        // Clean up closed windows
        let current_hwnds: HashSet<isize> = crate::windows::enumerate_windows()?
            .into_iter()
            .map(|w| w.hwnd)
            .collect();
        self.protected_windows
            .retain(|hwnd| current_hwnds.contains(hwnd));

        self.last_scan = Some(std::time::Instant::now());
        Ok(())
    }

    pub fn run(&mut self) -> anyhow::Result<()> {
        self.running = true;
        while self.running {
            if let Err(e) = self.tick() {
                eprintln!("[daemon] tick error: {e}");
            }
            std::thread::sleep(std::time::Duration::from_millis(self.config.poll_interval_ms));
        }
        Ok(())
    }

    pub fn stop(&mut self) {
        self.running = false;
    }

    pub fn status(&self) -> DaemonStatus {
        DaemonStatus {
            running: self.running,
            protected_count: self.protected_windows.len(),
            rule_count: self.rule_engine.rules().len(),
            last_scan_secs_ago: self
                .last_scan
                .map(|t| t.elapsed().as_secs())
                .unwrap_or(0),
        }
    }

    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    pub fn rule_engine(&self) -> &RuleEngine {
        &self.rule_engine
    }

    pub fn rule_engine_mut(&mut self) -> &mut RuleEngine {
        &mut self.rule_engine
    }

    pub fn store(&self) -> &PolicyStore {
        &self.store
    }
}
