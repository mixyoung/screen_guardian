use std::path::PathBuf;

use anyhow::Context;
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use screen_guardian_core::{
    audit_protected_windows, enumerate_windows, AffinityOrchestrator, AffinityValue, AppConfig,
    Daemon, PolicyChange, PolicyStore, Rule, RuleEngine, SortBy, SortOrder, WindowInfo,
};
use tabled::{Table, Tabled};

#[derive(Parser, Debug)]
#[command(
    name = "screen-guardian",
    version,
    about = "Windows 截屏录屏行为审计与管控 CLI"
)]
struct Cli {
    #[arg(long, default_value = "./data/config.json")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// 列出所有可见窗口
    List {
        #[arg(long, value_enum, default_value = "index")]
        sort_by: SortByArg,
        #[arg(long, value_enum, default_value = "asc")]
        order: SortOrderArg,
    },
    /// 审计已启用防截屏的窗口
    Audit,
    /// 手动设置窗口保护状态
    Set {
        #[arg(long)]
        hwnd: isize,
        #[arg(long)]
        pid: u32,
        #[arg(long)]
        protect: bool,
        #[arg(long, default_value = "cli")]
        actor: String,
    },
    /// 保存策略历史
    Save,
    /// 查看策略变更历史
    History,
    /// 规则管理
    #[command(subcommand)]
    Rule(RuleCommand),
    /// 监控管理
    #[command(subcommand)]
    Monitor(MonitorCommand),
}

#[derive(Subcommand, Debug)]
enum RuleCommand {
    /// 列出所有规则
    List,
    /// 添加规则
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        pattern: String,
        #[arg(long)]
        protect: bool,
        #[arg(long, default_value = "100")]
        priority: u32,
    },
    /// 删除规则
    Remove {
        #[arg(long)]
        id: String,
    },
    /// 启用规则
    Enable {
        #[arg(long)]
        id: String,
    },
    /// 禁用规则
    Disable {
        #[arg(long)]
        id: String,
    },
}

#[derive(Subcommand, Debug)]
enum MonitorCommand {
    /// 启动监控守护
    Start,
    /// 查看监控状态
    Status,
    /// 执行一次扫描
    Tick,
}

#[derive(Debug, Clone, ValueEnum)]
enum SortByArg {
    Index,
    AppName,
    Pid,
    Hwnd,
    Title,
    ExecutablePath,
    Protected,
}

#[derive(Debug, Clone, ValueEnum)]
enum SortOrderArg {
    Asc,
    Desc,
}

impl From<SortByArg> for SortBy {
    fn from(value: SortByArg) -> Self {
        match value {
            SortByArg::Index => SortBy::Index,
            SortByArg::AppName => SortBy::AppName,
            SortByArg::Pid => SortBy::Pid,
            SortByArg::Hwnd => SortBy::Hwnd,
            SortByArg::Title => SortBy::Title,
            SortByArg::ExecutablePath => SortBy::ExecutablePath,
            SortByArg::Protected => SortBy::Protected,
        }
    }
}

impl From<SortOrderArg> for SortOrder {
    fn from(value: SortOrderArg) -> Self {
        match value {
            SortOrderArg::Asc => SortOrder::Asc,
            SortOrderArg::Desc => SortOrder::Desc,
        }
    }
}

#[derive(Tabled)]
struct WindowRow {
    index: usize,
    app_name: String,
    pid: u32,
    hwnd: isize,
    title: String,
    executable_path: String,
    protected: bool,
}

#[derive(Tabled)]
struct RuleRow {
    id: String,
    name: String,
    pattern: String,
    protect: bool,
    enabled: bool,
    priority: u32,
}

fn to_table(windows: Vec<WindowInfo>) {
    let rows = windows
        .into_iter()
        .map(|w| WindowRow {
            index: w.index,
            app_name: w.app_name,
            pid: w.pid,
            hwnd: w.hwnd,
            title: w.title,
            executable_path: w.executable_path,
            protected: w.is_protected,
        })
        .collect::<Vec<_>>();
    println!("{}", Table::new(rows));
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = AppConfig::load(&cli.config)?;

    match cli.command {
        Command::List { sort_by, order } => {
            let mut windows = enumerate_windows()?;
            WindowInfo::sort(&mut windows, &sort_by.into(), &order.into());
            to_table(windows);
        }
        Command::Audit => {
            let windows = audit_protected_windows()?;
            to_table(windows);
        }
        Command::Set {
            hwnd,
            pid,
            protect,
            actor,
        } => {
            let orchestrator = AffinityOrchestrator::new(&config.helper_path);
            let mut store = PolicyStore::load(&config.policy_path)?;
            let windows = enumerate_windows()?;
            let current = windows
                .iter()
                .find(|w| w.hwnd == hwnd)
                .with_context(|| format!("hwnd {hwnd} not found"))?;

            orchestrator.apply(hwnd, pid, AffinityValue::from_bool(protect))?;

            store.record(PolicyChange {
                timestamp: Utc::now(),
                hwnd,
                pid,
                title: current.title.clone(),
                executable_path: current.executable_path.clone(),
                previous_protected: current.is_protected,
                current_protected: protect,
                actor,
            });
            store.save()?;
            println!("updated hwnd={hwnd} pid={pid} protect={protect}");
        }
        Command::Save => {
            let store = PolicyStore::load(&config.policy_path)?;
            store.save()?;
            println!("saved {}", config.policy_path.display());
        }
        Command::History => {
            let store = PolicyStore::load(&config.policy_path)?;
            for item in store.history() {
                println!(
                    "{} hwnd={} pid={} {} -> {} actor={} title={} path={}",
                    item.timestamp,
                    item.hwnd,
                    item.pid,
                    item.previous_protected,
                    item.current_protected,
                    item.actor,
                    item.title,
                    item.executable_path
                );
            }
        }
        Command::Rule(rule_cmd) => handle_rule(rule_cmd, &config)?,
        Command::Monitor(mon_cmd) => handle_monitor(mon_cmd, &config)?,
    }

    Ok(())
}

fn handle_rule(cmd: RuleCommand, config: &AppConfig) -> anyhow::Result<()> {
    let mut engine = RuleEngine::load(&config.rules_path)?;

    match cmd {
        RuleCommand::List => {
            let rows: Vec<RuleRow> = engine
                .rules()
                .iter()
                .map(|r| RuleRow {
                    id: r.id.clone(),
                    name: r.name.clone(),
                    pattern: r.process_pattern.clone(),
                    protect: r.protect,
                    enabled: r.enabled,
                    priority: r.priority,
                })
                .collect();
            if rows.is_empty() {
                println!("No rules configured.");
            } else {
                println!("{}", Table::new(rows));
            }
        }
        RuleCommand::Add {
            name,
            pattern,
            protect,
            priority,
        } => {
            let id = uuid();
            engine.add(Rule {
                id: id.clone(),
                group_id: "default".to_string(),
                name,
                process_pattern: pattern,
                protect,
                enabled: true,
                priority,
            })?;
            engine.save()?;
            println!("Rule added: {id}");
        }
        RuleCommand::Remove { id } => {
            if engine.remove(&id) {
                engine.save()?;
                println!("Rule removed: {id}");
            } else {
                println!("Rule not found: {id}");
            }
        }
        RuleCommand::Enable { id } => {
            if engine.enable(&id, true) {
                engine.save()?;
                println!("Rule enabled: {id}");
            } else {
                println!("Rule not found: {id}");
            }
        }
        RuleCommand::Disable { id } => {
            if engine.enable(&id, false) {
                engine.save()?;
                println!("Rule disabled: {id}");
            } else {
                println!("Rule not found: {id}");
            }
        }
    }

    Ok(())
}

fn handle_monitor(cmd: MonitorCommand, config: &AppConfig) -> anyhow::Result<()> {
    let mut daemon = Daemon::new(config.clone())?;

    match cmd {
        MonitorCommand::Start => {
            println!(
                "Starting monitor (interval: {}ms)...",
                config.poll_interval_ms
            );
            daemon.run()?;
        }
        MonitorCommand::Status => {
            let status = daemon.status();
            println!("Running: {}", status.running);
            println!("Protected windows: {}", status.protected_count);
            println!("Rules: {}", status.rule_count);
            println!("Last scan: {}s ago", status.last_scan_secs_ago);
        }
        MonitorCommand::Tick => {
            daemon.tick()?;
            let status = daemon.status();
            println!("Scan complete. Protected windows: {}", status.protected_count);
        }
    }

    Ok(())
}

fn uuid() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", t)
}
