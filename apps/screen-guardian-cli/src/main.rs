use std::path::PathBuf;

use anyhow::Context;
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use screen_guardian_core::{
    audit_protected_windows, enumerate_windows, AffinityOrchestrator, AffinityValue, PolicyChange,
    PolicyStore, SortBy, SortOrder, WindowInfo,
};
use tabled::{Table, Tabled};

#[derive(Parser, Debug)]
#[command(
    name = "screen-guardian",
    version,
    about = "Windows 截屏录屏行为审计与管控 CLI"
)]
struct Cli {
    #[arg(long, default_value = "./data/policy-history.json")]
    policy_file: PathBuf,

    #[arg(long, default_value = "./bin/screen-guardian-helper.exe")]
    helper_32: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    List {
        #[arg(long, value_enum, default_value = "index")]
        sort_by: SortByArg,
        #[arg(long, value_enum, default_value = "asc")]
        order: SortOrderArg,
    },
    Audit,
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
    Save,
    History,
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
    let mut store = PolicyStore::load(&cli.policy_file)?;
    let orchestrator = AffinityOrchestrator::new(cli.helper_32);

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
            store.save()?;
            println!("saved {}", cli.policy_file.display());
        }
        Command::History => {
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
    }

    Ok(())
}
