use anyhow::Context;
use clap::Parser;
use codex_core::config::ConfigBuilder;
use codex_protocol::ThreadId;
use codex_state::MemoryEntry;
use codex_state::StateRuntime;
use codex_utils_cli::CliConfigOverrides;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Parser)]
pub struct MemoryCli {
    #[command(subcommand)]
    pub subcommand: MemorySubcommand,
}

#[derive(Debug, clap::Subcommand)]
pub enum MemorySubcommand {
    /// List stored memory entries.
    List(MemoryListCommand),

    /// Search stored memory entries.
    Search(MemorySearchCommand),

    /// Show one stored memory entry by source thread id.
    Show(MemoryShowCommand),
}

#[derive(Debug, Parser)]
pub struct MemoryListCommand {
    /// Maximum number of memory entries to print.
    #[arg(long, short = 'n', default_value_t = 20)]
    pub limit: usize,

    /// Emit JSON instead of a human-readable table.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct MemorySearchCommand {
    /// Case-insensitive search term.
    #[arg(value_name = "QUERY")]
    pub query: String,

    /// Maximum number of memory entries to print.
    #[arg(long, short = 'n', default_value_t = 20)]
    pub limit: usize,

    /// Emit JSON instead of a human-readable table.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct MemoryShowCommand {
    /// Source thread id for the memory entry.
    #[arg(value_name = "THREAD_ID")]
    pub thread_id: String,

    /// Emit JSON instead of human-readable detail.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Serialize)]
struct SerializableMemoryEntry<'a> {
    thread_id: String,
    source_updated_at: String,
    generated_at: String,
    raw_memory: &'a str,
    rollout_summary: &'a str,
    rollout_slug: Option<&'a str>,
    usage_count: i64,
    last_usage: Option<String>,
    selected_for_phase2: bool,
    selected_for_phase2_source_updated_at: Option<String>,
    rollout_path: Option<&'a Path>,
    cwd: Option<&'a Path>,
    git_branch: Option<&'a str>,
    memory_mode: Option<&'a str>,
}

pub async fn run(cli: MemoryCli, root_config_overrides: CliConfigOverrides) -> anyhow::Result<()> {
    let cli_kv_overrides = root_config_overrides
        .parse_overrides()
        .map_err(anyhow::Error::msg)?;
    let config = ConfigBuilder::default()
        .cli_overrides(cli_kv_overrides)
        .build()
        .await?;
    let runtime = StateRuntime::init(config.sqlite_home.clone(), "codex-cli".to_string()).await?;

    match cli.subcommand {
        MemorySubcommand::List(cmd) => {
            let entries = runtime.memories().list_memory_entries(cmd.limit).await?;
            print_entries(&entries, cmd.json)?;
        }
        MemorySubcommand::Search(cmd) => {
            let entries = runtime
                .memories()
                .search_memory_entries(&cmd.query, cmd.limit)
                .await?;
            print_entries(&entries, cmd.json)?;
        }
        MemorySubcommand::Show(cmd) => {
            let thread_id = ThreadId::try_from(cmd.thread_id.as_str())
                .with_context(|| format!("invalid thread id `{}`", cmd.thread_id))?;
            let Some(entry) = runtime.memories().get_memory_entry(thread_id).await? else {
                anyhow::bail!("No memory entry found for thread `{}`.", cmd.thread_id);
            };
            print_entry_detail(&entry, cmd.json)?;
        }
    }

    runtime.close().await;
    Ok(())
}

fn print_entries(entries: &[MemoryEntry], json: bool) -> anyhow::Result<()> {
    if json {
        serde_json::to_writer_pretty(
            std::io::stdout(),
            &entries.iter().map(serialize_entry).collect::<Vec<_>>(),
        )?;
        println!();
        return Ok(());
    }

    if entries.is_empty() {
        println!("No memory entries found.");
        return Ok(());
    }

    println!(
        "{:<36}  {:<20}  {:<9}  {:<5}  {:<24}  Summary",
        "Thread", "Updated", "Mode", "Uses", "CWD"
    );
    for entry in entries {
        println!(
            "{:<36}  {:<20}  {:<9}  {:<5}  {:<24}  {}",
            entry.thread_id,
            entry.source_updated_at.format("%Y-%m-%d %H:%M:%S"),
            entry.memory_mode.as_deref().unwrap_or("missing"),
            entry.usage_count,
            truncate(
                entry
                    .cwd
                    .as_deref()
                    .map(path_display)
                    .unwrap_or("-".to_string()),
                24
            ),
            truncate(first_non_empty_line(&entry.rollout_summary), 80)
        );
    }
    Ok(())
}

fn print_entry_detail(entry: &MemoryEntry, json: bool) -> anyhow::Result<()> {
    if json {
        serde_json::to_writer_pretty(std::io::stdout(), &serialize_entry(entry))?;
        println!();
        return Ok(());
    }

    println!("thread_id: {}", entry.thread_id);
    println!(
        "source_updated_at: {}",
        entry.source_updated_at.to_rfc3339()
    );
    println!("generated_at: {}", entry.generated_at.to_rfc3339());
    println!("usage_count: {}", entry.usage_count);
    println!(
        "last_usage: {}",
        entry
            .last_usage
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "-".to_string())
    );
    println!("selected_for_phase2: {}", entry.selected_for_phase2);
    println!(
        "selected_for_phase2_source_updated_at: {}",
        entry
            .selected_for_phase2_source_updated_at
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "-".to_string())
    );
    println!(
        "memory_mode: {}",
        entry.memory_mode.as_deref().unwrap_or("missing")
    );
    println!(
        "cwd: {}",
        entry
            .cwd
            .as_deref()
            .map(path_display)
            .unwrap_or("-".to_string())
    );
    println!(
        "rollout_path: {}",
        entry
            .rollout_path
            .as_deref()
            .map(path_display)
            .unwrap_or("-".to_string())
    );
    println!("git_branch: {}", entry.git_branch.as_deref().unwrap_or("-"));
    println!(
        "rollout_slug: {}",
        entry.rollout_slug.as_deref().unwrap_or("-")
    );
    println!();
    println!("rollout_summary:");
    println!("{}", entry.rollout_summary.trim());
    println!();
    println!("raw_memory:");
    println!("{}", entry.raw_memory.trim());
    Ok(())
}

fn serialize_entry(entry: &MemoryEntry) -> SerializableMemoryEntry<'_> {
    SerializableMemoryEntry {
        thread_id: entry.thread_id.to_string(),
        source_updated_at: entry.source_updated_at.to_rfc3339(),
        generated_at: entry.generated_at.to_rfc3339(),
        raw_memory: &entry.raw_memory,
        rollout_summary: &entry.rollout_summary,
        rollout_slug: entry.rollout_slug.as_deref(),
        usage_count: entry.usage_count,
        last_usage: entry.last_usage.map(|dt| dt.to_rfc3339()),
        selected_for_phase2: entry.selected_for_phase2,
        selected_for_phase2_source_updated_at: entry
            .selected_for_phase2_source_updated_at
            .map(|dt| dt.to_rfc3339()),
        rollout_path: entry.rollout_path.as_deref(),
        cwd: entry.cwd.as_deref(),
        git_branch: entry.git_branch.as_deref(),
        memory_mode: entry.memory_mode.as_deref(),
    }
}

fn first_non_empty_line(value: &str) -> String {
    value
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("")
        .to_string()
}

fn path_display(path: &Path) -> String {
    path.display().to_string()
}

fn truncate(value: String, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value;
    }
    let keep = max_chars.saturating_sub(3);
    format!("{}...", value.chars().take(keep).collect::<String>())
}
