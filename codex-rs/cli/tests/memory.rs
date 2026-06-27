use std::path::Path;

use anyhow::Result;
use codex_state::StateRuntime;
use codex_state::memories_db_path;
use codex_state::state_db_path;
use predicates::prelude::*;
use sqlx::SqlitePool;
use tempfile::TempDir;

fn codex_command(codex_home: &Path) -> Result<assert_cmd::Command> {
    let mut cmd = assert_cmd::Command::new(codex_utils_cargo_bin::cargo_bin("codex")?);
    cmd.env("CODEX_HOME", codex_home);
    Ok(cmd)
}

async fn seed_memory_fixture(codex_home: &TempDir) -> Result<(String, String)> {
    let runtime =
        StateRuntime::init(codex_home.path().to_path_buf(), "test-provider".to_string()).await?;
    runtime.close().await;

    let state_pool = SqlitePool::connect(&format!(
        "sqlite://{}",
        state_db_path(codex_home.path()).display()
    ))
    .await?;
    let memories_pool = SqlitePool::connect(&format!(
        "sqlite://{}",
        memories_db_path(codex_home.path()).display()
    ))
    .await?;

    let alpha_thread = "00000000-0000-0000-0000-000000000101".to_string();
    let beta_thread = "00000000-0000-0000-0000-000000000202".to_string();

    insert_thread(
        &state_pool,
        &alpha_thread,
        codex_home.path(),
        "/repo/alpha",
        "main",
        "enabled",
    )
    .await?;
    insert_thread(
        &state_pool,
        &beta_thread,
        codex_home.path(),
        "/repo/beta",
        "stale",
        "polluted",
    )
    .await?;

    sqlx::query(
        r#"
INSERT INTO stage1_outputs (
    thread_id,
    source_updated_at,
    raw_memory,
    rollout_summary,
    rollout_slug,
    generated_at,
    usage_count,
    last_usage,
    selected_for_phase2,
    selected_for_phase2_source_updated_at
) VALUES
    (?, 200, 'alpha raw memory with durable project context', 'alpha summary line', 'alpha-scope', 210, 3, 220, 1, 200),
    (?, 100, 'beta raw memory with stale context', 'beta summary line', 'beta-scope', 110, NULL, NULL, 0, NULL)
        "#,
    )
    .bind(alpha_thread.as_str())
    .bind(beta_thread.as_str())
    .execute(&memories_pool)
    .await?;

    state_pool.close().await;
    memories_pool.close().await;
    Ok((alpha_thread, beta_thread))
}

async fn insert_thread(
    pool: &SqlitePool,
    thread_id: &str,
    codex_home: &Path,
    cwd: &str,
    git_branch: &str,
    memory_mode: &str,
) -> Result<()> {
    sqlx::query(
        r#"
INSERT INTO threads (
    id,
    rollout_path,
    created_at,
    updated_at,
    source,
    agent_nickname,
    agent_role,
    model_provider,
    cwd,
    cli_version,
    title,
    sandbox_policy,
    approval_mode,
    tokens_used,
    first_user_message,
    archived,
    archived_at,
    git_sha,
    git_branch,
    git_origin_url,
    memory_mode
) VALUES (?, ?, 1, 1, 'cli', NULL, NULL, 'test-provider', ?, '', '', 'read-only', 'on-request', 0, '', 0, NULL, NULL, ?, NULL, ?)
        "#,
    )
    .bind(thread_id)
    .bind(
        codex_home
            .join(format!("{thread_id}.jsonl"))
            .display()
            .to_string(),
    )
    .bind(cwd)
    .bind(git_branch)
    .bind(memory_mode)
    .execute(pool)
    .await?;
    Ok(())
}

#[tokio::test]
async fn memory_list_prints_inventory_rows() -> Result<()> {
    let codex_home = TempDir::new()?;
    let (alpha_thread, beta_thread) = seed_memory_fixture(&codex_home).await?;

    let mut cmd = codex_command(codex_home.path())?;
    cmd.args(["memory", "list", "--limit", "1"])
        .assert()
        .success()
        .stdout(predicate::str::contains(&alpha_thread))
        .stdout(predicate::str::contains("alpha summary line"))
        .stdout(predicate::str::contains(&beta_thread).not());

    Ok(())
}

#[tokio::test]
async fn memory_search_and_show_include_memory_details() -> Result<()> {
    let codex_home = TempDir::new()?;
    let (alpha_thread, _beta_thread) = seed_memory_fixture(&codex_home).await?;

    let mut search = codex_command(codex_home.path())?;
    search
        .args(["memory", "search", "durable", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"thread_id\""))
        .stdout(predicate::str::contains("alpha raw memory"));

    let mut scoped_search = codex_command(codex_home.path())?;
    scoped_search
        .args(["memory", "search", "/repo/alpha"])
        .assert()
        .success()
        .stdout(predicate::str::contains(&alpha_thread))
        .stdout(predicate::str::contains("alpha summary line"));

    let mut show = codex_command(codex_home.path())?;
    show.args(["memory", "show", alpha_thread.as_str()])
        .assert()
        .success()
        .stdout(predicate::str::contains("cwd:"))
        .stdout(predicate::str::contains("alpha"))
        .stdout(predicate::str::contains("selected_for_phase2: true"))
        .stdout(predicate::str::contains(
            "alpha raw memory with durable project context",
        ));

    Ok(())
}
