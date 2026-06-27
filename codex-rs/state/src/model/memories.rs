use chrono::DateTime;
use chrono::Utc;
use codex_protocol::ThreadId;
use std::path::PathBuf;

use super::ThreadMetadata;

/// User-facing inventory row for a stored stage-1 memory extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryEntry {
    pub thread_id: ThreadId,
    pub source_updated_at: DateTime<Utc>,
    pub raw_memory: String,
    pub rollout_summary: String,
    pub rollout_slug: Option<String>,
    pub generated_at: DateTime<Utc>,
    pub usage_count: i64,
    pub last_usage: Option<DateTime<Utc>>,
    pub selected_for_phase2: bool,
    pub selected_for_phase2_source_updated_at: Option<DateTime<Utc>>,
    pub rollout_path: Option<PathBuf>,
    pub cwd: Option<PathBuf>,
    pub git_branch: Option<String>,
    pub memory_mode: Option<String>,
}

/// Stored stage-1 memory extraction output for a single thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage1Output {
    pub thread_id: ThreadId,
    pub rollout_path: PathBuf,
    pub source_updated_at: DateTime<Utc>,
    pub raw_memory: String,
    pub rollout_summary: String,
    pub rollout_slug: Option<String>,
    pub cwd: PathBuf,
    pub git_branch: Option<String>,
    pub generated_at: DateTime<Utc>,
}

/// Result of trying to claim a stage-1 memory extraction job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage1JobClaimOutcome {
    /// The caller owns the job and should continue with extraction.
    Claimed { ownership_token: String },
    /// Existing output is already newer than or equal to the source rollout.
    SkippedUpToDate,
    /// Another worker currently owns a fresh lease for this job.
    SkippedRunning,
    /// The job is in backoff and should not be retried yet.
    SkippedRetryBackoff,
    /// The job has exhausted retries and should not be retried automatically.
    SkippedRetryExhausted,
}

/// Claimed stage-1 job with thread metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage1JobClaim {
    pub thread: ThreadMetadata,
    pub ownership_token: String,
}

#[derive(Debug, Clone, Copy)]
pub struct Stage1StartupClaimParams<'a> {
    pub scan_limit: usize,
    pub max_claimed: usize,
    pub max_age_days: i64,
    pub min_rollout_idle_hours: i64,
    pub allowed_sources: &'a [String],
    pub lease_seconds: i64,
}

/// Result of trying to claim a phase-2 consolidation job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase2JobClaimOutcome {
    /// The caller owns the global lock and may inspect the memory workspace.
    Claimed {
        ownership_token: String,
        /// Snapshot of `input_watermark` at claim time.
        input_watermark: i64,
    },
    /// The global job is in retry backoff.
    SkippedRetryUnavailable,
    /// The global job completed recently enough that consolidation is cooling down.
    SkippedCooldown,
    /// Another worker currently owns a fresh global consolidation lease.
    SkippedRunning,
}
