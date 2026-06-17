use pretty_assertions::assert_eq;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use uuid::Uuid;

use super::*;

#[tokio::test]
async fn sqlite_sink_default_filter_drops_low_value_logs() {
    let codex_home =
        std::env::temp_dir().join(format!("codex-state-log-db-filter-{}", Uuid::new_v4()));
    let runtime = StateRuntime::init(codex_home.clone(), "test-provider".to_string())
        .await
        .expect("initialize runtime");
    let layer = start(runtime.clone());

    let guard = tracing_subscriber::registry()
        .with(layer.clone().with_filter(default_filter()))
        .set_default();

    tracing::trace!(target: "opentelemetry_sdk", "dropped-trace");
    tracing::debug!(target: "opentelemetry_sdk", "dropped-debug");
    tracing::info!(target: "opentelemetry_sdk", "dropped-info");
    tracing::warn!(target: "opentelemetry_sdk", "retained-warn");
    tracing::trace!(target: "codex_state", "dropped-trace");
    tracing::info!(target: "codex_state", "retained-info");
    tracing::info!(target: "codex_otel.log_only", "dropped-otel-mirror-info");
    tracing::warn!(target: "codex_otel.log_only", "retained-otel-mirror-warn");

    layer.flush().await;
    drop(guard);

    let logs = runtime
        .query_logs(&crate::LogQuery::default())
        .await
        .expect("query logs after flush");
    let mut retained = logs
        .iter()
        .map(|row| {
            (
                row.level.as_str(),
                row.target.as_str(),
                row.message.as_deref(),
            )
        })
        .collect::<Vec<_>>();
    retained.sort();
    assert_eq!(
        retained,
        vec![
            ("INFO", "codex_state", Some("retained-info")),
            (
                "WARN",
                "codex_otel.log_only",
                Some("retained-otel-mirror-warn")
            ),
            ("WARN", "opentelemetry_sdk", Some("retained-warn")),
        ]
    );

    let _ = tokio::fs::remove_dir_all(codex_home).await;
}
