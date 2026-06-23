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

    tracing::trace!(target: "codex_api::endpoint::responses_websocket", "dropped-websocket-trace");
    tracing::debug!(target: "codex_core::stream_events_utils", "dropped-core-debug");
    tracing::info!(target: "codex_core::stream_events_utils", "retained-core-info");
    tracing::info!(target: "codex_otel.log_only", "dropped-mirror-info");
    tracing::info!(target: "codex_otel.trace_safe", "dropped-trace-safe-info");
    tracing::trace!(target: "log", "dropped-log-trace");
    tracing::info!(target: "hyper_util::client::legacy::pool", "dropped-hyper-info");
    tracing::info!(target: "opentelemetry_sdk", "dropped-otel-info");
    tracing::warn!(target: "external_dependency", "retained-global-warn");

    layer.flush().await;
    drop(guard);

    let logs = runtime
        .query_logs(&crate::LogQuery::default())
        .await
        .expect("query logs after flush");
    assert_eq!(
        logs.iter()
            .map(|row| (
                row.level.as_str(),
                row.target.as_str(),
                row.message.as_deref()
            ))
            .collect::<Vec<_>>(),
        vec![
            (
                "INFO",
                "codex_core::stream_events_utils",
                Some("retained-core-info")
            ),
            ("WARN", "external_dependency", Some("retained-global-warn")),
        ]
    );

    let _ = tokio::fs::remove_dir_all(codex_home).await;
}
