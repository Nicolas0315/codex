use codex_utils_absolute_path::test_support::PathExt;
use pretty_assertions::assert_eq;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use uuid::Uuid;

use super::*;

#[tokio::test]
async fn sqlite_sink_drops_low_level_opentelemetry_sdk_logs() {
    let codex_home =
        std::env::temp_dir().join(format!("codex-state-log-db-filter-{}", Uuid::new_v4()));
    let runtime = StateRuntime::init(
        crate::SqliteConfig::new_for_testing(codex_home.as_path().abs()),
        "test-provider".to_string(),
    )
    .await
    .expect("initialize runtime");
    let layer = start(runtime.clone());

    let guard = tracing_subscriber::registry()
        .with(layer.clone().with_filter(filter_from_directives(None)))
        .set_default();

    tracing::trace!(target: "opentelemetry_sdk", "dropped-trace");
    tracing::debug!(target: "opentelemetry_sdk", "dropped-debug");
    tracing::info!(target: "opentelemetry_sdk", "retained-info");
    tracing::trace!(target: "codex_state", "retained-trace");
    tracing::trace!(
        target: "codex_api::responses_websocket_timing",
        payload = "complete timing payload",
        "dropped-websocket-timing"
    );

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
            ("INFO", "opentelemetry_sdk", Some("retained-info")),
            ("TRACE", "codex_state", Some("retained-trace")),
        ]
    );

    let _ = tokio::fs::remove_dir_all(codex_home).await;
}

/// The ceiling logic relies on `min` picking the more restrictive filter, which
/// only holds because `LevelFilter` orders by verbosity rather than by severity.
#[test]
fn level_filter_min_is_the_more_restrictive_level() {
    assert_eq!(LevelFilter::TRACE.min(LevelFilter::WARN), LevelFilter::WARN);
    assert_eq!(LevelFilter::WARN.min(LevelFilter::INFO), LevelFilter::WARN);
    assert_eq!(LevelFilter::TRACE.min(LevelFilter::OFF), LevelFilter::OFF);
    assert!(LevelFilter::OFF < LevelFilter::ERROR);
    assert!(LevelFilter::ERROR < LevelFilter::WARN);
    assert!(LevelFilter::INFO < LevelFilter::TRACE);
}

/// Pins the variable name, which is the part of `default_filter` a rename or typo
/// would silently break — every other test here calls `filter_from_directives`
/// with a literal.
///
/// The `env::var` read itself stays uncovered on purpose: exercising it means
/// `set_var` in a parallel test binary whose siblings call `env::temp_dir`, and
/// that is undefined behaviour rather than coverage.
#[test]
fn sqlite_log_env_variable_name_is_stable() {
    assert_eq!(SQLITE_LOG_ENV, "CODEX_SQLITE_LOG");
}

/// `Targets::from_str` accepts every one of these, so the unparseable-value
/// fallback never sees them — a stray comma or space would otherwise invert what
/// the user asked for.
#[test]
fn persisted_filter_normalizes_directive_elements() {
    for directives in ["trace", "trace,", " trace ", "trace, ,"] {
        let filter = filter_from_directives(Some(directives));

        assert!(
            filter.would_enable("codex_state", &tracing::Level::TRACE),
            "expected trace for {directives:?}"
        );
    }

    for directives in ["off", "off,", " off "] {
        let filter = filter_from_directives(Some(directives));

        assert!(
            !filter.would_enable("codex_state", &tracing::Level::ERROR),
            "expected silence for {directives:?}"
        );
    }

    // Whitespace around `=` fails the other way: `Targets` rejects the value, so
    // without normalization this silently falls back to the default.
    for directives in ["warn , codex_core=debug", "warn, codex_core = debug"] {
        let filter = filter_from_directives(Some(directives));

        assert!(
            filter.would_enable("codex_state", &tracing::Level::WARN),
            "expected warn default for {directives:?}"
        );
        assert!(
            !filter.would_enable("codex_state", &tracing::Level::INFO),
            "expected the default to be honored for {directives:?}"
        );
        assert!(
            filter.would_enable("codex_core", &tracing::Level::DEBUG),
            "expected the per-target override for {directives:?}"
        );
    }
}

/// The escape hatch documented in `docs/install.md`: a target longer than a
/// ceiling overrides it, while the ceiling still governs the shorter name.
#[test]
fn a_longer_target_lifts_its_ceiling() {
    let filter = filter_from_directives(Some("trace,hyper_util::client=debug"));

    assert!(filter.would_enable("hyper_util::client::legacy::pool", &tracing::Level::DEBUG));
    assert!(!filter.would_enable("hyper_util::client::legacy::pool", &tracing::Level::TRACE));
    assert!(!filter.would_enable("hyper_util", &tracing::Level::INFO));
}

/// At `off` every ceiling has to resolve to OFF. Reverting the fold to
/// unconditional overrides leaves `hyper_util` at WARN and `opentelemetry_sdk` at
/// INFO, so this is what pins the clamp direction for the non-OFF entries.
#[test]
fn ceilings_clamp_to_off_when_everything_is_disabled() {
    let filter = filter_from_directives(Some("off"));

    assert!(!filter.would_enable("hyper_util", &tracing::Level::ERROR));
    assert!(!filter.would_enable("opentelemetry_sdk", &tracing::Level::ERROR));
    assert!(!filter.would_enable("rmcp::service", &tracing::Level::ERROR));
    assert!(!filter.would_enable("codex_state", &tracing::Level::ERROR));
}

#[test]
fn persisted_filter_defaults_to_trace_without_configuration() {
    let filter = filter_from_directives(None);

    assert!(filter.would_enable("codex_state", &tracing::Level::TRACE));
    assert!(!filter.would_enable("log", &tracing::Level::ERROR));
}

#[test]
fn persisted_filter_honors_configured_level() {
    let filter = filter_from_directives(Some("warn"));

    assert!(filter.would_enable("codex_state", &tracing::Level::WARN));
    assert!(!filter.would_enable("codex_state", &tracing::Level::INFO));
    assert!(!filter.would_enable("codex_state", &tracing::Level::TRACE));
}

#[test]
fn persisted_filter_honors_per_target_directives() {
    let filter = filter_from_directives(Some("warn,codex_core=debug"));

    assert!(filter.would_enable("codex_core", &tracing::Level::DEBUG));
    assert!(!filter.would_enable("codex_state", &tracing::Level::DEBUG));
}

/// Ceilings must not raise a target above a stricter configured level: at `warn`
/// the `rmcp::service` INFO ceiling has to stay dropped.
#[test]
fn noisy_ceilings_never_raise_a_stricter_configuration() {
    let filter = filter_from_directives(Some("warn"));

    assert!(!filter.would_enable("rmcp::service", &tracing::Level::INFO));
    assert!(filter.would_enable("rmcp::service", &tracing::Level::WARN));
    assert!(!filter.would_enable("hyper_util", &tracing::Level::INFO));
}

#[test]
fn noisy_ceilings_still_apply_to_a_verbose_configuration() {
    let filter = filter_from_directives(Some("trace"));

    assert!(!filter.would_enable("hyper_util", &tracing::Level::INFO));
    assert!(filter.would_enable("hyper_util", &tracing::Level::WARN));
    assert!(!filter.would_enable("rmcp::service", &tracing::Level::DEBUG));
    assert!(filter.would_enable("rmcp::service", &tracing::Level::INFO));
    assert!(!filter.would_enable(
        "codex_api::responses_websocket_timing",
        &tracing::Level::ERROR
    ));
    assert!(filter.would_enable("codex_state", &tracing::Level::TRACE));
}

#[test]
fn persisted_filter_falls_back_when_configuration_is_unusable() {
    for directives in ["", "   ", ",,,", "codex_state=notalevel"] {
        let filter = filter_from_directives(Some(directives));

        assert!(
            filter.would_enable("codex_state", &tracing::Level::TRACE),
            "expected fallback to trace for {directives:?}"
        );
    }
}

/// `Targets` accepts these but derives no default level from them, so directives
/// without a bare level silence the sink for every target the user did not name.
/// This is why the sink takes its own variable rather than reusing `RUST_LOG`:
/// `EnvFilter` tolerates span syntax that `Targets` reinterprets as a target
/// name, and neither form carries a bare level.
#[test]
fn directives_without_a_bare_level_silence_the_sink() {
    for directives in ["codex_core=debug", "[my_span]=debug"] {
        let filter = filter_from_directives(Some(directives));

        assert!(
            !filter.would_enable("codex_state", &tracing::Level::ERROR),
            "expected {directives:?} to silence unnamed targets"
        );
    }
}

#[tokio::test]
async fn sqlite_sink_respects_configured_level_filter() {
    let codex_home =
        std::env::temp_dir().join(format!("codex-state-log-db-filter-{}", Uuid::new_v4()));
    let runtime = StateRuntime::init(
        crate::SqliteConfig::new_for_testing(codex_home.as_path().abs()),
        "test-provider".to_string(),
    )
    .await
    .expect("initialize runtime");
    let layer = start(runtime.clone());

    let guard = tracing_subscriber::registry()
        .with(
            layer
                .clone()
                .with_filter(filter_from_directives(Some("warn"))),
        )
        .set_default();

    tracing::trace!(target: "codex_state", "dropped-trace");
    tracing::info!(target: "codex_state", "dropped-info");
    tracing::warn!(target: "codex_state", "retained-warn");
    tracing::info!(target: "rmcp::service", "dropped-ceiling-info");
    tracing::error!(target: "log", "dropped-bridged-error");

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
        vec![("WARN", "codex_state", Some("retained-warn"))]
    );

    let _ = tokio::fs::remove_dir_all(codex_home).await;
}
