use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use pretty_assertions::assert_eq;
use rmcp::RoleClient;
use rmcp::model::ClientCapabilities;
use rmcp::model::ClientInfo;
use rmcp::model::ClientResult;
use rmcp::model::Implementation;
use rmcp::model::ServerNotification;
use rmcp::model::ServerRequest;
use rmcp::service::NotificationContext;
use rmcp::service::RequestContext;
use rmcp::service::Service;
use serde_json::json;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::Event;
use tracing::Level;
use tracing::Metadata;
use tracing::Subscriber;
use tracing::field::Field;
use tracing::field::Visit;
use tracing::instrument::WithSubscriber;
use tracing::span::Attributes;
use tracing::span::Id;
use tracing::span::Record;

use crate::elicitation_client_service::ElicitationClientService;
use crate::logging_client_handler::log_message;
use crate::rmcp_client::ElicitationPauseState;

#[tokio::test]
async fn service_dispatch_logs_server_messages_and_delegates_resource_updates() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let (handled, mut notifications) = mpsc::unbounded_channel();
    let service = CapturedService {
        inner: ElicitationClientService::new(
            ClientInfo::new(
                ClientCapabilities::default(),
                Implementation::new("notification-test", "0.0.0"),
            ),
            Box::new(|_, _| Box::pin(async { anyhow::bail!("unexpected elicitation") })),
            ElicitationPauseState::new(),
        ),
        capture: Capture(Arc::clone(&events)),
        handled,
    };
    let (client, mut server) = tokio::io::duplex(/*max_buf_size*/ 4096);
    let mut running = rmcp::service::serve_directly::<RoleClient, _, _, _, _>(
        service, client, /*peer_info*/ None,
    );

    for notification in [
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/message",
            "params": {
                "level": "warning",
                "logger": "test-server",
                "data": { "detail": [1, "two"] },
                "_meta": { "trace": "server-trace" },
            },
        }),
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/resources/updated",
            "params": { "uri": "memo://changed" },
        }),
    ] {
        server
            .write_all(format!("{notification}\n").as_bytes())
            .await
            .expect("write notification to in-memory transport");
        tokio::time::timeout(Duration::from_secs(5), notifications.recv())
            .await
            .expect("notification dispatch should finish")
            .expect("notification completion channel should stay open")
            .expect("notification should be handled");
    }
    running.close().await.expect("service should close");

    assert_eq!(
        *events.lock().expect("events lock"),
        vec![
            (
                Level::WARN,
                "MCP server log message (level: Warning, logger: Some(\"test-server\"), data: {\"detail\":[1,\"two\"]})".to_string(),
            ),
            (
                Level::INFO,
                "MCP server resource updated (uri: memo://changed)".to_string(),
            ),
        ],
    );
}

struct CapturedService {
    inner: ElicitationClientService,
    capture: Capture,
    handled: mpsc::UnboundedSender<Result<(), rmcp::ErrorData>>,
}

impl Service<RoleClient> for CapturedService {
    async fn handle_request(
        &self,
        request: ServerRequest,
        context: RequestContext<RoleClient>,
    ) -> Result<ClientResult, rmcp::ErrorData> {
        self.inner.handle_request(request, context).await
    }

    async fn handle_notification(
        &self,
        notification: ServerNotification,
        context: NotificationContext<RoleClient>,
    ) -> Result<(), rmcp::ErrorData> {
        let result = self
            .inner
            .handle_notification(notification, context)
            .with_subscriber(self.capture.clone())
            .await;
        self.handled
            .send(result.clone())
            .expect("test should receive notification completion");
        result
    }

    fn get_info(&self) -> ClientInfo {
        self.inner.get_info()
    }
}

#[test]
fn server_logging_notifications_preserve_severity_logger_and_structured_data() {
    let events = Arc::new(Mutex::new(Vec::new()));
    tracing::subscriber::with_default(Capture(Arc::clone(&events)), || {
        for level in [
            "debug",
            "info",
            "notice",
            "warning",
            "error",
            "critical",
            "alert",
            "emergency",
        ] {
            let notification: ServerNotification = serde_json::from_value(json!({
                "method": "notifications/message",
                "params": {
                    "level": level,
                    "logger": "test-server",
                    "data": { "detail": [1, "two"] },
                    "_meta": { "trace": "server-trace" },
                },
            }))
            .expect("logging notification should deserialize");
            let ServerNotification::LoggingMessageNotification(notification) = notification else {
                panic!("expected a logging notification");
            };
            log_message(notification.params).expect("logging notification should be handled");
        }
    });

    let captured = events.lock().expect("events lock");
    assert_eq!(
        captured.iter().map(|(level, _)| *level).collect::<Vec<_>>(),
        vec![
            Level::DEBUG,
            Level::INFO,
            Level::INFO,
            Level::WARN,
            Level::ERROR,
            Level::ERROR,
            Level::ERROR,
            Level::ERROR,
        ],
    );
    for (_, message) in captured.iter() {
        assert!(message.contains("logger: Some(\"test-server\")"));
        assert!(message.contains("data: {\"detail\":[1,\"two\"]}"));
    }
}

#[test]
fn server_logging_accepts_absent_logger_and_arbitrary_json_data() {
    let events = Arc::new(Mutex::new(Vec::new()));
    tracing::subscriber::with_default(Capture(Arc::clone(&events)), || {
        for data in [json!(null), json!("message"), json!([1, true])] {
            let notification: ServerNotification = serde_json::from_value(json!({
                "method": "notifications/message",
                "params": { "level": "info", "data": data },
            }))
            .expect("logging notification should deserialize");
            let ServerNotification::LoggingMessageNotification(notification) = notification else {
                panic!("expected a logging notification");
            };
            log_message(notification.params).expect("logging notification should be handled");
        }
    });

    let captured = events.lock().expect("events lock");
    assert_eq!(captured.len(), 3);
    for (_, message) in captured.iter() {
        assert!(message.contains("logger: None"));
    }
}

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<(Level, String)>>>);

impl Subscriber for Capture {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut message = Message(String::new());
        event.record(&mut message);
        self.0
            .lock()
            .expect("events lock")
            .push((*event.metadata().level(), message.0));
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

struct Message(String);

impl Visit for Message {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}
