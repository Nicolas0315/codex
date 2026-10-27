use std::sync::Arc;

use rmcp::ClientHandler;
use rmcp::RoleClient;
use rmcp::model::CancelledNotificationParam;
use rmcp::model::ClientInfo;
use rmcp::model::ElicitRequestParams;
use rmcp::model::ElicitResult;
use rmcp::model::ProgressNotificationParam;
use rmcp::model::ResourceUpdatedNotificationParam;
use rmcp::service::NotificationContext;
use rmcp::service::RequestContext;
use serde::Deserialize;
use serde::Serialize;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::rmcp_client::SendElicitation;

#[derive(Clone)]
pub(crate) struct LoggingClientHandler {
    client_info: ClientInfo,
    send_elicitation: Arc<SendElicitation>,
}

impl LoggingClientHandler {
    pub(crate) fn new(client_info: ClientInfo, send_elicitation: SendElicitation) -> Self {
        Self {
            client_info,
            send_elicitation: Arc::new(send_elicitation),
        }
    }
}

impl ClientHandler for LoggingClientHandler {
    async fn create_elicitation(
        &self,
        request: ElicitRequestParams,
        context: RequestContext<RoleClient>,
    ) -> Result<ElicitResult, rmcp::ErrorData> {
        (self.send_elicitation)(context.id, request)
            .await
            .map(Into::into)
            .map_err(|err| rmcp::ErrorData::internal_error(err.to_string(), None))
    }

    async fn on_cancelled(
        &self,
        params: CancelledNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        info!(
            "MCP server cancelled request (request_id: {:?}, reason: {:?})",
            params.request_id, params.reason
        );
    }

    async fn on_progress(
        &self,
        params: ProgressNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        info!(
            "MCP server progress notification (token: {:?}, progress: {}, total: {:?}, message: {:?})",
            params.progress_token, params.progress, params.total, params.message
        );
    }

    async fn on_resource_updated(
        &self,
        params: ResourceUpdatedNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        info!("MCP server resource updated (uri: {})", params.uri);
    }

    async fn on_resource_list_changed(&self, _context: NotificationContext<RoleClient>) {
        info!("MCP server resource list changed");
    }

    async fn on_tool_list_changed(&self, _context: NotificationContext<RoleClient>) {
        info!("MCP server tool list changed");
    }

    async fn on_prompt_list_changed(&self, _context: NotificationContext<RoleClient>) {
        info!("MCP server prompt list changed");
    }

    fn get_info(&self) -> ClientInfo {
        self.client_info.clone()
    }
}

// RMCP deprecates logging under SEP-2577 without a replacement model. Keep
// accepting the existing wire format without depending on its deprecated types.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum LoggingLevel {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
    Alert,
    Emergency,
}

#[derive(Deserialize)]
struct LoggingMessage {
    level: LoggingLevel,
    logger: Option<String>,
    data: serde_json::Value,
}

pub(crate) fn log_message(params: impl Serialize) -> Result<(), rmcp::ErrorData> {
    let params = serde_json::to_value(params)
        .and_then(serde_json::from_value::<LoggingMessage>)
        .map_err(|err| rmcp::ErrorData::internal_error(err.to_string(), None))?;
    let LoggingMessage {
        level,
        logger,
        data,
    } = params;
    let logger = logger.as_deref();
    match level {
        LoggingLevel::Emergency
        | LoggingLevel::Alert
        | LoggingLevel::Critical
        | LoggingLevel::Error => {
            error!(
                "MCP server log message (level: {:?}, logger: {:?}, data: {})",
                level, logger, data
            );
        }
        LoggingLevel::Warning => {
            warn!(
                "MCP server log message (level: {:?}, logger: {:?}, data: {})",
                level, logger, data
            );
        }
        LoggingLevel::Notice | LoggingLevel::Info => {
            info!(
                "MCP server log message (level: {:?}, logger: {:?}, data: {})",
                level, logger, data
            );
        }
        LoggingLevel::Debug => {
            debug!(
                "MCP server log message (level: {:?}, logger: {:?}, data: {})",
                level, logger, data
            );
        }
    }
    Ok(())
}
