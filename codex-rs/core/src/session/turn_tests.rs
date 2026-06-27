use super::*;
use codex_extension_api::ExtensionData;
use codex_extension_api::TurnItemContributor;
use codex_protocol::items::AgentMessageContent;
use pretty_assertions::assert_eq;
use std::sync::Arc;

struct RewriteAgentMessageContributor;

impl TurnItemContributor for RewriteAgentMessageContributor {
    fn contribute<'a>(
        &'a self,
        _thread_store: &'a ExtensionData,
        _turn_store: &'a ExtensionData,
        item: &'a mut TurnItem,
    ) -> codex_extension_api::ExtensionFuture<'a, Result<(), String>> {
        Box::pin(async move {
            if let TurnItem::AgentMessage(agent_message) = item {
                agent_message.content = vec![AgentMessageContent::Text {
                    text: "plan contributed assistant text".to_string(),
                }];
            }
            Ok(())
        })
    }
}

fn assistant_output_text_with_id_phase(
    id: &str,
    text: &str,
    phase: Option<MessagePhase>,
) -> ResponseItem {
    ResponseItem::Message {
        id: Some(id.to_string()),
        role: "assistant".to_string(),
        content: vec![ContentItem::OutputText {
            text: text.to_string(),
        }],
        phase,
        internal_chat_message_metadata_passthrough: None,
    }
}

fn assistant_output_text(text: &str) -> ResponseItem {
    assistant_output_text_with_id_phase("msg-1", text, None)
}

fn pending_snapshot(item: ResponseItem) -> PendingAssistantDoneSnapshot {
    PendingAssistantDoneSnapshot {
        item,
        response_id: None,
        output_index: None,
        previously_streamed_item: None,
    }
}

fn pending_snapshot_with_output_index(
    item: ResponseItem,
    response_id: &str,
    output_index: i64,
) -> PendingAssistantDoneSnapshot {
    PendingAssistantDoneSnapshot {
        item,
        response_id: Some(response_id.to_string()),
        output_index: Some(output_index),
        previously_streamed_item: None,
    }
}

fn assistant_output_text_without_id(text: &str) -> ResponseItem {
    let mut item = assistant_output_text_with_id_phase("", text, None);
    if let ResponseItem::Message { id, .. } = &mut item {
        *id = None;
    }
    item
}

#[test]
fn same_id_assistant_done_snapshot_replaces_pending_snapshot() {
    let pending = pending_snapshot(assistant_output_text_with_id_phase("msg-1", "hello", None));
    let next = pending_snapshot(assistant_output_text_with_id_phase(
        "msg-1",
        "hello world",
        None,
    ));

    assert!(should_replace_pending_assistant_done_snapshot(
        &pending, &next
    ));
}

#[test]
fn distinct_id_prefix_assistant_done_snapshot_does_not_replace_pending_snapshot() {
    let pending = pending_snapshot(assistant_output_text_with_id_phase("msg-1", "hello", None));
    let next = pending_snapshot(assistant_output_text_with_id_phase(
        "msg-2",
        "hello world",
        None,
    ));

    assert!(!should_replace_pending_assistant_done_snapshot(
        &pending, &next
    ));
}

#[test]
fn distinct_id_same_output_index_prefix_assistant_done_snapshot_replaces_pending_snapshot() {
    let pending = pending_snapshot_with_output_index(
        assistant_output_text_with_id_phase("msg-1", "hello", None),
        "resp-1",
        0,
    );
    let next = pending_snapshot_with_output_index(
        assistant_output_text_with_id_phase("msg-2", "hello world", None),
        "resp-1",
        0,
    );

    assert!(should_replace_pending_assistant_done_snapshot(
        &pending, &next
    ));
}

#[test]
fn distinct_id_different_output_index_prefix_assistant_done_snapshot_does_not_replace_pending_snapshot()
 {
    let pending = pending_snapshot_with_output_index(
        assistant_output_text_with_id_phase("msg-1", "hello", None),
        "resp-1",
        0,
    );
    let next = pending_snapshot_with_output_index(
        assistant_output_text_with_id_phase("msg-2", "hello world", None),
        "resp-1",
        1,
    );

    assert!(!should_replace_pending_assistant_done_snapshot(
        &pending, &next
    ));
}

#[test]
fn distinct_id_non_prefix_assistant_done_snapshot_does_not_replace_pending_snapshot() {
    let pending = pending_snapshot(assistant_output_text_with_id_phase("msg-1", "hello", None));
    let next = pending_snapshot(assistant_output_text_with_id_phase(
        "msg-2", "goodbye", None,
    ));

    assert!(!should_replace_pending_assistant_done_snapshot(
        &pending, &next
    ));
}

#[test]
fn assistant_done_snapshot_phase_change_does_not_replace_pending_snapshot() {
    let pending = pending_snapshot(assistant_output_text_with_id_phase(
        "msg-1",
        "hello",
        Some(MessagePhase::Commentary),
    ));
    let next = pending_snapshot(assistant_output_text_with_id_phase(
        "msg-2",
        "hello world",
        Some(MessagePhase::FinalAnswer),
    ));

    assert!(!should_replace_pending_assistant_done_snapshot(
        &pending, &next
    ));
}

#[test]
fn empty_assistant_done_snapshot_does_not_replace_pending_snapshot() {
    let pending = pending_snapshot(assistant_output_text_with_id_phase("msg-1", "", None));
    let next = pending_snapshot(assistant_output_text_with_id_phase("msg-2", "hello", None));

    assert!(!should_replace_pending_assistant_done_snapshot(
        &pending, &next
    ));
}

#[test]
fn empty_id_assistant_done_snapshot_does_not_replace_pending_snapshot() {
    let pending = pending_snapshot(assistant_output_text_with_id_phase("", "hello", None));
    let next = pending_snapshot(assistant_output_text_with_id_phase("", "hello world", None));

    assert!(!should_replace_pending_assistant_done_snapshot(
        &pending, &next
    ));
}

#[test]
fn missing_id_prefix_assistant_done_snapshot_does_not_replace_pending_snapshot() {
    let pending = pending_snapshot(assistant_output_text_without_id("hello"));
    let next = pending_snapshot(assistant_output_text_without_id("hello world"));

    assert!(!should_replace_pending_assistant_done_snapshot(
        &pending, &next
    ));
}

#[test]
fn user_message_done_snapshot_does_not_replace_pending_snapshot() {
    let pending = pending_snapshot(assistant_output_text_with_id_phase("msg-1", "hello", None));
    let next = pending_snapshot(ResponseItem::Message {
        id: Some("msg-2".to_string()),
        role: "user".to_string(),
        content: vec![ContentItem::InputText {
            text: "hello world".to_string(),
        }],
        phase: None,
        internal_chat_message_metadata_passthrough: None,
    });

    assert!(!should_replace_pending_assistant_done_snapshot(
        &pending, &next
    ));
}

#[tokio::test]
async fn plan_mode_uses_contributed_turn_item_for_last_agent_message() {
    let (mut session, turn_context) = crate::session::tests::make_session_and_context().await;
    let mut builder = codex_extension_api::ExtensionRegistryBuilder::new();
    builder.turn_item_contributor(Arc::new(RewriteAgentMessageContributor));
    session.services.extensions = Arc::new(builder.build());
    let turn_store = ExtensionData::new(turn_context.sub_id.clone());
    let mut state = PlanModeStreamState::new(&turn_context.sub_id);
    let mut last_agent_message = None;
    let item = assistant_output_text("original assistant text");

    let handled = handle_assistant_item_done_in_plan_mode(
        &session,
        &turn_context,
        &turn_store,
        &item,
        &mut state,
        /*previously_active_item*/ None,
        &mut last_agent_message,
    )
    .await;

    assert!(handled);
    assert_eq!(
        last_agent_message.as_deref(),
        Some("plan contributed assistant text")
    );
}
