use anyhow::Result;
use codex_protocol::items::TurnItem;
use codex_protocol::models::ContentItem;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::ItemCompletedEvent;
use codex_protocol::protocol::ItemStartedEvent;
use codex_protocol::protocol::Op;
use codex_protocol::user_input::UserInput;
use core_test_support::responses::ev_assistant_message;
use core_test_support::responses::ev_completed;
use core_test_support::responses::ev_message_item_added;
use core_test_support::responses::ev_reasoning_item;
use core_test_support::responses::ev_response_created;
use core_test_support::responses::mount_sse_once;
use core_test_support::responses::sse;
use core_test_support::responses::start_mock_server;
use core_test_support::skip_if_no_network;
use core_test_support::test_codex::TestCodexBuilder;
use core_test_support::test_codex::test_codex;
use pretty_assertions::assert_eq;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use wiremock::MockServer;

fn ev_assistant_message_for_output(
    id: &str,
    text: &str,
    response_id: &str,
    output_index: i64,
) -> serde_json::Value {
    let mut event = ev_assistant_message(id, text);
    event["response_id"] = json!(response_id);
    event["output_index"] = json!(output_index);
    event
}

#[derive(Debug, Default, Eq, PartialEq)]
struct CollectedOutput {
    agent_messages: Vec<String>,
    started_agent_message_ids: Vec<String>,
    completed_agent_message_ids: Vec<String>,
    raw_assistant_messages: Vec<(Option<String>, String)>,
    errors: Vec<String>,
}

async fn submit_and_collect_agent_messages(
    test: &core_test_support::test_codex::TestCodex,
) -> Result<Vec<String>> {
    Ok(submit_and_collect_output(test).await?.agent_messages)
}

async fn submit_and_collect_output(
    test: &core_test_support::test_codex::TestCodex,
) -> Result<CollectedOutput> {
    test.codex
        .submit(Op::UserInput {
            items: vec![UserInput::Text {
                text: "record assistant output".to_string(),
                text_elements: Vec::new(),
            }],
            final_output_json_schema: None,
            responsesapi_client_metadata: None,
            additional_context: Default::default(),
            thread_settings: Default::default(),
        })
        .await?;

    let mut output = CollectedOutput::default();
    loop {
        let event = test
            .codex
            .next_event()
            .await
            .expect("event stream should stay open")
            .msg;
        match event {
            EventMsg::AgentMessage(message) => output.agent_messages.push(message.message),
            EventMsg::ItemStarted(ItemStartedEvent {
                item: TurnItem::AgentMessage(message),
                ..
            }) => output.started_agent_message_ids.push(message.id),
            EventMsg::ItemCompleted(ItemCompletedEvent {
                item: TurnItem::AgentMessage(message),
                ..
            }) => output.completed_agent_message_ids.push(message.id),
            EventMsg::RawResponseItem(raw) => {
                if let ResponseItem::Message {
                    id, role, content, ..
                } = raw.item
                    && role == "assistant"
                {
                    let text = content
                        .into_iter()
                        .filter_map(|item| match item {
                            ContentItem::OutputText { text } => Some(text),
                            _ => None,
                        })
                        .collect::<String>();
                    output.raw_assistant_messages.push((id, text));
                }
            }
            EventMsg::Error(error) => output.errors.push(error.message),
            EventMsg::TurnComplete(_) => break,
            _ => {}
        }
    }

    Ok(output)
}

async fn resumed_agent_messages(
    builder: &mut TestCodexBuilder,
    server: &MockServer,
    home: Arc<TempDir>,
    rollout_path: PathBuf,
    expected_count: usize,
) -> Result<Vec<String>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let poll_interval = Duration::from_millis(10);
    let mut last_messages = "<missing initial messages>".to_string();

    loop {
        let resumed = builder
            .resume(server, Arc::clone(&home), rollout_path.clone())
            .await?;
        if let Some(initial_messages) = resumed.session_configured.initial_messages.as_ref() {
            let agent_messages = initial_messages
                .iter()
                .filter_map(|message| match message {
                    EventMsg::AgentMessage(message) => Some(message.message.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            if agent_messages.len() == expected_count {
                return Ok(agent_messages);
            }
            last_messages = format!("{initial_messages:#?}");
        }

        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for resumed agent messages: {last_messages}");
        }

        drop(resumed);
        tokio::time::sleep(poll_interval).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_id_cumulative_assistant_output_item_done_snapshots_collapse_to_one_message()
-> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;
    let mut builder = test_codex();
    let test = builder.build(&server).await?;
    let home = Arc::clone(&test.home);
    let rollout_path = test
        .session_configured
        .rollout_path
        .clone()
        .expect("rollout path");
    mount_sse_once(
        &server,
        sse(vec![
            ev_response_created("resp-1"),
            ev_assistant_message("msg-1", "hello"),
            ev_assistant_message("msg-1", "hello world"),
            ev_completed("resp-1"),
        ]),
    )
    .await;

    let agent_messages = submit_and_collect_agent_messages(&test).await?;

    assert_eq!(agent_messages, vec!["hello world"]);
    assert_eq!(
        resumed_agent_messages(&mut builder, &server, home, rollout_path, 1).await?,
        vec!["hello world"]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_output_index_distinct_id_assistant_snapshots_collapse_to_one_message() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;
    let mut builder = test_codex();
    let test = builder.build(&server).await?;
    let home = Arc::clone(&test.home);
    let rollout_path = test
        .session_configured
        .rollout_path
        .clone()
        .expect("rollout path");
    mount_sse_once(
        &server,
        sse(vec![
            ev_response_created("resp-1"),
            ev_assistant_message_for_output("msg-1", "hello", "resp-1", 0),
            ev_assistant_message_for_output("msg-2", "hello world", "resp-1", 0),
            ev_completed("resp-1"),
        ]),
    )
    .await;

    let output = submit_and_collect_output(&test).await?;

    assert_eq!(output.agent_messages, vec!["hello world"]);
    assert_eq!(
        output.raw_assistant_messages,
        vec![(Some("msg-2".to_string()), "hello world".to_string())]
    );
    assert_eq!(
        resumed_agent_messages(&mut builder, &server, home, rollout_path, 1).await?,
        vec!["hello world"]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn distinct_id_prefix_assistant_messages_remain_separate_messages() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;
    let mut builder = test_codex();
    let test = builder.build(&server).await?;
    let home = Arc::clone(&test.home);
    let rollout_path = test
        .session_configured
        .rollout_path
        .clone()
        .expect("rollout path");
    mount_sse_once(
        &server,
        sse(vec![
            ev_response_created("resp-1"),
            ev_assistant_message("msg-1", "hello"),
            ev_assistant_message("msg-2", "hello world"),
            ev_completed("resp-1"),
        ]),
    )
    .await;

    let output = submit_and_collect_output(&test).await?;

    assert_eq!(output.agent_messages, vec!["hello", "hello world"]);
    assert_eq!(
        output.raw_assistant_messages,
        vec![
            (Some("msg-1".to_string()), "hello".to_string()),
            (Some("msg-2".to_string()), "hello world".to_string()),
        ]
    );
    assert_eq!(
        resumed_agent_messages(&mut builder, &server, home, rollout_path, 2).await?,
        vec!["hello", "hello world"]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn different_output_index_prefix_assistant_messages_remain_separate_messages() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;
    let mut builder = test_codex();
    let test = builder.build(&server).await?;
    let home = Arc::clone(&test.home);
    let rollout_path = test
        .session_configured
        .rollout_path
        .clone()
        .expect("rollout path");
    mount_sse_once(
        &server,
        sse(vec![
            ev_response_created("resp-1"),
            ev_assistant_message_for_output("msg-1", "hello", "resp-1", 0),
            ev_assistant_message_for_output("msg-2", "hello world", "resp-1", 1),
            ev_completed("resp-1"),
        ]),
    )
    .await;

    let output = submit_and_collect_output(&test).await?;

    assert_eq!(output.agent_messages, vec!["hello", "hello world"]);
    assert_eq!(
        output.raw_assistant_messages,
        vec![
            (Some("msg-1".to_string()), "hello".to_string()),
            (Some("msg-2".to_string()), "hello world".to_string()),
        ]
    );
    assert_eq!(
        resumed_agent_messages(&mut builder, &server, home, rollout_path, 2).await?,
        vec!["hello", "hello world"]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streamed_same_id_assistant_snapshot_keeps_item_lifecycle_ids_consistent() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;
    let test = test_codex().build(&server).await?;
    mount_sse_once(
        &server,
        sse(vec![
            ev_response_created("resp-1"),
            ev_message_item_added("msg-1", "hello"),
            ev_assistant_message("msg-1", "hello"),
            ev_assistant_message("msg-1", "hello world"),
            ev_completed("resp-1"),
        ]),
    )
    .await;

    let output = submit_and_collect_output(&test).await?;

    assert_eq!(output.agent_messages, vec!["hello world"]);
    assert_eq!(output.started_agent_message_ids, vec!["msg-1"]);
    assert_eq!(output.completed_agent_message_ids, vec!["msg-1"]);
    assert_eq!(
        output.raw_assistant_messages,
        vec![(Some("msg-1".to_string()), "hello world".to_string())]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streamed_same_output_index_distinct_id_assistant_snapshot_keeps_item_lifecycle_ids_consistent()
-> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;
    let test = test_codex().build(&server).await?;
    mount_sse_once(
        &server,
        sse(vec![
            ev_response_created("resp-1"),
            ev_message_item_added("msg-1", "hello"),
            ev_assistant_message_for_output("msg-1", "hello", "resp-1", 0),
            ev_assistant_message_for_output("msg-2", "hello world", "resp-1", 0),
            ev_completed("resp-1"),
        ]),
    )
    .await;

    let output = submit_and_collect_output(&test).await?;

    assert_eq!(output.agent_messages, vec!["hello world"]);
    assert_eq!(output.started_agent_message_ids, vec!["msg-1"]);
    assert_eq!(output.completed_agent_message_ids, vec!["msg-1"]);
    assert_eq!(
        output.raw_assistant_messages,
        vec![(Some("msg-1".to_string()), "hello world".to_string())]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_failed_flushes_pending_assistant_snapshot_before_error() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;
    let test = test_codex().build(&server).await?;
    mount_sse_once(
        &server,
        sse(vec![
            ev_response_created("resp-1"),
            ev_assistant_message("msg-1", "hello"),
            json!({
                "type": "response.failed",
                "response": {
                    "id": "resp-1",
                    "error": {
                        "code": "insufficient_quota",
                        "message": "You exceeded your current quota, please check your plan and billing details."
                    }
                }
            }),
        ]),
    )
    .await;

    let output = submit_and_collect_output(&test).await?;

    assert_eq!(output.agent_messages, vec!["hello"]);
    assert_eq!(
        output.raw_assistant_messages,
        vec![(Some("msg-1".to_string()), "hello".to_string())]
    );
    assert_eq!(
        output.errors,
        vec!["Quota exceeded. Check your plan and billing details."]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reasoning_boundary_flushes_pending_assistant_snapshot() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;
    let mut builder = test_codex();
    let test = builder.build(&server).await?;
    let home = Arc::clone(&test.home);
    let rollout_path = test
        .session_configured
        .rollout_path
        .clone()
        .expect("rollout path");
    mount_sse_once(
        &server,
        sse(vec![
            ev_response_created("resp-1"),
            ev_assistant_message("msg-1", "hello"),
            ev_reasoning_item("reason-1", &["thinking"], &[]),
            ev_assistant_message("msg-2", "hello world"),
            ev_completed("resp-1"),
        ]),
    )
    .await;

    let output = submit_and_collect_output(&test).await?;

    assert_eq!(output.agent_messages, vec!["hello", "hello world"]);
    assert_eq!(
        output.raw_assistant_messages,
        vec![
            (Some("msg-1".to_string()), "hello".to_string()),
            (Some("msg-2".to_string()), "hello world".to_string()),
        ]
    );
    assert_eq!(
        resumed_agent_messages(&mut builder, &server, home, rollout_path, 2).await?,
        vec!["hello", "hello world"]
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_prefix_assistant_output_item_done_snapshots_remain_separate_messages() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;
    let mut builder = test_codex();
    let test = builder.build(&server).await?;
    let home = Arc::clone(&test.home);
    let rollout_path = test
        .session_configured
        .rollout_path
        .clone()
        .expect("rollout path");
    mount_sse_once(
        &server,
        sse(vec![
            ev_response_created("resp-1"),
            ev_assistant_message("msg-1", "hello"),
            ev_assistant_message("msg-2", "goodbye"),
            ev_completed("resp-1"),
        ]),
    )
    .await;

    let agent_messages = submit_and_collect_agent_messages(&test).await?;

    assert_eq!(agent_messages, vec!["hello", "goodbye"]);
    assert_eq!(
        resumed_agent_messages(&mut builder, &server, home, rollout_path, 2).await?,
        vec!["hello", "goodbye"]
    );
    Ok(())
}
