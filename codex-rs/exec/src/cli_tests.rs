use super::*;
use pretty_assertions::assert_eq;

#[test]
fn resume_parses_prompt_after_global_flags() {
    const PROMPT: &str = "echo resume-with-global-flags-after-subcommand";
    let cli = Cli::parse_from([
        "codex-exec",
        "resume",
        "--last",
        "--json",
        "--model",
        "gpt-5.2-codex",
        "--dangerously-bypass-approvals-and-sandbox",
        "--skip-git-repo-check",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        PROMPT,
    ]);

    assert!(cli.ephemeral);
    assert!(cli.ignore_user_config);
    assert!(cli.ignore_rules);
    let Some(Command::Resume(args)) = cli.command else {
        panic!("expected resume command");
    };
    let effective_prompt = args.prompt.clone().or_else(|| {
        if args.last {
            args.session_id.clone()
        } else {
            None
        }
    });
    assert_eq!(effective_prompt.as_deref(), Some(PROMPT));
}

#[test]
fn resume_accepts_output_flags_after_subcommand() {
    const PROMPT: &str = "echo resume-with-output-file";
    let cli = Cli::parse_from([
        "codex-exec",
        "resume",
        "session-123",
        "-o",
        "/tmp/resume-output.md",
        "--output-schema",
        "/tmp/schema.json",
        PROMPT,
    ]);

    assert_eq!(
        cli.last_message_file,
        Some(PathBuf::from("/tmp/resume-output.md"))
    );
    assert_eq!(cli.output_schema, Some(PathBuf::from("/tmp/schema.json")));
    let Some(Command::Resume(args)) = cli.command else {
        panic!("expected resume command");
    };
    assert_eq!(args.session_id.as_deref(), Some("session-123"));
    assert_eq!(args.prompt.as_deref(), Some(PROMPT));
}

#[test]
fn parses_config_isolation_flags() {
    let cli = Cli::parse_from([
        "codex-exec",
        "--ignore-user-config",
        "--ignore-rules",
        "summarize",
    ]);

    assert!(cli.ignore_user_config);
    assert!(cli.ignore_rules);
}

#[test]
fn exec_image_preserves_positional_prompt() {
    let cli = Cli::parse_from([
        "codex-exec",
        "--image",
        "screenshot.png",
        "describe this image",
    ]);

    assert_eq!(cli.images, vec![PathBuf::from("screenshot.png")]);
    assert_eq!(cli.prompt.as_deref(), Some("describe this image"));
}

#[test]
fn exec_image_accepts_repeated_and_comma_delimited_values() {
    let cli = Cli::parse_from([
        "codex-exec",
        "--image",
        "a.png,b.png",
        "--image",
        "c.png",
        "describe these images",
    ]);

    assert_eq!(
        cli.images,
        vec![
            PathBuf::from("a.png"),
            PathBuf::from("b.png"),
            PathBuf::from("c.png"),
        ]
    );
    assert_eq!(cli.prompt.as_deref(), Some("describe these images"));
}

#[test]
fn removed_full_auto_flag_reports_migration_path() {
    let cli = Cli::parse_from(["codex-exec", "--full-auto", "summarize"]);

    assert_eq!(
        cli.removed_full_auto_warning(),
        Some("warning: `--full-auto` is deprecated; use `--sandbox workspace-write` instead.")
    );
}
