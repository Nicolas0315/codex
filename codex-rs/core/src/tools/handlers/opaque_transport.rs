const OPAQUE_ENCODED_PATCH_TRANSPORT_MESSAGE: &str = "opaque encoded patch/script transport rejected: use the native apply_patch tool, \
an inspectable stdin/heredoc transfer, or file APIs with visible source content. \
If the terminal or PTY path failed, report that original terminal error instead of \
retrying with base64 or EncodedCommand shell recovery.";

pub(crate) fn reject_opaque_encoded_patch_transport(command: &[String]) -> Option<String> {
    let command_text = command.join(" ");
    let normalized = normalize_for_matching(&command_text);

    if !contains_encoded_transport_marker(&normalized) {
        return None;
    }

    if contains_patch_sink(&normalized) || contains_decoded_script_execution(&normalized) {
        return Some(OPAQUE_ENCODED_PATCH_TRANSPORT_MESSAGE.to_string());
    }

    None
}

fn normalize_for_matching(command: &str) -> String {
    command.to_ascii_lowercase().replace("\r\n", "\n")
}

fn contains_encoded_transport_marker(command: &str) -> bool {
    command.contains("base64")
        || command.contains("frombase64string")
        || command.contains("-encodedcommand")
        || command.contains("certutil")
}

fn contains_patch_sink(command: &str) -> bool {
    command.contains("apply_patch")
        || command.contains("git apply")
        || command.contains("git am")
        || command.contains("| patch")
        || command.contains(" patch -p")
}

fn contains_decoded_script_execution(command: &str) -> bool {
    command.contains("| bash")
        || command.contains("|bash")
        || command.contains("| sh")
        || command.contains("|sh")
        || command.contains("| zsh")
        || command.contains("|zsh")
        || command.contains("| pwsh")
        || command.contains("|pwsh")
        || command.contains("| powershell")
        || command.contains("|powershell")
        || command.contains("invoke-expression")
        || command.contains("| iex")
        || command.contains("|iex")
        || command.contains(" iex ")
        || command.contains("iex(")
}

#[cfg(test)]
mod tests {
    use super::reject_opaque_encoded_patch_transport;

    #[test]
    fn rejects_base64_piped_to_apply_patch() {
        let command = vec![
            "bash".to_string(),
            "-lc".to_string(),
            "printf '%s' abc | base64 -d | apply_patch".to_string(),
        ];

        assert!(reject_opaque_encoded_patch_transport(&command).is_some());
    }

    #[test]
    fn rejects_powershell_base64_invoke_expression() {
        let command = vec![
            "powershell.exe".to_string(),
            "-NoProfile".to_string(),
            "-Command".to_string(),
            "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | IEX"
                .to_string(),
        ];

        assert!(reject_opaque_encoded_patch_transport(&command).is_some());
    }

    #[test]
    fn allows_plain_apply_patch_command_for_interception() {
        let command = vec![
            "bash".to_string(),
            "-lc".to_string(),
            "apply_patch <<'PATCH'\n*** Begin Patch\n*** End Patch\nPATCH".to_string(),
        ];

        assert_eq!(reject_opaque_encoded_patch_transport(&command), None);
    }

    #[test]
    fn allows_non_executed_base64_artifact_decode() {
        let command = vec![
            "bash".to_string(),
            "-lc".to_string(),
            "printf '%s' abc | base64 -d > artifact.bin".to_string(),
        ];

        assert_eq!(reject_opaque_encoded_patch_transport(&command), None);
    }
}
