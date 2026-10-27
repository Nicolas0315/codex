#![cfg(target_os = "linux")]

use codex_protocol::models::PermissionProfile;
use codex_protocol::permissions::NetworkSandboxPolicy;
use codex_utils_absolute_path::AbsolutePathBuf;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn writable_path_bwrap_is_not_executed_before_sandbox_setup() {
    let temp = tempdir().expect("temp dir");
    let workspace = temp.path().join("workspace");
    let extra_write = temp.path().join("extra-write");
    let unrelated = temp.path().join("unrelated");
    for dir in [&workspace, &extra_write, &unrelated] {
        fs::create_dir(dir).expect("create directory");
    }
    let marker = temp.path().join("executed-before-sandbox");
    for bin_dir in [&workspace, &extra_write] {
        let helper = bin_dir.join("bwrap");
        fs::write(
            &helper,
            "#!/bin/sh\nprintf executed > \"$BWRAP_TEST_MARKER\"\nprintf '%s\\n' --perms --argv0\n",
        )
        .expect("write fake helper");
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).expect("chmod helper");
    }
    let profile = PermissionProfile::workspace_write_with(
        &[AbsolutePathBuf::from_absolute_path(&extra_write).expect("absolute")],
        NetworkSandboxPolicy::Restricted,
        /*exclude_tmpdir_env_var*/ true,
        /*exclude_slash_tmp*/ true,
    );
    for cwd in [std::path::Path::new("/"), unrelated.as_path()] {
        for bin_dir in [&workspace, &extra_write] {
            let output = Command::new(super::landlock::codex_linux_sandbox_exe())
                .current_dir(cwd)
                .env_clear()
                .env("PATH", bin_dir)
                .env("BWRAP_TEST_MARKER", &marker)
                .args([
                    "--sandbox-policy-cwd",
                    workspace.to_str().expect("workspace"),
                ])
                .args(["--command-cwd", cwd.to_str().expect("cwd")])
                .args([
                    "--permission-profile",
                    &serde_json::to_string(&profile).expect("serialize profile"),
                    "--no-proc",
                    "--",
                    "/bin/true",
                ])
                .output()
                .expect("run sandbox helper");
            assert!(
                !marker.exists(),
                "PATH helper executed outside sandbox: cwd={cwd:?}, PATH={bin_dir:?}, output={output:?}"
            );
        }
    }
}
