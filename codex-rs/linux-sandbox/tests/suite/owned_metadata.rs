#![cfg(target_os = "linux")]

use codex_file_system::existing_synthetic_metadata_authorities;
use codex_file_system::is_synthetic_metadata_directory;
use codex_file_system::synthetic_metadata_authority_paths;
use codex_git_utils::get_git_repo_root;
use codex_protocol::models::PermissionProfile;
use codex_protocol::permissions::NetworkSandboxPolicy;
use codex_utils_absolute_path::AbsolutePathBuf;
use pretty_assertions::assert_eq;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::symlink;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Output;
use std::process::Stdio;
use std::time::Duration;
use tempfile::TempDir;
use tokio::process::Command;

const TIMEOUT: Duration = Duration::from_secs(15);

fn sandbox(cwd: &Path, extra_roots: &[PathBuf], command: &[&str]) -> Command {
    let roots = extra_roots
        .iter()
        .map(|root| AbsolutePathBuf::from_absolute_path(root).expect("absolute writable root"))
        .collect::<Vec<_>>();
    let profile = PermissionProfile::workspace_write_with(
        &roots,
        NetworkSandboxPolicy::Enabled,
        /*exclude_tmpdir_env_var*/ true,
        /*exclude_slash_tmp*/ true,
    );
    let mut child = Command::new(super::landlock::codex_linux_sandbox_exe());
    child
        .current_dir(cwd)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(["--sandbox-policy-cwd", cwd.to_str().expect("cwd")])
        .args(["--command-cwd", cwd.to_str().expect("cwd")])
        .args([
            "--permission-profile",
            &serde_json::to_string(&profile).expect("profile"),
        ])
        .arg("--")
        .args(command)
        .stdin(Stdio::null())
        .kill_on_drop(true);
    child
}

async fn run(cwd: &Path, extra_roots: &[PathBuf], command: &[&str]) -> Output {
    tokio::time::timeout(TIMEOUT, sandbox(cwd, extra_roots, command).output())
        .await
        .expect("sandbox command timed out")
        .expect("run sandbox command")
}

fn assert_success(output: &Output) {
    assert!(output.status.success(), "sandbox failed: {output:?}");
}

async fn prerequisites() -> bool {
    if !std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
    {
        eprintln!("skipping owned metadata test: git is unavailable");
        return false;
    }
    let probe = tempfile::tempdir_in("/var/tmp").expect("probe directory");
    let output = run(probe.path(), &[], &["/bin/true"]).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("bubblewrap is unavailable: no system bwrap was found")
        || stderr.contains("Creating new namespace failed: Operation not permitted")
        || (stderr.contains("Can't mount proc on /newroot/proc")
            && (stderr.contains("Operation not permitted")
                || stderr.contains("Permission denied")
                || stderr.contains("Invalid argument")))
    {
        eprintln!("skipping owned metadata test: bwrap prerequisites are unavailable");
        return false;
    }
    assert_success(&output);
    true
}

fn repository() -> (TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir_in("/var/tmp").expect("test directory");
    let repo = temp.path().join("repo");
    let workspace = repo.join("sub");
    fs::create_dir_all(&workspace).expect("workspace");
    let output = std::process::Command::new("git")
        .args(["-c", "init.defaultBranch=main", "init", "-q"])
        .arg(&repo)
        .output()
        .expect("git init");
    assert_success(&output);
    (temp, repo, workspace)
}

fn metadata_id(path: &Path) -> (u64, u64, u32, i64, i64) {
    let metadata = fs::symlink_metadata(path).expect("metadata still exists");
    (
        metadata.dev(),
        metadata.ino(),
        metadata.mode(),
        metadata.mtime(),
        metadata.mtime_nsec(),
    )
}

fn assert_discovery(repo: &Path, workspace: &Path) {
    assert_eq!(get_git_repo_root(workspace), Some(repo.to_path_buf()));
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(workspace)
        .output()
        .expect("host git discovery");
    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        repo.to_str().expect("repo")
    );
}

fn owned_ids(workspace: &Path) -> Vec<(u64, u64, u32, i64, i64)> {
    [".git", ".codex", ".agents"]
        .map(|name| {
            let path = workspace.join(name);
            assert!(
                is_synthetic_metadata_directory(&path),
                "unowned placeholder: {path:?}"
            );
            metadata_id(&path)
        })
        .into()
}

#[tokio::test]
async fn normal_exit_and_later_invocations_preserve_owned_metadata_and_git_discovery() {
    if !prerequisites().await {
        return;
    }
    let (_temp, repo, workspace) = repository();
    assert_discovery(&repo, &workspace);
    let command = [
        "/bin/sh",
        "-c",
        "git rev-parse --show-toplevel; for name in .git .codex .agents; do if touch \"$name/forbidden\" 2>/dev/null; then exit 31; fi; done",
    ];
    let output = run(&workspace, &[], &command).await;
    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        repo.to_str().expect("repo")
    );
    let identities = owned_ids(&workspace);
    assert_discovery(&repo, &workspace);
    assert_success(&run(&workspace, &[], &command).await);
    assert_eq!(owned_ids(&workspace), identities);
    assert_discovery(&repo, &workspace);
}

#[tokio::test]
async fn killed_test_supervisor_leaves_owned_metadata_discoverable_before_and_after_next_run() {
    if !prerequisites().await {
        return;
    }
    let (_temp, repo, workspace) = repository();
    let diagnostics = tempfile::NamedTempFile::new_in(&workspace).expect("diagnostics");
    let mut supervisor = sandbox(
        &workspace,
        &[],
        &[
            "/bin/sh",
            "-c",
            "git rev-parse --show-toplevel > discovered && printf ready > ready && exec sleep 60",
        ],
    )
    .stdout(Stdio::null())
    .stderr(diagnostics.reopen().expect("diagnostic file"))
    .spawn()
    .expect("spawn test-owned sandbox supervisor");
    tokio::time::timeout(TIMEOUT, async {
        while !workspace.join("ready").exists() {
            assert!(
                supervisor.try_wait().expect("poll supervisor").is_none(),
                "supervisor exited before readiness: {}",
                fs::read_to_string(diagnostics.path()).expect("diagnostics")
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("sandbox readiness timed out");
    assert_eq!(
        fs::read_to_string(workspace.join("discovered"))
            .expect("discovered repo")
            .trim(),
        repo.to_str().expect("repo")
    );
    let identities = owned_ids(&workspace);
    // Signal only the child this test just spawned, never a build or test PID.
    supervisor
        .start_kill()
        .expect("SIGKILL test-owned supervisor");
    let status = tokio::time::timeout(TIMEOUT, supervisor.wait())
        .await
        .expect("supervisor termination timed out")
        .expect("reap supervisor");
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert_discovery(&repo, &workspace);
    assert_eq!(owned_ids(&workspace), identities);
    let output = run(&workspace, &[], &["git", "rev-parse", "--show-toplevel"]).await;
    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        repo.to_str().expect("repo")
    );
    assert_eq!(owned_ids(&workspace), identities);
    assert_discovery(&repo, &workspace);
}

#[tokio::test]
async fn genuine_existing_metadata_keeps_its_inode_type_and_contents() {
    if !prerequisites().await {
        return;
    }
    let temp = tempfile::tempdir_in("/var/tmp").expect("test directory");
    for kind in [
        "empty-directory",
        "empty-file",
        "symlink",
        "nonempty-directory",
    ] {
        let case = temp.path().join(kind);
        let workspace = case.join("workspace");
        fs::create_dir_all(&workspace).expect("workspace");
        let metadata = workspace.join(".codex");
        let target = case.join("user-metadata");
        match kind {
            "empty-directory" => fs::create_dir(&metadata).expect("empty metadata"),
            "empty-file" => fs::write(&metadata, b"").expect("empty metadata file"),
            "symlink" => {
                fs::create_dir(&target).expect("symlink target");
                fs::write(target.join("important"), b"user data").expect("user data");
                symlink(&target, &metadata).expect("metadata symlink");
            }
            "nonempty-directory" => {
                fs::create_dir(&metadata).expect("metadata directory");
                fs::write(metadata.join("important"), b"user data").expect("user data");
            }
            _ => unreachable!("fixture kind"),
        }
        let before = metadata_id(&metadata);
        let output = run(&workspace, &[], &["/bin/true"]).await;
        if kind != "symlink" {
            assert_success(&output);
        } else if !output.status.success() {
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("writable symlink"),
                "unexpected symlink failure: {output:?}"
            );
        }
        assert_eq!(metadata_id(&metadata), before, "changed {kind}");
        assert!(!is_synthetic_metadata_directory(&metadata));
        match kind {
            "empty-directory" => {
                assert_eq!(fs::read_dir(&metadata).expect("empty directory").count(), 0)
            }
            "empty-file" => assert_eq!(fs::read(&metadata).expect("empty file"), b""),
            "symlink" => {
                assert_eq!(fs::read_link(&metadata).expect("symlink survives"), target);
                assert_eq!(
                    fs::read(metadata.join("important")).expect("user data survives"),
                    b"user data"
                );
            }
            "nonempty-directory" => assert_eq!(
                fs::read(metadata.join("important")).expect("user data survives"),
                b"user data"
            ),
            _ => unreachable!("fixture kind"),
        }
    }
}

#[tokio::test]
async fn ownership_authorities_stay_read_only_even_when_named_as_writable_roots() {
    if !prerequisites().await {
        return;
    }
    let temp = tempfile::tempdir_in("/var/tmp").expect("workspace");
    let authorities = synthetic_metadata_authority_paths()
        .into_iter()
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    assert!(!authorities.is_empty());
    let basename = temp
        .path()
        .file_name()
        .expect("unique basename")
        .to_str()
        .expect("basename");
    let probe_name = format!("authority-write-test-{basename}");
    let mut command = vec![
        "/bin/sh",
        "-c",
        "probe=$1; shift; for authority; do if printf forged > \"$authority/$probe\" 2>/dev/null; then exit 41; fi; done",
        "sh",
        &probe_name,
    ];
    command.extend(
        authorities
            .iter()
            .map(|path| path.to_str().expect("authority")),
    );
    let output = run(temp.path(), &authorities, &command).await;
    assert_success(&output);
    for authority in authorities {
        assert!(
            !authority.join(&probe_name).exists(),
            "ownership authority was writable"
        );
    }
}

#[tokio::test]
async fn genuine_metadata_writer_prepares_and_protects_its_future_publication_stage() {
    if !prerequisites().await {
        return;
    }
    let (_temp, _repo, workspace) = repository();
    for name in [".git", ".codex", ".agents"] {
        fs::create_dir(workspace.join(name)).expect("genuine empty metadata");
    }
    let before = [".git", ".codex", ".agents"].map(|name| metadata_id(&workspace.join(name)));
    assert_success(
        &run(
            &workspace,
            &[],
            &["/bin/sh", "-c", "printf ordinary > ordinary"],
        )
        .await,
    );
    assert_eq!(get_git_repo_root(&workspace), Some(workspace.clone()));
    assert_eq!(
        [".git", ".codex", ".agents"].map(|name| metadata_id(&workspace.join(name))),
        before
    );
    let stage = existing_synthetic_metadata_authorities()
        .expect("authenticated authorities")
        .into_iter()
        .find(|path| {
            path.file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .starts_with(".codex-synthetic-stage-v2-")
            }) && path
                .parent()
                .is_some_and(|parent| workspace.starts_with(parent))
        })
        .expect("stage exists despite all metadata being genuine");
    let sentinel = stage.join(format!(
        "test-owned-{}",
        workspace.file_name().unwrap().to_string_lossy()
    ));
    fs::write(&sentinel, b"test-owned sentinel").expect("create test-owned authority sentinel");
    let output = run(&workspace, std::slice::from_ref(&stage), &[
        "/bin/sh", "-c", "if printf forged > \"$1\" 2>/dev/null; then exit 51; fi; if rm \"$1\" 2>/dev/null; then exit 52; fi; if mv \"$1\" \"$1-moved\" 2>/dev/null; then exit 53; fi",
        "sh", sentinel.to_str().expect("sentinel path"),
    ]).await;
    assert_success(&output);
    assert_eq!(
        fs::read(&sentinel).expect("sentinel preserved"),
        b"test-owned sentinel"
    );
    fs::remove_file(sentinel).expect("remove only test-owned sentinel");
}

#[tokio::test]
async fn nss_home_as_an_extra_writable_root_keeps_its_codex_authority_protected() {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;
    if !prerequisites().await {
        return;
    }
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 65536];
    assert_eq!(
        unsafe {
            libc::getpwuid_r(
                libc::geteuid(),
                &mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut found,
            )
        },
        0
    );
    assert!(!found.is_null());
    let home = PathBuf::from(std::ffi::OsStr::from_bytes(
        unsafe { CStr::from_ptr(entry.pw_dir) }.to_bytes(),
    ));
    let probe = tempfile::tempdir_in(&home).expect("test-owned NSS home directory");
    let workspace = tempfile::tempdir_in("/var/tmp").expect("workspace");
    let output = run(workspace.path(), std::slice::from_ref(&home), &[
        "/bin/sh", "-c", "printf workspace > ordinary; printf home > \"$1/ordinary\"; if printf forged > \"$2/.codex/synthetic-metadata-v2/forged\" 2>/dev/null; then exit 71; fi",
        "sh", probe.path().to_str().expect("probe"), home.to_str().expect("NSS home"),
    ]).await;
    assert_success(&output);
    assert_eq!(
        fs::read(workspace.path().join("ordinary")).unwrap(),
        b"workspace"
    );
    assert_eq!(fs::read(probe.path().join("ordinary")).unwrap(), b"home");
}
