use crate::policy_transforms::should_require_platform_sandbox;
use codex_protocol::models::PermissionProfile;
use codex_protocol::protocol::FileSystemSandboxPolicy;
use std::io::ErrorKind;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;
use std::thread;
use std::time::Duration;
use std::time::Instant;

const SYSTEM_BWRAP_PROGRAM: &str = "bwrap";
const MISSING_BWRAP_WARNING: &str = concat!(
    "Codex could not find bubblewrap on PATH. ",
    "Install bubblewrap with your OS package manager. ",
    "See the sandbox prerequisites: ",
    "https://developers.openai.com/codex/concepts/sandboxing#prerequisites. ",
    "Codex will use the bundled bubblewrap in the meantime.",
);
const USER_NAMESPACE_WARNING: &str =
    "Codex's Linux sandbox uses bubblewrap and needs access to create user namespaces.";
pub(crate) const WSL1_BWRAP_WARNING: &str = concat!(
    "Codex's Linux sandbox uses bubblewrap, which is not supported on WSL1 ",
    "because WSL1 cannot create the required user namespaces. ",
    "Use WSL2 for sandboxed shell commands."
);
const USER_NAMESPACE_FAILURES: [&str; 4] = [
    "loopback: Failed RTM_NEWADDR",
    "loopback: Failed RTM_NEWLINK",
    "setting up uid map: Permission denied",
    "No permissions to create a new namespace",
];
const SYSTEM_BWRAP_PROBE_TIMEOUT: Duration = Duration::from_millis(500);
const SYSTEM_BWRAP_PROBE_POLL_INTERVAL: Duration = Duration::from_millis(50);
const SYSTEM_BWRAP_PROBE_STDERR_LIMIT_BYTES: u64 = 64 * 1024;

pub fn system_bwrap_warning(
    permission_profile: &PermissionProfile,
    sandbox_policy_cwd: &Path,
) -> Option<String> {
    if !should_warn_about_system_bwrap(permission_profile) {
        return None;
    }

    let (file_system_policy, _) = permission_profile.to_runtime_permissions();
    let system_bwrap_path = find_system_bwrap_in_path(&file_system_policy, sandbox_policy_cwd);
    system_bwrap_warning_for_path(system_bwrap_path.as_deref())
}

fn should_warn_about_system_bwrap(permission_profile: &PermissionProfile) -> bool {
    let (file_system_policy, network_policy) = permission_profile.to_runtime_permissions();
    should_require_platform_sandbox(
        &file_system_policy,
        network_policy,
        /*has_managed_network_requirements*/ false,
    )
}

fn system_bwrap_warning_for_path(system_bwrap_path: Option<&Path>) -> Option<String> {
    if is_wsl1() {
        return Some(WSL1_BWRAP_WARNING.to_string());
    }

    let Some(system_bwrap_path) = system_bwrap_path else {
        return Some(MISSING_BWRAP_WARNING.to_string());
    };

    if !system_bwrap_has_user_namespace_access(system_bwrap_path, SYSTEM_BWRAP_PROBE_TIMEOUT) {
        return Some(USER_NAMESPACE_WARNING.to_string());
    }

    None
}

fn system_bwrap_has_user_namespace_access(system_bwrap_path: &Path, timeout: Duration) -> bool {
    let mut child = match Command::new(system_bwrap_path)
        .args([
            "--unshare-user",
            "--unshare-net",
            "--ro-bind",
            "/",
            "/",
            "/bin/true",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return true,
    };

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stderr = child.stderr.take().map_or_else(Vec::new, |stderr| {
                    let fd = stderr.as_raw_fd();
                    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                    if flags < 0
                        || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
                    {
                        return Vec::new();
                    }

                    let mut bytes = Vec::new();
                    let mut stderr = stderr.take(SYSTEM_BWRAP_PROBE_STDERR_LIMIT_BYTES);
                    if let Err(err) = stderr.read_to_end(&mut bytes)
                        && err.kind() != ErrorKind::WouldBlock
                    {
                        return bytes;
                    }
                    bytes
                });
                let output = Output {
                    status,
                    stdout: Vec::new(),
                    stderr,
                };
                return output.status.success() || !is_user_namespace_failure(&output);
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return true;
                }
                thread::sleep(SYSTEM_BWRAP_PROBE_POLL_INTERVAL);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return true;
            }
        }
    }
}

pub(crate) fn is_wsl1() -> bool {
    std::fs::read_to_string("/proc/version")
        .is_ok_and(|proc_version| proc_version_indicates_wsl1(&proc_version))
}

fn proc_version_indicates_wsl1(proc_version: &str) -> bool {
    let proc_version = proc_version.to_ascii_lowercase();
    let mut remaining = proc_version.as_str();
    while let Some(marker) = remaining.find("wsl") {
        let version_start = marker + "wsl".len();
        let version_digits: String = remaining[version_start..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if let Ok(version) = version_digits.parse::<u32>() {
            return version == 1;
        }
        remaining = &remaining[version_start..];
    }

    proc_version.contains("microsoft") && !proc_version.contains("microsoft-standard")
}

fn is_user_namespace_failure(output: &Output) -> bool {
    let stderr = String::from_utf8_lossy(&output.stderr);
    USER_NAMESPACE_FAILURES
        .iter()
        .any(|failure| stderr.contains(failure))
}

pub fn find_system_bwrap_in_path(
    file_system_policy: &FileSystemSandboxPolicy,
    sandbox_policy_cwd: &Path,
) -> Option<PathBuf> {
    let search_path = std::env::var_os("PATH")?;
    find_system_bwrap_in_search_paths(
        std::env::split_paths(&search_path),
        file_system_policy,
        sandbox_policy_cwd,
    )
}

fn find_system_bwrap_in_search_paths(
    search_paths: impl IntoIterator<Item = PathBuf>,
    file_system_policy: &FileSystemSandboxPolicy,
    sandbox_policy_cwd: &Path,
) -> Option<PathBuf> {
    let search_path = std::env::join_paths(search_paths).ok()?;
    let workspace = std::fs::canonicalize(sandbox_policy_cwd).ok()?;
    let unrestricted = file_system_policy.has_full_disk_write_access();
    let writable_roots: Vec<PathBuf> = file_system_policy
        .get_writable_roots_with_cwd(sandbox_policy_cwd)
        .iter()
        .filter_map(|root| std::fs::canonicalize(root.root.as_path()).ok())
        .collect();
    // The command's working directory is tool-controlled. Only the trusted
    // policy context can decide whether an executable is outside agent control.
    // Check parents too: a read-only executable can be replaced through a
    // writable directory, and a write root can use a different symlink alias.
    let is_untrusted = |path: &Path| {
        path.ancestors().any(|ancestor| {
            ancestor.starts_with(&workspace)
                || ancestor.starts_with(sandbox_policy_cwd)
                || (!unrestricted
                    && file_system_policy.can_write_path_with_cwd(ancestor, sandbox_policy_cwd))
                || writable_roots.iter().any(|root| ancestor.starts_with(root))
        })
    };
    which::which_in_all(SYSTEM_BWRAP_PROGRAM, Some(search_path), sandbox_policy_cwd)
        .ok()?
        .find_map(|path| {
            let canonical_path = std::fs::canonicalize(&path).ok()?;
            // Network-only sandboxes can allow all filesystem writes. In that
            // mode only an OS-protected installation is outside agent control;
            // root cannot rely on Unix ownership and must use the bundled helper.
            if unrestricted
                && (unsafe { libc::geteuid() } == 0
                    || !canonical_path.ancestors().all(|ancestor| {
                        std::fs::metadata(ancestor).is_ok_and(|metadata| {
                            metadata.uid() == 0 && metadata.mode() & 0o022 == 0
                        })
                    }))
            {
                return None;
            }
            if is_untrusted(&path) || is_untrusted(&canonical_path) {
                None
            } else {
                Some(canonical_path)
            }
        })
}

#[cfg(test)]
#[path = "bwrap_tests.rs"]
mod tests;
