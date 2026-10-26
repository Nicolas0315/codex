//! Protect durable ownership evidence from filesystem-restricted commands.

use codex_file_system::existing_synthetic_metadata_authorities;
use codex_file_system::initialize_synthetic_metadata_registry;
use codex_file_system::synthetic_metadata_authority_paths;
use codex_protocol::error::CodexErr;
use codex_protocol::error::Result;
use codex_protocol::protocol::FileSystemSandboxPolicy;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub(crate) fn validate_policy(policy: &FileSystemSandboxPolicy, policy_cwd: &Path) -> Result<()> {
    if policy.has_full_disk_write_access() {
        return Ok(());
    }
    // A read-only leaf mount prevents replacing the authority itself. Its
    // ancestors must also be outside actual write authority, otherwise a
    // command could rename an ancestor and replace the trusted registry path.
    for authority in synthetic_metadata_authority_paths() {
        for ancestor in authority.ancestors().skip(1) {
            let Some(parent) = ancestor.parent() else {
                continue;
            };
            if policy.can_write_path_with_cwd(parent, policy_cwd) {
                let parent_c = CString::new(parent.as_os_str().as_bytes())
                    .map_err(|_| CodexErr::Fatal("invalid ownership authority parent".into()))?;
                if unsafe {
                    libc::faccessat(
                        libc::AT_FDCWD,
                        parent_c.as_ptr(),
                        libc::W_OK,
                        libc::AT_EACCESS,
                    )
                } == 0
                {
                    return Err(CodexErr::Fatal(
                        "cannot protect synthetic metadata ownership from a writable ancestor"
                            .into(),
                    ));
                }
            }
        }
    }
    // A command with write access to a not-yet-created authority must not get
    // the opportunity to precreate it before a later trusted initializer.
    // Read-only commands need no registry creation on a read-only host.
    if synthetic_metadata_authority_paths().iter().any(|path| {
        policy.can_write_path_with_cwd(path, policy_cwd)
            && std::fs::symlink_metadata(path)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    }) {
        initialize_synthetic_metadata_registry().map_err(|error| {
            CodexErr::Fatal(format!(
                "cannot initialize synthetic metadata ownership: {error}"
            ))
        })?;
    }
    Ok(())
}

pub(crate) fn protect_arguments(
    policy: &FileSystemSandboxPolicy,
    args: &mut Vec<String>,
) -> Result<()> {
    if policy.has_full_disk_write_access() {
        return Ok(());
    }
    let Some(command) = args.iter().position(|arg| arg == "--") else {
        return Ok(());
    };
    let authorities = existing_synthetic_metadata_authorities().map_err(|error| {
        CodexErr::Fatal(format!(
            "cannot validate synthetic metadata ownership: {error}"
        ))
    })?;
    let mounts = authorities.into_iter().flat_map(|path| {
        let path = path.to_string_lossy().into_owned();
        ["--ro-bind".to_string(), path.clone(), path]
    });
    args.splice(command..command, mounts);
    Ok(())
}
