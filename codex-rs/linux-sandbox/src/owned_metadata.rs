//! Protect durable ownership evidence from filesystem-restricted commands.

use codex_file_system::initialize_synthetic_metadata_registry;
use codex_file_system::synthetic_metadata_authority_paths;
use codex_file_system::synthetic_metadata_protection;
use codex_file_system::validate_synthetic_metadata_writer;
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
    validate_synthetic_metadata_writer(policy, policy_cwd).map_err(|error| {
        CodexErr::Fatal(format!("cannot protect synthetic metadata writer: {error}"))
    })?;
    let writable_roots = policy.get_writable_roots_with_cwd(policy_cwd);
    let mut mounted_masks = policy
        .get_unreadable_roots_with_cwd(policy_cwd)
        .into_iter()
        .map(|path| path.as_path().to_path_buf())
        .collect::<Vec<_>>();
    for root in &writable_roots {
        mounted_masks.extend(
            root.read_only_subpaths
                .iter()
                .map(|path| path.as_path().to_path_buf()),
        );
        mounted_masks.extend(
            root.protected_metadata_names
                .iter()
                .map(|name| root.root.as_path().join(name)),
        );
    }
    // A read-only/denied carveout is a mountpoint, so its writable parent
    // cannot rename it. This includes the default NSS HOME/.codex carveout.
    // Ancestors above those mounts still need an independent replacement check.
    for authority in synthetic_metadata_authority_paths() {
        for ancestor in authority.ancestors().skip(1) {
            let Some(parent) = ancestor.parent() else {
                continue;
            };
            if !policy.can_write_path_with_cwd(ancestor, policy_cwd)
                && mounted_masks.iter().any(|mask| ancestor.starts_with(mask))
            {
                continue;
            }
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
    if !writable_roots.is_empty()
        || synthetic_metadata_authority_paths().iter().any(|path| {
            policy.can_write_path_with_cwd(path, policy_cwd)
                && std::fs::symlink_metadata(path)
                    .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        })
    {
        initialize_synthetic_metadata_registry().map_err(|error| {
            CodexErr::Fatal(format!(
                "cannot initialize synthetic metadata ownership: {error}"
            ))
        })?;
    }
    if !writable_roots.is_empty() {
        codex_file_system::prepare_synthetic_metadata_staging_for_policy(policy, policy_cwd)
            .map_err(|error| {
                CodexErr::Fatal(format!(
                    "cannot prepare synthetic metadata staging: {error}"
                ))
            })?;
    }
    Ok(())
}

pub(crate) fn protect_arguments(
    policy: &FileSystemSandboxPolicy,
    policy_cwd: &Path,
    args: &mut Vec<String>,
) -> Result<()> {
    if policy.has_full_disk_write_access() {
        return Ok(());
    }
    let Some(command) = args.iter().position(|arg| arg == "--") else {
        return Ok(());
    };
    let protection = synthetic_metadata_protection(policy, policy_cwd).map_err(|error| {
        CodexErr::Fatal(format!(
            "cannot validate synthetic metadata ownership: {error}"
        ))
    })?;
    let mut mounts = Vec::new();
    let path_string = |path: &Path| -> Result<String> {
        path.to_str()
            .map(str::to_owned)
            .ok_or_else(|| CodexErr::Fatal("ownership mount path is not UTF-8".into()))
    };
    // A public projection prevents a registry bind from reopening denied child
    // paths or disclosing private workspace history. Source paths still resolve
    // in bubblewrap's original root while targets are built in the new root.
    for (registry_path, records, public_records) in protection.registries {
        let registry = path_string(&registry_path)?;
        mounts.extend([
            "--perms".into(),
            "700".into(),
            "--tmpfs".into(),
            registry.clone(),
        ]);
        let mut parents = records
            .iter()
            .filter_map(|record| record.parent())
            .filter(|parent| *parent != registry_path.as_path())
            .map(Path::to_path_buf)
            .collect::<Vec<_>>();
        parents.sort();
        parents.dedup();
        for parent in parents {
            let perms = if policy.can_read_path_with_cwd(&parent, policy_cwd) {
                "700"
            } else {
                "111"
            };
            mounts.extend([
                "--perms".into(),
                perms.into(),
                "--dir".into(),
                path_string(&parent)?,
            ]);
        }
        for record in records {
            let record = path_string(&record)?;
            mounts.extend(["--ro-bind".into(), record.clone(), record]);
        }
        if let Some((source, target)) = public_records {
            mounts.extend([
                "--ro-bind".into(),
                path_string(&source)?,
                path_string(&target)?,
            ]);
        }
        mounts.extend(["--remount-ro".into(), registry]);
    }
    for (source, target) in protection.bindings {
        mounts.extend([
            "--ro-bind".into(),
            path_string(&source)?,
            path_string(&target)?,
        ]);
    }
    for path in protection.read_only {
        let path = path_string(&path)?;
        mounts.extend(["--ro-bind".into(), path.clone(), path]);
    }
    for path in protection.hidden_directories {
        let path = path_string(&path)?;
        mounts.extend([
            "--perms".into(),
            "700".into(),
            "--tmpfs".into(),
            path.clone(),
            "--remount-ro".into(),
            path,
        ]);
    }
    for path in protection.hidden_files {
        mounts.extend(["--ro-bind".into(), "/dev/null".into(), path_string(&path)?]);
    }
    args.splice(command..command, mounts);
    Ok(())
}
