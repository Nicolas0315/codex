//! Prevent restricted writers from selecting a future administrator authority.

use super::super::linux::c_path;
use super::super::linux::invalid;
use super::MountTable;
use super::registry;
use codex_protocol::protocol::FileSystemSandboxPolicy;
use std::io;
use std::path::Path;

/// Refuse restricted commands that could fabricate an absent administrator
/// configuration or a still-trusted NSS authority. Existing state is protected
/// separately by mounts; this check never creates files or missing parents.
pub fn validate_synthetic_metadata_writer(
    policy: &FileSystemSandboxPolicy,
    cwd: &Path,
) -> io::Result<()> {
    validate_with_authorities(
        policy,
        cwd,
        &MountTable::read()?,
        &registry::Authorities::load()?,
    )
}

pub(super) fn validate_with_authorities(
    policy: &FileSystemSandboxPolicy,
    cwd: &Path,
    mounts: &MountTable,
    authorities: &registry::Authorities,
) -> io::Result<()> {
    // Reject invalid retained evidence before mount preparation can publish
    // targets which that same read set could no longer classify as owned.
    let _ = authorities.readers()?;
    validate_with_mounts(policy, cwd, authorities.configuration_path(), mounts)?;
    if authorities.configured {
        // The active store can be inspected without NSS, but a restricted
        // command cannot protect historical state at an unresolved NSS home.
        if !authorities.has_nss_home() {
            return Err(invalid("cannot protect unresolved NSS metadata authority"));
        }
        for path in authorities.optional_paths()? {
            validate_missing_path(policy, cwd, &path, mounts, MissingPath::NssAuthority)?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum MissingPath {
    Configuration,
    NssAuthority,
}

fn validate_with_mounts(
    policy: &FileSystemSandboxPolicy,
    cwd: &Path,
    path: &Path,
    mounts: &MountTable,
) -> io::Result<()> {
    validate_missing_path(policy, cwd, path, mounts, MissingPath::Configuration)
}

fn validate_missing_path(
    policy: &FileSystemSandboxPolicy,
    cwd: &Path,
    path: &Path,
    mounts: &MountTable,
    kind: MissingPath,
) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error)
            if matches!(kind, MissingPath::NssAuthority)
                && error.kind() == io::ErrorKind::NotADirectory
                && path.parent().is_some_and(|parent| {
                    std::fs::metadata(parent).is_ok_and(|metadata| !metadata.is_dir())
                }) =>
        {
            return Ok(());
        }
        Err(error) => return Err(error),
    }
    let writable_roots = policy.get_writable_roots_with_cwd(cwd);
    for alias in mounts.unchecked_aliases(path) {
        let can_create = match kind {
            MissingPath::Configuration => writable_roots.iter().any(|root| {
                alias.starts_with(root.root.as_path()) || root.root.as_path().starts_with(&alias)
            }),
            MissingPath::NssAuthority => {
                policy.can_write_path_with_cwd(&alias, cwd)
                    || writable_roots
                        .iter()
                        .any(|root| root.root.as_path().starts_with(&alias))
            }
        };
        if !can_create {
            continue;
        }
        // A deeper grant may cause trusted mount-target preparation to create
        // missing parents. Check the first slot the host can actually create.
        for parent in alias.ancestors().skip(1) {
            match std::fs::metadata(parent) {
                Ok(metadata) if metadata.is_dir() => {}
                Ok(_) => return Err(invalid("configuration ancestor is not a directory")),
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            }
            if mounts.writable(parent) {
                let parent = c_path(parent)?;
                if unsafe {
                    libc::faccessat(
                        libc::AT_FDCWD,
                        parent.as_ptr(),
                        libc::W_OK,
                        libc::AT_EACCESS,
                    )
                } == 0
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "restricted writer could create an uninitialized metadata authority",
                    ));
                }
                let error = io::Error::last_os_error();
                if !matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem
                ) {
                    return Err(error);
                }
            }
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "synthetic_metadata_configuration_protection_tests.rs"]
mod tests;
