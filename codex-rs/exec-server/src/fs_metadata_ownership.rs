//! Receiving-host ownership classification after a successful sandbox metadata read.

use codex_protocol::permissions::FileSystemPath;
use codex_protocol::permissions::FileSystemSandboxPolicy;
use codex_protocol::permissions::ReadDenyMatcher;
use std::io;
use std::path::Path;

use crate::fs_helper::FsHelperPayload;
use crate::fs_helper::FsHelperRequest;

pub(crate) fn augment_metadata_ownership(
    policy: &FileSystemSandboxPolicy,
    cwd: &Path,
    request: &FsHelperRequest,
    payload: &mut FsHelperPayload,
) -> io::Result<()> {
    let (FsHelperRequest::GetMetadata(params), FsHelperPayload::GetMetadata(response)) =
        (request, payload)
    else {
        return Ok(());
    };
    response.is_synthetic_directory = false;
    if !response.is_directory || response.is_symlink {
        return Ok(());
    }
    let path = params.path.to_abs_path()?;
    if !policy.can_read_path_with_cwd(path.as_path(), cwd) {
        return Ok(());
    }
    // Exact entries keep their normal precedence; only glob matching needs a
    // separate matcher because can_read_path_with_cwd resolves concrete entries.
    let mut globs = policy.clone();
    globs
        .entries
        .retain(|entry| matches!(&entry.path, FileSystemPath::GlobPattern { .. }));
    let matcher = ReadDenyMatcher::try_new(&globs, cwd)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    if matcher.is_some_and(|matcher| matcher.is_read_denied(path.as_path())) {
        return Ok(());
    }
    response.is_synthetic_directory =
        codex_file_system::is_synthetic_metadata_directory(path.as_path());
    Ok(())
}

#[cfg(test)]
#[path = "fs_metadata_ownership_tests.rs"]
mod tests;
