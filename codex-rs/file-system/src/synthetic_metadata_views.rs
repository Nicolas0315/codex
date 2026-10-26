//! Rebuildable private caches of policy-filtered, path-free ownership evidence.

use super::super::linux::*;
use super::registry;
use sha2::Digest;
use sha2::Sha256;
use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ViewAccess {
    Readable,
    TraverseOnly,
}

const VIEWS: &CStr = c"private-public-views";

fn data_directory(view: &File) -> io::Result<File> {
    let data = open_at(
        view,
        c"records",
        libc::O_RDONLY | libc::O_DIRECTORY,
        /*mode*/ 0,
    )?;
    let metadata = data.metadata()?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o700 {
        return Err(invalid("untrusted filtered proof view"));
    }
    Ok(data)
}

fn matches_records(view: &File, records: &[(CString, Vec<u8>)]) -> io::Result<bool> {
    let data = data_directory(view)?;
    let mut actual = std::fs::read_dir(format!("/proc/self/fd/{}", data.as_raw_fd()))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    actual.sort();
    let mut expected = records
        .iter()
        .map(|(name, _)| OsString::from_vec(name.to_bytes().to_vec()))
        .collect::<Vec<_>>();
    expected.sort();
    if actual != expected {
        return Ok(false);
    }
    for (name, bytes) in records {
        if read_bounded(open_at(&data, name, libc::O_RDONLY, /*mode*/ 0)?)? != *bytes {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Views never establish ownership; they only copy already-validated evidence.
/// Corrupted or interrupted caches are retained and rebuilt under fresh names.
pub(super) fn filtered_view(
    source: &File,
    names: &[OsString],
    access: ViewAccess,
) -> io::Result<PathBuf> {
    let registry = registry::open(AuthorityMode::Initialize)?;
    let views = registry::authority(&registry, VIEWS, AuthorityMode::Initialize)?;
    let mut records = Vec::new();
    for name in names {
        let name =
            CString::new(name.as_bytes()).map_err(|_| invalid("invalid filtered record name"))?;
        let bytes = if name.as_c_str() == c"format" {
            let bytes = read_bounded(open_at(source, &name, libc::O_RDONLY, /*mode*/ 0)?)?;
            if bytes != b"codex-synthetic-metadata-v1\n" {
                return Err(invalid("invalid proof format"));
            }
            Some(bytes)
        } else {
            registry::ownership_record(source, &name)?
        };
        if let Some(bytes) = bytes {
            records.push((name, bytes));
        }
    }
    records.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    let mut digest = Sha256::new();
    digest.update(b"codex-filtered-proof-view-v1\n");
    digest.update([u8::from(access == ViewAccess::Readable)]);
    for (name, bytes) in &records {
        digest.update((name.as_bytes().len() as u64).to_le_bytes());
        digest.update(name.as_bytes());
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    let key = CString::new(format!("view-{:x}", digest.finalize()))
        .map_err(|_| invalid("invalid proof view key"))?;
    if access == ViewAccess::Readable
        && let Ok(view) = registry::authority(&views, &key, AuthorityMode::ReadOnly)
        && matches_records(&view, &records).unwrap_or(false)
    {
        return Ok(registry::path()?
            .join(OsString::from_vec(VIEWS.to_bytes().to_vec()))
            .join(OsString::from_vec(key.as_bytes().to_vec()))
            .join("records"));
    }
    let (temporary, view) = stage_authority(&views)?;
    if unsafe {
        libc::mkdirat(view.as_raw_fd(), c"records".as_ptr(), /*mode*/ 0o700)
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let data = data_directory(&view)?;
    for (name, bytes) in &records {
        if unsafe {
            libc::linkat(
                source.as_raw_fd(),
                name.as_ptr(),
                data.as_raw_fd(),
                name.as_ptr(),
                /*flags*/ 0,
            )
        } != 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EXDEV)
                || error.kind() == io::ErrorKind::Unsupported
            {
                super::write_record(&data, name, bytes)?;
            } else {
                return Err(error);
            }
        }
        if read_bounded(open_at(&data, name, libc::O_RDONLY, /*mode*/ 0)?)? != *bytes {
            return Err(invalid("proof source changed while filtering"));
        }
    }
    data.sync_all()?;
    if access == ViewAccess::TraverseOnly {
        // A denied parent with readable descendants must stay unlistable. Build
        // this rare view fresh; never relax a live cached directory to inspect it.
        if unsafe {
            libc::fchmod(data.as_raw_fd(), /*mode*/ 0o111)
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        data.sync_all()?;
    }
    view.sync_all()?;
    let key = if access == ViewAccess::Readable {
        key
    } else {
        super::random_name("traverse-proof-view")?
    };
    let name = match publish(&views, &temporary, &views, &key)? {
        Publication::Published => key,
        Publication::AlreadyExists => {
            if let Ok(existing) = registry::authority(&views, &key, AuthorityMode::ReadOnly)
                && matches_records(&existing, &records).unwrap_or(false)
            {
                key
            } else {
                let fresh = super::random_name("rebuilt-proof-view")?;
                if !matches!(
                    publish(&views, &temporary, &views, &fresh)?,
                    Publication::Published
                ) {
                    return Err(invalid("proof view reservation collided"));
                }
                fresh
            }
        }
    };
    views.sync_all()?;
    Ok(registry::path()?
        .join(OsString::from_vec(VIEWS.to_bytes().to_vec()))
        .join(OsString::from_vec(name.as_bytes().to_vec()))
        .join("records"))
}
