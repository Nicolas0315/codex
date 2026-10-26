//! Destination-local publication backed by durable native ownership records.

use super::linux::*;
use codex_protocol::permissions::FileSystemPath;
use codex_protocol::permissions::ReadDenyMatcher;
use codex_protocol::protocol::FileSystemSandboxPolicy;
use sha2::Digest;
use sha2::Sha256;
use std::ffi::CString;
use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::io::{self};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;

const TAG: &std::ffi::CStr = c"user.codex.synthetic-metadata-v2";

#[path = "synthetic_metadata_mount_table.rs"]
mod mounts;
#[path = "synthetic_metadata_protection.rs"]
mod protection;
#[path = "synthetic_metadata_registry.rs"]
mod registry;
#[path = "synthetic_metadata_views.rs"]
mod views;
use mounts::MountTable;
pub use protection::SyntheticMetadataProtection;
pub use protection::synthetic_metadata_protection;

/// Durable native authority and legacy authority paths. Ambient HOME is ignored.
pub fn synthetic_metadata_authority_paths() -> Vec<PathBuf> {
    let mut paths = registry::paths().unwrap_or_default();
    paths.extend(super::linux::synthetic_metadata_authority_paths());
    let Ok(mounts) = MountTable::read() else {
        return paths;
    };
    paths
        .into_iter()
        .flat_map(|path| mounts.aliases(&path))
        .collect()
}

/// The native registry beneath the effective user's NSS home directory.
pub fn synthetic_metadata_registry_path() -> PathBuf {
    registry::path().unwrap_or_else(|_| PathBuf::from("/nonexistent/codex-synthetic-metadata-v2"))
}

fn native_registry(initialize: bool) -> io::Result<File> {
    registry::open(if initialize {
        AuthorityMode::Initialize
    } else {
        AuthorityMode::ReadOnly
    })
}

/// Initialize durable native evidence before permitting a restricted writer.
pub fn initialize_synthetic_metadata_registry() -> io::Result<PathBuf> {
    // The legacy predicate still accepts this primary authority. Reserve it
    // before a writer can fabricate a valid-looking root and kernel records.
    super::linux::initialize_authority_if_absent(&super::linux::synthetic_metadata_registry_path())?;
    native_registry(/*initialize*/ true)?;
    registry::path()
}

fn random_name(prefix: &str) -> io::Result<CString> {
    let mut nonce = [0_u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    let suffix = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    CString::new(format!("{prefix}-{suffix}")).map_err(|_| invalid("invalid staging name"))
}

fn tag(directory: &File) -> io::Result<Vec<u8>> {
    let mut nonce = [0_u8; 32];
    let length = unsafe {
        libc::fgetxattr(
            directory.as_raw_fd(),
            TAG.as_ptr(),
            nonce.as_mut_ptr().cast(),
            nonce.len(),
        )
    };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    if length != nonce.len() as isize {
        return Err(invalid("invalid synthetic metadata nonce"));
    }
    // User xattrs can be copied onto a later object. Retain the immutable
    // kernel identity as well, so a copied nonce cannot authenticate a reused
    // inode. Filesystems without that identity still fail closed.
    let kernel = super::linux::identity(directory)?;
    let mut identity = b"CSM3".to_vec();
    identity.extend_from_slice(
        &u16::try_from(kernel.len())
            .map_err(|_| invalid("oversized kernel identity"))?
            .to_le_bytes(),
    );
    identity.extend_from_slice(&kernel);
    identity.extend_from_slice(&nonce);
    Ok(identity)
}

fn set_tag(directory: &File) -> io::Result<()> {
    let mut nonce = [0_u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    if unsafe {
        libc::fsetxattr(
            directory.as_raw_fd(),
            TAG.as_ptr(),
            nonce.as_ptr().cast(),
            nonce.len(),
            libc::XATTR_CREATE,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn identity_after_tag_write(directory: &File, result: io::Result<()>) -> io::Result<()> {
    match result {
        Ok(()) => super::linux::identity(directory).map(|_| ()),
        // Unsupported xattrs retain the reliable v1 kernel identity route.
        // Permission and storage failures must never silently downgrade.
        Err(error) if error.kind() == io::ErrorKind::Unsupported => {
            super::linux::identity(directory).map(|_| ())
        }
        Err(error) => Err(error),
    }
}

fn object_identity(directory: &File) -> io::Result<Vec<u8>> {
    match tag(directory) {
        Ok(identity) => Ok(identity),
        Err(error)
            if error.kind() == io::ErrorKind::Unsupported
                || error.raw_os_error() == Some(libc::ENODATA) =>
        {
            super::linux::identity(directory)
        }
        Err(error) => Err(error),
    }
}

fn nonce_record(directory: &File) -> io::Result<(CString, Vec<u8>)> {
    let identity = object_identity(directory)?;
    let key = CString::new(format!("{:x}", Sha256::digest(&identity)))
        .map_err(|_| invalid("invalid record name"))?;
    let metadata = directory.metadata()?;
    let mut bytes = identity;
    bytes.extend_from_slice(&metadata.mtime().to_le_bytes());
    bytes.extend_from_slice(&metadata.mtime_nsec().to_le_bytes());
    Ok((key, bytes))
}

fn write_record(registry: &File, key: &std::ffi::CStr, bytes: &[u8]) -> io::Result<()> {
    let mut file = open_at(
        registry,
        key,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        /*mode*/ 0o600,
    )?;
    file.write_all(bytes)?;
    file.sync_all()?;
    registry.sync_all()
}

fn mount_id(directory: &File) -> io::Result<u64> {
    let mut stat: libc::statx = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::statx(
            directory.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_MNT_ID,
            &mut stat,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if stat.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(invalid("mount identity unavailable"));
    }
    Ok(stat.stx_mnt_id)
}

fn stage_key(mounts: &MountTable, parent: &Path) -> io::Result<CString> {
    CString::new(format!("{:x}", Sha256::digest(mounts.key(parent))))
        .map_err(|_| invalid("invalid stage key"))
}

fn authenticated_aliases(record: &registry::StageRecord, mounts: &MountTable) -> Vec<PathBuf> {
    mounts
        .aliases(&record.path)
        .into_iter()
        .filter(|path| {
            open_directory(path).is_ok_and(|directory| {
                object_identity(&directory).is_ok_and(|identity| identity == record.identity)
            })
        })
        .collect()
}

fn protected_stage_aliases(
    record: &registry::StageRecord,
    mounts: &MountTable,
    candidates: Vec<PathBuf>,
) -> io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for path in candidates {
        let aliases = match mounts.protected_aliases(&path) {
            Ok(aliases) => aliases,
            // Historical stages can disappear with a test/workspace directory
            // after the initial identity check. Missing history is not evidence.
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        // Expansion re-resolves paths. Require the same authenticated object
        // again, so a racing genuine replacement is never returned as owned.
        if open_directory(&path).is_ok_and(|directory| {
            object_identity(&directory).is_ok_and(|identity| identity == record.identity)
        }) {
            paths.extend(aliases);
        }
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn staging_directory(
    parent_path: &Path,
    mounts: &MountTable,
    registry: &File,
) -> io::Result<PathBuf> {
    let parent = open_directory(parent_path)?;
    if !mounts.writable(parent_path) {
        return Err(io::Error::new(
            io::ErrorKind::ReadOnlyFilesystem,
            "staging parent is read-only",
        ));
    }
    // Serialize reservations against other trusted launchers. The index remains
    // private to the launcher; the command only needs path-free ownership data.
    if unsafe { libc::flock(registry.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let index = registry::authority(registry, registry::INDEX, AuthorityMode::Initialize)?;
    let parent_mount = mount_id(&parent)?;
    for ancestor in parent_path.ancestors() {
        let key = stage_key(mounts, ancestor)?;
        match registry::stage_record(&index, &key) {
            Ok(Some(record)) => {
                for alias in authenticated_aliases(&record, mounts) {
                    if alias.parent() != Some(ancestor) {
                        continue;
                    }
                    let directory = match open_directory(&alias) {
                        Ok(directory) => directory,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                        Err(error) => return Err(error),
                    };
                    if object_identity(&directory).is_ok_and(|identity| identity == record.identity)
                        && mount_id(&directory)? == parent_mount
                    {
                        return Ok(alias);
                    }
                }
            }
            Ok(None) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let name = random_name(".codex-synthetic-stage-v2")?;
    if unsafe {
        libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), /*mode*/ 0o700)
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let directory = open_at(
        &parent,
        &name,
        libc::O_RDONLY | libc::O_DIRECTORY,
        /*mode*/ 0,
    )?;
    identity_after_tag_write(&directory, set_tag(&directory))?;
    directory.sync_all()?;
    parent.sync_all()?;
    let path = parent_path.join(OsString::from_vec(name.as_bytes().to_vec()));
    registry::write_stage_record(
        &index,
        &stage_key(mounts, parent_path)?,
        &registry::StageRecord {
            path: path.clone(),
            identity: object_identity(&directory)?,
        },
    )?;
    Ok(path)
}

/// Establish a stage on this parent and each writable nested mount.
pub fn prepare_synthetic_metadata_staging(parent: &Path) -> io::Result<PathBuf> {
    let parent = parent.canonicalize()?;
    let mounts = MountTable::read()?;
    let registry = native_registry(/*initialize*/ true)?;
    for mount in mounts.nested_mounts(&parent) {
        staging_directory(&mount, &mounts, &registry)?;
    }
    staging_directory(&parent, &mounts, &registry)
}

/// Reserve stages only where the effective policy and mount both permit writes.
pub fn prepare_synthetic_metadata_staging_for_policy(
    policy: &FileSystemSandboxPolicy,
    cwd: &Path,
) -> io::Result<()> {
    let mounts = MountTable::read()?;
    let mut glob_policy = policy.clone();
    glob_policy
        .entries
        .retain(|entry| matches!(&entry.path, FileSystemPath::GlobPattern { .. }));
    let matcher = ReadDenyMatcher::try_new(&glob_policy, cwd)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let registry = native_registry(/*initialize*/ true)?;
    for root in policy.get_writable_roots_with_cwd(cwd) {
        if !root.root.as_path().is_dir() {
            continue;
        }
        let parent = root.root.as_path().canonicalize()?;
        for mount in mounts.nested_mounts(&parent) {
            if policy.can_write_path_with_cwd(&mount, cwd)
                && !matcher
                    .as_ref()
                    .is_some_and(|matcher| matcher.is_read_denied(&mount))
                && mounts.writable(&mount)
            {
                staging_directory(&mount, &mounts, &registry)?;
            }
        }
    }
    Ok(())
}

fn all_stages(registry: &File) -> io::Result<Vec<registry::StageRecord>> {
    let mut records = registry::stage_records(registry, /*legacy*/ true)?;
    match registry::authority(registry, registry::INDEX, AuthorityMode::ReadOnly) {
        Ok(index) => records.extend(registry::stage_records(&index, /*legacy*/ false)?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(records)
}

/// Existing evidence and authenticated destination-local stages, for inspection.
pub fn existing_synthetic_metadata_authorities() -> io::Result<Vec<PathBuf>> {
    let mounts = MountTable::read()?;
    let mut paths = super::linux::existing_synthetic_metadata_authorities()?;
    let registry = match native_registry(/*initialize*/ false) {
        Ok(registry) => registry,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(paths),
        Err(error) => return Err(error),
    };
    paths.extend(registry::paths()?);
    let mut aliases = Vec::new();
    for path in paths {
        aliases.extend(mounts.protected_aliases(&path)?);
    }
    for record in all_stages(&registry)? {
        aliases.extend(protected_stage_aliases(
            &record,
            &mounts,
            authenticated_aliases(&record, &mounts),
        )?);
    }
    aliases.sort();
    aliases.dedup();
    Ok(aliases)
}

pub(super) fn is_owned(path: &Path) -> io::Result<bool> {
    let directory = open_directory(path)?;
    let registry = native_registry(/*initialize*/ false)?;
    let (name, expected) = nonce_record(&directory)?;
    let public_record = registry::records(&registry, AuthorityMode::ReadOnly)
        .and_then(|records| open_at(&records, &name, libc::O_RDONLY, /*mode*/ 0));
    let file = match public_record {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            open_at(&registry, &name, libc::O_RDONLY, /*mode*/ 0)?
        }
        Err(error) => return Err(error),
    };
    let recorded = read_bounded(file)?;
    Ok(recorded == expected && is_empty(&directory)? && nonce_record(&directory)?.1 == expected)
}

/// Publish an empty directory without replacing any existing destination.
pub fn prepare_synthetic_metadata_directory(path: &Path) -> io::Result<()> {
    prepare_directory_with_tagger(path, set_tag)
}

fn prepare_directory_with_tagger(
    path: &Path,
    tagger: impl FnOnce(&File) -> io::Result<()>,
) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if !super::is_protected_metadata_path(path) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "only protected metadata names may be published",
        ));
    }
    let parent_path = path
        .parent()
        .ok_or_else(|| invalid("destination has no parent"))?
        .canonicalize()?;
    let parent = open_directory(&parent_path)?;
    let mounts = MountTable::read()?;
    let registry = native_registry(/*initialize*/ true)?;
    let stage_path = staging_directory(&parent_path, &mounts, &registry)?;
    let stage = open_directory(&stage_path)?;
    if mount_id(&parent)? != mount_id(&stage)? {
        return Err(invalid("staging mount changed before publication"));
    }
    let name = random_name("pending")?;
    if unsafe {
        libc::mkdirat(stage.as_raw_fd(), name.as_ptr(), /*mode*/ 0o755)
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let directory = open_at(
        &stage,
        &name,
        libc::O_RDONLY | libc::O_DIRECTORY,
        /*mode*/ 0,
    )?;
    identity_after_tag_write(&directory, tagger(&directory))?;
    let (key, bytes) = nonce_record(&directory)?;
    write_record(
        &registry::records(&registry, AuthorityMode::Initialize)?,
        &key,
        &bytes,
    )?;
    directory.sync_all()?;
    stage.sync_all()?;
    let target = c_path(Path::new(
        path.file_name()
            .ok_or_else(|| invalid("destination has no name"))?,
    ))?;
    if matches!(
        publish(&stage, &name, &parent, &target)?,
        Publication::AlreadyExists
    ) {
        return Ok(());
    }
    parent.sync_all()?;
    stage.sync_all()?;
    let published = open_at(
        &parent,
        &target,
        libc::O_RDONLY | libc::O_DIRECTORY,
        /*mode*/ 0,
    )?;
    if nonce_record(&published)?.1 != bytes
        || !is_empty(&published)?
        || nonce_record(&published)?.1 != bytes
    {
        return Err(invalid("synthetic metadata changed during publication"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "synthetic_metadata_publication_tests.rs"]
mod tests;
