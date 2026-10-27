//! Durable ownership for empty directories used as Linux sandbox mount sources.
//!
//! Publication is one-way: a record is synced before the directory is renamed
//! into place, and published directories are never removed here. Restricted
//! commands must protect every [`synthetic_metadata_authority_paths`] entry,
//! including its writable ancestors, before they can run. Ownership records
//! contain kernel identities and initial mtimes, never paths or user contents.

use std::path::Path;

/// Whether this protected metadata name is a still-empty object published by Codex.
///
/// Unknown identities, changed mtimes, symlinks and registry errors all preserve
/// ordinary directory discovery. This deliberately does not recognize artifacts
/// left by older versions which did not establish durable ownership.
pub fn is_synthetic_metadata_directory(path: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        is_protected_metadata_path(path) && publication::is_owned(path).unwrap_or(false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        false
    }
}

#[cfg(target_os = "linux")]
fn is_protected_metadata_path(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some(".git" | ".agents" | ".codex")
    )
}

#[cfg(target_os = "linux")]
pub use publication::SyntheticMetadataProtection;
#[cfg(target_os = "linux")]
pub use publication::existing_synthetic_metadata_authorities;
#[cfg(target_os = "linux")]
pub use publication::initialize_synthetic_metadata_registry;
#[cfg(target_os = "linux")]
pub use publication::initialize_synthetic_metadata_storage;
#[cfg(target_os = "linux")]
pub use publication::prepare_synthetic_metadata_directory;
#[cfg(target_os = "linux")]
pub use publication::prepare_synthetic_metadata_staging;
#[cfg(target_os = "linux")]
pub use publication::prepare_synthetic_metadata_staging_for_policy;
#[cfg(target_os = "linux")]
pub use publication::synthetic_metadata_authority_paths;
#[cfg(target_os = "linux")]
pub use publication::synthetic_metadata_protection;
#[cfg(target_os = "linux")]
pub use publication::synthetic_metadata_registry_path;
#[cfg(target_os = "linux")]
pub use publication::validate_synthetic_metadata_writer;

#[cfg(target_os = "linux")]
#[path = "synthetic_metadata_publication.rs"]
mod publication;

#[cfg(target_os = "linux")]
mod linux {
    use sha2::Digest;
    use sha2::Sha256;
    use std::ffi::CStr;
    use std::ffi::CString;
    use std::fs::File;
    use std::io;
    use std::io::Read;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    const FORMAT: &[u8] = b"codex-synthetic-metadata-v1\n";
    const MAX_RECORD: u64 = 256;
    static NEXT_STAGE: AtomicU64 = AtomicU64::new(0);

    /// Protected directories which every restricted Linux command must mount
    /// read-only. Fixed locations intentionally ignore TMPDIR and other input.
    pub fn synthetic_metadata_authority_paths() -> Vec<PathBuf> {
        let uid = unsafe { libc::geteuid() };
        ["/var/tmp", "/tmp", "/dev/shm"]
            .map(|parent| Path::new(parent).join(format!("codex-synthetic-metadata-v1-{uid}")))
            .into()
    }

    /// The durable registry location, independent of process lifetime.
    pub fn synthetic_metadata_registry_path() -> PathBuf {
        synthetic_metadata_authority_paths().remove(0)
    }

    /// Validates already-present fixed authorities without creating or syncing
    /// anything. Only absent authority paths are skipped; malformed or
    /// inaccessible evidence is an error rather than trusted mount input.
    pub fn existing_synthetic_metadata_authorities() -> io::Result<Vec<PathBuf>> {
        let mut existing = Vec::new();
        for path in synthetic_metadata_authority_paths() {
            match open_authority(&path, AuthorityMode::ReadOnly) {
                Ok(_) => existing.push(path),
                Err(err)
                    if err.kind() == io::ErrorKind::NotFound
                        && std::fs::symlink_metadata(&path)
                            .is_err_and(|err| err.kind() == io::ErrorKind::NotFound) => {}
                Err(err) => return Err(err),
            }
        }
        Ok(existing)
    }

    /// Reserve an authority before a restricted writer can precreate its path.
    /// Existing valid state is only read; unknown objects are never initialized.
    pub(super) fn initialize_authority_if_absent(path: &Path) -> io::Result<File> {
        match open_authority(path, AuthorityMode::ReadOnly) {
            Ok(authority) => Ok(authority),
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && std::fs::symlink_metadata(path)
                        .is_err_and(|error| error.kind() == io::ErrorKind::NotFound) =>
            {
                open_authority(path, AuthorityMode::Initialize)
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn invalid(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    pub(super) fn c_path(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes()).map_err(|_| invalid("path contains NUL"))
    }

    pub(super) fn open_at(
        parent: &File,
        name: &CStr,
        flags: i32,
        mode: libc::mode_t,
    ) -> io::Result<File> {
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                mode,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    pub(super) fn open_directory(path: &Path) -> io::Result<File> {
        let path = c_path(path)?;
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    pub(super) fn read_bounded(file: File) -> io::Result<Vec<u8>> {
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() > MAX_RECORD
        {
            return Err(invalid("untrusted synthetic metadata record"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_RECORD + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_RECORD {
            return Err(invalid("oversized synthetic metadata record"));
        }
        Ok(bytes)
    }

    #[derive(Clone, Copy)]
    pub(super) enum AuthorityMode {
        Initialize,
        ReadOnly,
    }

    pub(super) fn open_authority(path: &Path, mode: AuthorityMode) -> io::Result<File> {
        let parent = open_directory(
            path.parent()
                .ok_or_else(|| invalid("authority has no parent"))?,
        )?;
        let metadata = parent.metadata()?;
        // OS-owned paths may map to the overflow UID in an unprivileged user
        // namespace. Compare to the trusted filesystem root in this namespace
        // rather than interpreting an unmapped owner as literal UID zero.
        let os_owner = open_directory(Path::new("/"))?.metadata()?.uid();
        if metadata.uid() != os_owner
            || (metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0)
        {
            return Err(invalid(
                "synthetic metadata authority parent is not protected",
            ));
        }
        let name = c_path(Path::new(
            path.file_name()
                .ok_or_else(|| invalid("authority has no name"))?,
        ))?;
        let directory = match open_at(
            &parent,
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            /*mode*/ 0,
        ) {
            Ok(directory) => directory,
            Err(err)
                if err.kind() == io::ErrorKind::NotFound
                    && matches!(mode, AuthorityMode::Initialize) =>
            {
                let (stage_name, _staged) = stage_authority(&parent)?;
                publish(&parent, &stage_name, &parent, &name)?;
                parent.sync_all()?;
                open_at(
                    &parent,
                    &name,
                    libc::O_RDONLY | libc::O_DIRECTORY,
                    /*mode*/ 0,
                )?
            }
            Err(err) => return Err(err),
        };
        validate_authority(&directory)?;
        if read_bounded(open_at(
            &directory,
            c"format",
            libc::O_RDONLY,
            /*mode*/ 0,
        )?)? != FORMAT
        {
            return Err(invalid("unknown synthetic metadata authority format"));
        }
        if matches!(mode, AuthorityMode::Initialize) {
            directory.sync_all()?;
            parent.sync_all()?;
        }
        Ok(directory)
    }

    fn validate_authority(directory: &File) -> io::Result<()> {
        let metadata = directory.metadata()?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o700 {
            return Err(invalid("untrusted synthetic metadata authority"));
        }
        Ok(())
    }

    // The final authority basename is never visible without a complete synced
    // format marker. Interruption can only orphan this private preparation.
    pub(super) fn stage_authority(parent: &File) -> io::Result<(CString, File)> {
        let name = loop {
            let name = unique_name("codex-synthetic-metadata-init-v1")?;
            if unsafe {
                libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), /*mode*/ 0o700)
            } == 0
            {
                break name;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        };
        let directory = open_at(
            parent,
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            /*mode*/ 0,
        )?;
        validate_authority(&directory)?;
        let mut marker = open_at(
            &directory,
            c"format",
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            /*mode*/ 0o600,
        )?;
        marker.write_all(FORMAT)?;
        marker.sync_all()?;
        if read_bounded(open_at(
            &directory,
            c"format",
            libc::O_RDONLY,
            /*mode*/ 0,
        )?)? != FORMAT
        {
            return Err(invalid("unknown synthetic metadata authority format"));
        }
        directory.sync_all()?;
        parent.sync_all()?;
        Ok((name, directory))
    }

    fn unique_name(prefix: &str) -> io::Result<CString> {
        let sequence = NEXT_STAGE.fetch_add(1, Ordering::Relaxed);
        CString::new(format!("{prefix}-{}-{sequence}", std::process::id()))
            .map_err(|_| invalid("invalid staging name"))
    }

    pub(super) enum Publication {
        Published,
        AlreadyExists,
    }

    pub(super) fn publish(
        source: &File,
        name: &CStr,
        destination: &File,
        target: &CStr,
    ) -> io::Result<Publication> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                source.as_raw_fd(),
                name.as_ptr(),
                destination.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if result != 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::AlreadyExists {
                Ok(Publication::AlreadyExists)
            } else {
                Err(error)
            };
        }
        Ok(Publication::Published)
    }

    // The directory FD is used both for identity and enumeration, so replacing
    // the leaf or an ancestor cannot attach an ownership record to another object.
    pub(super) fn identity(directory: &File) -> io::Result<Vec<u8>> {
        let metadata = directory.metadata()?;
        let mut bytes = Vec::from(b"CSM1".as_slice());
        bytes.extend_from_slice(&metadata.dev().to_le_bytes());
        bytes.extend_from_slice(&metadata.ino().to_le_bytes());
        let mut stat: libc::statx = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::statx(
                directory.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                libc::STATX_BTIME,
                &mut stat,
            )
        };
        if result == 0 && stat.stx_mask & libc::STATX_BTIME != 0 {
            bytes.push(1);
            bytes.extend_from_slice(&stat.stx_btime.tv_sec.to_le_bytes());
            bytes.extend_from_slice(&stat.stx_btime.tv_nsec.to_le_bytes());
            return Ok(bytes);
        }
        // file_handle is variable-sized. An aligned allocation holds its two
        // header fields followed by at most 128 bytes of opaque kernel identity.
        let mut handle = [0_u64; 17];
        let raw = handle.as_mut_ptr().cast::<u8>();
        unsafe { raw.cast::<u32>().write(128) };
        let mut mount_id = 0_i32;
        let result = unsafe {
            libc::syscall(
                libc::SYS_name_to_handle_at,
                directory.as_raw_fd(),
                c"".as_ptr(),
                raw,
                &mut mount_id,
                libc::AT_EMPTY_PATH,
            )
        };
        if result != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "filesystem has no reliable synthetic metadata identity: {}",
                    io::Error::last_os_error()
                ),
            ));
        }
        let length = unsafe { raw.cast::<u32>().read() } as usize;
        if length == 0 || length > 128 {
            return Err(invalid("invalid kernel file handle"));
        }
        bytes.push(2);
        bytes.extend_from_slice(unsafe { std::slice::from_raw_parts(raw.add(4), 4 + length) });
        Ok(bytes)
    }

    pub(super) fn record(directory: &File) -> io::Result<(CString, Vec<u8>)> {
        let identity = identity(directory)?;
        let key = format!("{:x}", Sha256::digest(&identity));
        let metadata = directory.metadata()?;
        let mut bytes = identity;
        bytes.extend_from_slice(&metadata.mtime().to_le_bytes());
        bytes.extend_from_slice(&metadata.mtime_nsec().to_le_bytes());
        Ok((
            CString::new(key).map_err(|_| invalid("invalid record key"))?,
            bytes,
        ))
    }

    pub(super) fn is_empty(directory: &File) -> io::Result<bool> {
        let mut buffer = [0_u8; 4096];
        loop {
            let count = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    directory.as_raw_fd(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                )
            };
            if count < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if count == 0 {
                return Ok(true);
            }
            let mut offset = 0;
            while offset < count as usize {
                if offset + 20 > count as usize {
                    return Err(invalid("invalid directory entry"));
                }
                let length =
                    u16::from_ne_bytes([buffer[offset + 16], buffer[offset + 17]]) as usize;
                if length < 20 || offset + length > count as usize {
                    return Err(invalid("invalid directory entry length"));
                }
                let name = &buffer[offset + 19..offset + length];
                let end = name
                    .iter()
                    .position(|byte| *byte == 0)
                    .ok_or_else(|| invalid("invalid directory entry name"))?;
                if &name[..end] != b"." && &name[..end] != b".." {
                    return Ok(false);
                }
                offset += length;
            }
        }
    }

    pub(super) fn is_owned(path: &Path) -> io::Result<bool> {
        let directory = open_directory(path)?;
        let registry =
            open_authority(&synthetic_metadata_registry_path(), AuthorityMode::ReadOnly)?;
        let (name, expected) = record(&directory)?;
        let recorded = read_bounded(open_at(&registry, &name, libc::O_RDONLY, /*mode*/ 0)?)?;
        if recorded != expected || !is_empty(&directory)? {
            return Ok(false);
        }
        // Enumeration may overlap a writer; require the initial mtime again.
        Ok(record(&directory)?.1 == expected)
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "synthetic_metadata_tests.rs"]
mod tests;
