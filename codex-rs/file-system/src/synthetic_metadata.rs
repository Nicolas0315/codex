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
        is_protected_metadata_path(path) && linux::is_owned(path).unwrap_or(false)
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
pub use linux::existing_synthetic_metadata_authorities;
#[cfg(target_os = "linux")]
pub use linux::initialize_synthetic_metadata_registry;
#[cfg(target_os = "linux")]
pub use linux::prepare_synthetic_metadata_directory;
#[cfg(target_os = "linux")]
pub use linux::synthetic_metadata_authority_paths;
#[cfg(target_os = "linux")]
pub use linux::synthetic_metadata_registry_path;

#[cfg(target_os = "linux")]
mod linux {
    use sha2::Digest;
    use sha2::Sha256;
    use std::ffi::CStr;
    use std::ffi::CString;
    use std::fs::File;
    use std::fs::OpenOptions;
    use std::io;
    use std::io::Read;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::OpenOptionsExt;
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

    /// Initializes the durable registry and available fixed staging authorities.
    ///
    /// Authorities must remain protected from restricted commands even when the
    /// workspace itself is writable. Existing unmarked authorities are rejected.
    pub fn initialize_synthetic_metadata_registry() -> io::Result<PathBuf> {
        let paths = synthetic_metadata_authority_paths();
        for path in &paths {
            match open_authority(path, AuthorityMode::Initialize) {
                Ok(_) => {}
                Err(err) if optional_authority_unavailable(path, &err) => {}
                Err(err) => return Err(err),
            }
        }
        Ok(paths[0].clone())
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

    fn optional_authority_unavailable(path: &Path, error: &io::Error) -> bool {
        !path.starts_with("/var/tmp")
            && matches!(
                error.raw_os_error(),
                Some(libc::ENOENT | libc::EACCES | libc::EPERM | libc::EROFS)
            )
            && std::fs::symlink_metadata(path)
                .is_err_and(|err| err.kind() == io::ErrorKind::NotFound)
    }

    fn invalid(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    fn c_path(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes()).map_err(|_| invalid("path contains NUL"))
    }

    fn open_at(parent: &File, name: &CStr, flags: i32, mode: libc::mode_t) -> io::Result<File> {
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

    fn open_directory(path: &Path) -> io::Result<File> {
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

    fn read_bounded(file: File) -> io::Result<Vec<u8>> {
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

    enum Publication {
        Published,
        AlreadyExists,
    }

    fn publish(
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
    fn identity(directory: &File) -> io::Result<Vec<u8>> {
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

    fn record(directory: &File) -> io::Result<(CString, Vec<u8>)> {
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

    fn is_empty(directory: &File) -> io::Result<bool> {
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

    /// Creates an owned empty directory if the destination does not exist.
    ///
    /// Only protected metadata names may be newly published. Existing objects
    /// (including symlinks and other names) are preserved. Filesystems without
    /// birth times or generation-bearing file handles, or without a protected
    /// same-filesystem staging authority, fail before publication. Nothing here
    /// removes published paths, including after errors or process termination.
    pub fn prepare_synthetic_metadata_directory(path: &Path) -> io::Result<()> {
        // The destination leaf must not be followed; its parent aliases have
        // normal path semantics and are pinned by this directory descriptor.
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NONBLOCK)
            .open(
                path.parent()
                    .ok_or_else(|| invalid("destination has no parent"))?,
            )?;
        let name = c_path(Path::new(
            path.file_name()
                .ok_or_else(|| invalid("destination has no name"))?,
        ))?;
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
        {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound {
            return Err(error);
        }
        if !super::is_protected_metadata_path(path) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "only protected metadata names may be published",
            ));
        }
        initialize_synthetic_metadata_registry()?;
        let registry =
            open_authority(&synthetic_metadata_registry_path(), AuthorityMode::ReadOnly)?;
        let device = parent.metadata()?.dev();
        let mut stage_root = None;
        for authority in synthetic_metadata_authority_paths() {
            match open_authority(&authority, AuthorityMode::ReadOnly) {
                Ok(candidate) if candidate.metadata()?.dev() == device => {
                    stage_root = Some(candidate);
                    break;
                }
                Ok(_) => {}
                Err(err) if optional_authority_unavailable(&authority, &err) => {}
                Err(err) => return Err(err),
            }
        }
        let stage_root = stage_root.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "no protected synthetic metadata staging authority on destination filesystem",
            )
        })?;
        let stage_name = loop {
            let name = unique_name("stage")?;
            if unsafe {
                libc::mkdirat(stage_root.as_raw_fd(), name.as_ptr(), /*mode*/ 0o755)
            } == 0
            {
                break name;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        };
        let staged = open_at(
            &stage_root,
            &stage_name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            /*mode*/ 0,
        )?;
        let (key, bytes) = record(&staged)?;
        match open_at(
            &registry,
            &key,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            /*mode*/ 0o600,
        ) {
            Ok(mut file) => {
                file.write_all(&bytes)?;
                file.sync_all()?;
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                if read_bounded(open_at(&registry, &key, libc::O_RDONLY, /*mode*/ 0)?)? != bytes {
                    return Err(invalid("synthetic metadata identity collision"));
                }
            }
            Err(err) => return Err(err),
        }
        registry.sync_all()?;
        if read_bounded(open_at(&registry, &key, libc::O_RDONLY, /*mode*/ 0)?)? != bytes {
            return Err(invalid(
                "synthetic metadata registration changed before publication",
            ));
        }
        staged.sync_all()?;
        stage_root.sync_all()?;
        if matches!(
            publish(&stage_root, &stage_name, &parent, &name)?,
            Publication::AlreadyExists
        ) {
            return Ok(());
        }
        parent.sync_all()?;
        stage_root.sync_all()?;
        let published = open_at(
            &parent,
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            /*mode*/ 0,
        )?;
        if record(&published)?.1 != bytes
            || !is_empty(&published)?
            || record(&published)?.1 != bytes
        {
            return Err(invalid(
                "synthetic metadata publication changed identity or contents",
            ));
        }
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "synthetic_metadata_tests.rs"]
mod tests;
