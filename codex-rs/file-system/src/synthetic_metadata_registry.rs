//! Native, durable ownership records and the private staging index.

#[path = "synthetic_metadata_authorities.rs"]
mod authorities;
#[path = "synthetic_metadata_storage.rs"]
mod storage;
pub(super) use authorities::Authorities;

use super::super::linux::*;
use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;

pub(super) const INDEX: &CStr = c"private-stage-index";
pub(super) const PUBLIC: &CStr = c"public-records";

fn nss_home() -> io::Result<PathBuf> {
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 65536];
    let result = unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut found,
        )
    };
    if result != 0 || found.is_null() || entry.pw_dir.is_null() {
        return Err(invalid("cannot resolve native synthetic metadata home"));
    }
    let home = PathBuf::from(OsString::from_vec(
        unsafe { CStr::from_ptr(entry.pw_dir) }.to_bytes().to_vec(),
    ));
    if !home.is_absolute() {
        return Err(invalid("synthetic metadata home is not absolute"));
    }
    Ok(home)
}

pub(super) fn paths() -> io::Result<Vec<PathBuf>> {
    Authorities::load()?.paths()
}

pub(super) fn path() -> io::Result<PathBuf> {
    Authorities::load()?.active_path()
}

pub(super) fn configuration_path() -> PathBuf {
    storage::configuration_path()
}

fn validate_native_chain(path: &Path) -> io::Result<()> {
    let os_owner = open_directory(Path::new("/"))?.metadata()?.uid();
    for ancestor in path.ancestors() {
        let metadata = open_directory(ancestor)?.metadata()?;
        if (metadata.uid() != unsafe { libc::geteuid() } && metadata.uid() != os_owner)
            || (metadata.mode() & 0o022 != 0
                && !(metadata.uid() == os_owner && metadata.mode() & 0o1000 != 0))
        {
            return Err(invalid(
                "synthetic metadata path is not protected native storage",
            ));
        }
    }
    Ok(())
}

pub(super) fn authority(parent: &File, name: &CStr, mode: AuthorityMode) -> io::Result<File> {
    let directory = match open_at(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY,
        /*mode*/ 0,
    ) {
        Ok(directory) => directory,
        Err(error)
            if matches!(mode, AuthorityMode::Initialize)
                && error.kind() == io::ErrorKind::NotFound =>
        {
            let (temporary, _directory) = stage_authority(parent)?;
            publish(parent, &temporary, parent, name)?;
            parent.sync_all()?;
            open_at(
                parent,
                name,
                libc::O_RDONLY | libc::O_DIRECTORY,
                /*mode*/ 0,
            )?
        }
        Err(error) => return Err(error),
    };
    let metadata = directory.metadata()?;
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o700
        || read_bounded(open_at(
            &directory,
            c"format",
            libc::O_RDONLY,
            /*mode*/ 0,
        )?)? != b"codex-synthetic-metadata-v1\n"
    {
        return Err(invalid("untrusted native ownership authority"));
    }
    Ok(directory)
}

pub(super) fn open(mode: AuthorityMode) -> io::Result<File> {
    Authorities::load()?.open_write(mode)
}

pub(super) fn storage_parent(path: &Path) -> io::Result<(File, CString)> {
    if !path.is_absolute() {
        return Err(invalid("registry path is not absolute"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("registry has no parent"))?
        .canonicalize()?;
    validate_native_chain(&parent)?;
    let name = path
        .file_name()
        .ok_or_else(|| invalid("registry has no name"))?;
    Ok((open_directory(&parent)?, c_path(Path::new(name))?))
}

pub(super) fn open_path(path: &Path, mode: AuthorityMode) -> io::Result<File> {
    let (parent, name) = storage_parent(path)?;
    let registry = authority(&parent, &name, mode)?;
    if matches!(mode, AuthorityMode::Initialize) {
        initialize_public_records(&registry)?;
    }
    Ok(registry)
}

fn open_home(home: &Path, mode: AuthorityMode) -> io::Result<File> {
    let home = home.canonicalize()?;
    validate_native_chain(&home)?;
    let home_directory = open_directory(&home)?;
    let metadata = home_directory.metadata()?;
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(invalid(
            "synthetic metadata home owner differs from effective user",
        ));
    }
    let codex_path = home.join(".codex");
    // An existing home may be mounted read-only even when its .codex symlink
    // resolves to writable native storage. Do not attempt mkdir on that home.
    let (codex, created_codex) = match codex_path.canonicalize() {
        Ok(codex) => (codex, false),
        Err(error)
            if matches!(mode, AuthorityMode::Initialize)
                && error.kind() == io::ErrorKind::NotFound
                && std::fs::symlink_metadata(&codex_path)
                    .is_err_and(|error| error.kind() == io::ErrorKind::NotFound) =>
        {
            let created = if unsafe {
                libc::mkdirat(
                    home_directory.as_raw_fd(),
                    c".codex".as_ptr(),
                    /*mode*/ 0o700,
                )
            } == 0
            {
                true
            } else {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(error);
                }
                false
            };
            (codex_path.canonicalize()?, created)
        }
        Err(error) => return Err(error),
    };
    validate_native_chain(&codex)?;
    let codex_directory = open_directory(&codex)?;
    let registry = authority(&codex_directory, c"synthetic-metadata-v2", mode)?;
    if matches!(mode, AuthorityMode::Initialize) {
        initialize_public_records(&registry)?;
        if created_codex {
            home_directory.sync_all()?;
        }
    }
    Ok(registry)
}

pub(super) fn records(registry: &File, mode: AuthorityMode) -> io::Result<File> {
    authority(registry, PUBLIC, mode)
}

fn valid_kernel_identity(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"CSM1") || bytes.len() <= 20 {
        return false;
    }
    match bytes[20] {
        1 => {
            bytes.len() == 33
                && u32::from_le_bytes([bytes[29], bytes[30], bytes[31], bytes[32]]) < 1_000_000_000
        }
        2 => (26..=153).contains(&bytes.len()),
        _ => false,
    }
}

pub(super) fn ownership_record(directory: &File, name: &CStr) -> io::Result<Option<Vec<u8>>> {
    use sha2::Digest;
    use sha2::Sha256;
    let mut before: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            &mut before,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(error)
        };
    }
    if before.st_mode & libc::S_IFMT != libc::S_IFREG
        || before.st_uid != unsafe { libc::geteuid() }
        || before.st_mode & 0o777 != 0o600
        || !(20..=256).contains(&before.st_size)
    {
        return Ok(None);
    }
    let file = match open_at(directory, name, libc::O_RDONLY, /*mode*/ 0) {
        Ok(file) => file,
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ELOOP) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let actual = file.metadata()?;
    if (actual.dev(), actual.ino()) != (before.st_dev, before.st_ino) {
        return Ok(None);
    }
    let bytes = match read_bounded(file) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::InvalidData => return Ok(None),
        Err(error) => return Err(error),
    };
    let Some((identity, timestamps)) = bytes.split_last_chunk::<16>() else {
        return Ok(None);
    };
    let valid_layout = if identity.starts_with(b"CSM3") && identity.len() >= 38 {
        let length = usize::from(u16::from_le_bytes([identity[4], identity[5]]));
        identity.len() == 6 + length + 32 && valid_kernel_identity(&identity[6..6 + length])
    } else {
        valid_kernel_identity(identity)
    };
    // Unreleased CSM2 records lacked an immutable kernel identity. Preserve
    // those files, but never migrate or adopt them as ownership evidence.
    if !valid_layout {
        return Ok(None);
    }
    let nanoseconds = i64::from_le_bytes([
        timestamps[8],
        timestamps[9],
        timestamps[10],
        timestamps[11],
        timestamps[12],
        timestamps[13],
        timestamps[14],
        timestamps[15],
    ]);
    if !(0..1_000_000_000).contains(&nanoseconds)
        || format!("{:x}", Sha256::digest(identity)).as_bytes() != name.to_bytes()
    {
        return Ok(None);
    }
    Ok(Some(bytes))
}

pub(super) fn initialize_public_records(registry: &File) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let public = records(registry, AuthorityMode::Initialize)?;
    match open_at(
        registry,
        c"public-records-migrated",
        libc::O_RDONLY,
        /*mode*/ 0,
    ) {
        Ok(marker) => {
            if !read_bounded(marker)?.is_empty() {
                return Err(invalid("invalid public records migration marker"));
            }
            return Ok(());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    // Unreleased v2 builds wrote path-free records in the registry root.
    // Copy only validated records; retain every old file and all stage paths.
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", registry.as_raw_fd()))? {
        let name = entry?.file_name();
        if name.as_bytes().len() != 64 || !name.as_bytes().iter().all(u8::is_ascii_hexdigit) {
            continue;
        }
        let name = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| invalid("invalid public record name"))?;
        let Some(bytes) = ownership_record(registry, &name)? else {
            continue;
        };
        let temporary = super::random_name("migration")?;
        super::write_record(&public, &temporary, &bytes)?;
        if matches!(
            publish(&public, &temporary, &public, &name)?,
            Publication::AlreadyExists
        ) && read_bounded(open_at(&public, &name, libc::O_RDONLY, /*mode*/ 0)?)? != bytes
        {
            return Err(invalid("native ownership record migration collision"));
        }
    }
    public.sync_all()?;
    match open_at(
        registry,
        c"public-records-migrated",
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        /*mode*/ 0o600,
    ) {
        Ok(marker) => marker.sync_all()?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if !read_bounded(open_at(
                registry,
                c"public-records-migrated",
                libc::O_RDONLY,
                /*mode*/ 0,
            )?)?
            .is_empty()
            {
                return Err(invalid("invalid public records migration marker"));
            }
        }
        Err(error) => return Err(error),
    }
    registry.sync_all()
}

const MAX_STAGE_RECORD: u64 = 8192;

pub(super) struct StageRecord {
    pub(super) path: PathBuf,
    pub(super) identity: Vec<u8>,
}

pub(super) fn stage_record(parent: &File, name: &CStr) -> io::Result<Option<StageRecord>> {
    use std::io::Read;
    let file = open_at(parent, name, libc::O_RDONLY, /*mode*/ 0)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > MAX_STAGE_RECORD
    {
        return Err(invalid("untrusted staging record"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_STAGE_RECORD + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STAGE_RECORD {
        return Err(invalid("oversized staging record"));
    }
    // Incomplete reservations cannot authenticate any directory.
    let (identity, path) = if bytes.starts_with(b"CSS3") && bytes.len() >= 6 {
        let length = usize::from(u16::from_le_bytes([bytes[4], bytes[5]]));
        if length < 4 || bytes.len() <= 6 + length {
            return Ok(None);
        }
        (&bytes[6..6 + length], &bytes[6 + length..])
    } else if bytes.starts_with(b"CSM2") && bytes.len() > 52 {
        (&bytes[..52], &bytes[52..])
    } else {
        return Ok(None);
    };
    let path = PathBuf::from(OsString::from_vec(path.to_vec()));
    if !path.is_absolute() {
        return Err(invalid("relative staging authority"));
    }
    Ok(Some(StageRecord {
        path,
        identity: identity.to_vec(),
    }))
}

pub(super) fn stage_records(parent: &File, legacy: bool) -> io::Result<Vec<StageRecord>> {
    use std::os::unix::ffi::OsStrExt;
    let mut records = Vec::new();
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", parent.as_raw_fd()))? {
        let name = entry?.file_name();
        // Reservations are renamed into hash keys only after they are synced.
        // Opening their transient names can race that rename. They are never
        // published index entries, including after an interrupted writer.
        let committed = if legacy {
            name.as_bytes().starts_with(b"stage-")
        } else {
            name.as_bytes().len() == 64 && name.as_bytes().iter().all(u8::is_ascii_hexdigit)
        };
        if !committed {
            continue;
        }
        let name = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| invalid("invalid stage record name"))?;
        if let Some(record) = stage_record(parent, &name)? {
            records.push(record);
        }
    }
    Ok(records)
}

pub(super) fn write_stage_record(index: &File, key: &CStr, record: &StageRecord) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    let mut bytes = b"CSS3".to_vec();
    bytes.extend_from_slice(
        &u16::try_from(record.identity.len())
            .map_err(|_| invalid("oversized stage identity"))?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&record.identity);
    bytes.extend_from_slice(record.path.as_os_str().as_bytes());
    if bytes.len() as u64 > MAX_STAGE_RECORD {
        return Err(invalid("staging path exceeds record limit"));
    }
    // Validate an existing reservation before replacing it. Only index records,
    // never workspace entries, use replacing rename.
    match stage_record(index, key) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let temporary = super::random_name("reservation")?;
    let mut file = open_at(
        index,
        &temporary,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        /*mode*/ 0o600,
    )?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    if unsafe {
        libc::renameat(
            index.as_raw_fd(),
            temporary.as_ptr(),
            index.as_raw_fd(),
            key.as_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    index.sync_all()
}

#[cfg(test)]
#[path = "synthetic_metadata_registry_tests.rs"]
mod tests;
