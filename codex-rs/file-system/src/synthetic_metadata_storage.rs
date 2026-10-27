//! Administrator-owned configuration for durable native metadata storage.

use super::super::super::linux::invalid;
use super::super::super::linux::open_at;
use super::super::super::linux::open_directory;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs::File;
use std::fs::Metadata;
use std::io;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

// Bound parsing and history discovery without silently dropping old evidence.
const MAX_CONFIGURATION_BYTES: u64 = 64 * 1024;
const MAX_RETAINED_ROOTS: usize = 32;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Configuration {
    pub(super) write_root: PathBuf,
    pub(super) retained_read_roots: Vec<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigurationFile {
    version: u32,
    write_root: PathBuf,
    #[serde(default)]
    retained_read_roots: Vec<PathBuf>,
}

pub(super) fn configuration_path() -> PathBuf {
    let uid = unsafe { libc::geteuid() };
    PathBuf::from(format!("/etc/codex/synthetic-metadata/{uid}.toml"))
}

pub(super) fn load() -> io::Result<Option<Configuration>> {
    load_from_root(&open_directory(Path::new("/"))?, unsafe { libc::geteuid() })
}

fn validate_owner_and_mode(metadata: &Metadata, owner: libc::uid_t) -> io::Result<()> {
    if metadata.uid() != owner || metadata.mode() & 0o022 != 0 {
        return Err(invalid(
            "untrusted synthetic metadata configuration ownership or mode",
        ));
    }
    Ok(())
}

// The caller supplies an already trusted root FD. Production always uses '/';
// fixtures can exercise the same walk without administering the host's /etc.
fn load_from_root(root: &File, uid: libc::uid_t) -> io::Result<Option<Configuration>> {
    let metadata = root.metadata()?;
    let owner = metadata.uid();
    validate_owner_and_mode(&metadata, owner)?;
    let mut directory = root.try_clone()?;
    for name in [c"etc", c"codex", c"synthetic-metadata"] {
        directory = match open_at(
            &directory,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            /*mode*/ 0,
        ) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        validate_owner_and_mode(&directory.metadata()?, owner)?;
    }
    let name = std::ffi::CString::new(format!("{uid}.toml"))
        .map_err(|_| invalid("invalid synthetic metadata configuration filename"))?;
    let file = match open_at(&directory, &name, libc::O_RDONLY, /*mode*/ 0) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    validate_owner_and_mode(&metadata, owner)?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > MAX_CONFIGURATION_BYTES {
        return Err(invalid(
            "invalid synthetic metadata configuration file type, links or size",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONFIGURATION_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONFIGURATION_BYTES {
        return Err(invalid("oversized synthetic metadata configuration"));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| invalid("synthetic metadata configuration is not UTF-8"))?;
    let configuration: ConfigurationFile =
        toml::from_str(text).map_err(|_| invalid("invalid synthetic metadata configuration"))?;
    if configuration.version != 1 || configuration.retained_read_roots.len() > MAX_RETAINED_ROOTS {
        return Err(invalid(
            "unsupported synthetic metadata configuration version or root count",
        ));
    }
    let mut roots = HashSet::new();
    for path in
        std::iter::once(&configuration.write_root).chain(configuration.retained_read_roots.iter())
    {
        if !path.is_absolute()
            || path.as_os_str().as_bytes().contains(&0)
            || path
                .components()
                .any(|component| component == Component::ParentDir)
            || !roots.insert(path)
        {
            return Err(invalid(
                "invalid or duplicate synthetic metadata storage root",
            ));
        }
    }
    Ok(Some(Configuration {
        write_root: configuration.write_root,
        retained_read_roots: configuration.retained_read_roots,
    }))
}

#[cfg(test)]
#[path = "synthetic_metadata_storage_tests.rs"]
mod tests;
