//! One byte-preserving mount snapshot per ownership operation.

use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;

struct Mount {
    device: Vec<u8>,
    root: PathBuf,
    point: PathBuf,
    read_only: bool,
}
pub(super) struct MountTable(Vec<Mount>);

fn mount_path(field: &[u8]) -> io::Result<PathBuf> {
    let mut bytes = Vec::new();
    let mut input = field.iter().copied();
    while let Some(byte) = input.next() {
        if byte != b'\\' {
            bytes.push(byte);
            continue;
        }
        let [
            Some(a @ b'0'..=b'7'),
            Some(b @ b'0'..=b'7'),
            Some(c @ b'0'..=b'7'),
        ] = [input.next(), input.next(), input.next()]
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid mount path escape",
            ));
        };
        let value = u16::from(a - b'0') * 64 + u16::from(b - b'0') * 8 + u16::from(c - b'0');
        bytes.push(
            u8::try_from(value).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid mount path byte")
            })?,
        );
    }
    Ok(PathBuf::from(OsString::from_vec(bytes)))
}

fn containing_mount<'p, 'm>(path: &'p Path, mounts: &'m [Mount]) -> Option<(&'m Mount, &'p Path)> {
    mounts
        .iter()
        .filter_map(|mount| {
            path.strip_prefix(&mount.point)
                .ok()
                .map(|relative| (mount, relative))
        })
        .max_by_key(|(mount, _)| mount.point.components().count())
}

fn translate(path: &Path, mounts: &[Mount]) -> Vec<PathBuf> {
    let Some((source, relative)) = containing_mount(path, mounts) else {
        return vec![path.to_path_buf()];
    };
    let coordinate = source.root.join(relative);
    let mut aliases = vec![path.to_path_buf()];
    for mount in mounts {
        if mount.device == source.device
            && let Ok(relative) = coordinate.strip_prefix(&mount.root)
        {
            aliases.push(mount.point.join(relative));
        }
    }
    aliases.sort();
    aliases.dedup();
    aliases
}

impl MountTable {
    pub(super) fn read() -> io::Result<Self> {
        Self::parse(&std::fs::read("/proc/self/mountinfo")?)
    }

    fn parse(table: &[u8]) -> io::Result<Self> {
        let mounts = table
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| {
                let fields = line
                    .split(u8::is_ascii_whitespace)
                    .filter(|field| !field.is_empty())
                    .collect::<Vec<_>>();
                if fields.len() < 6 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid mount table",
                    ));
                }
                Ok(Mount {
                    device: fields[2].to_vec(),
                    root: mount_path(fields[3])?,
                    point: mount_path(fields[4])?,
                    read_only: fields[5]
                        .split(|byte| *byte == b',')
                        .any(|flag| flag == b"ro"),
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self(mounts))
    }

    // The device and filesystem coordinate are stable through bind aliases.
    // Hashing this key lets ancestor lookup avoid enumerating prior workspaces.
    pub(super) fn key(&self, path: &Path) -> Vec<u8> {
        let Some((source, relative)) = containing_mount(path, &self.0) else {
            return path.as_os_str().as_encoded_bytes().to_vec();
        };
        let mut key = source.device.clone();
        key.push(0);
        key.extend_from_slice(source.root.join(relative).as_os_str().as_encoded_bytes());
        key
    }

    pub(super) fn unchecked_aliases(&self, path: &Path) -> Vec<PathBuf> {
        translate(path, &self.0)
    }

    pub(super) fn descendant_aliases(&self, path: &Path) -> Vec<(PathBuf, PathBuf)> {
        let Some((source, relative)) = containing_mount(path, &self.0) else {
            return Vec::new();
        };
        let coordinate = source.root.join(relative);
        self.0
            .iter()
            .filter_map(|mount| {
                if mount.device != source.device {
                    return None;
                }
                let relative = mount.root.strip_prefix(&coordinate).ok()?;
                if relative.as_os_str().is_empty() {
                    return None;
                }
                Some((path.join(relative), mount.point.clone()))
            })
            .collect()
    }

    pub(super) fn aliases(&self, path: &Path) -> Vec<PathBuf> {
        let resolved = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let expected = std::fs::metadata(&resolved).ok();
        let mut aliases = translate(&resolved, &self.0)
            .into_iter()
            .filter(|alias| {
                expected.as_ref().is_none_or(|expected| {
                    std::fs::metadata(alias).is_ok_and(|actual| {
                        (actual.dev(), actual.ino()) == (expected.dev(), expected.ino())
                    })
                })
            })
            .collect::<Vec<_>>();
        aliases.push(path.to_path_buf());
        aliases.sort();
        aliases.dedup();
        aliases
    }

    pub(super) fn protected_aliases(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        let mut paths = self.aliases(path);
        let path = path.canonicalize()?;
        let Some((source, relative)) = containing_mount(&path, &self.0) else {
            return Ok(paths);
        };
        let coordinate = source.root.join(relative);
        for mount in &self.0 {
            if mount.device == source.device
                && let Ok(relative) = mount.root.strip_prefix(&coordinate)
                && let Ok(expected) = std::fs::metadata(path.join(relative))
                && let Ok(actual) = std::fs::metadata(&mount.point)
                && (expected.dev(), expected.ino()) == (actual.dev(), actual.ino())
            {
                paths.push(mount.point.clone());
            }
        }
        paths.sort();
        paths.dedup();
        Ok(paths)
    }

    pub(super) fn nested_mounts(&self, root: &Path) -> Vec<PathBuf> {
        let mut paths = vec![root.to_path_buf()];
        paths.extend(
            self.0
                .iter()
                .filter(|mount| {
                    mount.point.starts_with(root) && !mount.read_only && mount.point.is_dir()
                })
                .map(|mount| mount.point.clone()),
        );
        paths.sort_by_key(|path| path.components().count());
        paths.dedup();
        paths
    }

    pub(super) fn writable(&self, path: &Path) -> bool {
        self.0
            .iter()
            .filter(|mount| path.starts_with(&mount.point))
            .max_by_key(|mount| mount.point.components().count())
            .is_some_and(|mount| !mount.read_only)
    }
}

#[cfg(test)]
#[path = "synthetic_metadata_mounts_tests.rs"]
mod tests;
