//! Policy-scoped mounts and bounded, path-free proof projections.

use super::super::linux::*;
use super::MountTable;
use super::all_stages;
use super::native_registry;
use super::object_identity;
use super::registry;
use super::views;
use codex_protocol::permissions::FileSystemPath;
use codex_protocol::permissions::ReadDenyMatcher;
use codex_protocol::protocol::FileSystemSandboxPolicy;
use codex_utils_absolute_path::AbsolutePathBuf;
use std::ffi::CString;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;

type RegistryProjection = (PathBuf, Vec<PathBuf>, Option<(PathBuf, PathBuf)>);

/// Mount protection selected without granting read access to unrelated history.
pub struct SyntheticMetadataProtection {
    pub read_only: Vec<PathBuf>,
    pub bindings: Vec<(PathBuf, PathBuf)>,
    pub registries: Vec<RegistryProjection>,
    pub hidden_directories: Vec<PathBuf>,
    pub hidden_files: Vec<PathBuf>,
}

/// Hide private storage and its existing mount aliases without walking cache
/// contents. Exact grants can be mounted later below a denied private parent.
fn hide_private_storage(
    protection: &mut SyntheticMetadataProtection,
    mounts: &MountTable,
    path: &Path,
    readable_roots: &[AbsolutePathBuf],
) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Err(invalid("private ownership storage is not a directory")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    let aliases = mounts.protected_aliases(path)?;
    let mut hidden = aliases.clone();
    hidden.extend(
        readable_roots
            .iter()
            .map(AbsolutePathBuf::as_path)
            .filter(|grant| aliases.iter().any(|alias| grant.starts_with(alias)))
            .map(Path::to_path_buf),
    );
    for path in hidden {
        match std::fs::metadata(&path) {
            Ok(metadata) if metadata.is_dir() => protection.hidden_directories.push(path),
            Ok(_) => protection.hidden_files.push(path),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn public_record_names(directory: &File) -> io::Result<Vec<OsString>> {
    let mut records = Vec::new();
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
        let name = entry?.file_name();
        let bytes = name.as_bytes();
        if bytes == b"format" || (bytes.len() == 64 && bytes.iter().all(u8::is_ascii_hexdigit)) {
            let name_c =
                CString::new(bytes).map_err(|_| invalid("invalid ownership record name"))?;
            if bytes == b"format" {
                read_bounded(open_at(
                    directory,
                    &name_c,
                    libc::O_RDONLY,
                    /*mode*/ 0,
                )?)?;
                records.push(name);
            } else if registry::ownership_record(directory, &name_c)?.is_some() {
                records.push(name);
            }
        }
    }
    Ok(records)
}

fn glob_search_roots(pattern: &str) -> Vec<PathBuf> {
    let end = pattern
        .char_indices()
        .find_map(|(index, ch)| {
            matches!(ch, '*' | '?' | '[' | ']' | '{' | '}' | '\\').then_some(index)
        })
        .unwrap_or(pattern.len());
    let prefix = &pattern[..end];
    let directory_end = prefix.rfind('/').unwrap_or(0);
    let root = if directory_end == 0 {
        PathBuf::from("/")
    } else {
        PathBuf::from(&prefix[..directory_end])
    };
    let mut roots = vec![root.clone()];
    let mut ancestor = root.as_path();
    let mut suffix = Vec::new();
    loop {
        match ancestor.canonicalize() {
            Ok(mut resolved) => {
                for component in suffix.iter().rev() {
                    resolved.push(component);
                }
                roots.push(resolved);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let Some(name) = ancestor.file_name() else {
                    roots.push(PathBuf::from("/"));
                    break;
                };
                suffix.push(name.to_os_string());
                let Some(parent) = ancestor.parent() else {
                    roots.push(PathBuf::from("/"));
                    break;
                };
                ancestor = parent;
            }
            Err(_) => {
                roots.push(PathBuf::from("/"));
                break;
            }
        }
    }
    roots.sort();
    roots.dedup();
    roots
}

pub fn synthetic_metadata_protection(
    policy: &FileSystemSandboxPolicy,
    cwd: &Path,
) -> io::Result<SyntheticMetadataProtection> {
    protection_with_mounts(policy, cwd, &MountTable::read()?)
}

pub(super) fn protection_with_mounts(
    policy: &FileSystemSandboxPolicy,
    cwd: &Path,
    mounts: &MountTable,
) -> io::Result<SyntheticMetadataProtection> {
    let mut protection = SyntheticMetadataProtection {
        read_only: Vec::new(),
        bindings: Vec::new(),
        registries: Vec::new(),
        hidden_directories: Vec::new(),
        hidden_files: Vec::new(),
    };
    let writable_roots = policy.get_writable_roots_with_cwd(cwd);
    let readable_roots = policy.get_readable_roots_with_cwd(cwd);
    let denied = policy.get_unreadable_roots_with_cwd(cwd);
    let glob_roots = policy
        .get_unreadable_globs_with_cwd(cwd)
        .iter()
        .flat_map(|pattern| glob_search_roots(pattern))
        .collect::<Vec<_>>();
    let mut glob_policy = policy.clone();
    glob_policy
        .entries
        .retain(|entry| matches!(&entry.path, FileSystemPath::GlobPattern { .. }));
    let glob_matcher = ReadDenyMatcher::try_new(&glob_policy, cwd)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let read_allowed = |path: &Path| {
        policy.can_read_path_with_cwd(path, cwd)
            && !glob_matcher
                .as_ref()
                .is_some_and(|matcher| matcher.is_read_denied(path))
    };
    let public_read_allowed = |path: &Path| {
        read_allowed(path)
            && path
                .canonicalize()
                .is_ok_and(|resolved| resolved.as_path() == path || read_allowed(&resolved))
    };
    let intersects_denied_children = |path: &Path| {
        glob_roots
            .iter()
            .any(|root| root.starts_with(path) || path.starts_with(root))
            || denied
                .iter()
                .any(|denied| denied.as_path().starts_with(path))
    };
    let has_denied_children = |path: &Path| {
        intersects_denied_children(path)
            || path
                .canonicalize()
                .map_or(true, |path| intersects_denied_children(&path))
    };
    let writable_candidate = |path: &Path| {
        mounts.writable(path)
            && !glob_matcher
                .as_ref()
                .is_some_and(|matcher| matcher.is_read_denied(path))
            && writable_roots.iter().any(|root| {
                path.starts_with(root.root.as_path()) || root.root.as_path().starts_with(path)
            })
            && (policy.can_write_path_with_cwd(path, cwd)
                || path
                    .parent()
                    .is_some_and(|parent| policy.can_write_path_with_cwd(parent, cwd))
                || writable_roots
                    .iter()
                    .any(|root| root.root.as_path().starts_with(path)))
    };
    let primary = super::super::linux::synthetic_metadata_registry_path();
    if mounts.unchecked_aliases(&primary).iter().any(|alias| {
        read_allowed(alias)
            || readable_roots
                .iter()
                .any(|root| root.as_path().starts_with(alias) && read_allowed(root.as_path()))
    }) {
        // A reader must not see private caches created by a later launcher
        // through an authority root that was absent during this preparation.
        views::prepare_cache_authority(&primary, mounts)?;
    }
    match native_registry(/*initialize*/ false) {
        Ok(registry) => {
            let path = registry::path()?;
            let public = path.join(OsString::from_vec(registry::PUBLIC.to_bytes().to_vec()));
            let public_directory = match registry::records(&registry, AuthorityMode::ReadOnly) {
                Ok(directory) => Some(directory),
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => return Err(error),
            };
            let mut public_names = None;
            for alias in mounts.aliases(&path) {
                if !read_allowed(&alias) {
                    continue;
                }
                let format = alias.join("format");
                let files = if public_read_allowed(&format) {
                    vec![format]
                } else {
                    Vec::new()
                };
                let public_target = alias.join("public-records");
                let public_binding = if let Some(directory) = &public_directory {
                    if !has_denied_children(&alias) {
                        Some((public.clone(), public_target))
                    } else {
                        let names = match &public_names {
                            Some(names) => names,
                            None => public_names.insert(public_record_names(directory)?),
                        };
                        let selected = names
                            .iter()
                            .filter(|name| public_read_allowed(&public_target.join(name)))
                            .cloned()
                            .collect::<Vec<_>>();
                        let access = if read_allowed(&public_target) {
                            views::ViewAccess::Readable
                        } else {
                            views::ViewAccess::TraverseOnly
                        };
                        Some((
                            views::filtered_view(directory, &selected, access)?,
                            public_target,
                        ))
                    }
                } else {
                    let names = public_record_names(&registry)?;
                    let selected = names
                        .into_iter()
                        .filter(|name| public_read_allowed(&alias.join(name)))
                        .collect::<Vec<_>>();
                    protection.bindings.push((
                        views::filtered_view(&registry, &selected, views::ViewAccess::Readable)?,
                        alias,
                    ));
                    continue;
                };
                protection.registries.push((alias, files, public_binding));
            }
            if let Some(directory) = &public_directory {
                for alias in mounts.aliases(&public) {
                    if !read_allowed(&alias)
                        || protection
                            .registries
                            .iter()
                            .any(|(root, _, _)| alias.starts_with(root))
                    {
                        continue;
                    }
                    if !has_denied_children(&alias) {
                        protection.read_only.push(alias);
                    } else {
                        let names = match &public_names {
                            Some(names) => names,
                            None => public_names.insert(public_record_names(directory)?),
                        };
                        let selected = names
                            .iter()
                            .filter(|name| public_read_allowed(&alias.join(name)))
                            .cloned()
                            .collect::<Vec<_>>();
                        protection.bindings.push((
                            views::filtered_view(
                                directory,
                                &selected,
                                views::ViewAccess::Readable,
                            )?,
                            alias,
                        ));
                    }
                }
                for (_, alias) in mounts.descendant_aliases(&public) {
                    protection.read_only.push(alias);
                }
            }
            let private = path.join(OsString::from_vec(registry::INDEX.to_bytes().to_vec()));
            let private_views = path.join(OsString::from_vec(views::VIEWS.to_bytes().to_vec()));
            hide_private_storage(&mut protection, mounts, &private, &readable_roots)?;
            // Older versions placed caches here. Retain those directories and
            // apply the same private role to their aliases and explicit grants.
            hide_private_storage(&mut protection, mounts, &private_views, &readable_roots)?;
            for entry in std::fs::read_dir(format!("/proc/self/fd/{}", registry.as_raw_fd()))? {
                let name = entry?.file_name();
                if name.as_bytes().starts_with(b"stage-") {
                    let path = path.join(name);
                    if read_allowed(&path) {
                        protection
                            .hidden_files
                            .extend(mounts.unchecked_aliases(&path));
                    }
                }
            }
            // Independently bound old root records remain protected; stage paths
            // and private-index aliases remain hidden even outside the root view.
            for (source, alias) in mounts.descendant_aliases(&path) {
                if source.starts_with(&public) {
                    continue;
                }
                let name = source
                    .file_name()
                    .map(std::os::unix::ffi::OsStrExt::as_bytes)
                    .unwrap_or_default();
                if !source.starts_with(&private)
                    && !source.starts_with(&private_views)
                    && (name == b"format"
                        || (name.len() == 64 && name.iter().all(u8::is_ascii_hexdigit)))
                {
                    protection.read_only.push(alias);
                } else if alias.is_dir() {
                    protection.hidden_directories.push(alias);
                } else {
                    protection.hidden_files.push(alias);
                }
            }
            // History is read once. Unrelated stages are filtered geometrically
            // before performing filesystem validation or policy resolution.
            for record in all_stages(&registry)? {
                for alias in mounts.unchecked_aliases(&record.path) {
                    if writable_candidate(&alias)
                        && read_allowed(&alias)
                        && open_directory(&alias).is_ok_and(|directory| {
                            object_identity(&directory)
                                .is_ok_and(|identity| identity == record.identity)
                        })
                    {
                        protection.hidden_directories.push(alias);
                    }
                }
                for (source, alias) in mounts.descendant_aliases(&record.path) {
                    if !writable_candidate(&alias) || !read_allowed(&alias) {
                        continue;
                    }
                    if open_directory(&record.path).is_ok_and(|directory| {
                        object_identity(&directory)
                            .is_ok_and(|identity| identity == record.identity)
                    }) && let Ok(expected) = std::fs::metadata(source)
                        && let Ok(actual) = std::fs::metadata(&alias)
                        && (expected.dev(), expected.ino()) == (actual.dev(), actual.ino())
                    {
                        if actual.is_dir() {
                            protection.hidden_directories.push(alias);
                        } else {
                            protection.hidden_files.push(alias);
                        }
                    }
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    // NSS filtering may just have created the fixed cache authority. Include
    // that root as well as older fixed authorities before the child starts.
    for authority in super::super::linux::existing_synthetic_metadata_authorities()? {
        let private_views = authority.join(OsString::from_vec(views::VIEWS.to_bytes().to_vec()));
        let writable_storage = views::can_write_storage(&authority, mounts)?;
        let mut records = None;
        let mut all_public_view = None;
        for alias in mounts.aliases(&authority) {
            if !read_allowed(&alias) {
                continue;
            }
            let intersects_denies = has_denied_children(&alias);
            if !intersects_denies && !writable_storage {
                // No alias can create later private entries under stable host
                // configuration. Existing private caches are still masked below.
                protection.read_only.push(alias);
                continue;
            }
            let names = match &records {
                Some(names) => names,
                None => records.insert(public_record_names(&open_directory(&authority)?)?),
            };
            let source = if !intersects_denies {
                // The readable parent already grants every public child. Reuse
                // one snapshot rather than revalidating the same set per alias.
                match &all_public_view {
                    Some(view) => PathBuf::clone(view),
                    None => {
                        let view = views::filtered_view(
                            &open_directory(&authority)?,
                            names,
                            views::ViewAccess::Readable,
                        )?;
                        all_public_view = Some(view.clone());
                        view
                    }
                }
            } else {
                let selected = names
                    .iter()
                    .filter(|name| public_read_allowed(&alias.join(name)))
                    .cloned()
                    .collect::<Vec<_>>();
                views::filtered_view(
                    &open_directory(&authority)?,
                    &selected,
                    views::ViewAccess::Readable,
                )?
            };
            protection.bindings.push((source, alias));
        }
        for (source, alias) in mounts.descendant_aliases(&authority) {
            if !source.starts_with(&private_views) && read_allowed(&alias) {
                protection.read_only.push(alias);
            }
        }
        hide_private_storage(&mut protection, mounts, &private_views, &readable_roots)?;
    }
    protection.registries.sort();
    protection.registries.dedup();
    protection.bindings.retain(|(_, target)| {
        read_allowed(target)
            && !protection
                .registries
                .iter()
                .any(|(root, _, _)| target.starts_with(root))
    });
    protection.bindings.sort();
    protection.bindings.dedup();
    for paths in [
        &mut protection.read_only,
        &mut protection.hidden_directories,
        &mut protection.hidden_files,
    ] {
        paths.retain(|path| {
            read_allowed(path)
                && !protection
                    .registries
                    .iter()
                    .any(|(registry, _, _)| path.starts_with(registry))
                && !protection
                    .bindings
                    .iter()
                    .any(|(_, target)| path.starts_with(target))
        });
        paths.sort();
        paths.dedup();
    }
    protection
        .hidden_directories
        .sort_by_key(|path| path.components().count());
    let mut directories: Vec<PathBuf> = Vec::new();
    for path in protection.hidden_directories {
        if !directories.iter().any(|parent| path.starts_with(parent)) {
            directories.push(path);
        }
    }
    protection
        .hidden_files
        .retain(|path| !directories.iter().any(|parent| path.starts_with(parent)));
    protection
        .read_only
        .retain(|path| !directories.iter().any(|parent| path.starts_with(parent)));
    protection.hidden_directories = directories;
    Ok(protection)
}
