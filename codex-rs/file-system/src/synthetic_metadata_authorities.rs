//! Active native storage and retained ownership evidence.

use super::super::super::linux::AuthorityMode;
use super::super::super::linux::invalid;
use super::storage;
use std::fs::File;
use std::io;
use std::path::Path;
use std::path::PathBuf;

pub(crate) struct Authorities {
    pub(crate) configured: bool,
    active: PathBuf,
    home: Option<PathBuf>,
    roots: Vec<PathBuf>,
    required_roots: usize,
    configuration_path: PathBuf,
}

fn resolved_path(path: &Path) -> io::Result<PathBuf> {
    let mut ancestor = path
        .parent()
        .ok_or_else(|| invalid("registry has no parent"))?;
    let mut suffix = vec![
        path.file_name()
            .ok_or_else(|| invalid("registry has no name"))?
            .to_os_string(),
    ];
    loop {
        match ancestor.canonicalize() {
            Ok(mut parent) => {
                for part in suffix.into_iter().rev() {
                    parent.push(part);
                }
                return Ok(parent);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                suffix.push(
                    ancestor
                        .file_name()
                        .ok_or_else(|| invalid("registry ancestor missing"))?
                        .to_os_string(),
                );
                ancestor = ancestor
                    .parent()
                    .ok_or_else(|| invalid("registry ancestor has no parent"))?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn paths_for(roots: &[PathBuf]) -> io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for root in roots {
        for path in [root.clone(), resolved_path(root)?] {
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
    }
    Ok(paths)
}

impl Authorities {
    pub(crate) fn load() -> io::Result<Self> {
        Self::from_configuration(storage::load()?, super::nss_home())
    }

    pub(crate) fn load_for_classification() -> io::Result<Option<Self>> {
        Self::classification_from_configuration(storage::load()?, super::nss_home())
    }

    fn classification_from_configuration(
        configuration: Option<storage::Configuration>,
        home: io::Result<PathBuf>,
    ) -> io::Result<Option<Self>> {
        match home {
            Err(_) if configuration.is_none() => Ok(None),
            home => Self::from_configuration(configuration, home).map(Some),
        }
    }

    fn from_configuration(
        configuration: Option<storage::Configuration>,
        home: io::Result<PathBuf>,
    ) -> io::Result<Self> {
        let configured = configuration.is_some();
        let home = match home {
            Ok(home) => Some(home),
            Err(_) if configured => None,
            Err(error) => return Err(error),
        };
        let nss = home
            .as_ref()
            .map(|home| home.join(".codex/synthetic-metadata-v2"));
        let (active, mut roots, required_roots) = match configuration {
            Some(configuration) => {
                let mut roots = vec![configuration.write_root.clone()];
                roots.extend(configuration.retained_read_roots);
                let count = roots.len();
                (configuration.write_root, roots, count)
            }
            None => {
                let active = nss
                    .clone()
                    .ok_or_else(|| invalid("registry home missing"))?;
                (active.clone(), vec![active], 0)
            }
        };
        if let Some(nss) = nss
            && !roots.contains(&nss)
        {
            roots.push(nss);
        }
        Ok(Self {
            configured,
            active,
            home,
            roots,
            required_roots,
            configuration_path: storage::configuration_path(),
        })
    }

    pub(crate) fn active_path(&self) -> io::Result<PathBuf> {
        resolved_path(&self.active)
    }

    pub(crate) fn configuration_path(&self) -> &Path {
        &self.configuration_path
    }

    pub(crate) fn has_nss_home(&self) -> bool {
        self.home.is_some()
    }

    pub(crate) fn optional_paths(&self) -> io::Result<Vec<PathBuf>> {
        paths_for(&self.roots[self.required_roots..])
    }

    pub(crate) fn paths(&self) -> io::Result<Vec<PathBuf>> {
        paths_for(&self.roots)
    }

    pub(crate) fn open_write(&self, mode: AuthorityMode) -> io::Result<File> {
        if !self.configured {
            return super::open_home(
                self.home
                    .as_deref()
                    .ok_or_else(|| invalid("registry home missing"))?,
                mode,
            );
        }
        // Configured storage is provisioned before its administrator publishes
        // the configuration. Runtime initialization never adopts a missing root.
        let registry = super::open_path(&self.active, AuthorityMode::ReadOnly)?;
        if matches!(mode, AuthorityMode::Initialize) {
            super::initialize_public_records(&registry)?;
        }
        Ok(registry)
    }

    pub(crate) fn readers(&self) -> io::Result<Vec<(PathBuf, File)>> {
        let mut readers = Vec::new();
        for (index, root) in self.roots.iter().enumerate() {
            let opened = if index >= self.required_roots
                && let Some(home) = &self.home
            {
                super::open_home(home, AuthorityMode::ReadOnly)
            } else {
                super::open_path(root, AuthorityMode::ReadOnly)
            };
            match opened {
                Ok(registry) => {
                    let path = resolved_path(root)?;
                    if !readers.iter().any(|(existing, _)| existing == &path) {
                        readers.push((path, registry));
                    }
                }
                Err(error)
                    if index >= self.required_roots
                        && error.kind() == io::ErrorKind::NotFound
                        && std::fs::symlink_metadata(root)
                            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound) => {}
                Err(error)
                    if self.configured
                        && index >= self.required_roots
                        && error.kind() == io::ErrorKind::NotADirectory
                        && root.parent().is_some_and(|parent| {
                            std::fs::metadata(parent).is_ok_and(|metadata| !metadata.is_dir())
                        }) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(readers)
    }
}

#[cfg(test)]
#[path = "synthetic_metadata_authorities_tests.rs"]
mod tests;
