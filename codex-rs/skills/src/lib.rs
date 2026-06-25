use codex_utils_absolute_path::AbsolutePathBuf;
use include_dir::Dir;
use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::Hash;
use std::hash::Hasher;
use std::path::Path;
use std::path::PathBuf;

use thiserror::Error;

const SYSTEM_SKILLS_DIR: Dir = include_dir::include_dir!("$CARGO_MANIFEST_DIR/src/assets/samples");

const SYSTEM_SKILLS_DIR_NAME: &str = ".system";
const SKILLS_DIR_NAME: &str = "skills";
const SYSTEM_SKILLS_MARKER_FILENAME: &str = ".codex-system-skills.marker";
const SYSTEM_SKILLS_MARKER_SALT: &str = "v1";

/// Returns the on-disk cache location for embedded system skills from an absolute CODEX_HOME.
pub fn system_cache_root_dir(codex_home: &AbsolutePathBuf) -> AbsolutePathBuf {
    codex_home
        .join(SKILLS_DIR_NAME)
        .join(SYSTEM_SKILLS_DIR_NAME)
}

/// Installs embedded system skills into `CODEX_HOME/skills/.system`.
///
/// Refreshes any existing system skills directory in place so readers never
/// observe the cache root disappearing during startup. Stale entries are
/// removed after the embedded files are written.
///
/// To avoid doing unnecessary work on every startup, a marker file is written
/// with a fingerprint of the embedded directory. When the marker matches, the
/// install is skipped.
pub fn install_system_skills(codex_home: &AbsolutePathBuf) -> Result<(), SystemSkillsError> {
    let skills_root_dir = codex_home.join(SKILLS_DIR_NAME);
    fs::create_dir_all(skills_root_dir.as_path())
        .map_err(|source| SystemSkillsError::io("create skills root dir", source))?;

    let dest_system = system_cache_root_dir(codex_home);

    let marker_path = dest_system.join(SYSTEM_SKILLS_MARKER_FILENAME);
    let expected_fingerprint = embedded_system_skills_fingerprint();
    if dest_system.as_path().is_dir()
        && read_marker(&marker_path).is_ok_and(|marker| marker == expected_fingerprint)
    {
        return Ok(());
    }

    let mut embedded_paths = HashSet::new();
    collect_embedded_paths(&SYSTEM_SKILLS_DIR, &mut embedded_paths);
    write_embedded_dir(&SYSTEM_SKILLS_DIR, &dest_system)?;
    remove_stale_entries(dest_system.as_path(), &embedded_paths, Path::new(""))?;
    fs::write(marker_path.as_path(), format!("{expected_fingerprint}\n"))
        .map_err(|source| SystemSkillsError::io("write system skills marker", source))?;
    Ok(())
}

fn read_marker(path: &AbsolutePathBuf) -> Result<String, SystemSkillsError> {
    Ok(fs::read_to_string(path.as_path())
        .map_err(|source| SystemSkillsError::io("read system skills marker", source))?
        .trim()
        .to_string())
}

fn embedded_system_skills_fingerprint() -> String {
    let mut items = Vec::new();
    collect_fingerprint_items(&SYSTEM_SKILLS_DIR, &mut items);
    items.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));

    let mut hasher = DefaultHasher::new();
    SYSTEM_SKILLS_MARKER_SALT.hash(&mut hasher);
    for (path, contents_hash) in items {
        path.hash(&mut hasher);
        contents_hash.hash(&mut hasher);
    }
    format!("{:x}", hasher.finish())
}

fn collect_fingerprint_items(dir: &Dir<'_>, items: &mut Vec<(String, Option<u64>)>) {
    for entry in dir.entries() {
        match entry {
            include_dir::DirEntry::Dir(subdir) => {
                items.push((subdir.path().to_string_lossy().to_string(), None));
                collect_fingerprint_items(subdir, items);
            }
            include_dir::DirEntry::File(file) => {
                let mut file_hasher = DefaultHasher::new();
                file.contents().hash(&mut file_hasher);
                items.push((
                    file.path().to_string_lossy().to_string(),
                    Some(file_hasher.finish()),
                ));
            }
        }
    }
}

fn collect_embedded_paths(dir: &Dir<'_>, paths: &mut HashSet<PathBuf>) {
    for entry in dir.entries() {
        match entry {
            include_dir::DirEntry::Dir(subdir) => {
                paths.insert(subdir.path().to_path_buf());
                collect_embedded_paths(subdir, paths);
            }
            include_dir::DirEntry::File(file) => {
                paths.insert(file.path().to_path_buf());
            }
        }
    }
}

/// Writes the embedded `include_dir::Dir` to disk under `dest`.
///
/// Preserves the embedded directory structure.
fn write_embedded_dir(dir: &Dir<'_>, dest: &AbsolutePathBuf) -> Result<(), SystemSkillsError> {
    fs::create_dir_all(dest.as_path())
        .map_err(|source| SystemSkillsError::io("create system skills dir", source))?;

    for entry in dir.entries() {
        match entry {
            include_dir::DirEntry::Dir(subdir) => {
                let subdir_dest = dest.join(subdir.path());
                if subdir_dest.as_path().exists() && !subdir_dest.as_path().is_dir() {
                    fs::remove_file(subdir_dest.as_path()).map_err(|source| {
                        SystemSkillsError::io("remove stale system skill file", source)
                    })?;
                }
                fs::create_dir_all(subdir_dest.as_path()).map_err(|source| {
                    SystemSkillsError::io("create system skills subdir", source)
                })?;
                write_embedded_dir(subdir, dest)?;
            }
            include_dir::DirEntry::File(file) => {
                let path = dest.join(file.path());
                if path.as_path().is_dir() {
                    fs::remove_dir_all(path.as_path()).map_err(|source| {
                        SystemSkillsError::io("remove stale system skills dir", source)
                    })?;
                }
                if let Some(parent) = path.as_path().parent() {
                    fs::create_dir_all(parent).map_err(|source| {
                        SystemSkillsError::io("create system skills file parent", source)
                    })?;
                }
                fs::write(path.as_path(), file.contents())
                    .map_err(|source| SystemSkillsError::io("write system skill file", source))?;
            }
        }
    }

    Ok(())
}

fn remove_stale_entries(
    root: &Path,
    embedded_paths: &HashSet<PathBuf>,
    relative_dir: &Path,
) -> Result<(), SystemSkillsError> {
    let current_dir = root.join(relative_dir);
    for entry in fs::read_dir(&current_dir)
        .map_err(|source| SystemSkillsError::io("read system skills dir", source))?
    {
        let entry =
            entry.map_err(|source| SystemSkillsError::io("read system skills entry", source))?;
        let relative_path = relative_dir.join(entry.file_name());
        let file_type = entry
            .file_type()
            .map_err(|source| SystemSkillsError::io("read system skills entry type", source))?;

        if !embedded_paths.contains(&relative_path) {
            if file_type.is_dir() {
                fs::remove_dir_all(entry.path()).map_err(|source| {
                    SystemSkillsError::io("remove stale system skills dir", source)
                })?;
            } else {
                fs::remove_file(entry.path()).map_err(|source| {
                    SystemSkillsError::io("remove stale system skill file", source)
                })?;
            }
        } else if file_type.is_dir() {
            remove_stale_entries(root, embedded_paths, &relative_path)?;
        }
    }

    Ok(())
}

#[derive(Debug, Error)]
pub enum SystemSkillsError {
    #[error("io error while {action}: {source}")]
    Io {
        action: &'static str,
        #[source]
        source: std::io::Error,
    },
}

impl SystemSkillsError {
    fn io(action: &'static str, source: std::io::Error) -> Self {
        Self::Io { action, source }
    }
}

#[cfg(test)]
mod tests {
    use codex_utils_absolute_path::AbsolutePathBuf;

    use super::SYSTEM_SKILLS_DIR;
    use super::SYSTEM_SKILLS_MARKER_FILENAME;
    use super::collect_fingerprint_items;
    use super::install_system_skills;
    use super::system_cache_root_dir;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn fingerprint_traverses_nested_entries() {
        let mut items = Vec::new();
        collect_fingerprint_items(&SYSTEM_SKILLS_DIR, &mut items);
        let mut paths: Vec<String> = items.into_iter().map(|(path, _)| path).collect();
        paths.sort_unstable();

        assert!(
            paths
                .binary_search_by(|probe| probe.as_str().cmp("skill-creator/SKILL.md"))
                .is_ok()
        );
        assert!(
            paths
                .binary_search_by(|probe| probe.as_str().cmp("skill-creator/scripts/init_skill.py"))
                .is_ok()
        );
    }

    #[test]
    fn refresh_removes_stale_entries_and_writes_bundled_skills() {
        let codex_home = TestCodexHome::new();
        let codex_home_abs = codex_home.absolute();
        let system_dir = system_cache_root_dir(&codex_home_abs);
        fs::create_dir_all(system_dir.as_path()).expect("create system cache root");
        fs::write(
            system_dir.join(SYSTEM_SKILLS_MARKER_FILENAME).as_path(),
            "stale\n",
        )
        .expect("write stale marker");
        fs::write(system_dir.join("stale-file").as_path(), "stale")
            .expect("write stale cache entry");

        install_system_skills(&codex_home_abs).expect("refresh system skills");

        assert!(!system_dir.join("stale-file").as_path().exists());
        assert!(system_dir.join("imagegen/SKILL.md").as_path().is_file());
    }

    #[cfg(unix)]
    #[test]
    fn refresh_keeps_existing_system_cache_root() {
        let codex_home = TestCodexHome::new();
        let codex_home_abs = codex_home.absolute();
        let system_dir = system_cache_root_dir(&codex_home_abs);
        fs::create_dir_all(system_dir.as_path()).expect("create system cache root");
        fs::write(
            system_dir.join(SYSTEM_SKILLS_MARKER_FILENAME).as_path(),
            "stale\n",
        )
        .expect("write stale marker");

        let original_identity = system_dir_identity(system_dir.as_path());

        install_system_skills(&codex_home_abs).expect("refresh system skills");

        assert_eq!(system_dir_identity(system_dir.as_path()), original_identity);
    }

    #[cfg(unix)]
    fn system_dir_identity(path: &std::path::Path) -> SystemDirIdentity {
        use std::os::unix::fs::MetadataExt;

        let metadata = fs::metadata(path).expect("read system cache root metadata");
        SystemDirIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }

    #[cfg(unix)]
    #[derive(Debug, PartialEq, Eq)]
    struct SystemDirIdentity {
        dev: u64,
        ino: u64,
    }

    struct TestCodexHome {
        path: PathBuf,
    }

    impl TestCodexHome {
        fn new() -> Self {
            let unique_suffix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after Unix epoch")
                .as_nanos();
            let unique_id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "codex-skills-test-{}-{unique_suffix}-{unique_id}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create temporary Codex home");
            Self { path }
        }

        fn absolute(&self) -> AbsolutePathBuf {
            AbsolutePathBuf::try_from(self.path.clone())
                .expect("temporary Codex home should be absolute")
        }
    }

    impl Drop for TestCodexHome {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
