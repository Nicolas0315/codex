use super::super::super as publication;
use super::super::storage::Configuration;
use super::*;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;

fn fixture() -> PathBuf {
    super::super::super::tests::fixture(Path::new("/var/tmp"))
}

fn provision(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    publication::initialize_synthetic_metadata_storage(&path).unwrap();
    path
}

#[test]
fn explicit_writer_keeps_cold_read_only_home_unchanged() {
    let home = fixture();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o500)).unwrap();
    let before = fs::metadata(&home).unwrap();
    let state = provision(&fixture(), "active");
    let authorities = Authorities::from_configuration(
        Some(Configuration {
            write_root: state.clone(),
            retained_read_roots: vec![],
        }),
        Ok(home.clone()),
    )
    .unwrap();
    authorities
        .open_write(super::super::AuthorityMode::Initialize)
        .unwrap();
    let after = fs::metadata(&home).unwrap();
    assert_eq!(
        (after.ino(), after.mode(), after.mtime(), after.mtime_nsec()),
        (
            before.ino(),
            before.mode(),
            before.mtime(),
            before.mtime_nsec()
        )
    );
    assert!(!home.join(".codex").exists());
    assert_eq!(authorities.active_path().unwrap(), state);
}

#[test]
fn retained_and_nss_readers_survive_active_root_switch() {
    let home = fixture();
    super::super::open_home(&home, super::super::AuthorityMode::Initialize).unwrap();
    let parent = fixture();
    let old = provision(&parent, "old");
    let active = provision(&parent, "active");
    let authorities = Authorities::from_configuration(
        Some(Configuration {
            write_root: active.clone(),
            retained_read_roots: vec![old.clone()],
        }),
        Ok(home.clone()),
    )
    .unwrap();
    let readers = authorities
        .readers()
        .unwrap()
        .into_iter()
        .map(|(path, _)| path)
        .collect::<Vec<_>>();
    assert_eq!(
        readers,
        vec![active, old, home.join(".codex/synthetic-metadata-v2")]
    );
}

#[test]
fn explicit_storage_can_be_used_when_nss_home_resolution_fails() {
    let active = provision(&fixture(), "active");
    let authorities = Authorities::from_configuration(
        Some(Configuration {
            write_root: active.clone(),
            retained_read_roots: vec![],
        }),
        Err(io::Error::other("no NSS home")),
    )
    .unwrap();
    assert_eq!(authorities.active_path().unwrap(), active);
    assert_eq!(authorities.readers().unwrap().len(), 1);
    assert!(Authorities::from_configuration(None, Err(io::Error::other("no NSS home"))).is_err());
}

#[test]
fn configured_roots_must_already_be_provisioned_and_never_fall_back() {
    let home = fixture();
    let parent = fixture();
    let missing = parent.join("missing");
    let authorities = Authorities::from_configuration(
        Some(Configuration {
            write_root: missing.clone(),
            retained_read_roots: vec![],
        }),
        Ok(home.clone()),
    )
    .unwrap();
    assert!(
        authorities
            .open_write(super::super::AuthorityMode::Initialize)
            .is_err()
    );
    assert!(authorities.readers().is_err());
    assert!(!missing.exists());
    assert!(!home.join(".codex").exists());
    let active = provision(&parent, "active");
    let authorities = Authorities::from_configuration(
        Some(Configuration {
            write_root: active,
            retained_read_roots: vec![missing],
        }),
        Ok(home),
    )
    .unwrap();
    assert!(authorities.readers().is_err());
}

#[test]
fn provisioning_retains_genuine_directory_collisions() {
    let root = fixture();
    let genuine = root.join("user-directory");
    fs::create_dir(&genuine).unwrap();
    fs::set_permissions(&genuine, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(genuine.join("user-data"), b"preserve").unwrap();
    let before = fs::metadata(&genuine).unwrap();
    assert!(super::super::open_path(&genuine, super::super::AuthorityMode::Initialize).is_err());
    assert_eq!(fs::metadata(&genuine).unwrap().ino(), before.ino());
    assert_eq!(fs::read(genuine.join("user-data")).unwrap(), b"preserve");
    assert!(!genuine.join("format").exists());
}

#[test]
fn switched_storage_classifies_old_and_nss_objects_and_writes_only_active_records() {
    let home = fixture();
    super::super::open_home(&home, super::super::AuthorityMode::Initialize).unwrap();
    let parent = fixture();
    let old = provision(&parent, "old");
    let active = provision(&parent, "active");
    let nss = home.join(".codex/synthetic-metadata-v2");
    let mut objects = Vec::new();
    for root in [&old, &nss] {
        let registry =
            super::super::open_path(root, super::super::AuthorityMode::ReadOnly).unwrap();
        let object = fixture().join(".git");
        fs::create_dir(&object).unwrap();
        let directory = std::fs::File::open(&object).unwrap();
        publication::set_tag(&directory).unwrap();
        let (key, bytes) = publication::nonce_record(&directory).unwrap();
        publication::write_record(
            &super::super::records(&registry, super::super::AuthorityMode::ReadOnly).unwrap(),
            &key,
            &bytes,
        )
        .unwrap();
        objects.push(object);
    }
    let authorities = Authorities::from_configuration(
        Some(Configuration {
            write_root: active.clone(),
            retained_read_roots: vec![old.clone()],
        }),
        Ok(home),
    )
    .unwrap();
    for object in &objects {
        assert!(publication::inspection::is_owned_with_authorities(object, &authorities).unwrap());
    }
    let counts = [&active, &old, &nss]
        .map(|root| fs::read_dir(root.join("public-records")).unwrap().count());
    let published = fixture().join(".git");
    publication::prepare_missing_directory_with_authorities(
        &published,
        publication::set_tag,
        &authorities,
    )
    .unwrap();
    assert!(publication::inspection::is_owned_with_authorities(&published, &authorities).unwrap());
    assert_eq!(
        [&active, &old, &nss]
            .map(|root| fs::read_dir(root.join("public-records")).unwrap().count()),
        [counts[0] + 1, counts[1], counts[2]],
    );
    let genuine = fixture().join(".git");
    fs::create_dir(&genuine).unwrap();
    let before = fs::metadata(&genuine).unwrap();
    assert!(!publication::inspection::is_owned_with_authorities(&genuine, &authorities).unwrap());
    assert_eq!(fs::metadata(genuine).unwrap().ino(), before.ino());
}

#[test]
fn explicit_storage_retains_genuine_codex_entries_without_home_mutation() {
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemPath;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_protocol::protocol::FileSystemSandboxPolicy;
    use codex_utils_absolute_path::AbsolutePathBuf;
    let active = provision(&fixture(), "active");
    for kind in ["directory", "symlink", "file"] {
        let home = fixture();
        let codex = home.join(".codex");
        let user_file = match kind {
            "directory" => {
                fs::create_dir(&codex).unwrap();
                codex.join("user-data")
            }
            "symlink" => {
                let target = fixture();
                std::os::unix::fs::symlink(&target, &codex).unwrap();
                target.join("user-data")
            }
            _ => codex.clone(),
        };
        fs::write(&user_file, b"preserve user entry").unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o500)).unwrap();
        let before = fs::symlink_metadata(&codex).unwrap();
        let authorities = Authorities::from_configuration(
            Some(Configuration {
                write_root: active.clone(),
                retained_read_roots: vec![],
            }),
            Ok(home),
        )
        .unwrap();
        authorities
            .open_write(super::super::AuthorityMode::Initialize)
            .unwrap();
        assert_eq!(authorities.readers().unwrap().len(), 1);
        publication::configuration_protection::validate_with_authorities(
            &FileSystemSandboxPolicy::restricted(vec![FileSystemSandboxEntry {
                path: FileSystemPath::Path {
                    path: AbsolutePathBuf::from_absolute_path("/").unwrap(),
                },
                access: FileSystemAccessMode::Read,
            }]),
            Path::new("/"),
            &publication::MountTable::read().unwrap(),
            &authorities,
        )
        .unwrap();
        let after = fs::symlink_metadata(&codex).unwrap();
        assert_eq!(
            (after.ino(), after.mode(), after.mtime(), after.mtime_nsec()),
            (
                before.ino(),
                before.mode(),
                before.mtime(),
                before.mtime_nsec()
            )
        );
        assert_eq!(fs::read(user_file).unwrap(), b"preserve user entry");
    }
}

#[test]
fn retained_private_stages_stay_hidden_without_reopening_denied_authorities() {
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemPath;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_protocol::protocol::FileSystemSandboxPolicy;
    use codex_utils_absolute_path::AbsolutePathBuf;
    let home = fixture();
    super::super::open_home(&home, super::super::AuthorityMode::Initialize).unwrap();
    let old = provision(&fixture(), "old");
    let active = provision(&fixture(), "active");
    let workspace = fixture();
    let mounts = publication::MountTable::read().unwrap();
    let mut stages = Vec::new();
    for root in [&old, &home.join(".codex/synthetic-metadata-v2")] {
        let registry =
            super::super::open_path(root, super::super::AuthorityMode::ReadOnly).unwrap();
        stages.push(publication::staging_directory(&workspace, &mounts, &registry).unwrap());
    }
    let authorities = Authorities::from_configuration(
        Some(Configuration {
            write_root: active,
            retained_read_roots: vec![old.clone()],
        }),
        Ok(home),
    )
    .unwrap();
    let entry = |path: &Path, access| FileSystemSandboxEntry {
        path: FileSystemPath::Path {
            path: AbsolutePathBuf::from_absolute_path(path).unwrap(),
        },
        access,
    };
    let policy = FileSystemSandboxPolicy::restricted(vec![
        entry(Path::new("/"), FileSystemAccessMode::Read),
        entry(&workspace, FileSystemAccessMode::Write),
        entry(&old, FileSystemAccessMode::Deny),
    ]);
    let protection = publication::protection::protection_with_authorities(
        &policy,
        &workspace,
        &mounts,
        &authorities,
    )
    .unwrap();
    assert!(
        stages
            .iter()
            .all(|stage| protection.hidden_directories.contains(stage))
    );
    assert!(
        protection
            .registries
            .iter()
            .all(|(path, _, _)| !path.starts_with(&old))
    );
    assert!(
        protection
            .bindings
            .iter()
            .all(|(_, path)| !path.starts_with(&old))
    );
    assert!(
        protection
            .read_only
            .iter()
            .all(|path| !path.starts_with(&old))
    );
}

#[test]
fn configuration_protection_never_reopens_exact_or_glob_denied_paths() {
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemPath;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_protocol::protocol::FileSystemSandboxPolicy;
    use codex_utils_absolute_path::AbsolutePathBuf;
    let workspace = fixture();
    let active = provision(&fixture(), "active");
    let configuration_path = fixture().join("123.toml");
    fs::write(&configuration_path, b"preserve configuration").unwrap();
    let mut authorities = Authorities::from_configuration(
        Some(Configuration {
            write_root: active,
            retained_read_roots: vec![],
        }),
        Ok(fixture()),
    )
    .unwrap();
    authorities.configuration_path = configuration_path.clone();
    let entry = |path: &Path, access| FileSystemSandboxEntry {
        path: FileSystemPath::Path {
            path: AbsolutePathBuf::from_absolute_path(path).unwrap(),
        },
        access,
    };
    for denied in [
        None,
        Some(FileSystemPath::Path {
            path: AbsolutePathBuf::from_absolute_path(&configuration_path).unwrap(),
        }),
        Some(FileSystemPath::GlobPattern {
            pattern: format!("{}/*.toml", configuration_path.parent().unwrap().display()),
        }),
    ] {
        let has_deny = denied.is_some();
        let mut entries = vec![
            entry(Path::new("/"), FileSystemAccessMode::Read),
            entry(&workspace, FileSystemAccessMode::Write),
        ];
        if let Some(path) = denied {
            entries.push(FileSystemSandboxEntry {
                path,
                access: FileSystemAccessMode::Deny,
            });
        }
        let protection = publication::protection::protection_with_authorities(
            &FileSystemSandboxPolicy::restricted(entries),
            &workspace,
            &publication::MountTable::read().unwrap(),
            &authorities,
        )
        .unwrap();
        assert_eq!(
            protection.read_only.contains(&configuration_path),
            !has_deny
        );
        assert!(
            protection
                .bindings
                .iter()
                .all(|(_, path)| path != &configuration_path)
        );
    }
    assert_eq!(
        fs::read(configuration_path).unwrap(),
        b"preserve configuration"
    );
}

#[test]
fn configured_storage_must_not_leave_an_absent_nss_authority_forgeable() {
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemPath;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_protocol::protocol::FileSystemSandboxPolicy;
    use codex_utils_absolute_path::AbsolutePathBuf;
    let home = fixture();
    let codex = home.join(".codex");
    fs::create_dir(&codex).unwrap();
    let active = provision(&fixture(), "active");
    let authorities = Authorities::from_configuration(
        Some(Configuration {
            write_root: active,
            retained_read_roots: vec![],
        }),
        Ok(home.clone()),
    )
    .unwrap();
    let policy = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: AbsolutePathBuf::from_absolute_path("/").unwrap(),
            },
            access: FileSystemAccessMode::Read,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: AbsolutePathBuf::from_absolute_path(&codex).unwrap(),
            },
            access: FileSystemAccessMode::Write,
        },
    ]);
    assert!(
        publication::configuration_protection::validate_with_authorities(
            &policy,
            &home,
            &publication::MountTable::read().unwrap(),
            &authorities,
        )
        .is_err()
    );
    assert!(!codex.join("synthetic-metadata-v2").exists());
}

#[test]
fn nss_failure_without_configuration_keeps_legacy_classification_available() {
    let resolution = Authorities::classification_from_configuration(
        /*configuration*/ None,
        Err(io::Error::other("no NSS home")),
    )
    .unwrap();
    assert!(resolution.is_none());
}

#[test]
fn provisioning_does_not_adopt_a_preexisting_authority_shaped_directory() {
    let parent = fixture();
    let path = parent.join("preexisting");
    super::super::open_path(&path, super::super::AuthorityMode::Initialize).unwrap();
    fs::write(path.join("preserve-content"), b"preserve preexisting state").unwrap();
    let before = fs::metadata(&path).unwrap();
    assert!(publication::initialize_synthetic_metadata_storage(&path).is_err());
    assert_eq!(fs::metadata(&path).unwrap().ino(), before.ino());
    assert_eq!(
        fs::read(path.join("preserve-content")).unwrap(),
        b"preserve preexisting state"
    );
}

#[test]
fn missing_nss_authority_is_guarded_through_codex_and_home_symlink_spellings() {
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemPath;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_protocol::protocol::FileSystemSandboxPolicy;
    use codex_utils_absolute_path::AbsolutePathBuf;
    let active = provision(&fixture(), "active");
    for link_home in [false, true] {
        let parent = fixture();
        let external = fixture();
        let (home, writable) = if link_home {
            let home = parent.join("linked-home");
            std::os::unix::fs::symlink(&external, &home).unwrap();
            (home, external.join(".codex"))
        } else {
            std::os::unix::fs::symlink(&external, parent.join(".codex")).unwrap();
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o500)).unwrap();
            (parent, external.clone())
        };
        let authorities = Authorities::from_configuration(
            Some(Configuration {
                write_root: active.clone(),
                retained_read_roots: vec![],
            }),
            Ok(home.clone()),
        )
        .unwrap();
        let policy = FileSystemSandboxPolicy::restricted(vec![
            FileSystemSandboxEntry {
                path: FileSystemPath::Path {
                    path: AbsolutePathBuf::from_absolute_path("/").unwrap(),
                },
                access: FileSystemAccessMode::Read,
            },
            FileSystemSandboxEntry {
                path: FileSystemPath::Path {
                    path: AbsolutePathBuf::from_absolute_path(writable).unwrap(),
                },
                access: FileSystemAccessMode::Write,
            },
        ]);
        assert!(
            publication::configuration_protection::validate_with_authorities(
                &policy,
                &home,
                &publication::MountTable::read().unwrap(),
                &authorities,
            )
            .is_err()
        );
        assert!(!home.join(".codex/synthetic-metadata-v2").exists());
    }
}

#[test]
fn existing_home_metadata_carveout_keeps_optional_nss_slot_unwritable() {
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemPath;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_protocol::protocol::FileSystemSandboxPolicy;
    use codex_utils_absolute_path::AbsolutePathBuf;
    let home = fixture();
    fs::create_dir(home.join(".codex")).unwrap();
    let active = provision(&fixture(), "active");
    let authorities = Authorities::from_configuration(
        Some(Configuration {
            write_root: active,
            retained_read_roots: vec![],
        }),
        Ok(home.clone()),
    )
    .unwrap();
    let policy = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: AbsolutePathBuf::from_absolute_path("/").unwrap(),
            },
            access: FileSystemAccessMode::Read,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: AbsolutePathBuf::from_absolute_path(&home).unwrap(),
            },
            access: FileSystemAccessMode::Write,
        },
    ]);
    assert!(!policy.can_write_path_with_cwd(&home.join(".codex/synthetic-metadata-v2"), &home));
    publication::configuration_protection::validate_with_authorities(
        &policy,
        &home,
        &publication::MountTable::read().unwrap(),
        &authorities,
    )
    .unwrap();
    assert!(!home.join(".codex/synthetic-metadata-v2").exists());
}

#[test]
fn restricted_launch_does_not_guess_an_unresolved_historical_nss_authority() {
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemPath;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_protocol::protocol::FileSystemSandboxPolicy;
    use codex_utils_absolute_path::AbsolutePathBuf;
    let active = provision(&fixture(), "active");
    let authorities = Authorities::from_configuration(
        Some(Configuration {
            write_root: active,
            retained_read_roots: vec![],
        }),
        Err(io::Error::other("no NSS home")),
    )
    .unwrap();
    assert_eq!(authorities.readers().unwrap().len(), 1);
    let policy = FileSystemSandboxPolicy::restricted(vec![FileSystemSandboxEntry {
        path: FileSystemPath::Path {
            path: AbsolutePathBuf::from_absolute_path("/").unwrap(),
        },
        access: FileSystemAccessMode::Read,
    }]);
    assert!(
        publication::configuration_protection::validate_with_authorities(
            &policy,
            Path::new("/"),
            &publication::MountTable::read().unwrap(),
            &authorities,
        )
        .is_err()
    );
}

#[test]
fn all_retained_readers_are_validated_before_launch_can_publish_new_targets() {
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemPath;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_protocol::protocol::FileSystemSandboxPolicy;
    use codex_utils_absolute_path::AbsolutePathBuf;
    let home = fixture();
    let unknown = home.join(".codex/synthetic-metadata-v2");
    fs::create_dir_all(&unknown).unwrap();
    fs::set_permissions(&unknown, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(unknown.join("user-data"), b"preserve genuine entry").unwrap();
    let before = fs::metadata(&unknown).unwrap();
    let active = provision(&fixture(), "active");
    let authorities = Authorities::from_configuration(
        Some(Configuration {
            write_root: active,
            retained_read_roots: vec![],
        }),
        Ok(home),
    )
    .unwrap();
    let workspace = fixture();
    let policy = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: AbsolutePathBuf::from_absolute_path("/").unwrap(),
            },
            access: FileSystemAccessMode::Read,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: AbsolutePathBuf::from_absolute_path(&workspace).unwrap(),
            },
            access: FileSystemAccessMode::Write,
        },
    ]);
    assert!(
        publication::configuration_protection::validate_with_authorities(
            &policy,
            &workspace,
            &publication::MountTable::read().unwrap(),
            &authorities,
        )
        .is_err()
    );
    assert_eq!(fs::metadata(&unknown).unwrap().ino(), before.ino());
    assert_eq!(
        fs::read(unknown.join("user-data")).unwrap(),
        b"preserve genuine entry"
    );
    assert!(!unknown.join("format").exists());
}
