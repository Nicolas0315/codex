use super::*;
use std::fs;
use std::os::unix::ffi::OsStrExt;

pub(super) fn fixture(parent: &Path) -> PathBuf {
    let name = random_name("codex-publication-test").unwrap();
    let path = parent.join(OsString::from_vec(name.as_bytes().to_vec()));
    fs::create_dir(&path).unwrap();
    path
}

#[test]
fn nested_publication_reuses_the_stage_protected_by_an_earlier_writer() {
    let root = fixture(Path::new("/var/tmp"));
    let stage = prepare_synthetic_metadata_staging(&root).unwrap();
    let nested = root.join("nested");
    fs::create_dir(&nested).unwrap();
    assert_eq!(prepare_synthetic_metadata_staging(&nested).unwrap(), stage);
    let path = nested.join(".git");
    prepare_synthetic_metadata_directory(&path).unwrap();
    assert!(is_owned(&path).unwrap());
    assert_eq!(fs::read_dir(path).unwrap().count(), 0);
}

#[test]
fn publication_on_a_different_mount_uses_nonce_identity_and_local_staging() {
    if !Path::new("/dev/shm").is_dir() {
        return;
    }
    let root = fixture(Path::new("/dev/shm"));
    let path = root.join(".git");
    prepare_synthetic_metadata_directory(&path).unwrap();
    let directory = File::open(&path).unwrap();
    let kernel = super::super::linux::identity(&directory).unwrap();
    let identity = tag(&directory).unwrap();
    assert_eq!(&identity[6..6 + kernel.len()], kernel.as_slice());
    assert!(is_owned(&path).unwrap());
    assert_eq!(fs::read_dir(&path).unwrap().count(), 0);
    assert_eq!(
        mount_id(&directory).unwrap(),
        mount_id(&File::open(prepare_synthetic_metadata_staging(&root).unwrap()).unwrap()).unwrap()
    );
}

#[test]
fn unknown_stage_names_and_incomplete_reservations_are_preserved_and_ignored() {
    let root = fixture(Path::new("/var/tmp"));
    let unknown = root.join(".codex-synthetic-stage-v2-unknown");
    fs::create_dir(&unknown).unwrap();
    fs::write(unknown.join("user-data"), b"preserve").unwrap();
    let registry = native_registry(/*initialize*/ true).unwrap();
    write_record(
        &registry,
        &random_name("stage").unwrap(),
        b"CSM2interrupted",
    )
    .unwrap();
    let stage = prepare_synthetic_metadata_staging(&root).unwrap();
    assert_ne!(stage, unknown);
    assert_eq!(fs::read(unknown.join("user-data")).unwrap(), b"preserve");
    assert!(
        existing_synthetic_metadata_authorities()
            .unwrap()
            .contains(&stage)
    );
}

#[test]
fn replaced_nonce_and_genuine_empty_git_directories_never_match_native_records() {
    let root = fixture(Path::new("/var/tmp"));
    let path = root.join(".git");
    fs::create_dir(&path).unwrap();
    let before = fs::metadata(&path).unwrap();
    prepare_synthetic_metadata_directory(&path).unwrap();
    let after = fs::metadata(&path).unwrap();
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert!(!super::super::is_synthetic_metadata_directory(&path));
    let other = root.join(".agents");
    prepare_synthetic_metadata_directory(&other).unwrap();
    let directory = File::open(&other).unwrap();
    let nonce = [7_u8; 32];
    assert_eq!(
        unsafe {
            libc::fsetxattr(
                directory.as_raw_fd(),
                TAG.as_ptr(),
                nonce.as_ptr().cast(),
                nonce.len(),
                libc::XATTR_REPLACE,
            )
        },
        0
    );
    assert!(!super::super::is_synthetic_metadata_directory(&other));
}

#[test]
fn nonce_only_records_are_preserved_without_authenticating_a_genuine_directory() {
    let root = fixture(Path::new("/var/tmp"));
    let path = root.join(".git");
    fs::create_dir(&path).unwrap();
    let directory = File::open(&path).unwrap();
    let nonce = [9_u8; 32];
    assert_eq!(
        unsafe {
            libc::fsetxattr(
                directory.as_raw_fd(),
                TAG.as_ptr(),
                nonce.as_ptr().cast(),
                nonce.len(),
                libc::XATTR_CREATE,
            )
        },
        0
    );
    let before = directory.metadata().unwrap();
    let mut old_identity = b"CSM2".to_vec();
    old_identity.extend_from_slice(&before.dev().to_le_bytes());
    old_identity.extend_from_slice(&before.ino().to_le_bytes());
    old_identity.extend_from_slice(&nonce);
    let key = CString::new(format!("{:x}", Sha256::digest(&old_identity))).unwrap();
    let mut bytes = old_identity;
    bytes.extend_from_slice(&before.mtime().to_le_bytes());
    bytes.extend_from_slice(&before.mtime_nsec().to_le_bytes());
    let registry = native_registry(/*initialize*/ true).unwrap();
    let records = registry::records(&registry, AuthorityMode::ReadOnly).unwrap();
    write_record(&records, &key, &bytes).unwrap();
    assert_eq!(registry::ownership_record(&records, &key).unwrap(), None);
    assert!(!super::super::is_synthetic_metadata_directory(&path));
    assert_eq!(
        read_bounded(open_at(&records, &key, libc::O_RDONLY, /*mode*/ 0).unwrap()).unwrap(),
        bytes
    );
    let after = directory.metadata().unwrap();
    assert_eq!(
        (
            after.dev(),
            after.ino(),
            after.mode(),
            after.mtime(),
            after.mtime_nsec()
        ),
        (
            before.dev(),
            before.ino(),
            before.mode(),
            before.mtime(),
            before.mtime_nsec()
        )
    );
}

#[test]
fn legacy_v1_kernel_identity_records_remain_readable() {
    let root = fixture(Path::new("/var/tmp"));
    let path = root.join(".git");
    fs::create_dir(&path).unwrap();
    let directory = File::open(&path).unwrap();
    let legacy = super::super::linux::open_authority(
        &super::super::linux::synthetic_metadata_registry_path(),
        super::super::linux::AuthorityMode::Initialize,
    )
    .unwrap();
    let (key, bytes) = super::super::linux::record(&directory).unwrap();
    write_record(&legacy, &key, &bytes).unwrap();
    assert!(super::super::is_synthetic_metadata_directory(&path));
}

#[test]
fn unsupported_xattrs_use_kernel_identity_but_permission_errors_do_not() {
    let root = fixture(Path::new("/var/tmp"));
    let directory = File::open(&root).unwrap();
    identity_after_tag_write(
        &directory,
        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP)),
    )
    .unwrap();
    assert!(object_identity(&directory).unwrap().starts_with(b"CSM1"));
    assert_eq!(
        identity_after_tag_write(&directory, Err(io::Error::from_raw_os_error(libc::EPERM)))
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EPERM)
    );
}

#[test]
fn keyed_stage_lookup_ignores_unrelated_history_and_reuses_ancestors() {
    let root = fixture(Path::new("/var/tmp"));
    let authority_parent = fixture(Path::new("/var/tmp"));
    let (_, registry) = stage_authority(&File::open(&authority_parent).unwrap()).unwrap();
    let mounts = MountTable::read().unwrap();
    let stage = staging_directory(&root, &mounts, &registry).unwrap();
    let index = registry::authority(&registry, registry::INDEX, AuthorityMode::ReadOnly).unwrap();
    write_record(&index, c"unrelated-history", &vec![0; 9000]).unwrap();
    let child = root.join("child");
    fs::create_dir(&child).unwrap();
    assert_eq!(
        staging_directory(&child, &mounts, &registry).unwrap(),
        stage
    );
}

#[test]
fn unsupported_directory_xattrs_preserve_publication_and_native_discovery() {
    let root = fixture(Path::new("/var/tmp"));
    let path = root.join(".git");
    prepare_directory_with_tagger(&path, |_| {
        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
    })
    .unwrap();
    assert!(is_owned(&path).unwrap());
    assert!(super::super::is_synthetic_metadata_directory(&path));
    assert_eq!(fs::read_dir(path).unwrap().count(), 0);
}

#[test]
fn restricted_protection_omits_denied_stage_history_and_private_path_records() {
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemPath;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_utils_absolute_path::AbsolutePathBuf;
    let root = fixture(Path::new("/var/tmp"));
    let denied = root.join("denied");
    fs::create_dir(&denied).unwrap();
    // Use an isolated reservation index so preexisting broad-root stages from
    // other tests cannot change which ancestor these fixtures reuse.
    let authority_parent = fixture(Path::new("/var/tmp"));
    let (_, private_registry) = stage_authority(&File::open(&authority_parent).unwrap()).unwrap();
    let mounts = MountTable::read().unwrap();
    let denied_stage = staging_directory(&denied, &mounts, &private_registry).unwrap();
    let root_stage = staging_directory(&root, &mounts, &private_registry).unwrap();
    let native = native_registry(/*initialize*/ true).unwrap();
    let index = registry::authority(&native, registry::INDEX, AuthorityMode::Initialize).unwrap();
    for stage in [&denied_stage, &root_stage] {
        let identity = object_identity(&File::open(stage).unwrap()).unwrap();
        registry::write_stage_record(
            &index,
            &stage_key(&mounts, stage.parent().unwrap()).unwrap(),
            &registry::StageRecord {
                path: stage.clone(),
                identity,
            },
        )
        .unwrap();
    }
    let entry = |path: &Path, access| FileSystemSandboxEntry {
        path: FileSystemPath::Path {
            path: AbsolutePathBuf::from_absolute_path(path).unwrap(),
        },
        access,
    };
    let policy = FileSystemSandboxPolicy::restricted(vec![
        entry(&root, FileSystemAccessMode::Write),
        entry(&denied, FileSystemAccessMode::Deny),
    ]);
    let protection = synthetic_metadata_protection(&policy, &root).unwrap();
    assert!(protection.hidden_directories.contains(&root_stage));
    assert!(!protection.hidden_directories.contains(&denied_stage));
    assert!(
        !protection
            .read_only
            .iter()
            .any(|path| path.starts_with(&denied))
    );
    assert!(
        !protection
            .registries
            .iter()
            .any(|(path, _, _)| path.starts_with(&denied))
    );
    let readable = FileSystemSandboxPolicy::restricted(vec![
        entry(Path::new("/"), FileSystemAccessMode::Read),
        entry(&root, FileSystemAccessMode::Write),
    ]);
    let public = synthetic_metadata_protection(&readable, &root).unwrap();
    assert!(public.hidden_directories.contains(&denied_stage));
    assert!(
        public
            .registries
            .iter()
            .all(|(_, records, public)| public.is_some() && records.len() == 1)
    );
    assert!(
        public
            .registries
            .iter()
            .all(|(_, records, _)| records.iter().all(|path| {
                let name = path.file_name().unwrap().as_bytes();
                name == b"format" || (name.len() == 64 && name.iter().all(u8::is_ascii_hexdigit))
            }))
    );
}

#[test]
fn denied_public_record_uses_selective_projection_without_reopening_the_record() {
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemPath;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_utils_absolute_path::AbsolutePathBuf;
    let root = fixture(Path::new("/var/tmp"));
    let object = root.join(".git");
    prepare_synthetic_metadata_directory(&object).unwrap();
    let (key, _) = nonce_record(&File::open(&object).unwrap()).unwrap();
    let native = registry::path().unwrap();
    let denied = native
        .join("public-records")
        .join(OsString::from_vec(key.as_bytes().to_vec()));
    let entry = |path: &Path, access| FileSystemSandboxEntry {
        path: FileSystemPath::Path {
            path: AbsolutePathBuf::from_absolute_path(path).unwrap(),
        },
        access,
    };
    let policy = FileSystemSandboxPolicy::restricted(vec![
        entry(Path::new("/"), FileSystemAccessMode::Read),
        entry(&root, FileSystemAccessMode::Write),
        entry(&denied, FileSystemAccessMode::Deny),
    ]);
    let protection = synthetic_metadata_protection(&policy, &root).unwrap();
    let (_, records, public) = protection
        .registries
        .iter()
        .find(|(path, _, _)| path == &native)
        .unwrap();
    let (view, target) = public.as_ref().expect("bounded filtered directory");
    assert_eq!(target, &native.join("public-records"));
    assert!(!view.join(denied.file_name().unwrap()).exists());
    assert!(!records.contains(&denied));
    assert!(!protection.read_only.contains(&denied));
}

#[test]
fn explicit_private_file_read_grants_below_a_denied_registry_are_still_hidden() {
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemPath;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_utils_absolute_path::AbsolutePathBuf;
    let root = fixture(Path::new("/var/tmp"));
    let stage = prepare_synthetic_metadata_staging(&root).unwrap();
    let registry = native_registry(/*initialize*/ true).unwrap();
    let index = registry::authority(&registry, registry::INDEX, AuthorityMode::Initialize).unwrap();
    let name = random_name("explicit-read-control").unwrap();
    let identity = object_identity(&File::open(&stage).unwrap()).unwrap();
    registry::write_stage_record(
        &index,
        &name,
        &registry::StageRecord {
            path: stage.clone(),
            identity: identity.clone(),
        },
    )
    .unwrap();
    let native = registry::path().unwrap();
    let index_path = native
        .join("private-stage-index")
        .join(OsString::from_vec(name.as_bytes().to_vec()));
    let legacy_name = random_name("stage").unwrap();
    let legacy_path = native.join(OsString::from_vec(legacy_name.as_bytes().to_vec()));
    // Preserve the old root location without inventing an unframed CSM3
    // layout: the length-framed stage envelope carries the current identity.
    registry::write_stage_record(
        &registry,
        &legacy_name,
        &registry::StageRecord {
            path: stage,
            identity,
        },
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
        entry(&root, FileSystemAccessMode::Write),
        entry(&native, FileSystemAccessMode::Deny),
        entry(&index_path, FileSystemAccessMode::Read),
        entry(&legacy_path, FileSystemAccessMode::Read),
    ]);
    let protection = synthetic_metadata_protection(&policy, &root).unwrap();
    assert!(protection.hidden_files.contains(&index_path));
    assert!(protection.hidden_files.contains(&legacy_path));
    assert!(
        !protection
            .registries
            .iter()
            .any(|(path, _, _)| path == &native)
    );
    assert!(!protection.read_only.contains(&index_path));
    assert!(!protection.read_only.contains(&legacy_path));
}

#[test]
fn stage_expansion_ignores_vanished_history_and_genuine_racing_replacements() {
    let root = fixture(Path::new("/var/tmp"));
    let stage = fixture(&root);
    let directory = File::open(&stage).unwrap();
    set_tag(&directory).unwrap();
    let record = registry::StageRecord {
        path: stage.clone(),
        identity: object_identity(&directory).unwrap(),
    };
    let mounts = MountTable::read().unwrap();
    let authenticated = authenticated_aliases(&record, &mounts);
    assert!(authenticated.contains(&stage));
    fs::rename(&stage, root.join("original-stage")).unwrap();
    assert!(
        protected_stage_aliases(&record, &mounts, authenticated.clone())
            .unwrap()
            .is_empty()
    );
    fs::create_dir(&stage).unwrap();
    let genuine = fs::metadata(&stage).unwrap();
    assert!(
        protected_stage_aliases(&record, &mounts, authenticated)
            .unwrap()
            .is_empty()
    );
    let after = fs::metadata(&stage).unwrap();
    assert_eq!(
        (after.dev(), after.ino(), after.mode()),
        (genuine.dev(), genuine.ino(), genuine.mode())
    );
    assert_eq!(fs::read_dir(stage).unwrap().count(), 0);
}

#[test]
fn workspace_globs_keep_constant_native_proof_bindings() {
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemPath;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_utils_absolute_path::AbsolutePathBuf;
    let root = fixture(Path::new("/var/tmp"));
    prepare_synthetic_metadata_directory(&root.join(".git")).unwrap();
    let entry = |path: &Path, access| FileSystemSandboxEntry {
        path: FileSystemPath::Path {
            path: AbsolutePathBuf::from_absolute_path(path).unwrap(),
        },
        access,
    };
    let mut policy = FileSystemSandboxPolicy::restricted(vec![
        entry(Path::new("/"), FileSystemAccessMode::Read),
        entry(&root, FileSystemAccessMode::Write),
    ]);
    policy.entries.push(FileSystemSandboxEntry {
        path: FileSystemPath::GlobPattern {
            pattern: format!("{}/**/*.env", root.display()),
        },
        access: FileSystemAccessMode::Deny,
    });
    let protection = synthetic_metadata_protection(&policy, &root).unwrap();
    let native = registry::path().unwrap();
    let (_, files, public) = protection
        .registries
        .iter()
        .find(|(path, _, _)| path == &native)
        .unwrap();
    assert_eq!(files, &vec![native.join("format")]);
    assert_eq!(
        public,
        &Some((native.join("public-records"), native.join("public-records")))
    );
    let mounts = MountTable::read().unwrap();
    let legacy = super::super::linux::synthetic_metadata_authority_paths()
        .iter()
        .flat_map(|path| mounts.aliases(path))
        .collect::<Vec<_>>();
    let unexpected = protection
        .bindings
        .iter()
        .filter(|(_, target)| !legacy.contains(target))
        .map(|(_, target)| target.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        unexpected,
        Vec::<PathBuf>::new(),
        "only validated mount aliases of fixed legacy authorities should be projected"
    );
}

#[test]
fn intersecting_globs_use_one_filtered_directory_without_reopening_matching_records() {
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemPath;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_utils_absolute_path::AbsolutePathBuf;
    let root = fixture(Path::new("/var/tmp"));
    let object = root.join(".git");
    prepare_synthetic_metadata_directory(&object).unwrap();
    let (key, _) = nonce_record(&File::open(&object).unwrap()).unwrap();
    let native = registry::path().unwrap();
    let prefix = std::str::from_utf8(&key.as_bytes()[..1]).unwrap();
    let policy = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: AbsolutePathBuf::from_absolute_path("/").unwrap(),
            },
            access: FileSystemAccessMode::Read,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::GlobPattern {
                pattern: format!("{}/public-records/{prefix}*", native.display()),
            },
            access: FileSystemAccessMode::Deny,
        },
    ]);
    let protection = synthetic_metadata_protection(&policy, &root).unwrap();
    let (_, files, public) = protection
        .registries
        .iter()
        .find(|(path, _, _)| path == &native)
        .unwrap();
    assert!(files.len() <= 1);
    let (view, target) = public.as_ref().unwrap();
    assert_eq!(target, &native.join("public-records"));
    assert!(
        !view
            .join(OsString::from_vec(key.as_bytes().to_vec()))
            .exists()
    );
    assert!(fs::read_dir(view).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .as_bytes()
            .starts_with(prefix.as_bytes())
    }));
    // Other tests may publish new proofs concurrently. A later selection may
    // legitimately choose a new digest while the policy/binding stays bounded.
    let next = synthetic_metadata_protection(&policy, &root).unwrap();
    let (_, next_files, next_public) = next
        .registries
        .iter()
        .find(|(path, _, _)| path == &native)
        .unwrap();
    assert!(next_files.len() <= 1);
    let (next_view, next_target) = next_public.as_ref().unwrap();
    assert_eq!(next_target, target);
    assert!(
        !next_view
            .join(OsString::from_vec(key.as_bytes().to_vec()))
            .exists()
    );
    assert!(fs::read_dir(next_view).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .as_bytes()
            .starts_with(prefix.as_bytes())
    }));
}

#[test]
fn corrupted_filtered_cache_is_retained_and_rebuilt_as_nonauthoritative_data() {
    let root = fixture(Path::new("/var/tmp"));
    let (_, source) = stage_authority(&File::open(&root).unwrap()).unwrap();
    let object = fixture(&root);
    let directory = File::open(object).unwrap();
    set_tag(&directory).unwrap();
    let (key, bytes) = nonce_record(&directory).unwrap();
    write_record(&source, &key, &bytes).unwrap();
    let names = vec![
        OsString::from("format"),
        OsString::from_vec(key.as_bytes().to_vec()),
    ];
    let view = views::filtered_view(&source, &names, views::ViewAccess::Readable).unwrap();
    assert_eq!(
        views::filtered_view(&source, &names, views::ViewAccess::Readable).unwrap(),
        view
    );
    fs::write(
        view.join("unknown-preserve"),
        b"preserve cache contamination",
    )
    .unwrap();
    let rebuilt = views::filtered_view(&source, &names, views::ViewAccess::Readable).unwrap();
    assert_ne!(rebuilt, view);
    assert_eq!(
        fs::read(view.join("unknown-preserve")).unwrap(),
        b"preserve cache contamination"
    );
    assert_eq!(
        fs::read(rebuilt.join(OsString::from_vec(key.as_bytes().to_vec()))).unwrap(),
        bytes
    );
}

#[test]
fn filtered_view_copies_read_only_source_without_using_nss_home_for_cache_storage() {
    use std::os::unix::fs::PermissionsExt;
    let root = fixture(Path::new("/var/tmp"));
    let (name, source) = stage_authority(&File::open(&root).unwrap()).unwrap();
    let source_path = root.join(OsString::from_vec(name.as_bytes().to_vec()));
    fs::set_permissions(&source_path, fs::Permissions::from_mode(0o500)).unwrap();
    let before = fs::metadata(&source_path).unwrap();
    let view = views::filtered_view(
        &source,
        &[OsString::from("format")],
        views::ViewAccess::Readable,
    )
    .unwrap();
    let expected = Path::new("/var/tmp")
        .join(format!("codex-synthetic-metadata-v1-{}", unsafe {
            libc::geteuid()
        }))
        .join("private-public-views");
    assert!(view.starts_with(expected));
    assert_eq!(
        fs::read(view.join("format")).unwrap(),
        b"codex-synthetic-metadata-v1\n"
    );
    let after = fs::metadata(&source_path).unwrap();
    assert_eq!(
        (
            before.dev(),
            before.ino(),
            before.mode(),
            before.mtime(),
            before.mtime_nsec()
        ),
        (
            after.dev(),
            after.ino(),
            after.mode(),
            after.mtime(),
            after.mtime_nsec()
        )
    );
    assert_eq!(fs::read_dir(source_path).unwrap().count(), 1);
}

#[test]
fn legacy_authority_projection_excludes_private_entries_created_before_and_after_selection() {
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemPath;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_utils_absolute_path::AbsolutePathBuf;
    let path = super::super::linux::synthetic_metadata_registry_path();
    let authority = initialize_authority_if_absent(&path).unwrap();
    let before = random_name("private-before-selection").unwrap();
    write_record(&authority, &before, b"preserve private sentinel").unwrap();
    let policy = FileSystemSandboxPolicy::restricted(vec![FileSystemSandboxEntry {
        path: FileSystemPath::Path {
            path: AbsolutePathBuf::from_absolute_path("/").unwrap(),
        },
        access: FileSystemAccessMode::Read,
    }]);
    let protection = synthetic_metadata_protection(&policy, Path::new("/var/tmp")).unwrap();
    assert!(!protection.read_only.contains(&path));
    let (view, _) = protection
        .bindings
        .iter()
        .find(|(_, target)| target == &path)
        .unwrap();
    let later = random_name("private-after-selection").unwrap();
    write_record(&authority, &later, b"preserve later private sentinel").unwrap();
    for name in [before, later] {
        let name = OsString::from_vec(name.as_bytes().to_vec());
        assert!(!view.join(&name).exists());
        assert!(path.join(name).is_file());
    }
    assert_eq!(
        fs::read(view.join("format")).unwrap(),
        b"codex-synthetic-metadata-v1\n"
    );
}

#[test]
fn explicit_cached_proof_file_grants_below_denied_authorities_remain_private() {
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemPath;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_utils_absolute_path::AbsolutePathBuf;
    let legacy_path = super::super::linux::synthetic_metadata_registry_path();
    let legacy = initialize_authority_if_absent(&legacy_path).unwrap();
    let native_path = registry::path().unwrap();
    let native = native_registry(/*initialize*/ true).unwrap();
    let mut files = Vec::new();
    for (path, authority) in [(&legacy_path, &legacy), (&native_path, &native)] {
        let cache = registry::authority(
            authority,
            c"private-public-views",
            AuthorityMode::Initialize,
        )
        .unwrap();
        let (name, view) = stage_authority(&cache).unwrap();
        write_record(
            &view,
            c"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            b"private cached proof",
        )
        .unwrap();
        files.push(
            path.join("private-public-views")
                .join(OsString::from_vec(name.as_bytes().to_vec()))
                .join("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        );
    }
    let entry = |path: &Path, access| FileSystemSandboxEntry {
        path: FileSystemPath::Path {
            path: AbsolutePathBuf::from_absolute_path(path).unwrap(),
        },
        access,
    };
    let mut entries = vec![
        entry(Path::new("/"), FileSystemAccessMode::Read),
        entry(&legacy_path, FileSystemAccessMode::Deny),
        entry(&native_path, FileSystemAccessMode::Deny),
    ];
    entries.extend(
        files
            .iter()
            .map(|path| entry(path, FileSystemAccessMode::Read)),
    );
    let protection = synthetic_metadata_protection(
        &FileSystemSandboxPolicy::restricted(entries),
        Path::new("/var/tmp"),
    )
    .unwrap();
    for path in files {
        assert!(protection.hidden_files.contains(&path));
        assert!(!protection.read_only.contains(&path));
        assert_eq!(fs::read(path).unwrap(), b"private cached proof");
    }
}

#[test]
fn glob_denied_writable_root_is_not_modified_by_stage_preinitialization() {
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemPath;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_utils_absolute_path::AbsolutePathBuf;
    let root = fixture(Path::new("/var/tmp"));
    let denied = root.join("denied.env");
    fs::create_dir(&denied).unwrap();
    let before = fs::metadata(&denied).unwrap();
    let policy = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: AbsolutePathBuf::from_absolute_path(&denied).unwrap(),
            },
            access: FileSystemAccessMode::Write,
        },
        FileSystemSandboxEntry {
            path: FileSystemPath::GlobPattern {
                pattern: format!("{}/**/*.env", root.display()),
            },
            access: FileSystemAccessMode::Deny,
        },
    ]);
    assert!(policy.can_write_path_with_cwd(&denied, &root));
    prepare_synthetic_metadata_staging_for_policy(&policy, &root).unwrap();
    let after = fs::metadata(&denied).unwrap();
    assert_eq!(
        (
            after.dev(),
            after.ino(),
            after.mode(),
            after.mtime(),
            after.mtime_nsec()
        ),
        (
            before.dev(),
            before.ino(),
            before.mode(),
            before.mtime(),
            before.mtime_nsec()
        )
    );
    assert_eq!(fs::read_dir(denied).unwrap().count(), 0);
}

#[test]
fn oversized_or_symlinked_ownership_records_are_ordinary() {
    use std::os::unix::fs::symlink;
    let root = fixture(Path::new("/var/tmp"));
    let path = root.join(".git");
    prepare_synthetic_metadata_directory(&path).unwrap();
    let (key, expected) = nonce_record(&File::open(&path).unwrap()).unwrap();
    let record = registry::path()
        .unwrap()
        .join("public-records")
        .join(OsString::from_vec(key.as_bytes().to_vec()));
    let original = fs::read(&record).unwrap();
    assert_eq!(original, expected);
    fs::write(&record, vec![0; 4096]).unwrap();
    assert!(!super::super::is_synthetic_metadata_directory(&path));
    fs::write(&record, &original).unwrap();
    assert!(super::super::is_synthetic_metadata_directory(&path));
    let moved = root.join("record");
    fs::rename(&record, &moved).unwrap();
    symlink(&moved, &record).unwrap();
    assert!(!super::super::is_synthetic_metadata_directory(&path));
}
