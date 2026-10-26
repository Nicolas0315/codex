use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;

#[test]
fn stage_history_reads_only_published_keys_and_retains_pending_entries() {
    use std::os::unix::ffi::OsStrExt;
    let root = super::super::tests::fixture(Path::new("/var/tmp"));
    let (name, index) = stage_authority(&File::open(&root).unwrap()).unwrap();
    let index_path = root.join(OsString::from_vec(name.to_bytes().to_vec()));
    let stage = super::super::tests::fixture(Path::new("/var/tmp"));
    let directory = File::open(&stage).unwrap();
    super::super::set_tag(&directory).unwrap();
    let identity = super::super::object_identity(&directory).unwrap();
    let key = std::ffi::CString::new("f".repeat(64)).unwrap();
    write_stage_record(
        &index,
        &key,
        &StageRecord {
            path: stage.clone(),
            identity: identity.clone(),
        },
    )
    .unwrap();
    // The old path-bearing stage layout stored a CSM2 identity. Its reader
    // remains compatible even though it cannot authenticate a new CSM3 object.
    let metadata = directory.metadata().unwrap();
    let mut legacy_identity = b"CSM2".to_vec();
    legacy_identity.extend_from_slice(&metadata.dev().to_le_bytes());
    legacy_identity.extend_from_slice(&metadata.ino().to_le_bytes());
    legacy_identity.extend_from_slice(&[0; 32]);
    let mut legacy = legacy_identity.clone();
    legacy.extend_from_slice(stage.as_os_str().as_bytes());
    super::super::write_record(&index, c"stage-legacy", &legacy).unwrap();
    // A transient directory or symlink would fail strict record opening if
    // the history reader mistook it for a committed key.
    let pending = index_path.join("reservation-pending");
    fs::create_dir(&pending).unwrap();
    fs::write(pending.join("user-content"), b"preserve pending content").unwrap();
    let link = index_path.join("reservation-link");
    symlink(&pending, &link).unwrap();
    let before = fs::metadata(&pending).unwrap();
    for legacy in [false, true] {
        let actual = stage_records(&index, legacy)
            .unwrap()
            .into_iter()
            .map(|record| (record.path, record.identity))
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            vec![(
                stage.clone(),
                if legacy {
                    legacy_identity.clone()
                } else {
                    identity.clone()
                }
            )]
        );
    }
    let after = fs::metadata(&pending).unwrap();
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
    assert_eq!(fs::read_link(link).unwrap(), pending);
    assert_eq!(
        fs::read(pending.join("user-content")).unwrap(),
        b"preserve pending content"
    );
    // A malformed committed key still fails closed; the filter is not a
    // blanket suppression of index validation or storage errors.
    let malformed = index_path.join("a".repeat(64));
    fs::write(&malformed, b"preserve malformed record").unwrap();
    fs::set_permissions(&malformed, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(stage_records(&index, /*legacy*/ false).is_err());
    assert_eq!(fs::read(malformed).unwrap(), b"preserve malformed record");
}

#[test]
fn a_genuine_codex_symlink_to_protected_native_storage_is_supported() {
    let home = super::super::tests::fixture(Path::new("/var/tmp"));
    let state = super::super::tests::fixture(Path::new("/var/tmp"));
    symlink(&state, home.join(".codex")).unwrap();
    let registry = open_home(&home, AuthorityMode::Initialize).unwrap();
    assert_eq!(
        registry.metadata().unwrap().ino(),
        fs::metadata(state.join("synthetic-metadata-v2"))
            .unwrap()
            .ino()
    );
    assert!(
        fs::symlink_metadata(home.join(".codex"))
            .unwrap()
            .is_symlink()
    );
    assert!(open_home(&home, AuthorityMode::ReadOnly).is_ok());
}

#[test]
fn a_codex_symlink_does_not_bypass_native_ancestor_permissions() {
    let home = super::super::tests::fixture(Path::new("/var/tmp"));
    let state = super::super::tests::fixture(Path::new("/var/tmp"));
    fs::set_permissions(&state, fs::Permissions::from_mode(0o777)).unwrap();
    symlink(&state, home.join(".codex")).unwrap();
    assert!(open_home(&home, AuthorityMode::Initialize).is_err());
    assert!(!state.join("synthetic-metadata-v2").exists());
}

#[test]
fn migration_copies_only_path_free_legacy_native_records_and_preserves_sources() {
    let home = super::super::tests::fixture(Path::new("/var/tmp"));
    fs::create_dir(home.join(".codex")).unwrap();
    let codex = File::open(home.join(".codex")).unwrap();
    let (temporary, registry) = stage_authority(&codex).unwrap();
    publish(&codex, &temporary, &codex, c"synthetic-metadata-v2").unwrap();
    let object = super::super::tests::fixture(Path::new("/var/tmp"));
    let (key, bytes) = super::super::super::linux::record(&File::open(object).unwrap()).unwrap();
    super::super::write_record(&registry, &key, &bytes).unwrap();
    super::super::write_record(
        &registry,
        c"stage-old-path",
        b"CSM2old-private-workspace-path",
    )
    .unwrap();
    let source = open_at(&registry, &key, libc::O_RDONLY, /*mode*/ 0)
        .unwrap()
        .metadata()
        .unwrap()
        .ino();
    let initialized = open_home(&home, AuthorityMode::Initialize).unwrap();
    let public = records(&initialized, AuthorityMode::ReadOnly).unwrap();
    assert_eq!(
        read_bounded(open_at(&public, &key, libc::O_RDONLY, /*mode*/ 0).unwrap()).unwrap(),
        bytes
    );
    assert_eq!(
        open_at(&registry, &key, libc::O_RDONLY, /*mode*/ 0)
            .unwrap()
            .metadata()
            .unwrap()
            .ino(),
        source
    );
    assert_eq!(
        read_bounded(
            open_at(
                &registry,
                c"stage-old-path",
                libc::O_RDONLY,
                /*mode*/ 0
            )
            .unwrap()
        )
        .unwrap(),
        b"CSM2old-private-workspace-path"
    );
    assert!(open_at(&public, c"stage-old-path", libc::O_RDONLY, /*mode*/ 0).is_err());
    assert!(open_home(&home, AuthorityMode::Initialize).is_ok());
}

#[test]
fn contaminated_legacy_entries_are_retained_without_reading_or_migrating_them() {
    let home = super::super::tests::fixture(Path::new("/var/tmp"));
    fs::create_dir(home.join(".codex")).unwrap();
    let codex = File::open(home.join(".codex")).unwrap();
    let (temporary, registry) = stage_authority(&codex).unwrap();
    publish(&codex, &temporary, &codex, c"synthetic-metadata-v2").unwrap();
    let registry_path = home.join(".codex/synthetic-metadata-v2");
    let object = super::super::tests::fixture(Path::new("/var/tmp"));
    let (key, bytes) = super::super::super::linux::record(&File::open(object).unwrap()).unwrap();
    super::super::write_record(&registry, &key, &bytes).unwrap();
    let target = home.join("private-symlink-target");
    fs::write(&target, b"private target must remain untouched").unwrap();
    let target_c = c_path(&target).unwrap();
    let old_times = [libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    }; 2];
    assert_eq!(
        unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                target_c.as_ptr(),
                old_times.as_ptr(),
                /*flags*/ 0,
            )
        },
        0
    );
    let target_before = fs::metadata(&target).unwrap();
    let symlink_name = "a".repeat(64);
    symlink(&target, registry_path.join(&symlink_name)).unwrap();
    let malformed_name = "b".repeat(64);
    super::super::write_record(
        &registry,
        &std::ffi::CString::new(malformed_name.clone()).unwrap(),
        &[0; 68],
    )
    .unwrap();
    let directory_name = "c".repeat(64);
    fs::create_dir(registry_path.join(&directory_name)).unwrap();
    let wrong_mode_name = "d".repeat(64);
    let wrong_mode_path = registry_path.join(&wrong_mode_name);
    fs::write(&wrong_mode_path, &bytes).unwrap();
    fs::set_permissions(&wrong_mode_path, fs::Permissions::from_mode(0o644)).unwrap();
    let wrong_key_name = "e".repeat(64);
    super::super::write_record(
        &registry,
        &std::ffi::CString::new(wrong_key_name.clone()).unwrap(),
        &bytes,
    )
    .unwrap();
    let initialized = open_home(&home, AuthorityMode::Initialize).unwrap();
    let public = records(&initialized, AuthorityMode::ReadOnly).unwrap();
    assert_eq!(
        read_bounded(open_at(&public, &key, libc::O_RDONLY, /*mode*/ 0).unwrap()).unwrap(),
        bytes
    );
    assert_eq!(
        fs::read_link(registry_path.join(&symlink_name)).unwrap(),
        target
    );
    let target_after = fs::metadata(&target).unwrap();
    assert_eq!(
        (
            target_after.dev(),
            target_after.ino(),
            target_after.atime(),
            target_after.atime_nsec()
        ),
        (
            target_before.dev(),
            target_before.ino(),
            target_before.atime(),
            target_before.atime_nsec()
        )
    );
    for name in [
        symlink_name,
        malformed_name,
        directory_name,
        wrong_mode_name,
        wrong_key_name,
    ] {
        assert!(fs::symlink_metadata(registry_path.join(&name)).is_ok());
        assert!(
            open_at(
                &public,
                &std::ffi::CString::new(name).unwrap(),
                libc::O_RDONLY,
                /*mode*/ 0
            )
            .is_err()
        );
    }
    assert!(open_home(&home, AuthorityMode::Initialize).is_ok());
}
