use super::*;

#[test]
fn subtree_and_same_filesystem_bind_aliases_include_authority() {
    let mounts = MountTable::parse(b"1 0 8:1 / / rw - ext4 none rw\n2 1 8:1 /work /alias rw - ext4 none rw\n3 1 8:1 /work/project/stage /leaf rw - ext4 none rw\n4 1 9:1 /work /different rw - ext4 none rw\n").unwrap();
    assert_eq!(
        translate(Path::new("/work/project/stage"), &mounts.0),
        vec![
            PathBuf::from("/alias/project/stage"),
            PathBuf::from("/leaf"),
            PathBuf::from("/work/project/stage")
        ]
    );
    assert_eq!(
        translate(Path::new("/alias/project/stage"), &mounts.0),
        translate(Path::new("/work/project/stage"), &mounts.0)
    );
    assert_eq!(
        mounts.key(Path::new("/work/project")),
        mounts.key(Path::new("/alias/project"))
    );
}

#[test]
fn mountinfo_escapes_and_unrelated_non_utf8_paths_preserve_bytes() {
    assert_eq!(
        mount_path(b"/work\\040tree\\134name").unwrap(),
        PathBuf::from("/work tree\\name")
    );
    assert!(mount_path(b"/work\\04x").is_err());
    let mounts = MountTable::parse(
        b"1 0 8:1 / / rw - ext4 none rw\n2 1 9:1 / /unrelated-\xff ro - ext4 none ro\n",
    )
    .unwrap();
    assert_eq!(
        mounts.0[1].point.as_os_str().as_encoded_bytes(),
        b"/unrelated-\xff"
    );
    assert!(mounts.writable(Path::new("/work")));
}

#[test]
fn deepest_mount_read_only_state_controls_stage_creation() {
    let mounts = MountTable::parse(b"1 0 8:1 / / rw - ext4 none rw\n2 1 9:1 / /work/read-only ro - ext4 none ro\n3 2 10:1 / /work/read-only/granted rw - ext4 none rw\n").unwrap();
    assert!(!mounts.writable(Path::new("/work/read-only/child")));
    assert!(mounts.writable(Path::new("/work/read-only/granted/child")));
}

#[test]
fn cache_authority_reservation_skips_read_only_host_mounts_and_preserves_warm_state() {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let candidate = || {
        Path::new("/var/tmp").join(std::ffi::OsStr::from_bytes(
            super::super::random_name("codex-cache-reservation-test")
                .unwrap()
                .as_bytes(),
        ))
    };
    let read_only = MountTable::parse(b"1 0 8:1 / / ro - ext4 none ro\n").unwrap();
    let writable = MountTable::parse(b"1 0 8:1 / / rw - ext4 none rw\n").unwrap();
    let skipped = candidate();
    super::super::views::prepare_cache_authority(&skipped, &read_only).unwrap();
    assert!(!skipped.exists());
    let reserved = candidate();
    super::super::views::prepare_cache_authority(&reserved, &writable).unwrap();
    assert_eq!(
        std::fs::read(reserved.join("format")).unwrap(),
        b"codex-synthetic-metadata-v1\n"
    );
    let before = std::fs::metadata(&reserved).unwrap();
    super::super::views::prepare_cache_authority(&reserved, &read_only).unwrap();
    let after = std::fs::metadata(&reserved).unwrap();
    assert_eq!(
        (
            before.dev(),
            before.ino(),
            before.mtime(),
            before.mtime_nsec()
        ),
        (after.dev(), after.ino(), after.mtime(), after.mtime_nsec())
    );
    let unknown = candidate();
    std::fs::write(&unknown, b"preserve unknown authority candidate").unwrap();
    assert!(super::super::views::prepare_cache_authority(&unknown, &writable).is_err());
    assert_eq!(
        std::fs::read(unknown).unwrap(),
        b"preserve unknown authority candidate"
    );
}

#[test]
fn a_writable_native_parent_alias_still_requires_cache_reservation() {
    use std::os::unix::ffi::OsStrExt;
    let candidate = || {
        Path::new("/var/tmp").join(std::ffi::OsStr::from_bytes(
            super::super::random_name("codex-cache-alias-test")
                .unwrap()
                .as_bytes(),
        ))
    };
    // Represent an existing same-object alias with an isolated symlink fixture;
    // the parsed table supplies mount geometry without mounting a namespace.
    let alias = candidate();
    std::os::unix::fs::symlink("/var/tmp", &alias).unwrap();
    let mounts = MountTable::parse(
        format!(
            "1 0 8:1 / / ro - ext4 none ro\n2 1 8:1 /var/tmp {} rw - ext4 none rw\n",
            alias.display()
        )
        .as_bytes(),
    )
    .unwrap();
    let path = candidate();
    super::super::views::prepare_cache_authority(&path, &mounts).unwrap();
    assert_eq!(
        std::fs::read(path.join("format")).unwrap(),
        b"codex-synthetic-metadata-v1\n"
    );
}

#[test]
fn legacy_views_follow_host_storage_access_and_keep_existing_caches_private() {
    use super::super::super::linux;
    use super::super::registry;
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemPath;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_protocol::protocol::FileSystemSandboxPolicy;
    use codex_utils_absolute_path::AbsolutePathBuf;
    let authority = linux::synthetic_metadata_registry_path();
    let directory = linux::initialize_authority_if_absent(&authority).unwrap();
    registry::authority(
        &directory,
        c"private-public-views",
        linux::AuthorityMode::Initialize,
    )
    .unwrap();
    let policy = FileSystemSandboxPolicy::restricted(vec![FileSystemSandboxEntry {
        path: FileSystemPath::Path {
            path: AbsolutePathBuf::from_absolute_path("/").unwrap(),
        },
        access: FileSystemAccessMode::Read,
    }]);
    let read_only = MountTable::parse(b"1 0 8:1 / / ro - ext4 none ro\n").unwrap();
    let protection = super::super::protection::protection_with_mounts(
        &policy,
        Path::new("/var/tmp"),
        &read_only,
    )
    .unwrap();
    assert!(protection.read_only.contains(&authority));
    assert!(
        !protection
            .bindings
            .iter()
            .any(|(_, target)| target == &authority)
    );
    assert!(
        protection
            .hidden_directories
            .contains(&authority.join("private-public-views"))
    );
    let writable = MountTable::parse(b"1 0 8:1 / / rw - ext4 none rw\n").unwrap();
    let protection =
        super::super::protection::protection_with_mounts(&policy, Path::new("/var/tmp"), &writable)
            .unwrap();
    assert!(!protection.read_only.contains(&authority));
    let (view, _) = protection
        .bindings
        .iter()
        .find(|(_, target)| target == &authority)
        .unwrap();
    assert!(!view.join("private-public-views").exists());
    assert!(authority.join("private-public-views").is_dir());
}

#[test]
fn inherited_alias_reads_keep_canonical_child_denies_filtered() {
    use super::super::super::linux;
    use codex_protocol::permissions::FileSystemAccessMode;
    use codex_protocol::permissions::FileSystemPath;
    use codex_protocol::permissions::FileSystemSandboxEntry;
    use codex_protocol::protocol::FileSystemSandboxPolicy;
    use codex_utils_absolute_path::AbsolutePathBuf;
    use std::os::unix::ffi::OsStrExt;
    let authority = linux::synthetic_metadata_registry_path();
    linux::initialize_authority_if_absent(&authority).unwrap();
    let alias = Path::new("/var/tmp").join(std::ffi::OsStr::from_bytes(
        super::super::random_name("codex-canonical-child-alias-test")
            .unwrap()
            .as_bytes(),
    ));
    std::os::unix::fs::symlink("/var/tmp", &alias).unwrap();
    let mounts = MountTable::parse(
        format!(
            "1 0 8:1 / / rw - ext4 none rw\n2 1 8:1 /var/tmp {} rw - ext4 none rw\n",
            alias.display()
        )
        .as_bytes(),
    )
    .unwrap();
    let alias_authority = alias.join(authority.file_name().unwrap());
    for (kind, denied) in [
        (
            "exact",
            FileSystemPath::Path {
                path: AbsolutePathBuf::from_absolute_path(authority.join("format")).unwrap(),
            },
        ),
        (
            "glob",
            FileSystemPath::GlobPattern {
                pattern: format!("{}/f*", authority.display()),
            },
        ),
    ] {
        let policy = FileSystemSandboxPolicy::restricted(vec![
            FileSystemSandboxEntry {
                path: FileSystemPath::Path {
                    path: AbsolutePathBuf::from_absolute_path("/").unwrap(),
                },
                access: FileSystemAccessMode::Read,
            },
            FileSystemSandboxEntry {
                path: denied,
                access: FileSystemAccessMode::Deny,
            },
        ]);
        let protection = super::super::protection::protection_with_mounts(
            &policy,
            Path::new("/var/tmp"),
            &mounts,
        )
        .unwrap();
        let (view, _) = protection
            .bindings
            .iter()
            .find(|(_, target)| target == &alias_authority)
            .unwrap();
        assert!(
            !view.join("format").exists(),
            "{kind} canonical child deny reopened"
        );
        assert_eq!(
            std::fs::read(authority.join("format")).unwrap(),
            b"codex-synthetic-metadata-v1\n"
        );
    }
}
