use super::super::MountTable;
use super::*;
use codex_protocol::permissions::FileSystemAccessMode;
use codex_protocol::permissions::FileSystemPath;
use codex_protocol::permissions::FileSystemSandboxEntry;
use codex_protocol::protocol::FileSystemSandboxPolicy;
use codex_utils_absolute_path::AbsolutePathBuf;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

fn fixture() -> PathBuf {
    super::super::tests::fixture(Path::new("/var/tmp"))
}

fn policy(writable: Option<&Path>) -> FileSystemSandboxPolicy {
    let mut entries = vec![FileSystemSandboxEntry {
        path: FileSystemPath::Path {
            path: AbsolutePathBuf::from_absolute_path("/").unwrap(),
        },
        access: FileSystemAccessMode::Read,
    }];
    if let Some(path) = writable {
        entries.push(FileSystemSandboxEntry {
            path: FileSystemPath::Path {
                path: AbsolutePathBuf::from_absolute_path(path).unwrap(),
            },
            access: FileSystemAccessMode::Write,
        });
    }
    FileSystemSandboxPolicy::restricted(entries)
}

#[test]
fn absent_configuration_rejects_parent_leaf_and_descendant_writers() {
    let root = fixture();
    let parent = root.join("etc/codex/synthetic-metadata");
    fs::create_dir_all(&parent).unwrap();
    let path = parent.join("123.toml");
    let descendant = path.join("nested");
    for writable in [&parent, &path, &descendant] {
        assert!(
            validate_with_mounts(
                &policy(Some(writable)),
                &root,
                &path,
                &MountTable::read().unwrap()
            )
            .is_err()
        );
    }
    assert!(!path.exists());
}

#[test]
fn absent_configuration_at_each_depth_rejects_the_first_creatable_component() {
    for count in 0..=3 {
        let root = fixture();
        let mut existing = root.clone();
        for part in ["etc", "codex", "synthetic-metadata"]
            .into_iter()
            .take(count)
        {
            existing.push(part);
            fs::create_dir(&existing).unwrap();
        }
        let path = root.join("etc/codex/synthetic-metadata/123.toml");
        assert!(
            validate_with_mounts(
                &policy(Some(&existing)),
                &root,
                &path,
                &MountTable::read().unwrap()
            )
            .is_err()
        );
        assert!(!path.exists());
    }
}

#[test]
fn read_only_and_unrelated_writers_do_not_create_configuration() {
    let root = fixture();
    let workspace = fixture();
    let path = root.join("etc/codex/synthetic-metadata/123.toml");
    for writable in [None, Some(workspace.as_path())] {
        validate_with_mounts(
            &policy(writable),
            &workspace,
            &path,
            &MountTable::read().unwrap(),
        )
        .unwrap();
    }
    assert!(!root.join("etc").exists());
}

#[test]
fn an_existing_configuration_is_retained_for_separate_read_only_protection() {
    let root = fixture();
    let path = root.join("123.toml");
    fs::write(&path, b"preserve configuration").unwrap();
    validate_with_mounts(
        &policy(Some(&root)),
        &root,
        &path,
        &MountTable::read().unwrap(),
    )
    .unwrap();
    assert_eq!(fs::read(path).unwrap(), b"preserve configuration");
}

#[test]
fn read_only_mount_does_not_need_configuration_creation_reservation() {
    let root = fixture();
    let path = root.join("123.toml");
    let table = format!(
        "1 0 0:1 / / rw - ext4 none rw\n2 1 0:1 {} {} ro - ext4 none ro\n",
        root.display(),
        root.display()
    );
    validate_with_mounts(
        &policy(Some(&root)),
        &root,
        &path,
        &MountTable::parse(table.as_bytes()).unwrap(),
    )
    .unwrap();
    assert!(!path.exists());
}

#[test]
fn writable_mount_alias_of_read_only_parent_is_also_checked() {
    let root = fixture();
    let alias = fixture();
    let path = root.join("123.toml");
    let table = format!(
        "1 0 0:1 / / rw - ext4 none rw\n2 1 0:1 {} {} ro - ext4 none ro\n3 1 0:1 {} {} rw - ext4 none rw\n",
        root.display(),
        root.display(),
        root.display(),
        alias.display()
    );
    assert!(
        validate_with_mounts(
            &policy(Some(&alias)),
            &root,
            &path,
            &MountTable::parse(table.as_bytes()).unwrap()
        )
        .is_err()
    );
    assert!(!path.exists());
    assert!(!alias.join("123.toml").exists());
}
