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
