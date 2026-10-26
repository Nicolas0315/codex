use super::*;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

fn fixture() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = PathBuf::from(format!(
        "/var/tmp/codex-synthetic-test-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    path
}

#[test]
fn owned_empty_directory_is_recognized_after_publication() {
    let path = fixture().join(".git");
    prepare_synthetic_metadata_directory(&path).unwrap();
    assert!(is_synthetic_metadata_directory(&path));
    assert_eq!(fs::read_dir(&path).unwrap().count(), 0);
}

#[test]
fn ordinary_marker_names_are_not_published_or_hidden_after_a_rename() {
    let root = fixture();
    let ordinary = root.join("custom-marker");
    assert_eq!(
        prepare_synthetic_metadata_directory(&ordinary)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
    assert!(!ordinary.exists());
    let owned = root.join(".git");
    prepare_synthetic_metadata_directory(&owned).unwrap();
    assert!(is_synthetic_metadata_directory(&owned));
    fs::rename(&owned, &ordinary).unwrap();
    assert!(!is_synthetic_metadata_directory(&ordinary));
    assert!(ordinary.is_dir());
}

#[test]
fn real_existing_directories_and_leaf_symlinks_are_preserved() {
    let root = fixture();
    let empty = root.join("empty");
    fs::create_dir(&empty).unwrap();
    prepare_synthetic_metadata_directory(&empty).unwrap();
    assert!(!is_synthetic_metadata_directory(&empty));
    let nonempty = root.join("nonempty");
    fs::create_dir(&nonempty).unwrap();
    fs::write(nonempty.join("config"), b"real configuration").unwrap();
    prepare_synthetic_metadata_directory(&nonempty).unwrap();
    assert!(!is_synthetic_metadata_directory(&nonempty));
    let link = root.join("link");
    symlink(&empty, &link).unwrap();
    prepare_synthetic_metadata_directory(&link).unwrap();
    assert!(!is_synthetic_metadata_directory(&link));
    assert_eq!(
        fs::read(nonempty.join("config")).unwrap(),
        b"real configuration"
    );
    assert_eq!(fs::read_link(link).unwrap(), empty);
}

#[test]
fn replacements_and_directories_with_user_contents_are_ordinary() {
    let root = fixture();
    let path = root.join(".git");
    prepare_synthetic_metadata_directory(&path).unwrap();
    fs::rename(&path, root.join("old")).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(!is_synthetic_metadata_directory(&path));
    let old = root.join("old");
    fs::write(old.join("user-file"), b"important").unwrap();
    assert!(!is_synthetic_metadata_directory(&old));
}

#[test]
fn changed_mtime_and_forged_tags_do_not_establish_ownership() {
    let root = fixture();
    let path = root.join(".git");
    prepare_synthetic_metadata_directory(&path).unwrap();
    let dir = fs::File::open(&path).unwrap();
    dir.set_times(fs::FileTimes::new().set_modified(UNIX_EPOCH))
        .unwrap();
    assert!(!is_synthetic_metadata_directory(&path));
    let forged = root.join("forged");
    fs::create_dir(&forged).unwrap();
    fs::write(forged.join(".codex-synthetic"), b"owned").unwrap();
    assert!(!is_synthetic_metadata_directory(&forged));
}

#[test]
fn concurrent_publishers_do_not_replace_the_winning_directory() {
    let path = fixture().join(".git");
    let workers = (0..8)
        .map(|_| {
            let path = path.clone();
            std::thread::spawn(move || prepare_synthetic_metadata_directory(&path))
        })
        .collect::<Vec<_>>();
    for worker in workers {
        worker.join().unwrap().unwrap();
    }
    assert!(is_synthetic_metadata_directory(&path));
    assert_eq!(fs::read_dir(path).unwrap().count(), 0);
}

#[test]
fn oversized_or_symlinked_ownership_records_are_ordinary() {
    use std::os::unix::fs::MetadataExt;
    let root = fixture();
    let path = root.join(".git");
    prepare_synthetic_metadata_directory(&path).unwrap();
    let metadata = fs::metadata(&path).unwrap();
    let mut identity_prefix = b"CSM1".to_vec();
    identity_prefix.extend_from_slice(&metadata.dev().to_le_bytes());
    identity_prefix.extend_from_slice(&metadata.ino().to_le_bytes());
    let record = fs::read_dir(synthetic_metadata_registry_path())
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| entry.file_type().unwrap().is_file())
        .find(|entry| {
            fs::read(entry.path())
                .unwrap()
                .starts_with(&identity_prefix)
        })
        .unwrap()
        .path();
    let original = fs::read(&record).unwrap();
    fs::write(&record, vec![0; 4096]).unwrap();
    assert!(!is_synthetic_metadata_directory(&path));
    fs::write(&record, &original).unwrap();
    assert!(is_synthetic_metadata_directory(&path));
    let moved = root.join("record");
    fs::rename(&record, &moved).unwrap();
    symlink(&moved, &record).unwrap();
    assert!(!is_synthetic_metadata_directory(&path));
}

#[test]
fn parent_symlink_aliases_resolve_to_the_same_owned_object() {
    let root = fixture();
    let parent = root.join("real");
    fs::create_dir(&parent).unwrap();
    let alias = root.join("alias");
    symlink(&parent, &alias).unwrap();
    prepare_synthetic_metadata_directory(&alias.join(".git")).unwrap();
    assert!(is_synthetic_metadata_directory(&alias.join(".git")));
    assert!(is_synthetic_metadata_directory(&parent.join(".git")));
}

#[test]
fn interrupted_private_authority_preparation_does_not_block_next_initialization() {
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::fd::OwnedFd;
    use std::time::Duration;
    use std::time::Instant;

    let final_path = fixture().with_extension("authority");
    let parent = fs::File::open("/var/tmp").unwrap();
    let mut pipe = [0; 2];
    assert_eq!(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
        0
    );
    let read = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork test-owned initializer");
    if child == 0 {
        drop(read);
        let prepared = super::linux::stage_authority(&parent).is_ok();
        let signal = u8::from(prepared);
        unsafe {
            libc::write(write.as_raw_fd(), (&signal as *const u8).cast(), 1);
        }
        if !prepared {
            unsafe {
                libc::_exit(1);
            }
        }
        loop {
            unsafe {
                libc::pause();
            }
        }
    }
    drop(write);
    let mut poll = libc::pollfd {
        fd: read.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ready = unsafe { libc::poll(&mut poll, 1, 5_000) };
    let mut signal = 0_u8;
    let count = if ready > 0 {
        unsafe { libc::read(read.as_raw_fd(), (&mut signal as *mut u8).cast(), 1) }
    } else {
        0
    };
    // Only terminate and reap the initializer this test forked. Cleanup precedes
    // readiness assertions so a failed preparation cannot leave a paused child.
    let killed = unsafe { libc::kill(child, libc::SIGKILL) };
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if waited == child {
            break;
        }
        assert!(waited >= 0, "wait for test-owned initializer");
        assert!(
            Instant::now() < deadline,
            "test-owned initializer did not terminate"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!((ready, count, signal, killed), (1, 1, 1, 0));
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
    assert_eq!(
        fs::symlink_metadata(&final_path).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    super::linux::open_authority(&final_path, super::linux::AuthorityMode::Initialize).unwrap();
    super::linux::open_authority(&final_path, super::linux::AuthorityMode::ReadOnly).unwrap();
}

#[test]
fn simultaneous_first_authority_initializers_publish_one_complete_object() {
    use std::os::unix::fs::MetadataExt;
    use std::sync::Arc;
    use std::sync::Barrier;
    let path = fixture().with_extension("authority");
    let barrier = Arc::new(Barrier::new(8));
    let workers = (0..8)
        .map(|_| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                let directory =
                    super::linux::open_authority(&path, super::linux::AuthorityMode::Initialize)
                        .unwrap();
                let metadata = directory.metadata().unwrap();
                (metadata.dev(), metadata.ino(), metadata.mode() & 0o777)
            })
        })
        .collect::<Vec<_>>();
    let objects = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(objects, vec![objects[0]; 8]);
    assert_eq!(objects[0].2, 0o700);
    super::linux::open_authority(&path, super::linux::AuthorityMode::ReadOnly).unwrap();
}

#[test]
fn preexisting_unmarked_authority_is_not_adopted_or_modified() {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    let path = fixture();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(path.join("user-record"), b"untrusted ownership evidence").unwrap();
    let before = fs::metadata(&path).unwrap();
    assert!(super::linux::open_authority(&path, super::linux::AuthorityMode::Initialize).is_err());
    let after = fs::metadata(&path).unwrap();
    assert_eq!(
        (
            before.dev(),
            before.ino(),
            before.mtime(),
            before.mtime_nsec()
        ),
        (after.dev(), after.ino(), after.mtime(), after.mtime_nsec())
    );
    assert_eq!(
        fs::read(path.join("user-record")).unwrap(),
        b"untrusted ownership evidence"
    );
    assert!(!path.join("format").exists());
}

#[test]
fn read_only_authority_open_does_not_create_an_absent_final_path() {
    let path = fixture().with_extension("authority");
    assert_eq!(
        super::linux::open_authority(&path, super::linux::AuthorityMode::ReadOnly)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound,
    );
    assert!(!path.exists());
}

#[test]
fn user_owned_authority_parent_is_not_confused_with_os_owned_parent() {
    use std::os::unix::fs::MetadataExt;
    let parent = fixture();
    // Root itself owns OS-controlled paths when this test runs as root. The
    // non-root control is exercised inside the bwrap transport integration too.
    let path = parent.join("authority");
    let result = super::linux::open_authority(&path, super::linux::AuthorityMode::Initialize);
    if fs::metadata(&parent).unwrap().uid() != fs::metadata("/").unwrap().uid() {
        assert!(result.is_err());
        assert!(!path.exists());
    } else {
        assert!(result.is_ok());
        assert!(path.is_dir());
    }
}

#[test]
fn querying_existing_authorities_preserves_their_objects_and_contents() {
    use std::os::unix::fs::MetadataExt;
    initialize_synthetic_metadata_registry().unwrap();
    let before = existing_synthetic_metadata_authorities()
        .unwrap()
        .into_iter()
        .map(|path| {
            let metadata = fs::metadata(&path).unwrap();
            let marker_path = path.join("format");
            let marker_metadata = fs::metadata(&marker_path).unwrap();
            let marker = fs::read(marker_path).unwrap();
            (
                path,
                metadata.dev(),
                metadata.ino(),
                metadata.mode(),
                marker_metadata.ino(),
                marker,
            )
        })
        .collect::<Vec<_>>();
    let after = existing_synthetic_metadata_authorities()
        .unwrap()
        .into_iter()
        .map(|path| {
            let metadata = fs::metadata(&path).unwrap();
            let marker_path = path.join("format");
            let marker_metadata = fs::metadata(&marker_path).unwrap();
            let marker = fs::read(marker_path).unwrap();
            (
                path,
                metadata.dev(),
                metadata.ino(),
                metadata.mode(),
                marker_metadata.ino(),
                marker,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(after, before);
}
