use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;

const USER: libc::uid_t = 12345;
const VALID: &str = "version = 1\nwrite_root = '/srv/codex/current'\n";

fn fixture() -> PathBuf {
    let root = super::super::super::tests::fixture(Path::new("/var/tmp"));
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    root
}

fn configure(root: &Path, uid: libc::uid_t, contents: &str) -> PathBuf {
    let directory = root.join("etc/codex/synthetic-metadata");
    fs::create_dir_all(&directory).unwrap();
    for parent in ["etc", "etc/codex", "etc/codex/synthetic-metadata"] {
        fs::set_permissions(root.join(parent), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = directory.join(format!("{uid}.toml"));
    fs::write(&path, contents).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    path
}

fn read(root: &Path) -> io::Result<Option<Configuration>> {
    load_from_root(&File::open(root)?, USER)
}

#[test]
fn missing_configuration_at_each_directory_depth_returns_none() {
    let root = fixture();
    assert_eq!(read(&root).unwrap(), None);
    for directory in ["etc", "etc/codex", "etc/codex/synthetic-metadata"] {
        fs::create_dir(root.join(directory)).unwrap();
        assert_eq!(read(&root).unwrap(), None);
    }
}

#[test]
fn configuration_uses_requested_uid_and_defaults_retained_roots() {
    let root = fixture();
    configure(&root, USER + 1, "version = 99\n");
    assert_eq!(read(&root).unwrap(), None);
    configure(&root, USER, VALID);
    assert_eq!(
        read(&root).unwrap(),
        Some(Configuration {
            write_root: PathBuf::from("/srv/codex/current"),
            retained_read_roots: Vec::new(),
        })
    );
}

#[test]
fn configuration_preserves_retained_roots_in_order() {
    let root = fixture();
    configure(
        &root,
        USER,
        "version = 1\nwrite_root = '/srv/current'\nretained_read_roots = ['/srv/old', '/srv/older']\n",
    );
    assert_eq!(
        read(&root).unwrap(),
        Some(Configuration {
            write_root: PathBuf::from("/srv/current"),
            retained_read_roots: vec![PathBuf::from("/srv/old"), PathBuf::from("/srv/older")],
        })
    );
}

#[test]
fn configuration_rejects_hard_links_outside_the_protected_configuration_path() {
    let root = fixture();
    let path = configure(&root, USER, VALID);
    let copy = fixture().join("unprotected-copy");
    fs::hard_link(&path, &copy).unwrap();
    assert!(read(&root).is_err());
    assert_eq!(fs::read(path).unwrap(), VALID.as_bytes());
    assert_eq!(fs::read(copy).unwrap(), VALID.as_bytes());
}

#[test]
fn configuration_rejects_invalid_schema_versions_and_paths() {
    let root = fixture();
    for contents in [
        "version = 2\nwrite_root = '/srv/current'",
        "version = -1\nwrite_root = '/srv/current'",
        "version = '1'\nwrite_root = '/srv/current'",
        "write_root = '/srv/current'",
        "version = 1",
        "version = 1\nwrite_root = '/srv/current'\nunknown = true",
        "version = 1\nwrite_root = ['/srv/current']",
        "version = 1\nwrite_root = '/srv/current'\nretained_read_roots = '/srv/old'",
        "version = 1\nwrite_root = ''",
        "version = 1\nwrite_root = 'srv/current'",
        "version = 1\nwrite_root = '/srv/../current'",
        "version = 1\nwrite_root = \"/srv/\\u0000current\"",
        "version = 1\nwrite_root = '/srv/current'\nretained_read_roots = ['relative']",
        "version = 1\nwrite_root = '/srv/current'\nretained_read_roots = ['/srv/../old']",
        "version = 1\nwrite_root = '/srv/current'\nretained_read_roots = [\"/srv/\\u0000old\"]",
        "version = 1\nwrite_root = '/srv/current'\nretained_read_roots = ['/srv/current']",
        "version = 1\nwrite_root = '/srv/current'\nretained_read_roots = ['/srv/old', '/srv/old']",
        "version = 1\nwrite_root = '/srv/current'\nretained_read_roots = ['/srv/old', '/srv/./old/']",
        "not valid TOML",
    ] {
        configure(&root, USER, contents);
        assert!(read(&root).is_err(), "accepted {contents:?}");
    }
}

#[test]
fn configuration_parse_errors_do_not_disclose_configuration_contents() {
    let root = fixture();
    configure(&root, USER, "version = PRIVATE_PARSE_MARKER");
    let error = read(&root).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(!error.to_string().contains("PRIVATE_PARSE_MARKER"));
}

#[test]
fn configuration_rejects_excess_bytes_and_retained_roots() {
    let root = fixture();
    configure(&root, USER, &format!("{VALID}#{}", "x".repeat(65536)));
    assert!(read(&root).is_err());
    let roots = (0..33)
        .map(|index| format!("'/srv/history-{index}'"))
        .collect::<Vec<_>>()
        .join(",");
    configure(
        &root,
        USER,
        &format!("{VALID}retained_read_roots = [{roots}]"),
    );
    assert!(read(&root).is_err());
}

#[test]
fn configuration_accepts_bounded_retained_history() {
    let root = fixture();
    let expected = (0..32)
        .map(|index| PathBuf::from(format!("/srv/history-{index}")))
        .collect::<Vec<_>>();
    let roots = (0..32)
        .map(|index| format!("'/srv/history-{index}'"))
        .collect::<Vec<_>>()
        .join(",");
    configure(
        &root,
        USER,
        &format!("{VALID}retained_read_roots = [{roots}]"),
    );
    assert_eq!(
        read(&root).unwrap(),
        Some(Configuration {
            write_root: PathBuf::from("/srv/codex/current"),
            retained_read_roots: expected,
        })
    );
}

#[test]
fn configuration_rejects_untrusted_modes_on_each_ancestor_and_file() {
    for relative in [
        "",
        "etc",
        "etc/codex",
        "etc/codex/synthetic-metadata",
        "etc/codex/synthetic-metadata/12345.toml",
    ] {
        for mode in [0o775, 0o757, 0o1777] {
            let root = fixture();
            configure(&root, USER, VALID);
            fs::set_permissions(root.join(relative), fs::Permissions::from_mode(mode)).unwrap();
            assert!(read(&root).is_err(), "accepted mode {mode:o} on {relative}");
        }
    }
}

#[test]
fn configuration_rejects_symlinked_parents_and_files_including_dangling_links() {
    for relative in [
        "etc",
        "etc/codex",
        "etc/codex/synthetic-metadata",
        "etc/codex/synthetic-metadata/12345.toml",
    ] {
        for target_exists in [false, true] {
            let root = fixture();
            let path = root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let target = root.join("target");
            if target_exists {
                if relative.ends_with(".toml") {
                    fs::write(&target, VALID).unwrap();
                } else {
                    fs::create_dir(&target).unwrap();
                }
            }
            symlink(&target, path).unwrap();
            assert!(read(&root).is_err(), "accepted symlink {relative}");
        }
    }
}

#[test]
fn configuration_rejects_non_directory_ancestors_and_non_regular_files() {
    for relative in ["etc", "etc/codex", "etc/codex/synthetic-metadata"] {
        let root = fixture();
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, VALID).unwrap();
        assert!(read(&root).is_err(), "accepted non-directory {relative}");
    }
    let root = fixture();
    let directory = root.join("etc/codex/synthetic-metadata/12345.toml");
    fs::create_dir_all(directory).unwrap();
    assert!(read(&root).is_err());
    let root = fixture();
    let fifo = root.join("etc/codex/synthetic-metadata/12345.toml");
    fs::create_dir_all(fifo.parent().unwrap()).unwrap();
    let fifo = super::super::super::super::linux::c_path(&fifo).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(read(&root).is_err());
}

#[test]
fn configuration_owner_validation_uses_os_owner_not_effective_user() {
    let root = fixture();
    let metadata = File::open(&root).unwrap().metadata().unwrap();
    validate_owner_and_mode(&metadata, metadata.uid()).unwrap();
    assert!(validate_owner_and_mode(&metadata, metadata.uid().wrapping_add(1)).is_err());
}
