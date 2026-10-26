use super::*;
use crate::protocol::FsGetMetadataParams;
use crate::protocol::FsGetMetadataResponse;
use codex_protocol::permissions::FileSystemAccessMode;
use codex_protocol::permissions::FileSystemSandboxEntry;
use codex_utils_absolute_path::AbsolutePathBuf;
use codex_utils_path_uri::PathUri;
use pretty_assertions::assert_eq;

fn metadata_response() -> FsHelperPayload {
    FsHelperPayload::GetMetadata(FsGetMetadataResponse {
        is_directory: true,
        is_synthetic_directory: false,
        is_file: false,
        is_symlink: false,
        size: 0,
        created_at_ms: 0,
        modified_at_ms: 0,
    })
}

fn read_policy(path: &Path) -> FileSystemSandboxPolicy {
    FileSystemSandboxPolicy::restricted(vec![FileSystemSandboxEntry {
        path: FileSystemPath::Path {
            path: AbsolutePathBuf::from_absolute_path(path).unwrap(),
        },
        access: FileSystemAccessMode::Read,
    }])
}

#[test]
fn original_exact_and_glob_denies_never_receive_host_ownership() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join(".git");
    std::fs::create_dir(&path).unwrap();
    let request = FsHelperRequest::GetMetadata(FsGetMetadataParams {
        path: PathUri::from_path(&path).unwrap(),
        sandbox: None,
    });
    for denied in [
        FileSystemPath::Path {
            path: AbsolutePathBuf::from_absolute_path(&path).unwrap(),
        },
        FileSystemPath::GlobPattern {
            pattern: format!("{}/.*", temp.path().display()),
        },
    ] {
        let mut policy = read_policy(temp.path());
        policy.entries.push(FileSystemSandboxEntry {
            path: denied,
            access: FileSystemAccessMode::Deny,
        });
        let mut response = metadata_response();
        if let FsHelperPayload::GetMetadata(metadata) = &mut response {
            metadata.is_synthetic_directory = true;
        }
        augment_metadata_ownership(&policy, temp.path(), &request, &mut response).unwrap();
        assert_eq!(response, metadata_response());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn successful_scoped_metadata_uses_receiving_host_evidence_without_guest_registry_access() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join(".git");
    codex_file_system::prepare_synthetic_metadata_directory(&path).unwrap();
    let request = FsHelperRequest::GetMetadata(FsGetMetadataParams {
        path: PathUri::from_path(&path).unwrap(),
        sandbox: None,
    });
    let mut response = metadata_response();
    augment_metadata_ownership(
        &read_policy(temp.path()),
        temp.path(),
        &request,
        &mut response,
    )
    .unwrap();
    let FsHelperPayload::GetMetadata(metadata) = response else {
        panic!("metadata response")
    };
    assert!(metadata.is_synthetic_directory);
}
