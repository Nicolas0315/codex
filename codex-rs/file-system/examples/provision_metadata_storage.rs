//! Trusted provisioning helper: run as the target effective UID, after stopping
//! its restricted Codex processes and before publishing administrator config.
//! The selected native parent must exist and the final storage path must not.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    let (Some(root), None) = (arguments.next(), arguments.next()) else {
        eprintln!("usage: provision_metadata_storage ABSOLUTE_NEW_STORAGE_PATH");
        return std::process::ExitCode::FAILURE;
    };
    if root.to_str().is_none() {
        eprintln!("The storage path must be representable in UTF-8 administrator configuration.");
        return std::process::ExitCode::FAILURE;
    }
    match codex_file_system::initialize_synthetic_metadata_storage(std::path::Path::new(&root)) {
        Ok(_) => {
            println!("Metadata storage provisioned.");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Cannot provision metadata storage: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("Metadata storage provisioning requires Linux.");
    std::process::ExitCode::FAILURE
}
