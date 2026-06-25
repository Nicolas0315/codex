use std::error::Error;
use std::fmt;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OpenTarget {
    Url(String),
    Path(PathBuf),
}

impl OpenTarget {
    pub(crate) fn display_label(&self) -> String {
        match self {
            Self::Url(url) => url.clone(),
            Self::Path(path) => path.display().to_string(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum OpenCommandError {
    MissingTarget,
    InvalidUrl(String),
    UnsupportedScheme(String),
    NonLocalFileUrl,
    PathDoesNotExist(PathBuf),
}

impl fmt::Display for OpenCommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingTarget => f.write_str("Usage: /open <path-or-url>"),
            Self::InvalidUrl(err) => write!(f, "Invalid URL: {err}"),
            Self::UnsupportedScheme(scheme) => write!(
                f,
                "Unsupported URL scheme '{scheme}'. Use http://, https://, file://, or a local path."
            ),
            Self::NonLocalFileUrl => f.write_str("file:// URL must resolve to a local path."),
            Self::PathDoesNotExist(path) => write!(f, "Path does not exist: {}", path.display()),
        }
    }
}

impl Error for OpenCommandError {}

pub(crate) fn resolve_open_target(
    raw_target: &str,
    cwd: &Path,
) -> Result<OpenTarget, OpenCommandError> {
    let trimmed = raw_target.trim();
    if trimmed.is_empty() {
        return Err(OpenCommandError::MissingTarget);
    }

    match Url::parse(trimmed) {
        Ok(url) => resolve_url_target(trimmed, url, cwd),
        Err(err) if trimmed.contains("://") => Err(OpenCommandError::InvalidUrl(err.to_string())),
        Err(_) => resolve_path_target(PathBuf::from(trimmed), cwd),
    }
}

pub(crate) fn open_target(target: &OpenTarget) -> io::Result<()> {
    let mut command = system_opener_command()?;
    match target {
        OpenTarget::Url(url) => {
            command.arg(url);
        }
        OpenTarget::Path(path) => {
            command.arg(path);
        }
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
}

fn resolve_url_target(
    original: &str,
    url: Url,
    cwd: &Path,
) -> Result<OpenTarget, OpenCommandError> {
    match url.scheme() {
        "http" | "https" => Ok(OpenTarget::Url(original.to_string())),
        "file" => {
            if url.query().is_some() || url.fragment().is_some() {
                return Err(OpenCommandError::InvalidUrl(
                    "file:// URLs with query strings or fragments are unsupported".to_string(),
                ));
            }
            let path = url
                .to_file_path()
                .map_err(|_| OpenCommandError::NonLocalFileUrl)?;
            resolve_path_target(path, cwd)
        }
        scheme if cfg!(target_os = "windows") && scheme.len() == 1 => {
            resolve_path_target(PathBuf::from(original), cwd)
        }
        scheme => Err(OpenCommandError::UnsupportedScheme(scheme.to_string())),
    }
}

fn resolve_path_target(path: PathBuf, cwd: &Path) -> Result<OpenTarget, OpenCommandError> {
    let path = if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    };

    if !path.exists() {
        return Err(OpenCommandError::PathDoesNotExist(path));
    }

    Ok(OpenTarget::Path(path))
}

fn system_opener_command() -> io::Result<Command> {
    #[cfg(target_os = "windows")]
    {
        Ok(Command::new("explorer.exe"))
    }

    #[cfg(target_os = "macos")]
    {
        Ok(Command::new("open"))
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Ok(Command::new("xdg-open"))
    }

    #[cfg(not(any(windows, unix)))]
    {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "no system opener is configured for this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_dot_to_current_working_directory() {
        let temp = tempfile::tempdir().expect("temp dir");

        let target = resolve_open_target(".", temp.path()).expect("target");

        assert_eq!(target, OpenTarget::Path(temp.path().join(".")));
    }

    #[test]
    fn resolves_relative_paths_against_current_working_directory() {
        let temp = tempfile::tempdir().expect("temp dir");
        let file = temp.path().join("report.html");
        std::fs::write(&file, "<html></html>").expect("write file");

        let target = resolve_open_target("report.html", temp.path()).expect("target");

        assert_eq!(target, OpenTarget::Path(file));
    }

    #[test]
    fn resolves_http_and_https_urls() {
        assert_eq!(
            resolve_open_target("https://example.com/a?b=c", Path::new("/tmp")),
            Ok(OpenTarget::Url("https://example.com/a?b=c".to_string()))
        );
        assert_eq!(
            resolve_open_target("http://example.com", Path::new("/tmp")),
            Ok(OpenTarget::Url("http://example.com".to_string()))
        );
    }

    #[test]
    fn resolves_file_urls_to_local_paths() {
        let temp = tempfile::tempdir().expect("temp dir");
        let file = temp.path().join("image.png");
        std::fs::write(&file, "png").expect("write file");
        let url = Url::from_file_path(&file).expect("file url");

        let target = resolve_open_target(url.as_str(), temp.path()).expect("target");

        assert_eq!(target, OpenTarget::Path(file));
    }

    #[test]
    fn rejects_missing_paths() {
        let temp = tempfile::tempdir().expect("temp dir");
        let missing = temp.path().join("missing.txt");

        let err = resolve_open_target("missing.txt", temp.path()).expect_err("missing path");

        assert_eq!(err, OpenCommandError::PathDoesNotExist(missing));
    }

    #[test]
    fn rejects_unsupported_url_schemes() {
        let err = resolve_open_target("ftp://example.com/file", Path::new("/tmp"))
            .expect_err("unsupported scheme");

        assert_eq!(err, OpenCommandError::UnsupportedScheme("ftp".to_string()));
    }

    #[test]
    fn rejects_malformed_urls_that_look_like_urls() {
        let err = resolve_open_target("https://", Path::new("/tmp")).expect_err("invalid url");

        assert!(matches!(err, OpenCommandError::InvalidUrl(_)));
    }

    #[test]
    fn rejects_file_urls_with_fragments() {
        let temp = tempfile::tempdir().expect("temp dir");
        let file = temp.path().join("report.md");
        std::fs::write(&file, "# report").expect("write file");
        let target = format!("{}#L1", Url::from_file_path(&file).expect("file url"));

        let err = resolve_open_target(&target, temp.path()).expect_err("fragment");

        assert!(matches!(err, OpenCommandError::InvalidUrl(_)));
    }
}
