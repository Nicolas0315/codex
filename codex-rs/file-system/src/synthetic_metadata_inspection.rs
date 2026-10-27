//! Classify and inspect all retained ownership authorities.

use super::*;

/// Existing evidence and authenticated destination-local stages, for inspection.
pub fn existing_synthetic_metadata_authorities() -> io::Result<Vec<PathBuf>> {
    let authorities = registry::Authorities::load()?;
    let mounts = MountTable::read()?;
    let mut paths = super::super::linux::existing_synthetic_metadata_authorities()?;
    let readers = authorities.readers()?;
    paths.extend(
        authorities
            .paths()?
            .into_iter()
            .filter(|path| path.exists()),
    );
    if authorities.configuration_path().exists() {
        paths.push(authorities.configuration_path().to_path_buf());
    }
    let mut aliases = Vec::new();
    for path in paths {
        aliases.extend(mounts.protected_aliases(&path)?);
    }
    for (_, registry) in readers {
        for record in all_stages(&registry)? {
            aliases.extend(protected_stage_aliases(
                &record,
                &mounts,
                authenticated_aliases(&record, &mounts),
            )?);
        }
    }
    aliases.sort();
    aliases.dedup();
    Ok(aliases)
}

pub(crate) fn is_owned(path: &Path) -> io::Result<bool> {
    // Resolve before either native or legacy classification. An invalid
    // explicit configuration must not enable an independent legacy fallback.
    if let Some(authorities) = registry::Authorities::load_for_classification()? {
        let native = is_owned_with_authorities(path, &authorities);
        let native = if authorities.configured {
            native?
        } else {
            native.unwrap_or(false)
        };
        if native {
            return Ok(true);
        }
    }
    match super::super::linux::is_owned(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        result => result,
    }
}

pub(super) fn is_owned_with_authorities(
    path: &Path,
    authorities: &registry::Authorities,
) -> io::Result<bool> {
    let directory = open_directory(path)?;
    let (name, expected) = nonce_record(&directory)?;
    for (_, registry) in authorities.readers()? {
        let public_record = registry::records(&registry, AuthorityMode::ReadOnly)
            .and_then(|records| open_at(&records, &name, libc::O_RDONLY, /*mode*/ 0));
        let file = match public_record {
            Ok(file) => Ok(file),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                open_at(&registry, &name, libc::O_RDONLY, /*mode*/ 0)
            }
            Err(error) => return Err(error),
        };
        let file = match file {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if read_bounded(file)? == expected
            && is_empty(&directory)?
            && nonce_record(&directory)?.1 == expected
        {
            return Ok(true);
        }
    }
    Ok(false)
}
