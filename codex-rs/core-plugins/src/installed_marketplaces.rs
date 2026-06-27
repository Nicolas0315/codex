use std::path::Path;
use std::path::PathBuf;

use codex_config::ConfigLayerStack;
use codex_plugin::validate_plugin_segment;
use codex_utils_absolute_path::AbsolutePathBuf;
use tracing::warn;

use crate::OPENAI_BUNDLED_ALPHA_MARKETPLACE_NAME;
use crate::OPENAI_BUNDLED_MARKETPLACE_NAME;
use crate::marketplace::find_marketplace_manifest_path;

pub const INSTALLED_MARKETPLACES_DIR: &str = ".tmp/marketplaces";
pub const BUNDLED_MARKETPLACES_DIR: &str = ".tmp/bundled-marketplaces";

pub fn marketplace_install_root(codex_home: &Path) -> PathBuf {
    codex_home.join(INSTALLED_MARKETPLACES_DIR)
}

pub fn installed_marketplace_roots_from_layer_stack(
    config_layer_stack: &ConfigLayerStack,
    codex_home: &Path,
) -> Vec<AbsolutePathBuf> {
    let Some(user_config) = config_layer_stack.effective_user_config() else {
        return Vec::new();
    };
    let Some(marketplaces_value) = user_config.get("marketplaces") else {
        return Vec::new();
    };
    let Some(marketplaces) = marketplaces_value.as_table() else {
        warn!("invalid marketplaces config: expected table");
        return Vec::new();
    };
    let default_install_root = marketplace_install_root(codex_home);
    let mut roots = marketplaces
        .iter()
        .filter_map(|(marketplace_name, marketplace)| {
            if !marketplace.is_table() {
                warn!(
                    marketplace_name,
                    "ignoring invalid configured marketplace entry"
                );
                return None;
            }
            if let Err(err) = validate_plugin_segment(marketplace_name, "marketplace name") {
                warn!(
                    marketplace_name,
                    error = %err,
                    "ignoring invalid configured marketplace name"
                );
                return None;
            }
            let path = resolve_configured_marketplace_root(
                codex_home,
                marketplace_name,
                marketplace,
                &default_install_root,
            )?;
            find_marketplace_manifest_path(&path).map(|_| path)
        })
        .filter_map(|path| AbsolutePathBuf::try_from(path).ok())
        .collect::<Vec<_>>();
    roots.sort_unstable_by(|left, right| left.as_path().cmp(right.as_path()));
    roots
}

pub fn resolve_configured_marketplace_root(
    codex_home: &Path,
    marketplace_name: &str,
    marketplace: &toml::Value,
    default_install_root: &Path,
) -> Option<PathBuf> {
    let configured_root = resolve_configured_marketplace_root_from_config(
        marketplace_name,
        marketplace,
        default_install_root,
    );

    if configured_root
        .as_deref()
        .is_some_and(|root| find_marketplace_manifest_path(root).is_some())
    {
        return configured_root;
    }

    managed_bundled_marketplace_root(codex_home, marketplace_name)
        .filter(|root| find_marketplace_manifest_path(root).is_some())
        .or(configured_root)
}

pub fn resolve_configured_marketplace_root_from_config(
    marketplace_name: &str,
    marketplace: &toml::Value,
    default_install_root: &Path,
) -> Option<PathBuf> {
    match marketplace.get("source_type").and_then(toml::Value::as_str) {
        Some("local") => marketplace
            .get("source")
            .and_then(toml::Value::as_str)
            .filter(|source| !source.is_empty())
            .map(PathBuf::from),
        _ => Some(default_install_root.join(marketplace_name)),
    }
}

pub fn managed_bundled_marketplace_root(
    codex_home: &Path,
    marketplace_name: &str,
) -> Option<PathBuf> {
    if matches!(
        marketplace_name,
        OPENAI_BUNDLED_MARKETPLACE_NAME | OPENAI_BUNDLED_ALPHA_MARKETPLACE_NAME
    ) {
        return Some(
            codex_home
                .join(BUNDLED_MARKETPLACES_DIR)
                .join(marketplace_name),
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;
    use toml::map::Map;

    #[test]
    fn resolve_configured_marketplace_root_prefers_valid_configured_source() {
        let codex_home = TempDir::new().unwrap();
        let configured_root = codex_home.path().join("configured");
        let bundled_root =
            managed_bundled_marketplace_root(codex_home.path(), OPENAI_BUNDLED_MARKETPLACE_NAME)
                .unwrap();
        write_marketplace_manifest(&configured_root, OPENAI_BUNDLED_MARKETPLACE_NAME);
        write_marketplace_manifest(&bundled_root, OPENAI_BUNDLED_MARKETPLACE_NAME);
        let marketplace = local_marketplace_config(configured_root.display().to_string());

        let root = resolve_configured_marketplace_root(
            codex_home.path(),
            OPENAI_BUNDLED_MARKETPLACE_NAME,
            &marketplace,
            &marketplace_install_root(codex_home.path()),
        );

        assert_eq!(root, Some(configured_root));
    }

    #[test]
    fn resolve_configured_marketplace_root_falls_back_to_managed_bundled_cache() {
        let codex_home = TempDir::new().unwrap();
        let stale_root = codex_home.path().join("stale");
        let bundled_root =
            managed_bundled_marketplace_root(codex_home.path(), OPENAI_BUNDLED_MARKETPLACE_NAME)
                .unwrap();
        write_marketplace_manifest(&bundled_root, OPENAI_BUNDLED_MARKETPLACE_NAME);
        let marketplace = local_marketplace_config(stale_root.display().to_string());

        let root = resolve_configured_marketplace_root(
            codex_home.path(),
            OPENAI_BUNDLED_MARKETPLACE_NAME,
            &marketplace,
            &marketplace_install_root(codex_home.path()),
        );

        assert_eq!(root, Some(bundled_root));
    }

    fn local_marketplace_config(source: String) -> toml::Value {
        let mut table = Map::new();
        table.insert(
            "source_type".to_string(),
            toml::Value::String("local".to_string()),
        );
        table.insert("source".to_string(), toml::Value::String(source));
        toml::Value::Table(table)
    }

    fn write_marketplace_manifest(root: &Path, marketplace_name: &str) {
        std::fs::create_dir_all(root.join(".agents/plugins")).unwrap();
        std::fs::write(
            root.join(".agents/plugins/marketplace.json"),
            format!(r#"{{"name":"{marketplace_name}","plugins":[]}}"#),
        )
        .unwrap();
    }
}
