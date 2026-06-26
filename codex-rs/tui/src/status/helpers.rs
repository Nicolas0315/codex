use crate::exec_command::relativize_to_home;
use crate::legacy_core::config::Config;
use crate::status::StatusAccountDisplay;
use crate::text_formatting;
use chrono::DateTime;
use chrono::Local;
use codex_protocol::account::PlanType;
use codex_utils_path_uri::PathConvention;
use codex_utils_path_uri::PathUri;
use std::path::Path;
use unicode_width::UnicodeWidthStr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TimeFormatPreference {
    TwelveHour,
    TwentyFourHour,
}

impl TimeFormatPreference {
    fn detect() -> Self {
        #[cfg(test)]
        {
            Self::TwentyFourHour
        }

        #[cfg(all(windows, not(test)))]
        {
            windows_time_format_preference().unwrap_or(Self::TwentyFourHour)
        }

        #[cfg(all(not(windows), not(test)))]
        {
            Self::TwentyFourHour
        }
    }
}

fn normalize_agents_display_path(path: &Path) -> String {
    dunce::simplified(path).display().to_string()
}

pub(crate) fn compose_model_display(
    model_name: &str,
    entries: &[(&str, String)],
) -> (String, Vec<String>) {
    let mut details: Vec<String> = Vec::new();
    if let Some((_, effort)) = entries.iter().find(|(k, _)| *k == "reasoning effort") {
        details.push(format!("reasoning {}", effort.to_ascii_lowercase()));
    }
    if let Some((_, summary)) = entries.iter().find(|(k, _)| *k == "reasoning summaries") {
        let summary = summary.trim();
        if summary.eq_ignore_ascii_case("none") || summary.eq_ignore_ascii_case("off") {
            details.push("summaries off".to_string());
        } else if !summary.is_empty() {
            details.push(format!("summaries {}", summary.to_ascii_lowercase()));
        }
    }

    (model_name.to_string(), details)
}

pub(crate) fn compose_agents_summary(config: &Config, paths: &[PathUri]) -> String {
    let mut rels: Vec<String> = Vec::new();

    for path in paths {
        // TODO(anp): Rationalize instruction-source summaries with the TUI's broader foreign-path
        // display strategy once other status surfaces can retain environment-native paths.
        if path.infer_path_convention() != Some(PathConvention::native()) {
            rels.push(path.inferred_native_path_string());
            continue;
        }
        let Ok(p) = path.to_abs_path() else {
            rels.push(path.inferred_native_path_string());
            continue;
        };
        let p = p.as_path();
        let file_name = p
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "<unknown>".to_string());
        let display = if let Some(parent) = p.parent() {
            if parent == config.cwd.as_path() {
                file_name.clone()
            } else {
                let mut cur = config.cwd.as_path();
                let mut ups = 0usize;
                let mut reached = false;
                while let Some(c) = cur.parent() {
                    if cur == parent {
                        reached = true;
                        break;
                    }
                    cur = c;
                    ups += 1;
                }
                if reached {
                    let up = format!("..{}", std::path::MAIN_SEPARATOR);
                    format!("{}{}", up.repeat(ups), file_name)
                } else if let Ok(stripped) = p.strip_prefix(&config.cwd) {
                    normalize_agents_display_path(stripped)
                } else {
                    normalize_agents_display_path(p)
                }
            }
        } else {
            normalize_agents_display_path(p)
        };
        rels.push(display);
    }

    if rels.is_empty() {
        "<none>".to_string()
    } else {
        rels.join(", ")
    }
}

pub(crate) fn compose_account_display(
    account_display: Option<&StatusAccountDisplay>,
) -> Option<StatusAccountDisplay> {
    account_display.cloned()
}

pub(crate) fn plan_type_display_name(plan_type: PlanType) -> String {
    if plan_type.is_team_like() {
        "Business".to_string()
    } else if plan_type.is_business_like() {
        "Enterprise".to_string()
    } else if plan_type == PlanType::ProLite {
        "Pro Lite".to_string()
    } else {
        title_case(format!("{plan_type:?}").as_str())
    }
}

pub(crate) fn format_tokens_compact(value: i64) -> String {
    let value = value.max(0);
    if value == 0 {
        return "0".to_string();
    }
    if value < 1_000 {
        return value.to_string();
    }

    let value_f64 = value as f64;
    let (scaled, suffix) = if value >= 1_000_000_000_000 {
        (value_f64 / 1_000_000_000_000.0, "T")
    } else if value >= 1_000_000_000 {
        (value_f64 / 1_000_000_000.0, "B")
    } else if value >= 1_000_000 {
        (value_f64 / 1_000_000.0, "M")
    } else {
        (value_f64 / 1_000.0, "K")
    };

    let decimals = if scaled < 10.0 {
        2
    } else if scaled < 100.0 {
        1
    } else {
        0
    };

    let mut formatted = format!("{scaled:.decimals$}");
    if formatted.contains('.') {
        while formatted.ends_with('0') {
            formatted.pop();
        }
        if formatted.ends_with('.') {
            formatted.pop();
        }
    }

    format!("{formatted}{suffix}")
}

pub(crate) fn format_directory_display(directory: &Path, max_width: Option<usize>) -> String {
    let formatted = if let Some(rel) = relativize_to_home(directory) {
        if rel.as_os_str().is_empty() {
            "~".to_string()
        } else {
            format!("~{}{}", std::path::MAIN_SEPARATOR, rel.display())
        }
    } else {
        directory.display().to_string()
    };

    if let Some(max_width) = max_width {
        if max_width == 0 {
            return String::new();
        }
        if UnicodeWidthStr::width(formatted.as_str()) > max_width {
            return text_formatting::center_truncate_path(&formatted, max_width);
        }
    }

    formatted
}

pub(crate) fn format_reset_timestamp(dt: DateTime<Local>, captured_at: DateTime<Local>) -> String {
    format_reset_timestamp_with_preference(dt, captured_at, TimeFormatPreference::detect())
}

fn format_reset_timestamp_with_preference(
    dt: DateTime<Local>,
    captured_at: DateTime<Local>,
    preference: TimeFormatPreference,
) -> String {
    let time = format_reset_time(dt, preference);
    if dt.date_naive() == captured_at.date_naive() {
        time
    } else {
        format!("{time} on {}", dt.format("%-d %b"))
    }
}

fn format_reset_time(dt: DateTime<Local>, preference: TimeFormatPreference) -> String {
    match preference {
        TimeFormatPreference::TwelveHour => dt.format("%-I:%M %p").to_string(),
        TimeFormatPreference::TwentyFourHour => dt.format("%H:%M").to_string(),
    }
}

#[cfg(all(windows, not(test)))]
fn windows_time_format_preference() -> Option<TimeFormatPreference> {
    use std::ptr;
    use windows_sys::Win32::Globalization::GetLocaleInfoEx;
    use windows_sys::Win32::Globalization::LOCALE_STIMEFORMAT;

    let required_len =
        unsafe { GetLocaleInfoEx(ptr::null(), LOCALE_STIMEFORMAT, ptr::null_mut(), 0) };
    if required_len <= 1 {
        return None;
    }

    let mut buffer = vec![0u16; required_len as usize];
    let written = unsafe {
        GetLocaleInfoEx(
            ptr::null(),
            LOCALE_STIMEFORMAT,
            buffer.as_mut_ptr(),
            required_len,
        )
    };
    if written <= 1 {
        return None;
    }

    let nul_index = (written as usize).saturating_sub(1);
    let pattern = String::from_utf16_lossy(&buffer[..nul_index]);
    time_pattern_preference(&pattern)
}

#[cfg(any(windows, test))]
fn time_pattern_preference(pattern: &str) -> Option<TimeFormatPreference> {
    let mut chars = pattern.chars().peekable();
    let mut in_quoted_literal = false;
    while let Some(ch) = chars.next() {
        if ch == '\'' {
            if chars.peek() == Some(&'\'') {
                chars.next();
            } else {
                in_quoted_literal = !in_quoted_literal;
            }
            continue;
        }

        if in_quoted_literal {
            continue;
        }

        match ch {
            'h' => return Some(TimeFormatPreference::TwelveHour),
            'H' => return Some(TimeFormatPreference::TwentyFourHour),
            _ => {}
        }
    }

    None
}

fn title_case(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    let rest = chars.as_str().to_ascii_lowercase();
    first.to_uppercase().collect::<String>() + &rest
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy_core::config::ConfigBuilder;
    use chrono::TimeZone;
    use codex_utils_absolute_path::test_support::PathBufExt;
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    async fn test_config(codex_home: &TempDir, cwd: &TempDir) -> Config {
        ConfigBuilder::default()
            .codex_home(codex_home.path().to_path_buf())
            .fallback_cwd(Some(cwd.path().to_path_buf()))
            .build()
            .await
            .expect("load config")
    }

    #[test]
    fn plan_type_display_name_remaps_display_labels() {
        let cases = [
            (PlanType::Free, "Free"),
            (PlanType::Go, "Go"),
            (PlanType::Plus, "Plus"),
            (PlanType::Pro, "Pro"),
            (PlanType::ProLite, "Pro Lite"),
            (PlanType::Team, "Business"),
            (PlanType::SelfServeBusinessUsageBased, "Business"),
            (PlanType::Business, "Enterprise"),
            (PlanType::EnterpriseCbpUsageBased, "Enterprise"),
            (PlanType::Enterprise, "Enterprise"),
            (PlanType::Edu, "Edu"),
            (PlanType::Unknown, "Unknown"),
        ];

        for (plan_type, expected) in cases {
            assert_eq!(plan_type_display_name(plan_type), expected);
        }
    }

    #[test]
    fn reset_timestamp_formats_24_hour_time_by_default() {
        let captured_at = Local
            .with_ymd_and_hms(2024, 5, 6, 7, 8, 9)
            .single()
            .expect("timestamp");
        let reset_at = Local
            .with_ymd_and_hms(2024, 5, 6, 18, 49, 0)
            .single()
            .expect("timestamp");

        assert_eq!(format_reset_timestamp(reset_at, captured_at), "18:49");
    }

    #[test]
    fn reset_timestamp_can_format_12_hour_time() {
        let captured_at = Local
            .with_ymd_and_hms(2024, 5, 6, 7, 8, 9)
            .single()
            .expect("timestamp");
        let same_day_reset = Local
            .with_ymd_and_hms(2024, 5, 6, 18, 49, 0)
            .single()
            .expect("timestamp");
        let next_day_reset = Local
            .with_ymd_and_hms(2024, 5, 7, 18, 49, 0)
            .single()
            .expect("timestamp");

        assert_eq!(
            format_reset_timestamp_with_preference(
                same_day_reset,
                captured_at,
                TimeFormatPreference::TwelveHour
            ),
            "6:49 PM"
        );
        assert_eq!(
            format_reset_timestamp_with_preference(
                next_day_reset,
                captured_at,
                TimeFormatPreference::TwelveHour
            ),
            "6:49 PM on 7 May"
        );
    }

    #[test]
    fn reset_timestamp_uses_12_hour_midnight_and_noon_labels() {
        let captured_at = Local
            .with_ymd_and_hms(2024, 5, 6, 0, 0, 0)
            .single()
            .expect("timestamp");
        let midnight = Local
            .with_ymd_and_hms(2024, 5, 6, 0, 5, 0)
            .single()
            .expect("timestamp");
        let noon = Local
            .with_ymd_and_hms(2024, 5, 6, 12, 5, 0)
            .single()
            .expect("timestamp");

        assert_eq!(
            format_reset_timestamp_with_preference(
                midnight,
                captured_at,
                TimeFormatPreference::TwelveHour
            ),
            "12:05 AM"
        );
        assert_eq!(
            format_reset_timestamp_with_preference(
                noon,
                captured_at,
                TimeFormatPreference::TwelveHour
            ),
            "12:05 PM"
        );
    }

    #[test]
    fn detects_hour_cycle_from_windows_time_patterns() {
        assert_eq!(
            time_pattern_preference("h:mm tt"),
            Some(TimeFormatPreference::TwelveHour)
        );
        assert_eq!(
            time_pattern_preference("HH:mm"),
            Some(TimeFormatPreference::TwentyFourHour)
        );
        assert_eq!(
            time_pattern_preference("'h' HH:mm"),
            Some(TimeFormatPreference::TwentyFourHour)
        );
    }

    #[tokio::test]
    async fn compose_agents_summary_includes_global_agents_path() {
        let codex_home = TempDir::new().expect("temp codex home");
        let cwd = TempDir::new().expect("temp cwd");
        let global_agents_path = codex_home.path().join("global.md");
        let config = test_config(&codex_home, &cwd).await;

        assert_eq!(
            compose_agents_summary(
                &config,
                &[PathUri::from_abs_path(&global_agents_path.abs())]
            ),
            format_directory_display(&global_agents_path, /*max_width*/ None)
        );
    }

    #[tokio::test]
    async fn compose_agents_summary_names_global_agents_override() {
        let codex_home = TempDir::new().expect("temp codex home");
        let cwd = TempDir::new().expect("temp cwd");
        let override_path = codex_home.path().join("override.md");
        let config = test_config(&codex_home, &cwd).await;

        assert_eq!(
            compose_agents_summary(&config, &[PathUri::from_abs_path(&override_path.abs())]),
            format_directory_display(&override_path, /*max_width*/ None)
        );
    }

    #[tokio::test]
    async fn compose_agents_summary_shows_relative_native_and_full_foreign_paths() {
        let codex_home = TempDir::new().expect("temp codex home");
        let cwd = TempDir::new().expect("temp cwd");
        let config = test_config(&codex_home, &cwd).await;
        let native_source = PathUri::from_abs_path(&config.cwd.join("AGENTS.md"));
        let foreign_source = if cfg!(windows) {
            PathUri::parse("file:///remote%20workspace/AGENTS.md")
                .expect("POSIX instruction source")
        } else {
            PathUri::parse("file:///C:/remote%20workspace/AGENTS.md")
                .expect("Windows instruction source")
        };

        let summary = compose_agents_summary(&config, &[native_source, foreign_source]);
        if cfg!(windows) {
            insta::assert_snapshot!(summary, @r"AGENTS.md, /remote workspace/AGENTS.md");
        } else {
            insta::assert_snapshot!(summary, @r"AGENTS.md, C:\remote workspace\AGENTS.md");
        }
    }

    #[tokio::test]
    async fn compose_agents_summary_orders_global_before_project_agents() {
        let codex_home = TempDir::new().expect("temp codex home");
        let cwd = TempDir::new().expect("temp cwd");
        let global_agents_path = codex_home.path().join("global.md");
        let project_agents_path = cwd.path().join("project.md");
        let config = test_config(&codex_home, &cwd).await;

        let summary = compose_agents_summary(
            &config,
            &[
                PathUri::from_abs_path(&global_agents_path.clone().abs()),
                PathUri::from_abs_path(&project_agents_path.clone().abs()),
            ],
        );
        let mut paths = summary.split(", ");
        assert_eq!(
            paths.next(),
            Some(format_directory_display(&global_agents_path, /*max_width*/ None).as_str())
        );
        let project_path = paths.next().expect("project agents path");
        assert!(project_path.ends_with("project.md"));
        assert_eq!(paths.next(), None);
    }
}
