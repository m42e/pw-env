use anyhow::{Context, Result};
#[cfg(not(test))]
use dialoguer::{Confirm, Input};
use dialoguer::{MultiSelect, theme::ColorfulTheme};
use glob::Pattern;
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::backend::{self, ResolutionInteraction, ResolveContext, StoreContext};
use crate::config::{self, BwConfig, CacheConfig, Config, GpgConfig, OpConfig};
use crate::env_file::EnvFile;
use crate::resolve;

#[cfg(test)]
thread_local! {
    static MOCK_INTERACTIVE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    static MOCK_PROMPT_RESULT: std::cell::RefCell<Option<BTreeSet<usize>>> = const { std::cell::RefCell::new(None) };
    static MOCK_COMMAND_SCOPE: std::cell::RefCell<Option<Option<Vec<String>>>> = const { std::cell::RefCell::new(None) };
}

/// Run the migration process: detect plaintext secrets in .env, offer to store them
/// in the configured password backend, then rewrite .env to clear them.
#[cfg(test)]
pub fn migrate(dir: &Path, config: &Config, backend_override: Option<&str>) -> Result<()> {
    migrate_with_interaction(dir, config, backend_override, None)
}

pub fn migrate_with_interaction(
    dir: &Path,
    config: &Config,
    backend_override: Option<&str>,
    interaction: Option<&dyn ResolutionInteraction>,
) -> Result<()> {
    let effective_config = config_for_migration(config, dir, backend_override);
    let env_path =
        EnvFile::find_with_parents(dir, effective_config.effective_search_parent_env(dir))
            .ok_or_else(|| anyhow::anyhow!("No .env file found in {}", dir.display()))?;
    let env_file = EnvFile::parse(&env_path)?;
    let plaintext_entries = env_file.plaintext_entries();

    if plaintext_entries.is_empty() {
        eprintln!("No plaintext values found in .env that require migration.");
        return Ok(());
    }

    let likely_secret_count = plaintext_entries
        .iter()
        .filter(|entry| entry.is_likely_secret())
        .count();

    eprintln!(
        "Found {} plaintext value(s) in {}:",
        plaintext_entries.len(),
        env_path.display()
    );
    if likely_secret_count != 0 {
        eprintln!(
            "{} of them look like secrets based on key names or secret-like values.",
            likely_secret_count
        );
    }
    for entry in &plaintext_entries {
        // Show key and a masked value (first 3 chars + ***)
        let masked = mask_value(&entry.raw_value);
        let label = if entry.is_likely_secret() {
            "  [likely secret]"
        } else {
            ""
        };
        eprintln!("  {} = {}{}", entry.key, masked, label);
    }
    eprintln!();

    let backend_name = effective_config.effective_backend(dir);
    eprintln!("These will be stored in the '{}' backend.", backend_name);

    if !is_interactive() {
        anyhow::bail!("pw-env migrate requires an interactive terminal to select entries");
    }

    let selected_indexes = prompt_for_entries(&plaintext_entries, backend_name)?;
    if selected_indexes.is_empty() {
        eprintln!("No entries selected for migration.");
    }
    let command_scope = if selected_indexes.is_empty() {
        None
    } else {
        prompt_for_command_scope()?
    };

    let (selected_entries, skipped_entries): (Vec<_>, Vec<_>) = plaintext_entries
        .iter()
        .enumerate()
        .partition(|(index, _)| selected_indexes.contains(index));

    let selected_fingerprints = selected_entries
        .into_iter()
        .filter_map(|(_, entry)| entry.review_fingerprint())
        .collect::<Vec<_>>();
    let skipped_fingerprints = skipped_entries
        .into_iter()
        .filter_map(|(_, entry)| entry.review_fingerprint())
        .collect::<Vec<_>>();

    Config::forget_reviewed_migration_entries(&env_path, selected_fingerprints)?;

    let backend = backend::create_backend(backend_name)?;
    if uses_bitwarden_backend(backend_name)
        && let Some(interaction) = interaction
    {
        backend::bw::BwBackend::ensure_unlocked_with(interaction)?;
    }
    let project = resolve::detect_project_name(dir);
    let repository = resolve::detect_repository_remote(dir);
    let store_ctx = StoreContext {
        dir,
        config: &effective_config,
        project: project.clone(),
        repository: repository.clone(),
    };
    let resolve_ctx = ResolveContext {
        dir,
        config: &effective_config,
        project,
        repository,
        interaction,
    };
    let mut migrated_keys: Vec<&str> = Vec::new();

    for (index, entry) in plaintext_entries.iter().enumerate() {
        if !selected_indexes.contains(&index) {
            eprintln!("  Kept in .env: {}", entry.key);
            continue;
        }

        let value = strip_quotes(&entry.raw_value);
        info!("Storing '{}' in {}", entry.key, backend.name());

        match backend.store(&entry.key, &value, &store_ctx) {
            Ok(()) => match backend.has(&entry.key, &resolve_ctx) {
                Ok(true) => {
                    eprintln!("  Stored and verified: {}", entry.key);
                    migrated_keys.push(&entry.key);
                }
                Ok(false) => {
                    warn!(
                        "Stored '{}' but verification failed — keeping in .env",
                        entry.key
                    );
                    eprintln!(
                        "  Warning: stored '{}' but could not verify. Keeping in .env.",
                        entry.key
                    );
                }
                Err(e) => {
                    warn!("Verification error for '{}': {e}", entry.key);
                    eprintln!(
                        "  Warning: verification error for '{}': {e}. Keeping in .env.",
                        entry.key
                    );
                }
            },
            Err(e) => {
                warn!("Failed to store '{}': {e}", entry.key);
                eprintln!("  Error storing '{}': {e}", entry.key);
            }
        }
    }

    Config::remember_reviewed_migration_entries(&env_path, skipped_fingerprints)?;

    if !migrated_keys.is_empty() {
        if let Some(commands) = command_scope {
            let config_path =
                configure_command_scope(dir, Some(&env_path), &effective_config, &commands)?;
            eprintln!();
            eprintln!(
                "Configured migrated secrets for these commands only: {}",
                commands.join(", ")
            );
            eprintln!("Wrote project config: {}", config_path.display());
            print_command_scope_instructions(&config_path);
        }
        eprintln!();
        eprintln!(
            "Clearing {} migrated value(s) from .env...",
            migrated_keys.len()
        );
        env_file.rewrite_with_cleared_keys(&migrated_keys)?;
        info!("Cleared {} migrated values from .env", migrated_keys.len());
        eprintln!("Done. Migrated values have been removed from .env.");
    }

    Ok(())
}

fn uses_bitwarden_backend(backend_name: &str) -> bool {
    backend_name == "bw"
}

fn config_for_migration(config: &Config, dir: &Path, backend_override: Option<&str>) -> Config {
    config.with_backend_override_for_dir(dir, backend_override)
}

#[derive(Serialize)]
struct GeneratedProjectOverride {
    backend: String,
    search_parent_env: bool,
    source_all: bool,
    warn_missing: bool,
    fallback_example_env: bool,
    cache: CacheConfig,
    op: OpConfig,
    bw: BwConfig,
    gpg: GpgConfig,
    item: Option<String>,
    commands: Vec<String>,
}

pub fn configure_command_scope(
    dir: &Path,
    env_path: Option<&Path>,
    config: &Config,
    commands: &[String],
) -> Result<PathBuf> {
    let config_path = Config::project_override_path(dir).unwrap_or_else(|| {
        env_path
            .and_then(Path::parent)
            .unwrap_or(dir)
            .join(".pw-env.toml")
    });

    if config_path.is_symlink() {
        anyhow::bail!(
            "Refusing to update symlinked project override: {}",
            config_path.display()
        );
    }

    let mut document = if config_path.exists() {
        let contents = fs::read_to_string(&config_path).with_context(|| {
            format!(
                "Failed to read project override from {}",
                config_path.display()
            )
        })?;
        contents
            .parse::<toml_edit::DocumentMut>()
            .with_context(|| {
                format!(
                    "Failed to parse project override from {}",
                    config_path.display()
                )
            })?
    } else {
        let generated = GeneratedProjectOverride {
            backend: config.effective_backend(dir).to_string(),
            search_parent_env: config.effective_search_parent_env(dir),
            source_all: config.effective_source_all(dir),
            warn_missing: config.effective_warn_missing(dir),
            fallback_example_env: config.effective_fallback_example_env(dir),
            cache: config.effective_cache(dir).clone(),
            op: config.effective_op(dir).clone(),
            bw: config.effective_bw(dir).clone(),
            gpg: config.effective_gpg(dir).clone(),
            item: config.effective_item(dir).map(ToOwned::to_owned),
            commands: Vec::new(),
        };
        toml::to_string_pretty(&generated)
            .context("Failed to serialize generated project override")?
            .parse::<toml_edit::DocumentMut>()
            .context("Generated project override is invalid")?
    };

    let mut command_values = toml_edit::Array::new();
    for command in commands {
        command_values.push(command.as_str());
    }
    document["commands"] = toml_edit::value(command_values);

    config::write_private_file(&config_path, &document.to_string()).with_context(|| {
        format!(
            "Failed to write project override to {}",
            config_path.display()
        )
    })?;

    Ok(config_path)
}

pub fn project_override_commands(path: &Path) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read project override from {}", path.display()))?;
    let document = contents
        .parse::<toml_edit::DocumentMut>()
        .with_context(|| format!("Failed to parse project override from {}", path.display()))?;

    Ok(document
        .get("commands")
        .and_then(toml_edit::Item::as_array)
        .map(|commands| {
            commands
                .iter()
                .filter_map(toml_edit::Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default())
}

pub fn print_command_scope_instructions(config_path: &Path) {
    eprintln!(
        "Approve it with: pw-env approvals approve {}",
        config_path.display()
    );
    eprintln!("Then enable the shell wrappers once with one of these:");
    eprintln!("  bash:       eval \"$(pw-env init bash)\"");
    eprintln!("  zsh:        eval \"$(pw-env init zsh)\"");
    eprintln!("  fish:       pw-env init fish | source");
    eprintln!("  PowerShell: Invoke-Expression (& pw-env init powershell)");
}

fn is_interactive() -> bool {
    #[cfg(test)]
    if let Some(val) = MOCK_INTERACTIVE.with(|c| c.get()) {
        return val;
    }
    is_interactive_check(
        cfg!(not(test)),
        std::io::stdin().is_terminal(),
        std::io::stderr().is_terminal(),
    )
}

fn is_interactive_check(not_test: bool, stdin_terminal: bool, stderr_terminal: bool) -> bool {
    not_test && stdin_terminal && stderr_terminal
}

fn mask_value(value: &str) -> String {
    let v = strip_quotes(value);
    let char_count = v.chars().count();
    if char_count <= 3 {
        "***".to_string()
    } else {
        let prefix: String = v.chars().take(3).collect();
        format!("{prefix}***")
    }
}

fn strip_quotes(value: &str) -> String {
    let v = value.trim();
    if (v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\'')) {
        let mut chars = v.chars();
        chars.next(); // skip opening quote
        chars.next_back(); // skip closing quote
        chars.collect()
    } else {
        v.to_string()
    }
}

fn prompt_for_entries(
    entries: &[&crate::env_file::EnvEntry],
    backend_name: &str,
) -> Result<BTreeSet<usize>> {
    #[cfg(test)]
    if let Some(result) = MOCK_PROMPT_RESULT.with(|r| r.borrow().clone()) {
        return Ok(result);
    }

    let items = entries
        .iter()
        .map(|entry| {
            let masked = mask_value(&entry.raw_value);
            let label = if entry.is_likely_secret() {
                " [likely secret]"
            } else {
                ""
            };
            format!("{} = {}{}", entry.key, masked, label)
        })
        .collect::<Vec<_>>();

    let defaults = entries
        .iter()
        .map(|entry| entry.is_likely_secret())
        .collect::<Vec<_>>();

    let selected = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt(format!(
            "Select the plaintext entries to store in the '{}' backend",
            backend_name
        ))
        .items(&items)
        .defaults(&defaults)
        .report(false)
        .interact()
        .context("Migration selection was interrupted")?;

    Ok(selected.into_iter().collect())
}

fn prompt_for_command_scope() -> Result<Option<Vec<String>>> {
    #[cfg(test)]
    if let Some(result) = MOCK_COMMAND_SCOPE.with(|value| value.borrow().clone()) {
        return Ok(result);
    }

    #[cfg(test)]
    return Ok(None);

    #[cfg(not(test))]
    {
        let restricted = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Should migrated secrets be available only to specific commands?")
            .default(false)
            .interact()
            .context("Command-scope selection was interrupted")?;
        if !restricted {
            return Ok(None);
        }

        loop {
            let input = Input::<String>::with_theme(&ColorfulTheme::default())
                .with_prompt("Command names (space or comma separated, for example: cargo npm)")
                .interact_text()
                .context("Command-scope editing was interrupted")?;
            match parse_command_names(&input) {
                Ok(commands) => return Ok(Some(commands)),
                Err(error) => eprintln!("Invalid command list: {error}"),
            }
        }
    }
}

pub fn parse_command_names(input: &str) -> Result<Vec<String>> {
    let mut commands = BTreeSet::new();
    for command in input.split(|character: char| character == ',' || character.is_whitespace()) {
        if command.is_empty() {
            continue;
        }
        if !is_safe_command_pattern(command) {
            anyhow::bail!("'{command}' is not a safe command name; use names such as cargo or npm");
        }
        commands.insert(command.to_string());
    }

    if commands.is_empty() {
        anyhow::bail!("enter at least one command name");
    }

    Ok(commands.into_iter().collect())
}

fn is_safe_command_pattern(command: &str) -> bool {
    if crate::output::is_safe_command_name(command) {
        return true;
    }

    let has_glob = command.contains(['*', '?', '[']);
    has_glob
        && command.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '_' | '-' | '.' | ':' | '*' | '?' | '[' | ']')
        })
        && Pattern::new(command).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProjectOverride;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    #[test]
    fn bitwarden_unlock_is_selected_only_for_bitwarden_backend() {
        assert!(uses_bitwarden_backend("bw"));
        assert!(!uses_bitwarden_backend("gpg"));
    }

    #[test]
    fn mask_value_returns_stars_for_short_values() {
        assert_eq!(mask_value(""), "***");
        assert_eq!(mask_value("ab"), "***");
        assert_eq!(mask_value("abc"), "***");
    }

    #[test]
    fn mask_value_shows_prefix_for_longer_values() {
        assert_eq!(mask_value("abcd"), "abc***");
        assert_eq!(mask_value("abcdef"), "abc***");
    }

    #[test]
    fn mask_value_strips_quotes_before_masking() {
        assert_eq!(mask_value("\"abcdef\""), "abc***");
        assert_eq!(mask_value("'abcdef'"), "abc***");
    }

    #[test]
    fn strip_quotes_removes_double_quotes() {
        assert_eq!(strip_quotes("\"hello\""), "hello");
    }

    #[test]
    fn strip_quotes_removes_single_quotes() {
        assert_eq!(strip_quotes("'hello'"), "hello");
    }

    #[test]
    fn strip_quotes_leaves_unquoted_value() {
        assert_eq!(strip_quotes("hello"), "hello");
    }

    #[test]
    fn strip_quotes_leaves_mismatched_quotes() {
        assert_eq!(strip_quotes("\"hello'"), "\"hello'");
        assert_eq!(strip_quotes("'hello\""), "'hello\"");
    }

    #[test]
    fn strip_quotes_trims_surrounding_whitespace() {
        assert_eq!(strip_quotes("  \"hello\"  "), "hello");
        assert_eq!(strip_quotes("  'hello'  "), "hello");
    }

    #[test]
    fn strip_quotes_preserves_inner_content_exactly() {
        // Verifies the slice bounds use subtraction (not division or addition).
        assert_eq!(strip_quotes("\"hello world\""), "hello world");
        assert_eq!(strip_quotes("'it\\'s here'"), "it\\'s here");
    }

    #[test]
    fn migrate_returns_err_when_no_env_file() {
        let temp_dir = TempDir::new().unwrap();
        let config = crate::config::Config {
            defaults: crate::config::Defaults::default(),
            log: crate::config::LogConfig::default(),
            updates: crate::config::UpdateConfig::default(),
            projects: vec![],
        };
        let result = migrate(temp_dir.path(), &config, None);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("No .env file found"));
    }

    #[test]
    fn migrate_returns_ok_with_no_plaintext_entries() {
        let temp_dir = TempDir::new().unwrap();
        let env_path = temp_dir.path().join(".env");
        // An env file with only empty/op/bw entries — no plaintext
        fs::write(&env_path, "API_KEY=op://vault/item/field\nDB_URL=\n").unwrap();
        let config = crate::config::Config {
            defaults: crate::config::Defaults::default(),
            log: crate::config::LogConfig::default(),
            updates: crate::config::UpdateConfig::default(),
            projects: vec![],
        };
        let result = migrate(temp_dir.path(), &config, None);
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);
    }

    #[test]
    fn migrate_bails_with_plaintext_and_non_interactive_stdin() {
        let temp_dir = TempDir::new().unwrap();
        let env_path = temp_dir.path().join(".env");
        // Plaintext entry that looks like a secret
        fs::write(
            &env_path,
            "API_KEY=super_secret_value_that_is_long_enough\n",
        )
        .unwrap();
        let config = crate::config::Config {
            defaults: crate::config::Defaults::default(),
            log: crate::config::LogConfig::default(),
            updates: crate::config::UpdateConfig::default(),
            projects: vec![],
        };
        // In test env, stdin is not a terminal, so this should bail
        let result = migrate(temp_dir.path(), &config, None);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("interactive terminal"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn config_for_migration_overrides_default_backend() {
        let dir = Path::new("/home/user/project");
        let config = crate::config::Config {
            defaults: crate::config::Defaults {
                backend: "op".to_string(),
                ..crate::config::Defaults::default()
            },
            log: crate::config::LogConfig::default(),
            updates: crate::config::UpdateConfig::default(),
            projects: vec![],
        };

        let effective_config = config_for_migration(&config, dir, Some("gpg"));

        assert_eq!(effective_config.effective_backend(dir), "gpg");
        assert_eq!(config.effective_backend(dir), "op");
    }

    #[test]
    fn config_for_migration_overrides_project_backend() {
        let dir = Path::new("/home/user/project");
        let config = crate::config::Config {
            defaults: crate::config::Defaults::default(),
            log: crate::config::LogConfig::default(),
            updates: crate::config::UpdateConfig::default(),
            projects: vec![ProjectOverride {
                path: dir.to_string_lossy().to_string(),
                backend: Some("bw".to_string()),
                ..ProjectOverride::default()
            }],
        };

        let effective_config = config_for_migration(&config, dir, Some("gpg"));

        assert_eq!(effective_config.effective_backend(dir), "gpg");
        assert_eq!(config.effective_backend(dir), "bw");
    }

    #[test]
    fn test_mask_value_short() {
        assert_eq!(mask_value("ab"), "***");
    }

    #[test]
    fn test_mask_value_exactly_three_chars() {
        assert_eq!(mask_value("abc"), "***");
    }

    #[test]
    fn test_mask_value_longer_than_three() {
        assert_eq!(mask_value("abcdef"), "abc***");
    }

    #[test]
    fn test_mask_value_quoted_double() {
        // Quotes are stripped before masking
        assert_eq!(mask_value("\"secretvalue\""), "sec***");
    }

    #[test]
    fn test_mask_value_quoted_single() {
        assert_eq!(mask_value("'mysecret'"), "mys***");
    }

    #[test]
    fn test_strip_quotes_double_quoted() {
        assert_eq!(strip_quotes("\"hello\""), "hello");
    }

    #[test]
    fn test_strip_quotes_single_quoted() {
        assert_eq!(strip_quotes("'hello'"), "hello");
    }

    #[test]
    fn test_strip_quotes_unquoted() {
        assert_eq!(strip_quotes("hello"), "hello");
    }

    #[test]
    fn test_strip_quotes_trims_surrounding_whitespace() {
        assert_eq!(strip_quotes("  hello  "), "hello");
    }

    #[test]
    fn test_strip_quotes_mismatched_not_stripped() {
        // Mismatched quotes: starts with " but ends with '
        assert_eq!(strip_quotes("\"hello'"), "\"hello'");
    }

    #[test]
    fn test_strip_quotes_single_char_between_quotes() {
        assert_eq!(strip_quotes("\"a\""), "a");
    }

    #[test]
    fn mask_value_handles_multibyte_utf8() {
        // Emoji are 4 bytes each — this must not panic on byte slicing
        assert_eq!(mask_value("😀😁😂😃"), "😀😁😂***");
    }

    #[test]
    fn strip_quotes_handles_multibyte_utf8() {
        assert_eq!(strip_quotes("\"héllo\""), "héllo");
        assert_eq!(strip_quotes("'日本語'"), "日本語");
    }

    #[test]
    fn mask_value_multibyte_short_returns_stars() {
        // A single emoji (4 bytes but 1 char) is ≤3 chars
        assert_eq!(mask_value("😀"), "***");
        // Three emoji (12 bytes but 3 chars) is ≤3 chars
        assert_eq!(mask_value("😀😁😂"), "***");
    }

    #[test]
    fn is_interactive_check_requires_all_true() {
        assert!(!is_interactive_check(false, true, true));
        assert!(!is_interactive_check(true, false, true));
        assert!(!is_interactive_check(true, true, false));
        assert!(is_interactive_check(true, true, true));
        assert!(!is_interactive_check(false, false, false));
    }

    #[cfg(unix)]
    fn set_mock_interactive(val: bool) {
        MOCK_INTERACTIVE.with(|c| c.set(Some(val)));
    }

    #[cfg(unix)]
    #[allow(dead_code)]
    fn clear_mock_interactive() {
        MOCK_INTERACTIVE.with(|c| c.set(None));
    }

    fn set_mock_prompt(indexes: BTreeSet<usize>) {
        MOCK_PROMPT_RESULT.with(|r| *r.borrow_mut() = Some(indexes));
    }

    fn set_mock_command_scope(commands: Option<Vec<String>>) {
        MOCK_COMMAND_SCOPE.with(|value| *value.borrow_mut() = Some(commands));
    }

    #[allow(dead_code)]
    fn clear_mock_prompt() {
        MOCK_PROMPT_RESULT.with(|r| *r.borrow_mut() = None);
    }

    fn clear_mock_command_scope() {
        MOCK_COMMAND_SCOPE.with(|value| *value.borrow_mut() = None);
    }

    #[test]
    fn parse_command_names_accepts_space_and_comma_separated_names() {
        let commands = parse_command_names("npm, cargo cargo").unwrap();

        assert_eq!(commands, vec!["cargo", "npm"]);
    }

    #[test]
    fn parse_command_names_accepts_executable_glob_patterns() {
        let commands = parse_command_names("cargo* npm?").unwrap();

        assert_eq!(commands, vec!["cargo*", "npm?"]);
    }

    #[test]
    fn parse_command_names_rejects_glob_patterns_with_unsafe_characters() {
        assert_eq!(is_safe_command_pattern("cargo*;rm"), false);
    }

    #[test]
    fn parse_command_names_rejects_unsafe_non_glob_patterns() {
        assert_eq!(is_safe_command_pattern("cargo/rm"), false);
    }

    #[test]
    fn parse_command_names_rejects_shell_syntax() {
        let error = parse_command_names("cargo;rm").unwrap_err();

        assert!(error.to_string().contains("not a safe command name"));
    }

    #[test]
    fn configure_command_scope_preserves_existing_override_settings() {
        let temp_dir = TempDir::new().unwrap();
        let env_path = temp_dir.path().join(".env");
        let override_path = temp_dir.path().join(".pw-env.toml");
        fs::write(&env_path, "API_KEY=plain\n").unwrap();
        fs::write(
            &override_path,
            "# Keep this comment.\nbackend = \"op\"\nitem = \"project-env\"\n",
        )
        .unwrap();

        let config = Config::default();
        let path = configure_command_scope(
            temp_dir.path(),
            Some(&env_path),
            &config,
            &["cargo".to_string(), "npm".to_string()],
        )
        .unwrap();

        assert_eq!(path, override_path);
        let contents = fs::read_to_string(&override_path).unwrap();
        assert!(contents.contains("# Keep this comment."));
        assert!(contents.contains("item = \"project-env\""));
        assert!(contents.contains("commands = [\"cargo\", \"npm\"]"));
        let parsed: toml::Value = toml::from_str(&contents).unwrap();
        assert_eq!(
            parsed
                .get("commands")
                .and_then(toml::Value::as_array)
                .map(|values| values.len()),
            Some(2)
        );
    }

    #[test]
    fn prompt_for_entries_returns_configured_mock_selection() {
        let temp_dir = TempDir::new().unwrap();
        let env_path = temp_dir.path().join(".env");
        fs::write(
            &env_path,
            "FIRST_SECRET=super_secret_long_value\nSECOND_SECRET=another_secret_value\n",
        )
        .unwrap();

        let env_file = EnvFile::parse(&env_path).unwrap();
        let entries = env_file.plaintext_entries();

        set_mock_prompt(BTreeSet::from([1]));
        let selected = prompt_for_entries(&entries, "op").unwrap();
        clear_mock_prompt();

        assert_eq!(selected, BTreeSet::from([1]));
    }

    #[cfg(unix)]
    fn with_mock_op_backend<F: FnOnce()>(script: &str, f: F) {
        let _guard = crate::backend::MOCK_PATH_MUTEX
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = TempDir::new().unwrap();
        let script_path = dir.path().join("op");
        fs::write(&script_path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script_path, perms).unwrap();
        }
        let old_path = std::env::var_os("PATH").unwrap_or_default();
        let new_path = std::env::join_paths(
            std::iter::once(dir.path().to_path_buf()).chain(std::env::split_paths(&old_path)),
        )
        .unwrap();
        unsafe { std::env::set_var("PATH", &new_path) };
        f();
        unsafe { std::env::set_var("PATH", &old_path) };
    }

    #[cfg(unix)]
    #[test]
    fn migrate_selects_and_stores_chosen_entries() {
        let temp_dir = TempDir::new().unwrap();
        let env_path = temp_dir.path().join(".env");
        // Two plaintext entries: one selected (index 0), one skipped (index 1)
        fs::write(
            &env_path,
            "SECRET_KEY=super_secret_long_value_here\nOTHER_VAL=another_long_plaintext_value\n",
        )
        .unwrap();

        let reviewed_dir = TempDir::new().unwrap();
        crate::config::set_test_reviewed_migrations_path(Some(
            reviewed_dir.path().join("reviewed-migrations.json"),
        ));

        let config = crate::config::Config {
            defaults: crate::config::Defaults {
                backend: "op".to_string(),
                op: crate::config::OpConfig {
                    vault: Some("TestVault".to_string()),
                    ..crate::config::OpConfig::default()
                },
                ..crate::config::Defaults::default()
            },
            log: crate::config::LogConfig::default(),
            updates: crate::config::UpdateConfig::default(),
            projects: vec![],
        };

        set_mock_interactive(true);
        // Select only the first entry (SECRET_KEY at index 0)
        set_mock_prompt(BTreeSet::from([0]));

        // Mock op that succeeds for all operations (create, get/verify)
        let script = r#"#!/bin/sh
# Handle any op command with success
echo "mock-value"
exit 0
"#;

        with_mock_op_backend(script, || {
            let result = migrate(temp_dir.path(), &config, None);
            assert!(result.is_ok(), "migration failed: {:?}", result);

            // The .env file should have SECRET_KEY cleared (migrated)
            // and OTHER_VAL preserved (skipped)
            let content = fs::read_to_string(&env_path).unwrap();
            assert!(
                content.contains("SECRET_KEY="),
                "SECRET_KEY should still be present as a key"
            );
            // The migrated entry should have its value cleared
            assert!(
                !content.contains("super_secret_long_value_here"),
                "migrated value should be cleared from .env"
            );
            // The skipped entry should be preserved
            assert!(
                content.contains("another_long_plaintext_value"),
                "skipped entry value should be preserved"
            );
        });

        clear_mock_interactive();
        clear_mock_prompt();
        crate::config::set_test_reviewed_migrations_path(None);
    }

    #[cfg(unix)]
    #[test]
    fn migrate_writes_command_scope_to_project_override() {
        let temp_dir = TempDir::new().unwrap();
        let env_path = temp_dir.path().join(".env");
        fs::write(&env_path, "SECRET_KEY=super_secret_long_value_here\n").unwrap();

        let reviewed_dir = TempDir::new().unwrap();
        crate::config::set_test_reviewed_migrations_path(Some(
            reviewed_dir.path().join("reviewed-migrations.json"),
        ));

        let config = crate::config::Config {
            defaults: crate::config::Defaults {
                backend: "op".to_string(),
                ..crate::config::Defaults::default()
            },
            log: crate::config::LogConfig::default(),
            updates: crate::config::UpdateConfig::default(),
            projects: vec![],
        };

        set_mock_interactive(true);
        set_mock_prompt(BTreeSet::from([0]));
        set_mock_command_scope(Some(vec!["cargo".to_string(), "npm".to_string()]));

        with_mock_op_backend("#!/bin/sh\necho mock-value\nexit 0\n", || {
            let result = migrate(temp_dir.path(), &config, None);
            assert!(result.is_ok(), "migration failed: {:?}", result);
        });

        let override_path = temp_dir.path().join(".pw-env.toml");
        let contents = fs::read_to_string(override_path).unwrap();
        assert!(contents.contains("commands = [\"cargo\", \"npm\"]"));

        clear_mock_interactive();
        clear_mock_prompt();
        clear_mock_command_scope();
        crate::config::set_test_reviewed_migrations_path(None);
    }

    #[cfg(unix)]
    #[test]
    fn migrate_with_empty_selection_does_not_rewrite_env() {
        let temp_dir = TempDir::new().unwrap();
        let env_path = temp_dir.path().join(".env");
        let original_content = "PASSWORD=very_secret_long_value\n";
        fs::write(&env_path, original_content).unwrap();

        let reviewed_dir = TempDir::new().unwrap();
        crate::config::set_test_reviewed_migrations_path(Some(
            reviewed_dir.path().join("reviewed-migrations.json"),
        ));

        let config = crate::config::Config {
            defaults: crate::config::Defaults::default(),
            log: crate::config::LogConfig::default(),
            updates: crate::config::UpdateConfig::default(),
            projects: vec![],
        };

        set_mock_interactive(true);
        // Select nothing
        set_mock_prompt(BTreeSet::new());

        // No backend needed since nothing is selected
        let script = "#!/bin/sh\nexit 1\n";
        with_mock_op_backend(script, || {
            let result = migrate(temp_dir.path(), &config, None);
            assert!(result.is_ok(), "migration failed: {:?}", result);

            let content = fs::read_to_string(&env_path).unwrap();
            assert_eq!(content, original_content, ".env should not be modified");
        });

        clear_mock_interactive();
        clear_mock_prompt();
        crate::config::set_test_reviewed_migrations_path(None);
    }

    #[cfg(unix)]
    #[test]
    fn migrate_only_clears_entries_selected_by_prompt() {
        let temp_dir = TempDir::new().unwrap();
        let env_path = temp_dir.path().join(".env");
        fs::write(
            &env_path,
            "FIRST_VALUE=plain_visible_value\nSECOND_VALUE=another_plaintext_value\n",
        )
        .unwrap();

        let reviewed_dir = TempDir::new().unwrap();
        crate::config::set_test_reviewed_migrations_path(Some(
            reviewed_dir.path().join("reviewed-migrations.json"),
        ));

        let config = crate::config::Config {
            defaults: crate::config::Defaults::default(),
            log: crate::config::LogConfig::default(),
            updates: crate::config::UpdateConfig::default(),
            projects: vec![],
        };

        set_mock_interactive(true);
        set_mock_prompt(BTreeSet::from([1]));

        let script = r#"#!/bin/sh
echo "mock-value"
exit 0
"#;

        with_mock_op_backend(script, || {
            let result = migrate(temp_dir.path(), &config, None);
            assert!(result.is_ok(), "migration failed: {:?}", result);

            let content = fs::read_to_string(&env_path).unwrap();
            assert!(
                content.contains("FIRST_VALUE=plain_visible_value"),
                "unselected entry should remain unchanged"
            );
            assert!(
                content.contains("SECOND_VALUE="),
                "selected entry key should remain present"
            );
            assert!(
                !content.contains("SECOND_VALUE=another_plaintext_value"),
                "selected entry value should be cleared from .env"
            );
        });

        clear_mock_interactive();
        clear_mock_prompt();
        crate::config::set_test_reviewed_migrations_path(None);
    }
}
