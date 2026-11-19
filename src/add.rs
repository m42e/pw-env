use anyhow::{Context, Result, bail};
use dialoguer::Password;
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use tracing::info;

use crate::backend::{self, ResolutionInteraction, ResolveContext, StoreContext};
use crate::config::Config;
use crate::env_file::{self, EntryKind};
use crate::output;
use crate::resolve;

#[cfg(test)]
pub fn add_entry(
    dir: &Path,
    config: &Config,
    key: &str,
    provided_value: Option<String>,
    backend_override: Option<&str>,
) -> Result<()> {
    add_entry_with_interaction(dir, config, key, provided_value, backend_override, None)
}

pub fn add_entry_with_interaction(
    dir: &Path,
    config: &Config,
    key: &str,
    provided_value: Option<String>,
    backend_override: Option<&str>,
    interaction: Option<&dyn ResolutionInteraction>,
) -> Result<()> {
    validate_key(key)?;

    let env_update = plan_env_entry_update(dir, config, key)?;
    let value = read_secret_value(key, provided_value)?;
    let effective_config = config.with_backend_override_for_dir(dir, backend_override);
    let backend_name = effective_config.effective_backend(dir);
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

    info!(key, backend = backend.name(), "Adding managed secret");
    backend
        .store_with_interaction(key, &value, &store_ctx, interaction)
        .with_context(|| format!("Failed to store '{key}' in {}", backend.name()))?;

    if !backend.has(key, &resolve_ctx).with_context(|| {
        format!(
            "Failed to verify '{key}' after storing it in {}",
            backend.name()
        )
    })? {
        bail!(
            "Stored '{key}' in {} but verification failed",
            backend.name()
        );
    }

    let url = backend.reference_url(key, &store_ctx);
    let env_message =
        apply_env_entry_update_after_store(env_update, key, url.as_deref(), backend.name())?;

    eprintln!("Stored {key} in {}.", backend.name());
    eprintln!("{env_message}");

    Ok(())
}

fn uses_bitwarden_backend(backend_name: &str) -> bool {
    backend_name == "bw"
}

#[derive(Debug)]
enum EnvEntryUpdate {
    Create(PathBuf),
    Append(env_file::EnvFile),
    AlreadyManaged(env_file::EnvFile),
}

fn validate_key(key: &str) -> Result<()> {
    if output::is_valid_env_key(key) {
        return Ok(());
    }

    bail!("Invalid environment variable name '{key}'. Expected [A-Za-z_][A-Za-z0-9_]*")
}

fn read_secret_value(key: &str, provided_value: Option<String>) -> Result<String> {
    let value = read_secret_value_with(
        key,
        provided_value,
        std::io::stdin().is_terminal(),
        |key| {
            Password::new()
                .with_prompt(format!("Value for {key}"))
                .with_confirmation("Confirm value", "Values do not match")
                .interact()
                .context("Failed to read secret value")
        },
        || read_secret_value_from_stdin(std::io::stdin()),
    )?;

    if value.is_empty() {
        bail!("Secret value cannot be empty")
    }

    Ok(value)
}

fn read_secret_value_with<Prompt, ReadStdin>(
    key: &str,
    provided_value: Option<String>,
    stdin_is_terminal: bool,
    prompt_secret_value: Prompt,
    read_secret_value_from_stdin: ReadStdin,
) -> Result<String>
where
    Prompt: FnOnce(&str) -> Result<String>,
    ReadStdin: FnOnce() -> Result<String>,
{
    let value = match provided_value {
        Some(value) => value,
        None => {
            if stdin_is_terminal {
                prompt_secret_value(key)?
            } else {
                read_secret_value_from_stdin()?
            }
        }
    };

    if value.is_empty() {
        bail!("Secret value cannot be empty")
    }

    Ok(value)
}
fn read_secret_value_from_stdin(mut reader: impl Read) -> Result<String> {
    let mut buffer = String::new();
    reader
        .read_to_string(&mut buffer)
        .context("Failed to read secret value from stdin")?;
    Ok(trim_single_trailing_newline(buffer))
}

fn trim_single_trailing_newline(mut value: String) -> String {
    if value.ends_with("\r\n") {
        value.truncate(value.len() - 2);
        return value;
    }

    if value.ends_with('\n') {
        value.pop();
    }

    value
}

fn plan_env_entry_update(dir: &Path, config: &Config, key: &str) -> Result<EnvEntryUpdate> {
    let env_path =
        env_file::EnvFile::find_with_parents(dir, config.effective_search_parent_env(dir))
            .unwrap_or_else(|| dir.join(".env"));
    if !env_path.exists() {
        return Ok(EnvEntryUpdate::Create(env_path));
    }

    if env_path.is_symlink() {
        bail!(
            "Refusing to update .env symlink at {}. Use a regular file.",
            env_path.display()
        );
    }

    let env_file = env_file::EnvFile::parse(&env_path)?;
    if let Some(existing_entry) = env_file
        .entries()
        .into_iter()
        .find(|entry| entry.key == key)
    {
        match &existing_entry.kind {
            EntryKind::Empty => return Ok(EnvEntryUpdate::AlreadyManaged(env_file)),
            EntryKind::OpReference(_) | EntryKind::BwReference(_) => {
                bail!(
                    "{key} already exists in {} as an explicit backend reference. Clear that value first if you want pw-env add to manage it via the default backend.",
                    env_path.display()
                )
            }
            EntryKind::Plaintext(_) => {
                bail!(
                    "{key} already exists in {} with a plaintext value. Clear it first or run pw-env migrate instead.",
                    env_path.display()
                )
            }
        }
    }

    Ok(EnvEntryUpdate::Append(env_file))
}

fn apply_env_entry_update(update: EnvEntryUpdate, key: &str, url: Option<&str>) -> Result<String> {
    match update {
        EnvEntryUpdate::Create(path) => {
            let entry_value = url.unwrap_or("");
            crate::config::atomic_write_file(
                &path,
                format!("{key}={entry_value}\n").as_bytes(),
                false,
            )
            .with_context(|| format!("Failed to create {}", path.display()))?;
            if url.is_some() {
                Ok(format!(
                    "Created {} with a managed entry for {key}.",
                    path.display()
                ))
            } else {
                Ok(format!(
                    "Created {} with an empty managed entry for {key}.",
                    path.display()
                ))
            }
        }
        EnvEntryUpdate::Append(env_file) => {
            let entry_value = url.unwrap_or("");
            env_file.append_with_key_value(key, entry_value)?;
            let path = env_file.path();
            if url.is_some() {
                Ok(format!(
                    "Added a managed entry for {key} to {}.",
                    path.display()
                ))
            } else {
                Ok(format!(
                    "Added an empty managed entry for {key} to {}.",
                    path.display()
                ))
            }
        }
        EnvEntryUpdate::AlreadyManaged(env_file) => {
            let path = env_file.path();
            if let Some(url) = url {
                env_file.rewrite_with_key_value(key, url)?;
                Ok(format!(
                    "Updated {} to write the backend URL for {key}.",
                    path.display()
                ))
            } else {
                Ok(format!(
                    "{} already contains an empty managed entry for {key}.",
                    path.display()
                ))
            }
        }
    }
}

fn apply_env_entry_update_after_store(
    update: EnvEntryUpdate,
    key: &str,
    url: Option<&str>,
    backend_name: &str,
) -> Result<String> {
    apply_env_entry_update(update, key, url).with_context(|| {
        format!(
            "Secret '{key}' was stored and verified in {backend_name}, but the environment file was not updated; resolve that file conflict before retrying to avoid creating another vault item"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{GpgStoreBindingAction, ProgressReporter};
    use crate::config::Config;
    #[cfg(unix)]
    use crate::config::{Defaults, GpgConfig, LogConfig, OpConfig, UpdateConfig};
    use tempfile::TempDir;

    #[cfg(unix)]
    struct ApproveGpgStoreEnrollment;

    #[cfg(unix)]
    struct TestProgress;

    #[cfg(unix)]
    impl ProgressReporter for TestProgress {
        fn set_message(&mut self, _message: &str) {}
        fn finish(&mut self, _message: &str) {}
    }

    #[cfg(unix)]
    impl crate::backend::ResolutionInteraction for ApproveGpgStoreEnrollment {
        fn confirm_gpg_store_binding(
            &self,
            _action: GpgStoreBindingAction,
            _project_path: &std::path::Path,
            _previous_recipients: &[String],
            _new_recipients: &[String],
        ) -> anyhow::Result<bool> {
            Ok(true)
        }

        fn prompt_bitwarden_password(&self) -> anyhow::Result<String> {
            anyhow::bail!("not used by add tests")
        }

        fn start_progress(&self, _initial_message: &str) -> Box<dyn ProgressReporter> {
            Box::new(TestProgress)
        }
    }

    #[test]
    fn bitwarden_unlock_is_selected_only_for_bitwarden_backend() {
        assert!(uses_bitwarden_backend("bw"));
        assert!(!uses_bitwarden_backend("op"));
    }

    #[test]
    fn trim_single_trailing_newline_removes_lf() {
        assert_eq!(
            trim_single_trailing_newline("secret\n".to_string()),
            "secret"
        );
    }

    #[test]
    fn trim_single_trailing_newline_removes_crlf() {
        assert_eq!(
            trim_single_trailing_newline("secret\r\n".to_string()),
            "secret"
        );
    }

    #[test]
    fn trim_single_trailing_newline_keeps_embedded_newlines() {
        assert_eq!(
            trim_single_trailing_newline("first\nsecond".to_string()),
            "first\nsecond"
        );
    }

    #[test]
    fn plan_env_entry_update_creates_new_env_when_missing() {
        let temp_dir = TempDir::new().unwrap();
        let result = plan_env_entry_update(temp_dir.path(), &Config::default(), "API_KEY").unwrap();
        assert!(matches!(
            result,
            EnvEntryUpdate::Create(path) if path == temp_dir.path().join(".env")
        ));
    }

    #[test]
    fn plan_env_entry_update_marks_existing_empty_entry_as_managed() {
        let temp_dir = TempDir::new().unwrap();
        let env_path = temp_dir.path().join(".env");
        std::fs::write(&env_path, "API_KEY=\n").unwrap();

        let result = plan_env_entry_update(temp_dir.path(), &Config::default(), "API_KEY").unwrap();
        assert!(matches!(
            result,
            EnvEntryUpdate::AlreadyManaged(env_file)
                if env_file.path() == env_path.canonicalize().unwrap()
        ));
    }

    #[test]
    fn plan_env_entry_update_rejects_plaintext_entry() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(temp_dir.path().join(".env"), "API_KEY=plaintext\n").unwrap();

        let result = plan_env_entry_update(temp_dir.path(), &Config::default(), "API_KEY");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("plaintext value"));
    }

    #[test]
    fn apply_env_entry_update_appends_missing_newline() {
        let temp_dir = TempDir::new().unwrap();
        let env_path = temp_dir.path().join(".env");
        std::fs::write(&env_path, "EXISTING_KEY=").unwrap();

        let update = plan_env_entry_update(temp_dir.path(), &Config::default(), "API_KEY").unwrap();
        apply_env_entry_update(update, "API_KEY", None).unwrap();

        let contents = std::fs::read_to_string(env_path).unwrap();
        assert_eq!(contents, "EXISTING_KEY=\nAPI_KEY=\n");
    }

    #[test]
    fn apply_env_entry_update_appends_to_empty_file_without_leading_newline() {
        let temp_dir = TempDir::new().unwrap();
        let env_path = temp_dir.path().join(".env");
        std::fs::write(&env_path, "").unwrap();

        let update = plan_env_entry_update(temp_dir.path(), &Config::default(), "API_KEY").unwrap();
        apply_env_entry_update(update, "API_KEY", None).unwrap();

        let contents = std::fs::read_to_string(env_path).unwrap();
        assert_eq!(contents, "API_KEY=\n");
    }

    #[cfg(unix)]
    #[test]
    fn apply_env_entry_update_preserves_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let env_path = temp_dir.path().join(".env");
        std::fs::write(&env_path, "EXISTING_KEY=\n").unwrap();
        std::fs::set_permissions(&env_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let update = plan_env_entry_update(temp_dir.path(), &Config::default(), "API_KEY").unwrap();
        apply_env_entry_update(update, "API_KEY", None).unwrap();

        assert_eq!(
            std::fs::metadata(&env_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::read_to_string(env_path).unwrap(),
            "EXISTING_KEY=\nAPI_KEY=\n"
        );
    }

    #[test]
    fn apply_env_entry_update_does_not_copy_replacement_file_contents() {
        let temp_dir = TempDir::new().unwrap();
        let env_path = temp_dir.path().join(".env");
        let displaced = temp_dir.path().join(".env.original");
        std::fs::write(&env_path, "EXISTING_KEY=\n").unwrap();
        let update = plan_env_entry_update(temp_dir.path(), &Config::default(), "API_KEY").unwrap();

        std::fs::rename(&env_path, &displaced).unwrap();
        std::fs::write(&env_path, "EXTERNAL=do-not-copy\n").unwrap();
        let error = apply_env_entry_update_after_store(
            update,
            "API_KEY",
            Some("op://vault/item/password"),
            "1Password",
        )
        .expect_err("replacement after planning must be reported as a conflict");

        assert!(format!("{error:#}").contains("changed after it was read"));
        assert!(format!("{error:#}").contains("stored and verified in 1Password"));
        assert!(format!("{error:#}").contains("avoid creating another vault item"));
        assert_eq!(
            std::fs::read_to_string(&env_path).unwrap(),
            "EXTERNAL=do-not-copy\n"
        );
        assert_eq!(
            std::fs::read_to_string(displaced).unwrap(),
            "EXISTING_KEY=\n"
        );
    }

    #[test]
    fn apply_env_entry_update_rejects_in_place_change_after_planning() {
        let temp_dir = TempDir::new().unwrap();
        let env_path = temp_dir.path().join(".env");
        std::fs::write(&env_path, "EXISTING_KEY=\n").unwrap();
        let update = plan_env_entry_update(temp_dir.path(), &Config::default(), "API_KEY").unwrap();

        std::fs::write(&env_path, "CHANGED=keep\n").unwrap();
        let error = apply_env_entry_update(update, "API_KEY", None)
            .expect_err("contents modified after planning must be rejected");

        assert!(format!("{error:#}").contains("changed after it was read"));
        assert_eq!(std::fs::read_to_string(env_path).unwrap(), "CHANGED=keep\n");
    }

    #[test]
    fn apply_env_entry_update_writes_url_on_create() {
        let temp_dir = TempDir::new().unwrap();
        let env_path = temp_dir.path().join(".env");

        apply_env_entry_update(
            EnvEntryUpdate::Create(env_path.clone()),
            "API_KEY",
            Some("op://vault/item/password"),
        )
        .unwrap();

        let contents = std::fs::read_to_string(env_path).unwrap();
        assert_eq!(contents, "API_KEY=op://vault/item/password\n");
    }

    #[test]
    fn apply_env_entry_update_writes_url_on_append() {
        let temp_dir = TempDir::new().unwrap();
        let env_path = temp_dir.path().join(".env");
        std::fs::write(&env_path, "EXISTING_KEY=\n").unwrap();

        apply_env_entry_update(
            EnvEntryUpdate::Append(env_file::EnvFile::parse(&env_path).unwrap()),
            "API_KEY",
            Some("op://vault/item/password"),
        )
        .unwrap();

        let contents = std::fs::read_to_string(env_path).unwrap();
        assert_eq!(
            contents,
            "EXISTING_KEY=\nAPI_KEY=op://vault/item/password\n"
        );
    }

    #[test]
    fn apply_env_entry_update_updates_empty_entry_with_url_when_already_managed() {
        let temp_dir = TempDir::new().unwrap();
        let env_path = temp_dir.path().join(".env");
        std::fs::write(&env_path, "API_KEY=\n").unwrap();

        apply_env_entry_update(
            EnvEntryUpdate::AlreadyManaged(env_file::EnvFile::parse(&env_path).unwrap()),
            "API_KEY",
            Some("op://vault/item/password"),
        )
        .unwrap();

        let contents = std::fs::read_to_string(env_path).unwrap();
        assert_eq!(contents, "API_KEY=op://vault/item/password\n");
    }

    #[test]
    fn apply_env_entry_update_already_managed_no_url_leaves_file_unchanged() {
        let temp_dir = TempDir::new().unwrap();
        let env_path = temp_dir.path().join(".env");
        std::fs::write(&env_path, "API_KEY=\n").unwrap();

        apply_env_entry_update(
            EnvEntryUpdate::AlreadyManaged(env_file::EnvFile::parse(&env_path).unwrap()),
            "API_KEY",
            None,
        )
        .unwrap();

        let contents = std::fs::read_to_string(env_path).unwrap();
        assert_eq!(contents, "API_KEY=\n");
    }

    #[test]
    fn read_secret_value_uses_prompt_when_stdin_is_terminal() {
        let value = read_secret_value_with(
            "API_KEY",
            None,
            true,
            |key| Ok(format!("prompted-{key}")),
            || bail!("stdin reader should not be used"),
        )
        .unwrap();

        assert_eq!(value, "prompted-API_KEY");
    }

    #[test]
    fn read_secret_value_reads_stdin_when_not_terminal() {
        let value = read_secret_value_with(
            "API_KEY",
            None,
            false,
            |_| bail!("prompt should not be used"),
            || read_secret_value_from_stdin(std::io::Cursor::new("secret\n")),
        )
        .unwrap();

        assert_eq!(value, "secret");
    }

    #[test]
    fn read_secret_value_rejects_empty_value_from_stdin() {
        let error = read_secret_value_with(
            "API_KEY",
            None,
            false,
            |_| bail!("prompt should not be used"),
            || read_secret_value_from_stdin(std::io::Cursor::new("\n")),
        )
        .unwrap_err();

        assert_eq!(error.to_string(), "Secret value cannot be empty");
    }

    #[test]
    fn read_secret_value_rejects_empty_value_from_prompt() {
        let error = read_secret_value_with(
            "API_KEY",
            None,
            true,
            |_| Ok(String::new()),
            || bail!("stdin reader should not be used"),
        )
        .unwrap_err();

        assert_eq!(error.to_string(), "Secret value cannot be empty");
    }

    #[test]
    fn read_secret_value_rejects_crlf_only_value_from_stdin() {
        let error = read_secret_value_with(
            "API_KEY",
            None,
            false,
            |_| bail!("prompt should not be used"),
            || read_secret_value_from_stdin(std::io::Cursor::new("\r\n")),
        )
        .unwrap_err();

        assert_eq!(error.to_string(), "Secret value cannot be empty");
    }

    #[test]
    #[cfg(unix)]
    fn add_entry_rejects_invalid_key_before_backend_interaction() {
        let _guard = crate::backend::MOCK_PATH_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp_dir = TempDir::new().unwrap();
        let bin_dir = TempDir::new().unwrap();
        let gpg_path = bin_dir.path().join("gpg");
        let gpg_output_path = temp_dir.path().join("captured-gpg-output.txt");
        let script = format!(
            "#!/bin/sh\nif [ \"$1\" = \"--decrypt\" ]; then\n  cat '{}'
\n  exit 0\nfi\nout=''\nprev=''\nfor arg in \"$@\"; do\n  if [ \"$prev\" = \"--output\" ]; then\n    out=\"$arg\"\n    break\n  fi\n  prev=\"$arg\"\ndone\ncat > \"$out\"\ncp \"$out\" '{}'\nexit 0\n",
            gpg_output_path.display(),
            gpg_output_path.display()
        );

        std::fs::write(&gpg_path, script).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&gpg_path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&gpg_path, permissions).unwrap();
        }

        let old_path = std::env::var_os("PATH").unwrap_or_default();
        let new_path = std::env::join_paths(
            std::iter::once(bin_dir.path().to_path_buf()).chain(std::env::split_paths(&old_path)),
        )
        .unwrap();
        unsafe { std::env::set_var("PATH", &new_path) };

        let config = Config {
            defaults: Defaults {
                backend: "gpg".to_string(),
                gpg: GpgConfig {
                    file_pattern: ".env.gpg".to_string(),
                    recipient: Some("test@example.com".to_string()),
                },
                ..Defaults::default()
            },
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };

        let result = add_entry(
            temp_dir.path(),
            &config,
            "INVALID-KEY",
            Some("super-secret".to_string()),
            None,
        );

        unsafe { std::env::set_var("PATH", &old_path) };

        let error = result.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Invalid environment variable name 'INVALID-KEY'"),
            "unexpected error: {error:#}"
        );
        assert!(!temp_dir.path().join(".env").exists());
        assert!(!temp_dir.path().join(".env.gpg").exists());
    }

    #[test]
    #[cfg(unix)]
    fn add_entry_stores_secret_and_creates_empty_env_entry_for_gpg_backend() {
        let _guard = crate::backend::MOCK_PATH_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp_dir = TempDir::new().unwrap();
        let bin_dir = TempDir::new().unwrap();
        let gpg_path = bin_dir.path().join("gpg");
        let gpg_output_path = temp_dir.path().join("captured-gpg-output.txt");
        let script = format!(
            "#!/bin/sh\nfor arg do\n  if [ \"$arg\" = \"--list-keys\" ]; then\n    printf 'pub:u:2048:1:KEYID::::::scESC::::::\\nfpr:::::::::0123456789ABCDEF0123456789ABCDEF01234567:\\n'\n    exit 0\n  fi\ndone\nif [ \"$1\" = \"--decrypt\" ]; then\n  cat '{}'\n  exit 0\nfi\ncat > '{}'\ncat '{}'\nexit 0\n",
            gpg_output_path.display(),
            gpg_output_path.display(),
            gpg_output_path.display()
        );

        std::fs::write(&gpg_path, script).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&gpg_path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&gpg_path, permissions).unwrap();
        }

        let old_path = std::env::var_os("PATH").unwrap_or_default();
        let new_path = std::env::join_paths(
            std::iter::once(bin_dir.path().to_path_buf()).chain(std::env::split_paths(&old_path)),
        )
        .unwrap();
        unsafe { std::env::set_var("PATH", &new_path) };

        let config = Config {
            defaults: Defaults {
                backend: "gpg".to_string(),
                gpg: GpgConfig {
                    file_pattern: ".env.gpg".to_string(),
                    recipient: Some("test@example.com".to_string()),
                },
                ..Defaults::default()
            },
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };

        let interaction = ApproveGpgStoreEnrollment;
        let result = add_entry_with_interaction(
            temp_dir.path(),
            &config,
            "API_KEY",
            Some("super-secret".to_string()),
            None,
            Some(&interaction),
        );

        unsafe { std::env::set_var("PATH", &old_path) };

        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        assert_eq!(
            std::fs::read_to_string(temp_dir.path().join(".env")).unwrap(),
            "API_KEY=\n"
        );
        assert!(temp_dir.path().join(".env.gpg").exists());

        let encrypted_payload = std::fs::read_to_string(gpg_output_path).unwrap();
        assert!(encrypted_payload.contains("API_KEY=\"super-secret\""));
    }

    #[test]
    #[cfg(unix)]
    fn add_entry_backend_override_uses_matching_backend_item_config() {
        let _guard = crate::backend::MOCK_PATH_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp_dir = TempDir::new().unwrap();
        let bin_dir = TempDir::new().unwrap();
        let op_path = bin_dir.path().join("op");
        let op_log_path = temp_dir.path().join("op-invocation.txt");
        let script = format!(
            "#!/bin/sh\nprintf '%s\n' \"$*\" >> '{}'\nif [ \"$1\" = \"item\" ] && [ \"$2\" = \"edit\" ] && [ \"$3\" = \"shared-item\" ]; then\n  cat >/dev/null\n  exit 0\nfi\nif [ \"$1\" = \"item\" ] && [ \"$2\" = \"get\" ] && [ \"$3\" = \"shared-item\" ] && [ \"$4\" = \"--fields\" ] && [ \"$5\" = \"label=API_KEY\" ] && [ \"$6\" = \"--reveal\" ]; then\n  printf 'super-secret'\n  exit 0\nfi\nif [ \"$1\" = \"item\" ] && [ \"$2\" = \"get\" ] && [ \"$3\" = \"shared-item\" ] && [ \"$4\" = \"--format=json\" ]; then\n  printf '%s' '{{\"category\":\"LOGIN\",\"title\":\"shared-item\",\"fields\":[]}}'\n  exit 0\nfi\nprintf 'unexpected args: %s\n' \"$*\" >&2\nexit 1\n",
            op_log_path.display()
        );

        std::fs::write(&op_path, script).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&op_path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&op_path, permissions).unwrap();
        }

        let old_path = std::env::var_os("PATH").unwrap_or_default();
        let new_path = std::env::join_paths(
            std::iter::once(bin_dir.path().to_path_buf()).chain(std::env::split_paths(&old_path)),
        )
        .unwrap();
        unsafe { std::env::set_var("PATH", &new_path) };

        let config = Config {
            defaults: Defaults {
                backend: "bw".to_string(),
                op: OpConfig {
                    item: Some("shared-item".to_string()),
                    ..OpConfig::default()
                },
                ..Defaults::default()
            },
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };

        let result = add_entry(
            temp_dir.path(),
            &config,
            "API_KEY",
            Some("super-secret".to_string()),
            Some("op"),
        );

        unsafe { std::env::set_var("PATH", &old_path) };

        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        assert_eq!(
            std::fs::read_to_string(temp_dir.path().join(".env")).unwrap(),
            "API_KEY=\n"
        );
        let logged_args = std::fs::read_to_string(op_log_path).unwrap();
        assert!(
            logged_args
                .lines()
                .any(|line| line.starts_with("item edit shared-item")),
            "unexpected op args: {logged_args}"
        );
        assert!(
            logged_args
                .lines()
                .any(|line| line.starts_with("item get shared-item --fields label=API_KEY")),
            "missing post-store verification: {logged_args}"
        );
        assert!(!logged_args.contains("super-secret"));
    }
}
