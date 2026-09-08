use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::io::Write;
use std::process::Command;
use tracing::{debug, info, warn};

use super::{
    Backend, CREATED_WITH_FIELD_NAME, MIGRATED_FROM_FIELD_NAME, PROJECT_FIELD_NAME,
    REPOSITORY_FIELD_NAME, ResolveContext, StoreContext,
};

pub struct OpBackend;

impl OpBackend {
    #[cfg(test)]
    fn text_field_assignment(field_name: &str, value: &str) -> String {
        format!("{field_name}[text]={value}")
    }

    #[cfg(test)]
    fn migration_field_assignments(ctx: &StoreContext) -> Vec<String> {
        let mut assignments = vec![
            Self::text_field_assignment(MIGRATED_FROM_FIELD_NAME, &ctx.migrated_from()),
            Self::text_field_assignment(CREATED_WITH_FIELD_NAME, &ctx.created_with()),
        ];
        if let Some(project) = ctx.project.as_deref() {
            assignments.push(Self::text_field_assignment(PROJECT_FIELD_NAME, project));
        }
        if let Some(repository) = ctx.repository.as_deref() {
            assignments.push(Self::text_field_assignment(
                REPOSITORY_FIELD_NAME,
                repository,
            ));
        }
        assignments
    }

    fn migration_fields(ctx: &StoreContext) -> Vec<serde_json::Value> {
        let mut fields = vec![
            serde_json::json!({
                "type": "STRING",
                "label": MIGRATED_FROM_FIELD_NAME,
                "value": ctx.migrated_from()
            }),
            serde_json::json!({
                "type": "STRING",
                "label": CREATED_WITH_FIELD_NAME,
                "value": ctx.created_with()
            }),
        ];
        if let Some(project) = ctx.project.as_deref() {
            fields.push(serde_json::json!({
                "type": "STRING",
                "label": PROJECT_FIELD_NAME,
                "value": project
            }));
        }
        if let Some(repository) = ctx.repository.as_deref() {
            fields.push(serde_json::json!({
                "type": "STRING",
                "label": REPOSITORY_FIELD_NAME,
                "value": repository
            }));
        }
        fields
    }

    fn upsert_json_field(
        item: &mut serde_json::Value,
        label: &str,
        value: &str,
        field_type: &str,
    ) -> Result<()> {
        let object = item
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("1Password item JSON must be an object"))?;
        let fields_value = object
            .entry("fields")
            .or_insert_with(|| serde_json::json!([]));
        let fields = fields_value
            .as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("1Password item fields must be an array"))?;

        if let Some(field) = fields.iter_mut().find(|field| {
            field.get("label").and_then(|value| value.as_str()) == Some(label)
                || field.get("id").and_then(|value| value.as_str()) == Some(label)
        }) {
            field["value"] = serde_json::Value::String(value.to_string());
        } else {
            fields.push(serde_json::json!({
                "type": field_type,
                "label": label,
                "value": value
            }));
        }
        Ok(())
    }

    fn contains_passkey(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Object(object) => object.iter().any(|(key, value)| {
                key.eq_ignore_ascii_case("passkey") || Self::contains_passkey(value)
            }),
            serde_json::Value::Array(values) => values.iter().any(Self::contains_passkey),
            serde_json::Value::String(value) => value.eq_ignore_ascii_case("passkey"),
            _ => false,
        }
    }

    /// Run `op` with the given arguments, optionally scoped to an account.
    fn run_op(args: &[&str], account: Option<&str>) -> Result<String> {
        let mut cmd = Command::new("op");
        cmd.args(args);
        if let Some(acct) = account {
            cmd.arg("--account").arg(acct);
        }
        // Ensure no interactive prompts corrupt our stdout
        cmd.stdin(std::process::Stdio::null());
        debug!("Running: op {}", args.join(" "));
        let output = super::run_command_with_timeout(
            cmd,
            "Failed to execute `op` CLI. Is 1Password CLI installed?",
        )?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("op command failed: {stderr}");
        }
        let stdout = String::from_utf8(output.stdout).context("op output was not valid UTF-8")?;
        Ok(stdout.trim().to_string())
    }

    fn run_op_write(
        args: &[&str],
        payload: &serde_json::Value,
        account: Option<&str>,
    ) -> Result<()> {
        let mut cmd = Command::new("op");
        cmd.args(args);
        if let Some(account) = account {
            cmd.arg("--account").arg(account);
        }
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        debug!("Writing 1Password item JSON");
        let mut child = cmd
            .spawn()
            .context("Failed to start 1Password item write")?;
        {
            let mut stdin = child
                .stdin
                .take()
                .context("Missing 1Password item write stdin")?;
            serde_json::to_writer(&mut stdin, payload)
                .context("Failed to send 1Password item JSON")?;
            stdin
                .flush()
                .context("Failed to flush 1Password item JSON")?;
        }
        let output = super::wait_with_output_timeout(child, "Failed to wait for 1Password item write")?;
        if !output.status.success() {
            bail!("1Password item write failed");
        }
        Ok(())
    }

    fn get_item_field(
        item: &str,
        field: &str,
        vault: Option<&str>,
        account: Option<&str>,
    ) -> Result<String> {
        let mut args = vec!["item", "get", item, "--fields", field, "--reveal"];
        let vault_arg;
        if let Some(v) = vault {
            vault_arg = format!("--vault={v}");
            args.push(&vault_arg);
        }
        Self::run_op(&args, account)
    }

    fn get_item_json(
        item: &str,
        vault: Option<&str>,
        account: Option<&str>,
    ) -> Result<serde_json::Value> {
        let mut args = vec!["item", "get", item, "--format=json", "--reveal"];
        let vault_arg;
        if let Some(v) = vault {
            vault_arg = format!("--vault={v}");
            args.push(&vault_arg);
        }
        let item_json = Self::run_op(&args, account)?;
        serde_json::from_str(&item_json).context("Failed to parse 1Password item JSON")
    }

    fn extract_field_from_value(item: &serde_json::Value, field_name: &str) -> Result<String> {
        item.get("fields")
            .and_then(|fields| fields.as_array())
            .and_then(|fields| {
                fields.iter().find(|field| {
                    field.get("label").and_then(|label| label.as_str()) == Some(field_name)
                })
            })
            .and_then(|field| field.get("value").and_then(|value| value.as_str()))
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("Field '{field_name}' not found in 1Password item"))
    }

    fn list_items(vault: Option<&str>, account: Option<&str>) -> Result<Vec<serde_json::Value>> {
        let mut args = vec!["item", "list", "--format=json"];
        let vault_arg;
        if let Some(v) = vault {
            vault_arg = format!("--vault={v}");
            args.push(&vault_arg);
        }
        let list_json = Self::run_op(&args, account)?;
        serde_json::from_str(&list_json).context("Failed to parse 1Password item list JSON")
    }

    fn item_matches_text_field(item: &serde_json::Value, field_name: &str, expected: &str) -> bool {
        item.get("fields")
            .and_then(|fields| fields.as_array())
            .is_some_and(|fields| {
                fields.iter().any(|field| {
                    let label = field.get("label").and_then(|value| value.as_str());
                    label.is_some_and(|label| label.eq_ignore_ascii_case(field_name))
                        && field.get("value").and_then(|value| value.as_str()) == Some(expected)
                })
            })
    }

    /// Resolve a key when multiple items share the same name, by checking
    /// metadata custom fields in repository-first order.
    fn resolve_by_metadata(
        key: &str,
        repository: Option<&str>,
        project: Option<&str>,
        vault: Option<&str>,
        account: Option<&str>,
    ) -> Result<String> {
        let items = Self::list_items(vault, account)?;
        Self::resolve_by_metadata_from_list(key, &items, repository, project, vault, account)
    }

    fn resolve_by_metadata_from_list(
        key: &str,
        items: &[serde_json::Value],
        repository: Option<&str>,
        project: Option<&str>,
        vault: Option<&str>,
        account: Option<&str>,
    ) -> Result<String> {
        // Filter by items whose title matches the key
        let matching: Vec<&serde_json::Value> = items
            .iter()
            .filter(|item| item.get("title").and_then(|t| t.as_str()) == Some(key))
            .collect();

        if matching.is_empty() {
            bail!("No 1Password items found with title '{key}'");
        }

        if matching.len() == 1 {
            let id = matching[0]
                .get("id")
                .and_then(|i| i.as_str())
                .ok_or_else(|| anyhow::anyhow!("1Password item missing id"))?;
            return Self::get_item_field(id, "label=password", vault, account);
        }

        let mut candidates: Vec<(String, serde_json::Value)> = Vec::with_capacity(matching.len());
        for item_summary in matching {
            let id = item_summary
                .get("id")
                .and_then(|i| i.as_str())
                .ok_or_else(|| anyhow::anyhow!("1Password item missing id"))?;
            let full_json = Self::run_op(&["item", "get", id, "--format=json"], account)?;
            let full_item: serde_json::Value =
                serde_json::from_str(&full_json).context("Failed to parse op item get JSON")?;
            candidates.push((id.to_string(), full_item));
        }

        if let Some(repository) = repository {
            info!(
                "Found {} items named '{key}', disambiguating by repository '{repository}'",
                candidates.len()
            );
            let repository_filtered: Vec<(String, serde_json::Value)> = candidates
                .iter()
                .filter(|(_, item)| {
                    Self::item_matches_text_field(item, REPOSITORY_FIELD_NAME, repository)
                })
                .cloned()
                .collect();
            if !repository_filtered.is_empty() {
                candidates = repository_filtered;
            }
            if candidates.len() == 1 {
                debug!(
                    "Matched item '{}' by repository field '{repository}'",
                    candidates[0].0
                );
                return Self::get_item_field(&candidates[0].0, "label=password", vault, account);
            }
        }

        if let Some(project) = project {
            info!(
                "Found {} items named '{key}', disambiguating by project '{project}'",
                candidates.len()
            );
            let project_filtered: Vec<(String, serde_json::Value)> = candidates
                .iter()
                .filter(|(_, item)| {
                    Self::item_matches_text_field(item, PROJECT_FIELD_NAME, project)
                })
                .cloned()
                .collect();
            if !project_filtered.is_empty() {
                candidates = project_filtered;
            }
            if candidates.len() == 1 {
                debug!(
                    "Matched item '{}' by project field '{project}'",
                    candidates[0].0
                );
                return Self::get_item_field(&candidates[0].0, "label=password", vault, account);
            }
        }

        bail!(
            "Multiple 1Password items found for '{key}' but repository/project metadata did not disambiguate them"
        );
    }

    /// Resolve multiple key-only lookups while reusing the item data that can be shared.
    ///
    /// A configured item is fetched once and all requested fields are extracted locally. When
    /// keys map to individual items, one list call identifies missing keys before the remaining
    /// matching items are fetched.
    pub fn resolve_batch(keys: &[&str], ctx: &ResolveContext) -> BTreeMap<String, Result<String>> {
        let op_config = ctx.config.effective_op(ctx.dir);
        let vault = op_config.vault.as_deref();
        let account = op_config.account.as_deref();
        let mut results = BTreeMap::new();

        if let Some(item) = ctx.config.effective_item(ctx.dir) {
            match Self::get_item_json(item, vault, account) {
                Ok(item_json) => {
                    for key in keys {
                        results.insert(
                            (*key).to_string(),
                            Self::extract_field_from_value(&item_json, key),
                        );
                    }
                }
                Err(error) => {
                    let error = error.to_string();
                    for key in keys {
                        results.insert(
                            (*key).to_string(),
                            Err(anyhow::anyhow!(
                                "Failed to fetch 1Password item '{item}': {error}"
                            )),
                        );
                    }
                }
            }
            return results;
        }

        let items = match Self::list_items(vault, account) {
            Ok(items) => items,
            Err(error) => {
                let error = error.to_string();
                for key in keys {
                    results.insert(
                        (*key).to_string(),
                        Err(anyhow::anyhow!("Failed to list 1Password items: {error}")),
                    );
                }
                return results;
            }
        };

        for key in keys {
            let matching: Vec<&serde_json::Value> = items
                .iter()
                .filter(|item| item.get("title").and_then(|title| title.as_str()) == Some(key))
                .collect();

            let result = if matching.is_empty() {
                Err(anyhow::anyhow!(
                    "No 1Password items found with title '{key}'"
                ))
            } else if matching.len() == 1 {
                let item_id = matching[0]
                    .get("id")
                    .and_then(|id| id.as_str())
                    .ok_or_else(|| anyhow::anyhow!("1Password item missing id"));
                match item_id {
                    Ok(item_id) => Self::get_item_field(item_id, "label=password", vault, account),
                    Err(error) => Err(error),
                }
            } else if ctx.repository.is_some() || ctx.project.is_some() {
                Self::resolve_by_metadata_from_list(
                    key,
                    &items,
                    ctx.repository.as_deref(),
                    ctx.project.as_deref(),
                    vault,
                    account,
                )
            } else {
                Err(anyhow::anyhow!(
                    "Multiple 1Password items found for '{key}' but repository/project metadata did not disambiguate them"
                ))
            };

            results.insert((*key).to_string(), result);
        }

        results
    }
}

impl Backend for OpBackend {
    fn resolve(&self, key: &str, reference: Option<&str>, ctx: &ResolveContext) -> Result<String> {
        let op_config = ctx.config.effective_op(ctx.dir);
        let account = op_config.account.as_deref();

        if let Some(ref_str) = reference {
            // Direct op:// reference
            if ref_str.starts_with("op://") {
                debug!("Resolving 1Password reference: {ref_str}");
                return Self::run_op(&["read", ref_str], account);
            }
        }

        // Key-based lookup: look up as a field on the configured item, or as an item name
        if let Some(item) = ctx.config.effective_item(ctx.dir) {
            debug!("Resolving key '{key}' as field on item '{item}'");
            let label_arg = format!("label={key}");
            Self::get_item_field(
                item,
                label_arg.as_str(),
                op_config.vault.as_deref(),
                account,
            )
        } else if let Some(ref vault) = op_config.vault {
            // Search for an item named after the key in the configured vault
            debug!("Resolving key '{key}' as item in vault '{vault}'");
            let result = Self::get_item_field(key, "label=password", Some(vault), account);
            match result {
                Ok(value) => Ok(value),
                Err(e) if format!("{e}").to_lowercase().contains("more than 1 item") => {
                    if ctx.repository.is_some() || ctx.project.is_some() {
                        debug!(
                            "Multiple items match '{key}', disambiguating by repository/project metadata"
                        );
                        Self::resolve_by_metadata(
                            key,
                            ctx.repository.as_deref(),
                            ctx.project.as_deref(),
                            Some(vault),
                            account,
                        )
                    } else {
                        Err(e)
                    }
                }
                Err(e) => Err(e),
            }
        } else {
            debug!("Resolving key '{key}' as item (no vault configured)");
            let result = Self::get_item_field(key, "label=password", None, account);
            match result {
                Ok(value) => Ok(value),
                Err(e) if format!("{e}").to_lowercase().contains("more than 1 item") => {
                    if ctx.repository.is_some() || ctx.project.is_some() {
                        debug!(
                            "Multiple items match '{key}', disambiguating by repository/project metadata"
                        );
                        Self::resolve_by_metadata(
                            key,
                            ctx.repository.as_deref(),
                            ctx.project.as_deref(),
                            None,
                            account,
                        )
                    } else {
                        Err(e)
                    }
                }
                Err(e) => Err(e),
            }
        }
    }

    fn store(&self, key: &str, value: &str, ctx: &StoreContext) -> Result<()> {
        let op_config = ctx.config.effective_op(ctx.dir);
        let account = op_config.account.as_deref();
        let metadata_fields = Self::migration_fields(ctx);
        let vault_arg = op_config
            .vault
            .as_ref()
            .map(|vault| format!("--vault={vault}"));

        if let Some(item) = ctx.config.effective_item(ctx.dir) {
            // Try to edit the existing item first, preserving its supported fields.
            debug!("Storing key '{key}' as field on item '{item}'");
            if let Ok(mut item_json) =
                Self::get_item_json(item, op_config.vault.as_deref(), account)
            {
                if Self::contains_passkey(&item_json) {
                    bail!(
                        "Cannot update 1Password item '{item}' because JSON templates do not support passkeys"
                    );
                }

                Self::upsert_json_field(&mut item_json, key, value, "CONCEALED")?;
                for field in &metadata_fields {
                    let label = field
                        .get("label")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| anyhow::anyhow!("1Password metadata field has no label"))?;
                    let field_value = field
                        .get("value")
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| anyhow::anyhow!("1Password metadata field has no value"))?;
                    Self::upsert_json_field(&mut item_json, label, field_value, "STRING")?;
                }

                let mut args = vec!["item", "edit", item];
                if let Some(vault_arg) = vault_arg.as_deref() {
                    args.push(vault_arg);
                }
                if Self::run_op_write(&args, &item_json, account).is_ok() {
                    return Ok(());
                }
            }
            warn!("Failed to edit item '{item}', trying to create new item");
        }

        // Create a new item with the key as the item name.
        let mut fields = vec![serde_json::json!({
            "id": "password",
            "type": "CONCEALED",
            "purpose": "PASSWORD",
            "label": "password",
            "value": value
        })];
        fields.extend(metadata_fields);
        let payload = serde_json::json!({
            "category": "LOGIN",
            "title": key,
            "fields": fields
        });
        let mut args = vec!["item", "create"];
        if let Some(vault_arg) = vault_arg.as_deref() {
            args.push(vault_arg);
        }
        args.push("-");
        Self::run_op_write(&args, &payload, account)?;
        Ok(())
    }

    fn has(&self, key: &str, ctx: &ResolveContext) -> Result<bool> {
        match self.resolve(key, None, ctx) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn reference_url(&self, key: &str, ctx: &StoreContext) -> Option<String> {
        let op_config = ctx.config.effective_op(ctx.dir);
        let vault = op_config.vault.as_deref()?;
        if let Some(item) = ctx.config.effective_item(ctx.dir) {
            Some(format!("op://{vault}/{item}/{key}"))
        } else {
            Some(format!("op://{vault}/{key}/password"))
        }
    }

    fn name(&self) -> &str {
        "1Password"
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::config::{Config, Defaults, LogConfig, UpdateConfig};
    use std::path::Path;

    #[test]
    fn migration_fields_include_required_metadata() {
        let config = Config {
            defaults: Defaults::default(),
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };
        let ctx = StoreContext {
            dir: Path::new("/work/project"),
            config: &config,
            project: Some("my-project".to_string()),
            repository: Some("my-repository".to_string()),
        };

        let fields = OpBackend::migration_fields(&ctx);

        assert_eq!(fields.len(), 4);
        assert!(fields.iter().any(|field| {
            field["label"] == MIGRATED_FROM_FIELD_NAME && field["value"] == "/work/project"
        }));
        assert!(fields.iter().any(|field| {
            field["label"] == CREATED_WITH_FIELD_NAME
                && field["value"] == format!("pw-env ({})", env!("CARGO_PKG_VERSION"))
        }));
        assert!(fields.iter().any(|field| {
            field["label"] == PROJECT_FIELD_NAME && field["value"] == "my-project"
        }));
        assert!(fields.iter().any(|field| {
            field["label"] == REPOSITORY_FIELD_NAME && field["value"] == "my-repository"
        }));
    }

    #[test]
    fn upsert_json_field_updates_a_field_matching_by_label_or_id() {
        let mut item = serde_json::json!({
            "fields": [
                {"label": "label-only", "value": "old-label"},
                {"id": "id-only", "value": "old-id"}
            ]
        });

        OpBackend::upsert_json_field(&mut item, "label-only", "new-label", "STRING").unwrap();
        OpBackend::upsert_json_field(&mut item, "id-only", "new-id", "STRING").unwrap();

        assert_eq!(item["fields"].as_array().unwrap().len(), 2);
        assert_eq!(item["fields"][0]["value"], "new-label");
        assert_eq!(item["fields"][1]["value"], "new-id");
    }

    #[test]
    fn contains_passkey_checks_array_and_string_values() {
        assert!(OpBackend::contains_passkey(&serde_json::json!([
            "not-a-passkey",
            "PassKey"
        ])));
        assert!(OpBackend::contains_passkey(&serde_json::json!("passkey")));
        assert!(!OpBackend::contains_passkey(&serde_json::json!("password")));
    }

    #[test]
    fn test_text_field_assignment_format() {
        let result = OpBackend::text_field_assignment("api_key", "myvalue");
        assert_eq!(result, "api_key[text]=myvalue");
    }

    #[test]
    fn test_migration_field_assignments_with_project() {
        let config = Config {
            defaults: Defaults::default(),
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };
        let ctx = StoreContext {
            dir: Path::new("/work/project"),
            config: &config,
            project: Some("my-project".to_string()),
            repository: None,
        };
        let assignments = OpBackend::migration_field_assignments(&ctx);
        assert!(assignments.contains(&"migrated_from[text]=/work/project".to_string()));
        assert!(assignments.contains(&format!(
            "created-with[text]=pw-env ({})",
            env!("CARGO_PKG_VERSION")
        )));
        assert!(assignments.contains(&"project[text]=my-project".to_string()));
    }

    #[test]
    fn test_migration_field_assignments_without_project() {
        let config = Config {
            defaults: Defaults::default(),
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };
        let ctx = StoreContext {
            dir: Path::new("/work/project"),
            config: &config,
            project: None,
            repository: None,
        };
        let assignments = OpBackend::migration_field_assignments(&ctx);
        assert!(assignments.contains(&"migrated_from[text]=/work/project".to_string()));
        assert!(assignments.contains(&format!(
            "created-with[text]=pw-env ({})",
            env!("CARGO_PKG_VERSION")
        )));
        assert_eq!(assignments.len(), 2);
    }

    #[test]
    fn test_migration_field_assignments_include_project_and_source_dir() {
        let config = Config {
            defaults: Defaults::default(),
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };
        let ctx = StoreContext {
            dir: Path::new("/tmp/example/service"),
            config: &config,
            project: Some("example".to_string()),
            repository: Some("git@github.com:example/example.git".to_string()),
        };

        let assignments = OpBackend::migration_field_assignments(&ctx);

        assert!(assignments.contains(&"migrated_from[text]=/tmp/example/service".to_string()));
        assert!(assignments.contains(&format!(
            "created-with[text]=pw-env ({})",
            env!("CARGO_PKG_VERSION")
        )));
        assert!(assignments.contains(&"project[text]=example".to_string()));
        assert!(
            assignments
                .contains(&"repository[text]=git@github.com:example/example.git".to_string())
        );
    }

    // ------- Mock-op infrastructure -------

    fn with_mock_op<F: FnOnce()>(script: &str, f: F) {
        let _guard = super::super::MOCK_PATH_MUTEX
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::TempDir::new().unwrap();
        let script_path = dir.path().join("op");
        std::fs::write(&script_path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_path, perms).unwrap();
        }
        let old_path = std::env::var_os("PATH").unwrap_or_default();
        let new_path = std::env::join_paths(
            std::iter::once(dir.path().to_path_buf()).chain(std::env::split_paths(&old_path)),
        )
        .unwrap();
        // SAFETY: guarded by MOCK_PATH_MUTEX, single-threaded access to PATH
        unsafe { std::env::set_var("PATH", &new_path) };
        f();
        unsafe { std::env::set_var("PATH", &old_path) };
    }

    fn make_op_resolve_context<'a>(
        config: &'a Config,
        dir: &'a Path,
    ) -> super::super::ResolveContext<'a> {
        super::super::ResolveContext {
            dir,
            config,
            project: Some("test-project".to_string()),
            repository: Some("git@github.com:example/test-repo.git".to_string()),
            interaction: None,
        }
    }

    #[test]
    fn backend_store_creates_password_field_for_new_item() {
        with_mock_op(
            "#!/bin/sh\nif [ \"$1\" = \"item\" ] && [ \"$2\" = \"create\" ]; then\n  payload=$(cat)\n  case \"$payload\" in\n    *CONCEALED*super-secret*) exit 0 ;;\n  esac\nfi\necho 'missing concealed password field' >&2\nexit 1\n",
            || {
                let config = Config {
                    defaults: Defaults::default(),
                    log: LogConfig::default(),
                    updates: UpdateConfig::default(),
                    projects: vec![],
                };
                let dir = Path::new("/tmp");
                let ctx = StoreContext {
                    dir,
                    config: &config,
                    project: None,
                    repository: None,
                };
                let backend = OpBackend;
                assert!(backend.store("MY_KEY", "super-secret", &ctx).is_ok());
            },
        );
    }

    #[test]
    fn backend_store_creation_sends_secret_only_in_json_stdin() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let argv_log = temp_dir.path().join("argv.log");
        let stdin_log = temp_dir.path().join("stdin.json");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\ncat > '{}'\nexit 0\n",
            argv_log.display(),
            stdin_log.display()
        );
        let secret = "line one 'quote' \\ path\nfield=value";

        with_mock_op(&script, || {
            let config = Config {
                defaults: Defaults {
                    op: crate::config::OpConfig {
                        vault: Some("WorkVault".to_string()),
                        account: Some("work@example.com".to_string()),
                        ..Default::default()
                    },
                    ..Defaults::default()
                },
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = StoreContext {
                dir: Path::new("/tmp"),
                config: &config,
                project: None,
                repository: None,
            };
            OpBackend.store("API_KEY", secret, &ctx).unwrap();
        });

        let argv = std::fs::read_to_string(&argv_log).unwrap();
        assert!(!argv.contains("line one"));
        assert!(argv.lines().any(|line| line == "--vault=WorkVault"));
        assert!(argv.lines().any(|line| line == "--account"));
        let payload: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&stdin_log).unwrap()).unwrap();
        let password_field = payload["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|field| field["label"] == "password")
            .unwrap();
        assert_eq!(password_field["type"], "CONCEALED");
        assert_eq!(password_field["value"], secret);
    }

    #[test]
    fn backend_store_edit_preserves_existing_fields_and_keeps_secret_out_of_argv() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let argv_log = temp_dir.path().join("argv.log");
        let stdin_log = temp_dir.path().join("stdin.json");
        let script = format!(
            "#!/bin/sh\nif [ \"$1\" = \"item\" ] && [ \"$2\" = \"get\" ]; then\n  printf '%s\\n' '{{\"category\":\"LOGIN\",\"title\":\"Existing\",\"fields\":[{{\"id\":\"username\",\"type\":\"STRING\",\"label\":\"username\",\"value\":\"keep-me\"}}],\"sections\":[{{\"id\":\"custom\",\"title\":\"Keep me\",\"fields\":[]}}]}}'\n  exit 0\nfi\nprintf '%s\\n' \"$@\" > '{}'\ncat > '{}'\nexit 0\n",
            argv_log.display(),
            stdin_log.display()
        );
        let secret = "edit secret with spaces = quotes ' and \\slashes\\";

        let config = Config {
            defaults: Defaults {
                op: crate::config::OpConfig {
                    item: Some("Existing".to_string()),
                    vault: Some("WorkVault".to_string()),
                    ..Default::default()
                },
                ..Defaults::default()
            },
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };
        let ctx = StoreContext {
            dir: Path::new("/tmp"),
            config: &config,
            project: None,
            repository: None,
        };
        with_mock_op(&script, || {
            OpBackend.store("API_KEY", secret, &ctx).unwrap();
        });

        let argv = std::fs::read_to_string(&argv_log).unwrap();
        assert!(!argv.contains("edit secret"));
        assert!(argv.lines().any(|line| line == "item"));
        let payload: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&stdin_log).unwrap()).unwrap();
        assert_eq!(payload["sections"][0]["title"], "Keep me");
        let api_field = payload["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|field| field["label"] == "API_KEY")
            .unwrap();
        assert_eq!(api_field["value"], secret);
        assert_eq!(payload["fields"][0]["value"], "keep-me");
    }

    #[test]
    fn backend_store_rejects_existing_passkey_items() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let marker = temp_dir.path().join("write-attempted");
        let script = format!(
            "#!/bin/sh\nif [ \"$1\" = \"item\" ] && [ \"$2\" = \"get\" ]; then\n  echo '{{\"category\":\"LOGIN\",\"passkey\":{{\"credentialId\":\"id\"}},\"fields\":[]}}'\n  exit 0\nfi\ntouch '{}'\nexit 0\n",
            marker.display()
        );
        let config = Config {
            defaults: Defaults {
                op: crate::config::OpConfig {
                    item: Some("Passkey item".to_string()),
                    ..Default::default()
                },
                ..Defaults::default()
            },
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };
        let ctx = StoreContext {
            dir: Path::new("/tmp"),
            config: &config,
            project: None,
            repository: None,
        };
        with_mock_op(&script, || {
            let error = OpBackend
                .store("API_KEY", "secret", &ctx)
                .expect_err("passkey item updates must be rejected");
            assert!(error.to_string().contains("passkeys"));
        });
        assert!(!marker.exists());
    }

    #[test]
    fn backend_store_does_not_return_secret_from_write_stderr() {
        let secret = "stderr synthetic secret";
        let script = format!("#!/bin/sh\necho '{}' >&2\nexit 1\n", secret);
        let config = Config {
            defaults: Defaults::default(),
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };
        let ctx = StoreContext {
            dir: Path::new("/tmp"),
            config: &config,
            project: None,
            repository: None,
        };
        with_mock_op(&script, || {
            let error = OpBackend
                .store("API_KEY", secret, &ctx)
                .expect_err("a failed OP write must return an error");
            assert!(!error.to_string().contains(secret));
            assert_eq!(error.to_string(), "1Password item write failed");
        });
    }

    #[test]
    fn run_op_returns_stdout_on_success() {
        with_mock_op("#!/bin/sh\necho 'op-value'\n", || {
            let result = OpBackend::run_op(&["any", "arg"], None);
            assert_eq!(result.unwrap(), "op-value");
        });
    }

    #[test]
    fn run_op_returns_err_on_non_zero_exit() {
        with_mock_op("#!/bin/sh\necho 'error' >&2\nexit 1\n", || {
            let result = OpBackend::run_op(&["any", "arg"], None);
            assert!(result.is_err());
        });
    }

    #[test]
    fn backend_resolve_with_op_reference() {
        with_mock_op("#!/bin/sh\necho 'op-secret'\n", || {
            let config = Config {
                defaults: Defaults::default(),
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let dir = Path::new("/tmp");
            let ctx = make_op_resolve_context(&config, dir);
            let backend = OpBackend;
            let result = backend.resolve("API_KEY", Some("op://vault/item/field"), &ctx);
            assert_eq!(result.unwrap(), "op-secret");
        });
    }

    #[test]
    fn backend_has_returns_true_when_resolve_succeeds() {
        with_mock_op("#!/bin/sh\necho 'some-value'\n", || {
            let config = Config {
                defaults: Defaults::default(),
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let dir = Path::new("/tmp");
            let ctx = make_op_resolve_context(&config, dir);
            let backend = OpBackend;
            assert_eq!(backend.has("MY_KEY", &ctx).unwrap(), true);
        });
    }

    #[test]
    fn backend_has_returns_false_when_resolve_fails() {
        with_mock_op("#!/bin/sh\necho 'error' >&2\nexit 1\n", || {
            let config = Config {
                defaults: Defaults::default(),
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let dir = Path::new("/tmp");
            let ctx = make_op_resolve_context(&config, dir);
            let backend = OpBackend;
            assert_eq!(backend.has("MY_KEY", &ctx).unwrap(), false);
        });
    }

    #[test]
    fn backend_name_is_1password() {
        assert_eq!(OpBackend.name(), "1Password");
    }

    #[test]
    fn run_op_with_account_argument() {
        with_mock_op("#!/bin/sh\necho 'acct-value'\n", || {
            let result = OpBackend::run_op(&["item", "get", "test"], Some("my-account"));
            assert_eq!(result.unwrap(), "acct-value");
        });
    }

    #[test]
    fn get_item_field_with_vault_arg() {
        with_mock_op("#!/bin/sh\necho 'vault-secret'\n", || {
            let result =
                OpBackend::get_item_field("my-item", "label=password", Some("MyVault"), None);
            assert_eq!(result.unwrap(), "vault-secret");
        });
    }

    #[test]
    fn backend_resolve_with_item_configured() {
        with_mock_op("#!/bin/sh\necho 'item-field-value'\n", || {
            let config = Config {
                defaults: Defaults {
                    op: crate::config::OpConfig {
                        item: Some("my-op-item".to_string()),
                        ..Default::default()
                    },
                    ..Defaults::default()
                },
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = make_op_resolve_context(&config, Path::new("/tmp"));
            let result = OpBackend.resolve("MY_KEY", None, &ctx);
            assert_eq!(result.unwrap(), "item-field-value");
        });
    }

    #[test]
    fn backend_resolve_with_vault_configured() {
        with_mock_op("#!/bin/sh\necho 'vault-item-value'\n", || {
            let config = Config {
                defaults: Defaults {
                    op: crate::config::OpConfig {
                        vault: Some("MyVault".to_string()),
                        ..Default::default()
                    },
                    ..Defaults::default()
                },
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = make_op_resolve_context(&config, Path::new("/tmp"));
            let result = OpBackend.resolve("MY_KEY", None, &ctx);
            assert_eq!(result.unwrap(), "vault-item-value");
        });
    }

    #[test]
    fn backend_resolve_with_vault_disambiguates_by_project_single_match() {
        // First call: op item get MY_KEY --fields ... → "more than 1 item found" (triggers disambiguation)
        // Second call: op item list → single-item list
        // Third call: op item get abc123 --fields ... (by id) → "resolved-value"
        let script = "#!/bin/sh\nif [ \"$2\" = \"get\" ] && [ \"$3\" = \"MY_KEY\" ]; then\necho 'more than 1 item found' >&2\nexit 1\nfi\nif [ \"$2\" = \"list\" ]; then\necho '[{\"id\":\"abc123\",\"title\":\"MY_KEY\"}]'\nexit 0\nfi\necho 'resolved-value'\n";
        with_mock_op(script, || {
            let config = Config {
                defaults: Defaults {
                    op: crate::config::OpConfig {
                        vault: Some("MyVault".to_string()),
                        ..Default::default()
                    },
                    ..Defaults::default()
                },
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = make_op_resolve_context(&config, Path::new("/tmp"));
            let result = OpBackend.resolve("MY_KEY", None, &ctx);
            assert_eq!(result.unwrap(), "resolved-value");
        });
    }

    #[test]
    fn backend_resolve_with_vault_disambiguates_by_repository_before_project() {
        let script = "#!/bin/sh\nif [ \"$2\" = \"get\" ] && [ \"$3\" = \"MY_KEY\" ]; then\necho 'more than 1 item found' >&2\nexit 1\nfi\nif [ \"$2\" = \"list\" ]; then\necho '[{\"id\":\"repo-item\",\"title\":\"MY_KEY\"},{\"id\":\"project-item\",\"title\":\"MY_KEY\"}]'\nexit 0\nfi\nif [ \"$2\" = \"get\" ] && [ \"$3\" = \"repo-item\" ] && [ \"$4\" = \"--format=json\" ]; then\necho '{\"id\":\"repo-item\",\"fields\":[{\"label\":\"repository\",\"value\":\"git@github.com:example/test-repo.git\"},{\"label\":\"project\",\"value\":\"other-project\"}]}'\nexit 0\nfi\nif [ \"$2\" = \"get\" ] && [ \"$3\" = \"project-item\" ] && [ \"$4\" = \"--format=json\" ]; then\necho '{\"id\":\"project-item\",\"fields\":[{\"label\":\"repository\",\"value\":\"git@github.com:example/other-repo.git\"},{\"label\":\"project\",\"value\":\"test-project\"}]}'\nexit 0\nfi\nif [ \"$2\" = \"get\" ] && [ \"$3\" = \"repo-item\" ]; then\necho 'repo-wins'\nexit 0\nfi\nif [ \"$2\" = \"get\" ] && [ \"$3\" = \"project-item\" ]; then\necho 'project-would-win'\nexit 0\nfi\necho 'unexpected command' >&2\nexit 1\n";

        with_mock_op(script, || {
            let config = Config {
                defaults: Defaults {
                    op: crate::config::OpConfig {
                        vault: Some("MyVault".to_string()),
                        ..Default::default()
                    },
                    ..Defaults::default()
                },
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = make_op_resolve_context(&config, Path::new("/tmp"));
            let result = OpBackend.resolve("MY_KEY", None, &ctx);
            assert_eq!(result.unwrap(), "repo-wins");
        });
    }

    #[test]
    fn backend_resolve_no_item_no_vault() {
        with_mock_op("#!/bin/sh\necho 'no-vault-value'\n", || {
            let config = Config {
                defaults: Defaults::default(), // no item, no vault
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = make_op_resolve_context(&config, Path::new("/tmp"));
            let result = OpBackend.resolve("MY_KEY", None, &ctx);
            assert_eq!(result.unwrap(), "no-vault-value");
        });
    }

    #[test]
    fn backend_store_with_item_configured_succeeds() {
        with_mock_op(
            "#!/bin/sh\nif [ \"$1\" = \"item\" ] && [ \"$2\" = \"get\" ]; then\n  echo '{\"category\":\"LOGIN\",\"title\":\"my-op-item\",\"fields\":[]}'\n  exit 0\nfi\nif [ \"$1\" = \"item\" ] && [ \"$2\" = \"edit\" ]; then\n  cat >/dev/null\n  exit 0\nfi\nexit 1\n",
            || {
                let config = Config {
                    defaults: Defaults {
                        op: crate::config::OpConfig {
                            item: Some("my-op-item".to_string()),
                            ..Default::default()
                        },
                        ..Defaults::default()
                    },
                    log: LogConfig::default(),
                    updates: UpdateConfig::default(),
                    projects: vec![],
                };
                let ctx = StoreContext {
                    dir: Path::new("/tmp"),
                    config: &config,
                    project: None,
                    repository: None,
                };
                let result = OpBackend.store("MY_KEY", "my-value", &ctx);
                assert!(result.is_ok(), "expected Ok, got: {:?}", result);
            },
        );
    }

    #[test]
    fn backend_store_with_item_configured_includes_vault_arg() {
        let script = "#!/bin/sh\nif [ \"$1\" = \"item\" ] && [ \"$2\" = \"get\" ]; then\n  echo '{\"category\":\"LOGIN\",\"title\":\"my-op-item\",\"fields\":[]}'\n  exit 0\nfi\nif [ \"$1\" = \"item\" ] && [ \"$2\" = \"edit\" ]; then\n  for arg in \"$@\"; do\n    if [ \"$arg\" = \"--vault=WorkVault\" ]; then\n      cat >/dev/null\n      exit 0\n    fi\n  done\n  echo 'missing vault arg' >&2\n  exit 1\nfi\necho 'unexpected command' >&2\nexit 1\n";

        with_mock_op(script, || {
            let config = Config {
                defaults: Defaults {
                    op: crate::config::OpConfig {
                        item: Some("my-op-item".to_string()),
                        vault: Some("WorkVault".to_string()),
                        ..Default::default()
                    },
                    ..Defaults::default()
                },
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = StoreContext {
                dir: Path::new("/tmp"),
                config: &config,
                project: None,
                repository: None,
            };

            let result = OpBackend.store("MY_KEY", "my-value", &ctx);
            assert!(result.is_ok(), "expected Ok, got: {:?}", result);
        });
    }

    #[test]
    fn backend_store_creates_new_item_when_no_item_config() {
        with_mock_op("#!/bin/sh\necho 'created'\n", || {
            let config = Config {
                defaults: Defaults::default(), // no item configured
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = StoreContext {
                dir: Path::new("/tmp"),
                config: &config,
                project: None,
                repository: None,
            };
            let result = OpBackend.store("NEW_KEY", "new-value", &ctx);
            assert!(result.is_ok(), "expected Ok, got: {:?}", result);
        });
    }

    #[test]
    fn get_item_field_calls_run_op_with_item_args() {
        with_mock_op("#!/bin/sh\necho 'field-value'\n", || {
            let result = OpBackend::get_item_field("my-item", "label=password", None, None);
            assert_eq!(result.unwrap(), "field-value");
        });
    }

    #[test]
    fn resolve_batch_rejects_multiple_items_without_metadata() {
        let script = "#!/bin/sh\nif [ \"$2\" = \"list\" ]; then\n  echo '[{\"id\":\"item-a\",\"title\":\"MY_KEY\"},{\"id\":\"item-b\",\"title\":\"MY_KEY\"}]'\n  exit 0\nfi\necho 'unexpected item fetch' >&2\nexit 1\n";
        with_mock_op(script, || {
            let config = Config {
                defaults: Defaults::default(),
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = super::super::ResolveContext {
                dir: Path::new("/tmp"),
                config: &config,
                project: None,
                repository: None,
                interaction: None,
            };
            let mut results = OpBackend::resolve_batch(&["MY_KEY"], &ctx);
            let result = results.remove("MY_KEY").expect("batch result should exist");
            let error = result.expect_err("duplicate items without metadata should fail");
            assert_eq!(
                error.to_string(),
                "Multiple 1Password items found for 'MY_KEY' but repository/project metadata did not disambiguate them"
            );
        });
    }

    #[test]
    fn resolve_batch_disambiguates_with_repository_only() {
        let script = "#!/bin/sh\nif [ \"$2\" = \"list\" ]; then\n  echo '[{\"id\":\"other-item\",\"title\":\"MY_KEY\"},{\"id\":\"repo-item\",\"title\":\"MY_KEY\"}]'\n  exit 0\nfi\nif [ \"$2\" = \"get\" ] && [ \"$4\" = \"--format=json\" ]; then\n  case \"$3\" in\n    other-item) echo '{\"id\":\"other-item\",\"fields\":[{\"label\":\"repository\",\"value\":\"other-repo\"}]}' ;;\n    repo-item) echo '{\"id\":\"repo-item\",\"fields\":[{\"label\":\"repository\",\"value\":\"test-repo\"}]}' ;;\n    *) exit 1 ;;\n  esac\n  exit 0\nfi\nif [ \"$2\" = \"get\" ] && [ \"$4\" = \"--fields\" ] && [ \"$3\" = \"repo-item\" ]; then\n  echo 'repository-password'\n  exit 0\nfi\necho 'unexpected command' >&2\nexit 1\n";
        with_mock_op(script, || {
            let config = Config {
                defaults: Defaults::default(),
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = super::super::ResolveContext {
                dir: Path::new("/tmp"),
                config: &config,
                project: None,
                repository: Some("test-repo".to_string()),
                interaction: None,
            };
            let mut results = OpBackend::resolve_batch(&["MY_KEY"], &ctx);
            let result = results.remove("MY_KEY").expect("batch result should exist");
            assert_eq!(result.unwrap(), "repository-password");
        });
    }

    // Kills mutants: 147 (== → !=), 168 (delete !), 171 (== → !=) in resolve_by_metadata.
    //
    // 3 items share the title "MY_KEY":
    //   item-a: repo=test-repo, project=other-project
    //   item-b: repo=test-repo, project=test-project  ← correct answer
    //   item-c: repo=other-repo, project=test-project
    //
    // Repository filter narrows to [item-a, item-b] (len=2, so no early return at line 147).
    // Project filter narrows to [item-b] (len=1, returns b-password at line 171).
    #[test]
    fn resolve_by_metadata_narrows_by_repo_then_project() {
        let script = "#!/bin/sh\n\
            if [ \"$2\" = \"list\" ]; then\n\
              echo '[{\"id\":\"item-a\",\"title\":\"MY_KEY\"},{\"id\":\"item-b\",\"title\":\"MY_KEY\"},{\"id\":\"item-c\",\"title\":\"MY_KEY\"}]'\n\
              exit 0\n\
            fi\n\
            if [ \"$2\" = \"get\" ] && [ \"$4\" = \"--format=json\" ]; then\n\
              case \"$3\" in\n\
                item-a) echo '{\"id\":\"item-a\",\"fields\":[{\"label\":\"repository\",\"value\":\"test-repo\"},{\"label\":\"project\",\"value\":\"other-project\"}]}' ;;\n\
                item-b) echo '{\"id\":\"item-b\",\"fields\":[{\"label\":\"repository\",\"value\":\"test-repo\"},{\"label\":\"project\",\"value\":\"test-project\"}]}' ;;\n\
                item-c) echo '{\"id\":\"item-c\",\"fields\":[{\"label\":\"repository\",\"value\":\"other-repo\"},{\"label\":\"project\",\"value\":\"test-project\"}]}' ;;\n\
                *) echo 'unknown item' >&2; exit 1 ;;\n\
              esac\n\
              exit 0\n\
            fi\n\
            if [ \"$2\" = \"get\" ] && [ \"$4\" = \"--fields\" ]; then\n\
              case \"$3\" in\n\
                item-a) echo 'a-password' ;;\n\
                item-b) echo 'b-password' ;;\n\
                item-c) echo 'c-password' ;;\n\
                *) echo 'unknown item' >&2; exit 1 ;;\n\
              esac\n\
              exit 0\n\
            fi\n\
            echo 'unexpected command' >&2\n\
            exit 1\n";
        with_mock_op(script, || {
            let result = OpBackend::resolve_by_metadata(
                "MY_KEY",
                Some("test-repo"),
                Some("test-project"),
                None,
                None,
            );
            assert_eq!(result.unwrap(), "b-password");
        });
    }

    // Kills mutant 215: match guard `contains("more than 1 item")` replaced with `true`.
    // A non-"more than 1 item" error must be returned directly, not trigger disambiguation.
    #[test]
    fn backend_resolve_with_vault_non_multiple_item_error_propagated() {
        let script = "#!/bin/sh\n\
            if [ \"$2\" = \"get\" ] && [ \"$3\" = \"MY_KEY\" ]; then\n\
              echo 'item not found' >&2\n\
              exit 1\n\
            fi\n\
            if [ \"$2\" = \"list\" ]; then\n\
              echo '[{\"id\":\"abc\",\"title\":\"MY_KEY\"}]'\n\
              exit 0\n\
            fi\n\
            echo 'found-via-disambiguation'\n";
        with_mock_op(script, || {
            let config = Config {
                defaults: Defaults {
                    op: crate::config::OpConfig {
                        vault: Some("MyVault".to_string()),
                        ..Default::default()
                    },
                    ..Defaults::default()
                },
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = make_op_resolve_context(&config, Path::new("/tmp"));
            let result = OpBackend.resolve("MY_KEY", None, &ctx);
            let err = result.unwrap_err();
            assert!(
                format!("{err}").to_lowercase().contains("item not found"),
                "unexpected error: {err}"
            );
        });
    }

    // Kills mutant 216: `||` replaced with `&&` in the vault branch.
    // Disambiguation must trigger when only repository is set (project is None).
    #[test]
    fn backend_resolve_with_vault_disambiguates_when_only_repository_set() {
        let script = "#!/bin/sh\n\
            if [ \"$2\" = \"get\" ] && [ \"$3\" = \"MY_KEY\" ]; then\n\
              echo 'more than 1 item found' >&2\n\
              exit 1\n\
            fi\n\
            if [ \"$2\" = \"list\" ]; then\n\
              echo '[{\"id\":\"abc\",\"title\":\"MY_KEY\"}]'\n\
              exit 0\n\
            fi\n\
            echo 'resolved-value'\n";
        with_mock_op(script, || {
            let config = Config {
                defaults: Defaults {
                    op: crate::config::OpConfig {
                        vault: Some("MyVault".to_string()),
                        ..Default::default()
                    },
                    ..Defaults::default()
                },
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = super::super::ResolveContext {
                dir: Path::new("/tmp"),
                config: &config,
                project: None,
                repository: Some("git@github.com:example/test-repo.git".to_string()),
                interaction: None,
            };
            let result = OpBackend.resolve("MY_KEY", None, &ctx);
            assert_eq!(result.unwrap(), "resolved-value");
        });
    }

    // Kills mutant 238→false: match guard replaced with `false` in no-vault branch.
    // A "more than 1 item" error with context set must trigger disambiguation.
    #[test]
    fn backend_resolve_no_vault_disambiguates_on_multiple_items() {
        let script = "#!/bin/sh\n\
            if [ \"$2\" = \"get\" ] && [ \"$3\" = \"MY_KEY\" ]; then\n\
              echo 'more than 1 item found' >&2\n\
              exit 1\n\
            fi\n\
            if [ \"$2\" = \"list\" ]; then\n\
              echo '[{\"id\":\"abc\",\"title\":\"MY_KEY\"}]'\n\
              exit 0\n\
            fi\n\
            echo 'resolved-value'\n";
        with_mock_op(script, || {
            let config = Config {
                defaults: Defaults::default(),
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = make_op_resolve_context(&config, Path::new("/tmp"));
            let result = OpBackend.resolve("MY_KEY", None, &ctx);
            assert_eq!(result.unwrap(), "resolved-value");
        });
    }

    // Kills mutant 238→true: match guard replaced with `true` in no-vault branch.
    // A non-"more than 1 item" error must be returned directly, not trigger disambiguation.
    #[test]
    fn backend_resolve_no_vault_non_multiple_item_error_propagated() {
        let script = "#!/bin/sh\n\
            if [ \"$2\" = \"get\" ] && [ \"$3\" = \"MY_KEY\" ]; then\n\
              echo 'some other error' >&2\n\
              exit 1\n\
            fi\n\
            if [ \"$2\" = \"list\" ]; then\n\
              echo '[{\"id\":\"abc\",\"title\":\"MY_KEY\"}]'\n\
              exit 0\n\
            fi\n\
            echo 'found-via-disambiguation'\n";
        with_mock_op(script, || {
            let config = Config {
                defaults: Defaults::default(),
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = make_op_resolve_context(&config, Path::new("/tmp"));
            let result = OpBackend.resolve("MY_KEY", None, &ctx);
            let err = result.unwrap_err();
            assert!(
                format!("{err}").to_lowercase().contains("some other error"),
                "unexpected error: {err}"
            );
        });
    }

    // Kills mutant 239: `||` replaced with `&&` in no-vault branch.
    // Disambiguation must trigger when only repository is set (project is None).
    #[test]
    fn backend_resolve_no_vault_disambiguates_when_only_repository_set() {
        let script = "#!/bin/sh\n\
            if [ \"$2\" = \"get\" ] && [ \"$3\" = \"MY_KEY\" ]; then\n\
              echo 'more than 1 item found' >&2\n\
              exit 1\n\
            fi\n\
            if [ \"$2\" = \"list\" ]; then\n\
              echo '[{\"id\":\"abc\",\"title\":\"MY_KEY\"}]'\n\
              exit 0\n\
            fi\n\
            echo 'resolved-value'\n";
        with_mock_op(script, || {
            let config = Config {
                defaults: Defaults::default(),
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = super::super::ResolveContext {
                dir: Path::new("/tmp"),
                config: &config,
                project: None,
                repository: Some("git@github.com:example/test-repo.git".to_string()),
                interaction: None,
            };
            let result = OpBackend.resolve("MY_KEY", None, &ctx);
            assert_eq!(result.unwrap(), "resolved-value");
        });
    }

    // Kills mutant 260: entire `store` body replaced with `Ok(())`.
    // store must propagate op failures rather than silently returning Ok.
    #[test]
    fn backend_store_fails_when_op_fails() {
        with_mock_op("#!/bin/sh\necho 'op error' >&2\nexit 1\n", || {
            let config = Config {
                defaults: Defaults::default(),
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = StoreContext {
                dir: Path::new("/tmp"),
                config: &config,
                project: None,
                repository: None,
            };
            let result = OpBackend.store("MY_KEY", "my-value", &ctx);
            assert!(result.is_err(), "expected Err when op fails, got Ok");
        });
    }

    // Kills mutant 406: entire `with_mock_op` body replaced with `()`.
    // The closure must actually be called, not silently dropped.
    #[test]
    fn with_mock_op_invokes_closure() {
        let invoked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let invoked_clone = invoked.clone();
        with_mock_op("#!/bin/sh\necho 'test'\n", move || {
            invoked_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        assert!(
            invoked.load(std::sync::atomic::Ordering::SeqCst),
            "with_mock_op did not invoke the closure"
        );
    }

    #[test]
    fn reference_url_with_vault_returns_op_url() {
        let config = Config {
            defaults: Defaults {
                op: crate::config::OpConfig {
                    vault: Some("Dev".to_string()),
                    ..crate::config::OpConfig::default()
                },
                ..Defaults::default()
            },
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };

        let ctx = super::super::StoreContext {
            dir: Path::new("/tmp/project"),
            config: &config,
            project: None,
            repository: None,
        };

        let url = OpBackend.reference_url("API_KEY", &ctx);
        assert_eq!(url.as_deref(), Some("op://Dev/API_KEY/password"));
    }

    #[test]
    fn reference_url_with_vault_and_item() {
        let config = Config {
            defaults: Defaults {
                op: crate::config::OpConfig {
                    vault: Some("Work".to_string()),
                    item: Some("shared".to_string()),
                    ..crate::config::OpConfig::default()
                },
                ..Defaults::default()
            },
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };

        let ctx = super::super::StoreContext {
            dir: Path::new("/tmp/project"),
            config: &config,
            project: None,
            repository: None,
        };

        let url = OpBackend.reference_url("SECRET", &ctx);
        assert_eq!(url.as_deref(), Some("op://Work/shared/SECRET"));
    }

    #[test]
    fn reference_url_without_vault_returns_none() {
        let config = Config {
            defaults: Defaults::default(),
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };

        let ctx = super::super::StoreContext {
            dir: Path::new("/tmp/project"),
            config: &config,
            project: None,
            repository: None,
        };

        let url = OpBackend.reference_url("KEY", &ctx);
        assert_eq!(url, None);
    }
}
