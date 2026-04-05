use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use tracing::debug;

use super::{Backend, ResolveContext, StoreContext};

pub struct GpgBackend;

impl GpgBackend {
    /// Decrypt a GPG file and return its contents entirely in memory.
    fn decrypt_file(path: &PathBuf) -> Result<String> {
        debug!("Decrypting GPG file: {}", path.display());
        let output = Command::new("gpg")
            .args(["--decrypt", "--batch", "--quiet"])
            .arg(path)
            .stdin(std::process::Stdio::null())
            .output()
            .context("Failed to execute `gpg`. Is GnuPG installed?")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("gpg decrypt failed: {stderr}");
        }
        String::from_utf8(output.stdout).context("GPG decrypted content was not valid UTF-8")
    }

    /// Parse KEY=VALUE lines from decrypted content (like a .env file).
    fn parse_env_content(content: &str) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                // Strip surrounding quotes
                let value = if (value.starts_with('"') && value.ends_with('"'))
                    || (value.starts_with('\'') && value.ends_with('\''))
                {
                    &value[1..value.len() - 1]
                } else {
                    value
                };
                if !key.is_empty() {
                    map.insert(key.to_string(), value.to_string());
                }
            }
        }
        map
    }

    /// Find the GPG file path for the given directory and config.
    fn gpg_file_path(ctx_dir: &std::path::Path, config: &crate::config::Config) -> PathBuf {
        let gpg_config = config.effective_gpg(ctx_dir);
        ctx_dir.join(&gpg_config.file_pattern)
    }

    /// Decrypt and parse the GPG env file, returning all key-value pairs.
    fn load_all(ctx: &ResolveContext) -> Result<HashMap<String, String>> {
        let path = Self::gpg_file_path(ctx.dir, ctx.config);
        if !path.exists() {
            bail!(
                "GPG encrypted file not found: {}",
                path.display()
            );
        }
        let content = Self::decrypt_file(&path)?;
        Ok(Self::parse_env_content(&content))
    }

    /// Encrypt content and write to the GPG file.
    fn encrypt_to_file(
        content: &str,
        path: &PathBuf,
        recipient: &str,
    ) -> Result<()> {
        debug!("Encrypting content to GPG file: {}", path.display());
        let mut cmd = Command::new("gpg");
        cmd.args([
            "--encrypt",
            "--batch",
            "--yes",
            "--recipient",
            recipient,
            "--output",
        ]);
        cmd.arg(path);
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().context("Failed to execute `gpg` for encryption")?;
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(content.as_bytes())?;
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("gpg encrypt failed: {stderr}");
        }
        Ok(())
    }
}

impl Backend for GpgBackend {
    fn resolve(&self, key: &str, _reference: Option<&str>, ctx: &ResolveContext) -> Result<String> {
        let all = Self::load_all(ctx)?;
        all.get(key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Key '{key}' not found in GPG encrypted env file"))
    }

    fn store(&self, key: &str, value: &str, ctx: &StoreContext) -> Result<()> {
        let gpg_config = ctx.config.effective_gpg(ctx.dir);
        let recipient = gpg_config
            .recipient
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("GPG recipient must be configured to store secrets"))?;

        let path = Self::gpg_file_path(ctx.dir, ctx.config);

        // Load existing content (or start empty)
        let resolve_ctx = ResolveContext {
            dir: ctx.dir,
            config: ctx.config,
            project: None,
        };
        let mut existing = if path.exists() {
            Self::load_all(&resolve_ctx).unwrap_or_default()
        } else {
            HashMap::new()
        };

        existing.insert(key.to_string(), value.to_string());

        // Serialize back to KEY=VALUE format in memory
        let mut content = String::new();
        let mut keys: Vec<&String> = existing.keys().collect();
        keys.sort();
        for k in keys {
            let v = &existing[k];
            content.push_str(&format!("{k}={v}\n"));
        }

        Self::encrypt_to_file(&content, &path, recipient)?;
        Ok(())
    }

    fn has(&self, key: &str, ctx: &ResolveContext) -> Result<bool> {
        let all = Self::load_all(ctx)?;
        Ok(all.contains_key(key))
    }

    fn name(&self) -> &str {
        "GPG"
    }
}

/// Special method: resolve ALL keys from the GPG file at once (more efficient than one-by-one).
impl GpgBackend {
    pub fn resolve_all(ctx: &ResolveContext) -> Result<HashMap<String, String>> {
        Self::load_all(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_env_content() {
        let content = r#"
# Database settings
DB_HOST=localhost
DB_PORT=5432
DB_PASSWORD="secret value"
API_KEY='my-api-key'
EMPTY=

# Comment line
SPACED_KEY = spaced_value
"#;
        let map = GpgBackend::parse_env_content(content);
        assert_eq!(map.get("DB_HOST").unwrap(), "localhost");
        assert_eq!(map.get("DB_PORT").unwrap(), "5432");
        assert_eq!(map.get("DB_PASSWORD").unwrap(), "secret value");
        assert_eq!(map.get("API_KEY").unwrap(), "my-api-key");
        assert_eq!(map.get("EMPTY").unwrap(), "");
        assert_eq!(map.get("SPACED_KEY").unwrap(), "spaced_value");
    }
}
