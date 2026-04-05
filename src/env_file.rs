use anyhow::{Context, Result};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use tracing::debug;

/// Classification of a .env entry's value.
#[derive(Debug, Clone, PartialEq)]
pub enum EntryKind {
    /// Value is empty or a placeholder — resolve from default backend by key name.
    Empty,
    /// Value is a 1Password reference (op://vault/item/field).
    OpReference(String),
    /// Value is a Bitwarden reference (bw://[folder/]item/field).
    BwReference(String),
    /// Value is plaintext — candidate for migration.
    Plaintext(String),
}

/// A parsed .env entry.
#[derive(Debug, Clone)]
pub struct EnvEntry {
    pub key: String,
    pub raw_value: String,
    pub kind: EntryKind,
}

/// All lines from the .env file, preserving comments and blanks for rewriting.
#[derive(Debug, Clone)]
pub enum EnvLine {
    /// A comment or blank line (preserved as-is).
    Comment(String),
    /// A key=value entry.
    Entry(EnvEntry),
}

/// Parsed .env file.
pub struct EnvFile {
    pub path: PathBuf,
    pub lines: Vec<EnvLine>,
}

impl EnvFile {
    /// Find the .env file in the given directory.
    pub fn find(dir: &Path) -> Option<PathBuf> {
        let env_path = dir.join(".env");
        if env_path.exists() {
            Some(env_path)
        } else {
            None
        }
    }

    /// Parse a .env file, classifying each entry.
    pub fn parse(path: &Path) -> Result<Self> {
        debug!("Parsing .env file: {}", path.display());
        let file = std::fs::File::open(path)
            .with_context(|| format!("Failed to open .env file: {}", path.display()))?;
        let reader = BufReader::new(file);
        let mut lines = Vec::new();

        for line_result in reader.lines() {
            let line = line_result.context("Failed to read line from .env file")?;
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                lines.push(EnvLine::Comment(line));
                continue;
            }

            if let Some((key, value)) = trimmed.split_once('=') {
                let key = key.trim().to_string();
                let value = value.trim().to_string();

                // Strip surrounding quotes for classification, but keep raw_value as-is
                let unquoted = strip_quotes(&value);
                let kind = classify_value(&unquoted);

                lines.push(EnvLine::Entry(EnvEntry {
                    key,
                    raw_value: value,
                    kind,
                }));
            } else {
                // Lines without '=' are treated as comments/passthrough
                lines.push(EnvLine::Comment(line));
            }
        }

        Ok(EnvFile {
            path: path.to_path_buf(),
            lines,
        })
    }

    /// Get all entries (filtering out comments).
    pub fn entries(&self) -> Vec<&EnvEntry> {
        self.lines
            .iter()
            .filter_map(|l| match l {
                EnvLine::Entry(e) => Some(e),
                _ => None,
            })
            .collect()
    }

    /// Get entries that have plaintext values (migration candidates).
    pub fn plaintext_entries(&self) -> Vec<&EnvEntry> {
        self.entries()
            .into_iter()
            .filter(|e| matches!(e.kind, EntryKind::Plaintext(_)))
            .collect()
    }

    /// Get entries that need resolution (empty or reference values).
    pub fn resolvable_entries(&self) -> Vec<&EnvEntry> {
        self.entries()
            .into_iter()
            .filter(|e| !matches!(e.kind, EntryKind::Plaintext(_)))
            .collect()
    }

    /// Rewrite the .env file, replacing specific keys' values.
    /// Used after migration to clear plaintext values.
    pub fn rewrite_with_cleared_keys(&self, keys_to_clear: &[&str]) -> Result<()> {
        let mut output = String::new();
        for line in &self.lines {
            match line {
                EnvLine::Comment(c) => {
                    output.push_str(c);
                    output.push('\n');
                }
                EnvLine::Entry(entry) => {
                    if keys_to_clear.contains(&entry.key.as_str()) {
                        // Write key with empty value
                        output.push_str(&format!("{}=\n", entry.key));
                    } else {
                        output.push_str(&format!("{}={}\n", entry.key, entry.raw_value));
                    }
                }
            }
        }
        std::fs::write(&self.path, output)
            .with_context(|| format!("Failed to rewrite .env file: {}", self.path.display()))?;
        debug!("Rewrote .env file: {}", self.path.display());
        Ok(())
    }

}

fn strip_quotes(value: &str) -> String {
    if (value.starts_with('"') && value.ends_with('"'))
        || (value.starts_with('\'') && value.ends_with('\''))
    {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

fn classify_value(value: &str) -> EntryKind {
    if value.is_empty() {
        EntryKind::Empty
    } else if value.starts_with("op://") {
        EntryKind::OpReference(value.to_string())
    } else if value.starts_with("bw://") {
        EntryKind::BwReference(value.to_string())
    } else {
        EntryKind::Plaintext(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_empty() {
        assert_eq!(classify_value(""), EntryKind::Empty);
    }

    #[test]
    fn test_classify_op_reference() {
        let val = "op://Private/MyApp/api-key";
        assert_eq!(
            classify_value(val),
            EntryKind::OpReference(val.to_string())
        );
    }

    #[test]
    fn test_classify_bw_reference() {
        let val = "bw://env-secrets/myapp/password";
        assert_eq!(
            classify_value(val),
            EntryKind::BwReference(val.to_string())
        );
    }

    #[test]
    fn test_classify_plaintext() {
        assert_eq!(
            classify_value("my-secret-value"),
            EntryKind::Plaintext("my-secret-value".to_string())
        );
    }

    #[test]
    fn test_strip_quotes() {
        assert_eq!(strip_quotes("\"hello\""), "hello");
        assert_eq!(strip_quotes("'hello'"), "hello");
        assert_eq!(strip_quotes("hello"), "hello");
        assert_eq!(strip_quotes("\"hello"), "\"hello");
    }
}
