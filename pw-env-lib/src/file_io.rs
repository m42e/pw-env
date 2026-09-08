use anyhow::{Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Write a file with owner-only permissions (0o600) on Unix.
pub fn write_private_file(path: &Path, contents: &str) -> Result<()> {
    atomic_write_file(path, contents.as_bytes(), true)
}

/// Replace a file atomically, preserving the existing mode for ordinary files.
///
/// The temporary file lives beside the destination, which keeps the final
/// rename on one filesystem. Data and the temporary file are synced before
/// replacement so a crash cannot leave a truncated destination behind.
pub fn atomic_write_file(path: &Path, contents: &[u8], private: bool) -> Result<()> {
    let (mut file, temporary_path) = create_temporary_file(path, private)?;
    let result = (|| {
        file.write_all(contents)
            .with_context(|| format!("Failed to write {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("Failed to sync {}", path.display()))?;
        drop(file);
        replace_file_atomically(&temporary_path, path)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

/// Create a restricted sibling file for an external writer such as GPG.
/// The caller must close and atomically replace it with [`replace_file_atomically`].
pub fn create_private_temp_file(path: &Path) -> Result<(File, PathBuf)> {
    create_temporary_file(path, true)
}

/// Atomically move a completed sibling file into place.
pub fn replace_file_atomically(temporary_path: &Path, destination: &Path) -> Result<()> {
    fs::rename(temporary_path, destination)
        .with_context(|| format!("Failed to atomically replace {}", destination.display()))?;

    if let Some(parent) = destination.parent() {
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    Ok(())
}

fn create_temporary_file(path: &Path, private: bool) -> Result<(File, PathBuf)> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    create_temporary_file_with_nonce(path, private, nonce)
}

pub(crate) fn create_temporary_file_with_nonce(
    path: &Path,
    private: bool,
    nonce: u128,
) -> Result<(File, PathBuf)> {
    #[cfg(not(unix))]
    let _ = private;
    let parent = path
        .parent()
        .and_then(|parent| {
            if parent.as_os_str().is_empty() {
                None
            } else {
                Some(parent)
            }
        })
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| std::borrow::Cow::Borrowed("pw-env-file"));
    #[cfg(unix)]
    let existing_mode = if !private {
        fs::metadata(path).ok().map(file_mode)
    } else {
        None
    };

    for attempt in 0..100u32 {
        let temporary_path = parent.join(format!(
            ".{file_name}.pw-env-{}-{nonce}-{attempt}.tmp",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(if private {
                0o600
            } else {
                existing_mode.unwrap_or(0o666)
            });
        }

        match options.open(&temporary_path) {
            Ok(file) => return Ok((file, temporary_path)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("Failed to create temporary file beside {}", path.display())
                });
            }
        }
    }

    anyhow::bail!(
        "Failed to choose a unique temporary file beside {}",
        path.display()
    )
}

#[cfg(unix)]
fn file_mode(metadata: fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}
