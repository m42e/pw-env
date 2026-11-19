use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Permissions and contents captured from the same opened environment file.
/// The content digest detects replacement or edits while a command is using a
/// parsed snapshot; the platform access data is applied to its replacement.
#[derive(Clone, Debug)]
pub(crate) struct FileProtectionSnapshot {
    content_sha256: [u8; 32],
    #[cfg(unix)]
    mode: u32,
    #[cfg(windows)]
    dacl: Vec<u64>,
    #[cfg(windows)]
    dacl_len: usize,
    #[cfg(windows)]
    dacl_present: bool,
    #[cfg(windows)]
    dacl_protected: bool,
}

impl FileProtectionSnapshot {
    #[cfg(test)]
    pub(crate) fn test_default() -> Self {
        Self {
            content_sha256: [0; 32],
            #[cfg(unix)]
            mode: 0o600,
            #[cfg(windows)]
            dacl: Vec::new(),
            #[cfg(windows)]
            dacl_len: 0,
            #[cfg(windows)]
            dacl_present: false,
            #[cfg(windows)]
            dacl_protected: false,
        }
    }

    pub(crate) fn capture(file: &File, contents: &[u8]) -> Result<Self> {
        let metadata = file
            .metadata()
            .context("Failed to inspect opened environment file")?;
        if !metadata.is_file() {
            anyhow::bail!("Environment path is not a regular file");
        }

        #[cfg(unix)]
        let mode = file_mode(metadata);
        #[cfg(windows)]
        let (dacl, dacl_len, dacl_present, dacl_protected) = windows_dacl(file)?;

        Ok(Self {
            content_sha256: Sha256::digest(contents).into(),
            #[cfg(unix)]
            mode,
            #[cfg(windows)]
            dacl,
            #[cfg(windows)]
            dacl_len,
            #[cfg(windows)]
            dacl_present,
            #[cfg(windows)]
            dacl_protected,
        })
    }

    fn matches_contents(&self, contents: &[u8]) -> bool {
        let digest: [u8; 32] = Sha256::digest(contents).into();
        self.content_sha256 == digest
    }

    fn apply_to(&self, file: &File) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(self.mode & 0o7777))
                .context("Failed to preserve environment file permissions")?;
        }

        #[cfg(windows)]
        self.apply_windows_dacl(file)?;

        Ok(())
    }

    fn matches_access_controls(&self, file: &File, destination: bool) -> Result<bool> {
        #[cfg(unix)]
        {
            let _ = destination;
            let metadata = file
                .metadata()
                .context("Failed to inspect environment file permissions")?;
            Ok(file_mode(metadata) == self.mode)
        }

        #[cfg(windows)]
        {
            let (dacl, dacl_len, dacl_present, dacl_protected) = windows_dacl(file)?;
            let dacl_words = dacl_len.div_ceil(std::mem::size_of::<u64>());
            let dacl_matches = dacl_len == self.dacl_len
                && (!destination || dacl_present == self.dacl_present)
                && dacl[..dacl_words] == self.dacl[..dacl_words];
            // The staged file's DACL is protected from later inheritance by a
            // broader parent. The source's protection state is still checked
            // before publication so a concurrent ACL edit is detected.
            Ok(dacl_matches
                && if destination {
                    dacl_protected == self.dacl_protected
                } else {
                    dacl_protected
                })
        }
    }

    #[cfg(windows)]
    fn apply_windows_dacl(&self, file: &File) -> Result<()> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
        use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetSecurityInfo};
        use windows_sys::Win32::Security::{
            ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        };

        let dacl = if self.dacl_len == 0 {
            std::ptr::null()
        } else {
            self.dacl.as_ptr().cast::<ACL>()
        };
        let status = unsafe {
            SetSecurityInfo(
                file.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            )
        };
        if status != ERROR_SUCCESS {
            anyhow::bail!(
                "Failed to preserve Windows environment file DACL: {}",
                std::io::Error::from_raw_os_error(status as i32)
            );
        }
        Ok(())
    }
}

#[cfg(windows)]
fn windows_dacl(file: &File) -> Result<(Vec<u64>, usize, bool, bool)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, PSECURITY_DESCRIPTOR,
        SE_DACL_PRESENT, SE_DACL_PROTECTED,
    };

    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        anyhow::bail!(
            "Failed to read Windows environment file DACL: {}",
            std::io::Error::from_raw_os_error(status as i32)
        );
    }
    if descriptor.is_null() {
        anyhow::bail!("Windows returned an empty environment file security descriptor");
    }

    let captured = (|| {
        let mut control = 0u16;
        let mut revision = 0u32;
        let control_read =
            unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) };
        if control_read == 0 {
            anyhow::bail!("Failed to inspect Windows environment file DACL controls");
        }
        let (present, protected) = windows_dacl_control_flags(control);
        if dacl.is_null() {
            return Ok((Vec::new(), 0, present, protected));
        }

        let acl_len = unsafe { (*dacl).AclSize as usize };
        validate_windows_acl_length(acl_len)?;
        let word_count = acl_len.div_ceil(std::mem::size_of::<u64>());
        let mut acl_words = vec![0u64; word_count];
        unsafe {
            std::ptr::copy_nonoverlapping(
                dacl.cast::<u8>(),
                acl_words.as_mut_ptr().cast::<u8>(),
                acl_len,
            );
        }
        Ok((acl_words, acl_len, present, protected))
    })();

    unsafe {
        LocalFree(descriptor.cast());
    }
    captured
}

#[cfg(windows)]
fn windows_dacl_control_flags(control: u16) -> (bool, bool) {
    use windows_sys::Win32::Security::{SE_DACL_PRESENT, SE_DACL_PROTECTED};

    (
        control & SE_DACL_PRESENT != 0,
        control & SE_DACL_PROTECTED != 0,
    )
}

#[cfg(windows)]
fn validate_windows_acl_length(acl_len: usize) -> Result<()> {
    use windows_sys::Win32::Security::ACL;

    if acl_len < std::mem::size_of::<ACL>() {
        anyhow::bail!("Windows returned an invalid environment file DACL");
    }
    Ok(())
}

/// Open a regular file without following a final-component symlink/reparse point.
pub(crate) fn open_regular_file_nofollow(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .with_context(|| format!("Failed to open {} without following links", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("Failed to inspect {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!("Refusing non-regular file at {}", path.display());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            anyhow::bail!("Refusing reparse point at {}", path.display());
        }
    }
    Ok(file)
}

/// Replace an existing file only if its contents and permissions still match
/// the parsed snapshot. The replacement inherits the snapshot's access policy.
pub(crate) fn atomic_write_file_with_protection(
    path: &Path,
    contents: &[u8],
    protection: &FileProtectionSnapshot,
) -> Result<()> {
    atomic_write_file_with_protection_before_publish(path, contents, protection, || Ok(()))
}

fn atomic_write_file_with_protection_before_publish(
    path: &Path,
    contents: &[u8],
    protection: &FileProtectionSnapshot,
    before_publish: impl FnOnce() -> Result<()>,
) -> Result<()> {
    verify_snapshot_destination(path, protection)?;
    let (mut file, temporary_path) = create_temporary_file(path, true)?;
    let result = (|| {
        protection.apply_to(&file)?;
        if !protection.matches_access_controls(&file, false)? {
            anyhow::bail!("Failed to apply the original environment file access controls");
        }
        file.write_all(contents)
            .with_context(|| format!("Failed to write {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("Failed to sync {}", path.display()))?;
        drop(file);
        verify_snapshot_destination(path, protection)?;
        // The final pathname can still be replaced after this check in a
        // shared directory. Publication never reads that entry: it replaces
        // it with the snapshot-derived file whose original access controls
        // were applied before any preserved plaintext was written.
        before_publish()?;
        replace_file_atomically(&temporary_path, path)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn verify_snapshot_destination(path: &Path, protection: &FileProtectionSnapshot) -> Result<()> {
    let mut file = open_regular_file_nofollow(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .with_context(|| format!("Failed to verify {}", path.display()))?;
    if !protection.matches_contents(&contents)
        || !protection.matches_access_controls(&file, true)?
    {
        anyhow::bail!(
            "Environment file changed after it was read; refusing to overwrite {}",
            path.display()
        );
    }
    Ok(())
}

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

    if let Some(parent) = destination.parent()
        && let Ok(directory) = File::open(parent)
    {
        let _ = directory.sync_all();
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
        .filter(|parent| !parent.as_os_str().is_empty())
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

#[cfg(test)]
mod tests {
    #[cfg(any(unix, windows))]
    use super::open_regular_file_nofollow;
    #[cfg(windows)]
    use super::windows_dacl;
    #[cfg(unix)]
    use super::{FileProtectionSnapshot, atomic_write_file_with_protection_before_publish};
    use std::fs;
    use tempfile::TempDir;

    #[cfg(any(unix, windows))]
    #[test]
    fn open_regular_file_nofollow_rejects_a_directory() {
        let directory = TempDir::new().unwrap();
        assert!(
            open_regular_file_nofollow(directory.path()).is_err(),
            "directories are not regular environment files"
        );
    }

    #[cfg(unix)]
    #[test]
    fn migration_rewrite_keeps_owner_only_mode_and_remaining_plaintext() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TempDir::new().unwrap();
        let path = directory.path().join(".env");
        fs::write(&path, "KEEP=unmigrated-secret\nAPI_KEY=migrated-secret\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let env_file = crate::env_file::EnvFile::parse(&path).unwrap();
        env_file.rewrite_with_cleared_keys(&["API_KEY"]).unwrap();

        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "KEEP=unmigrated-secret\nAPI_KEY=\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn migration_rewrite_rejects_replaced_destination_with_broader_mode() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TempDir::new().unwrap();
        let path = directory.path().join(".env");
        let displaced = directory.path().join(".env.original");
        fs::write(&path, "KEEP=owner-only-secret\nAPI_KEY=migrated-secret\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let env_file = crate::env_file::EnvFile::parse(&path).unwrap();
        fs::rename(&path, &displaced).unwrap();
        fs::write(&path, "EXTERNAL=must-not-be-copied\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let error = env_file
            .rewrite_with_cleared_keys(&["API_KEY"])
            .expect_err("changed destination must not be overwritten");
        assert!(format!("{error:#}").contains("changed after it was read"));
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "EXTERNAL=must-not-be-copied\n"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(
            fs::read_to_string(displaced).unwrap(),
            "KEEP=owner-only-secret\nAPI_KEY=migrated-secret\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn migration_rewrite_rejects_content_change_without_permission_change() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TempDir::new().unwrap();
        let path = directory.path().join(".env");
        fs::write(&path, "KEEP=original-secret\nAPI_KEY=migrated-secret\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let env_file = crate::env_file::EnvFile::parse(&path).unwrap();
        fs::write(&path, "KEEP=replacement-secret\nAPI_KEY=migrated-secret\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let error = env_file
            .rewrite_with_cleared_keys(&["API_KEY"])
            .expect_err("changed contents must be rejected even when permissions match");
        assert!(format!("{error:#}").contains("changed after it was read"));
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "KEEP=replacement-secret\nAPI_KEY=migrated-secret\n"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn migration_rewrite_rejects_permission_change_without_content_change() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TempDir::new().unwrap();
        let path = directory.path().join(".env");
        let original = "KEEP=original-secret\nAPI_KEY=migrated-secret\n";
        fs::write(&path, original).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let env_file = crate::env_file::EnvFile::parse(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let error = env_file
            .rewrite_with_cleared_keys(&["API_KEY"])
            .expect_err("changed permissions must be rejected even when contents match");
        assert!(format!("{error:#}").contains("changed after it was read"));
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[cfg(unix)]
    #[test]
    fn replacement_in_final_publish_window_cannot_change_snapshot_or_mode() {
        use std::io::Read;
        use std::os::unix::fs::PermissionsExt;

        let directory = TempDir::new().unwrap();
        let path = directory.path().join(".env");
        let displaced = directory.path().join(".env.replaced");
        fs::write(&path, "KEEP=owner-only-secret\nAPI_KEY=migrated-secret\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut source = open_regular_file_nofollow(&path).unwrap();
        let mut original = Vec::new();
        source.read_to_end(&mut original).unwrap();
        let protection = FileProtectionSnapshot::capture(&source, &original).unwrap();
        drop(source);

        atomic_write_file_with_protection_before_publish(
            &path,
            b"KEEP=owner-only-secret\nAPI_KEY=\n",
            &protection,
            || {
                fs::rename(&path, &displaced)?;
                fs::write(&path, "EXTERNAL=must-not-be-copied\n")?;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "KEEP=owner-only-secret\nAPI_KEY=\n"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::read_to_string(displaced).unwrap(),
            "KEEP=owner-only-secret\nAPI_KEY=migrated-secret\n"
        );
    }

    #[cfg(windows)]
    #[test]
    fn migration_rewrite_preserves_explicit_dacl_under_broader_parent_acl() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join(".env");
        fs::write(&path, "KEEP=unmigrated-secret\nAPI_KEY=migrated-secret\n").unwrap();

        let owner = std::env::var("USERNAME").expect("Windows tests need a user name");
        let users = "*S-1-5-32-545:(OI)(CI)(RX)";
        let output = std::process::Command::new("icacls")
            .args([
                directory.path().as_os_str(),
                std::ffi::OsStr::new("/grant"),
                std::ffi::OsStr::new(users),
            ])
            .output()
            .expect("icacls must be available on Windows");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );

        let output = std::process::Command::new("icacls")
            .arg(&path)
            .args(["/inheritance:r", "/grant:r"])
            .arg(format!("{owner}:(F)"))
            .output()
            .expect("icacls must be available on Windows");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );

        let source = open_regular_file_nofollow(&path).unwrap();
        let (source_dacl, source_len, _, source_protected) = windows_dacl(&source).unwrap();
        assert!(source_protected, "test source ACL should be protected");
        let env_file = crate::env_file::EnvFile::parse(&path).unwrap();

        env_file.rewrite_with_cleared_keys(&["API_KEY"]).unwrap();

        let replacement = open_regular_file_nofollow(&path).unwrap();
        let (replacement_dacl, replacement_len, _, replacement_protected) =
            windows_dacl(&replacement).unwrap();
        let words = source_len.div_ceil(std::mem::size_of::<u64>());
        assert_eq!(replacement_len, source_len);
        assert_eq!(replacement_dacl[..words], source_dacl[..words]);
        assert!(
            replacement_protected,
            "replacement must not inherit broader parent grants"
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "KEEP=unmigrated-secret\nAPI_KEY=\n"
        );
    }

    #[cfg(windows)]
    #[test]
    fn migration_rewrite_accepts_an_ordinary_inherited_dacl() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join(".env");
        let users = "*S-1-5-32-545:(OI)(CI)(RX)";
        let output = std::process::Command::new("icacls")
            .args([
                directory.path().as_os_str(),
                std::ffi::OsStr::new("/grant"),
                std::ffi::OsStr::new(users),
            ])
            .output()
            .expect("icacls must be available on Windows");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        fs::write(&path, "KEEP=unmigrated-secret\nAPI_KEY=migrated-secret\n").unwrap();

        let source = open_regular_file_nofollow(&path).unwrap();
        let (source_dacl, source_len, _, source_protected) = windows_dacl(&source).unwrap();
        assert!(
            !source_protected,
            "source should use its parent's inherited DACL"
        );
        let env_file = crate::env_file::EnvFile::parse(&path).unwrap();

        env_file.rewrite_with_cleared_keys(&["API_KEY"]).unwrap();

        let replacement = open_regular_file_nofollow(&path).unwrap();
        let (replacement_dacl, replacement_len, _, replacement_protected) =
            windows_dacl(&replacement).unwrap();
        let words = source_len.div_ceil(std::mem::size_of::<u64>());
        assert_eq!(replacement_len, source_len);
        assert_eq!(replacement_dacl[..words], source_dacl[..words]);
        assert!(replacement_protected);
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "KEEP=unmigrated-secret\nAPI_KEY=\n"
        );
    }

    #[cfg(windows)]
    #[test]
    fn add_append_preserves_private_dacl_under_broader_parent_acl() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join(".env");
        fs::write(&path, "EXISTING_KEY=\n").unwrap();

        let owner = std::env::var("USERNAME").expect("Windows tests need a user name");
        let users = "*S-1-5-32-545:(OI)(CI)(RX)";
        let output = std::process::Command::new("icacls")
            .args([
                directory.path().as_os_str(),
                std::ffi::OsStr::new("/grant"),
                std::ffi::OsStr::new(users),
            ])
            .output()
            .expect("icacls must be available on Windows");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = std::process::Command::new("icacls")
            .arg(&path)
            .args(["/inheritance:r", "/grant:r"])
            .arg(format!("{owner}:(F)"))
            .output()
            .expect("icacls must be available on Windows");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );

        let source = open_regular_file_nofollow(&path).unwrap();
        let (source_dacl, source_len, _, source_protected) = windows_dacl(&source).unwrap();
        assert!(source_protected, "test source ACL should be protected");
        let env_file = crate::env_file::EnvFile::parse(&path).unwrap();

        env_file
            .append_with_key_value("API_KEY", "op://vault/item/password")
            .unwrap();

        let replacement = open_regular_file_nofollow(&path).unwrap();
        let (replacement_dacl, replacement_len, _, replacement_protected) =
            windows_dacl(&replacement).unwrap();
        let words = source_len.div_ceil(std::mem::size_of::<u64>());
        assert_eq!(replacement_len, source_len);
        assert_eq!(replacement_dacl[..words], source_dacl[..words]);
        assert!(replacement_protected);
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "EXISTING_KEY=\nAPI_KEY=op://vault/item/password\n"
        );
    }

    #[cfg(windows)]
    mod windows_mutation_tests {
        use super::super::{
            FileProtectionSnapshot, atomic_write_file_with_protection, open_regular_file_nofollow,
            validate_windows_acl_length, windows_dacl, windows_dacl_control_flags,
        };
        use std::fs;
        use std::path::Path;
        use tempfile::TempDir;
        use windows_sys::Win32::Security::{SE_DACL_PRESENT, SE_DACL_PROTECTED};

        fn assert_icacls(args: &[&std::ffi::OsStr]) {
            let output = std::process::Command::new("icacls")
                .args(args)
                .output()
                .expect("icacls must be available on Windows");
            assert!(
                output.status.success(),
                "icacls failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        fn make_parent_broad_and_file_private(directory: &TempDir, path: &Path) {
            let owner = std::env::var("USERNAME").expect("Windows tests need a user name");
            let owner_acl = format!("{owner}:(F)");
            assert_icacls(&[
                directory.path().as_os_str(),
                std::ffi::OsStr::new("/grant"),
                std::ffi::OsStr::new("*S-1-5-32-545:(OI)(CI)(RX)"),
            ]);
            assert_icacls(&[
                path.as_os_str(),
                std::ffi::OsStr::new("/inheritance:r"),
                std::ffi::OsStr::new("/grant:r"),
                std::ffi::OsStr::new(&owner_acl),
            ]);
        }

        #[test]
        fn windows_mutation_tests_dacl_application_preserves_explicit_acl() {
            let directory = TempDir::new().unwrap();
            let path = directory.path().join(".env");
            let original = b"KEEP=secret\nAPI_KEY=old\n";
            fs::write(&path, original).unwrap();
            make_parent_broad_and_file_private(&directory, &path);

            let source = open_regular_file_nofollow(&path).unwrap();
            let (source_acl, source_len, source_present, source_protected) =
                windows_dacl(&source).unwrap();
            assert!(source_present, "test source ACL should be present");
            assert!(source_protected, "test source ACL should be protected");
            let protection = FileProtectionSnapshot::capture(&source, original).unwrap();

            atomic_write_file_with_protection(&path, b"KEEP=secret\nAPI_KEY=\n", &protection)
                .unwrap();

            let replacement = open_regular_file_nofollow(&path).unwrap();
            let (replacement_acl, replacement_len, replacement_present, replacement_protected) =
                windows_dacl(&replacement).unwrap();
            let words = source_len.div_ceil(std::mem::size_of::<u64>());
            assert_eq!(replacement_len, source_len);
            assert!(replacement_present);
            assert_eq!(replacement_acl[..words], source_acl[..words]);
            assert!(replacement_protected);
            assert_eq!(fs::read(&path).unwrap(), b"KEEP=secret\nAPI_KEY=\n");
        }

        #[test]
        fn windows_mutation_tests_changed_dacl_is_rejected_before_replacement() {
            let directory = TempDir::new().unwrap();
            let path = directory.path().join(".env");
            let original = b"KEEP=secret\nAPI_KEY=old\n";
            fs::write(&path, original).unwrap();
            make_parent_broad_and_file_private(&directory, &path);
            let env_file = crate::env_file::EnvFile::parse(&path).unwrap();

            assert_icacls(&[
                path.as_os_str(),
                std::ffi::OsStr::new("/grant"),
                std::ffi::OsStr::new("*S-1-1-0:(R)"),
            ]);

            let error = env_file
                .rewrite_with_cleared_keys(&["API_KEY"])
                .expect_err("a DACL edit after parsing must be rejected");
            assert!(format!("{error:#}").contains("changed after it was read"));
            assert_eq!(fs::read(&path).unwrap(), original);
        }

        #[test]
        fn windows_mutation_tests_dacl_snapshot_checks_presence_and_bytes() {
            let directory = TempDir::new().unwrap();
            let path = directory.path().join(".env");
            let contents = b"KEY=value\n";
            fs::write(&path, contents).unwrap();
            let file = open_regular_file_nofollow(&path).unwrap();
            let protection = FileProtectionSnapshot::capture(&file, contents).unwrap();

            assert!(protection.matches_access_controls(&file, true).unwrap());

            let mut different_presence = protection.clone();
            different_presence.dacl_present = !protection.dacl_present;
            assert!(
                !different_presence
                    .matches_access_controls(&file, true)
                    .unwrap(),
                "destination DACL presence is part of the snapshot"
            );

            let mut different_bytes = protection.clone();
            different_bytes.dacl[0] ^= 1;
            assert!(
                !different_bytes
                    .matches_access_controls(&file, true)
                    .unwrap(),
                "destination DACL bytes are part of the snapshot"
            );
        }

        #[test]
        fn windows_mutation_tests_dacl_control_flags_match_each_bit() {
            assert_eq!(windows_dacl_control_flags(0), (false, false));
            assert_eq!(windows_dacl_control_flags(SE_DACL_PRESENT), (true, false));
            assert_eq!(windows_dacl_control_flags(SE_DACL_PROTECTED), (false, true));
            assert_eq!(
                windows_dacl_control_flags(SE_DACL_PRESENT | SE_DACL_PROTECTED),
                (true, true)
            );
        }

        #[test]
        fn windows_mutation_tests_acl_length_checks_boundary_values() {
            use windows_sys::Win32::Security::ACL;

            let minimum = std::mem::size_of::<ACL>();
            assert!(validate_windows_acl_length(minimum - 1).is_err());
            assert!(validate_windows_acl_length(minimum).is_ok());
            assert!(validate_windows_acl_length(minimum + 1).is_ok());
        }

        #[test]
        fn windows_mutation_tests_reparse_points_are_not_opened_as_regular_files() {
            use std::os::windows::fs::symlink_file;

            let directory = TempDir::new().unwrap();
            let target = directory.path().join("target.env");
            let link = directory.path().join("link.env");
            fs::write(&target, "SECRET=value\n").unwrap();
            symlink_file(&target, &link).expect("Windows runner must support file symlinks");

            let error =
                open_regular_file_nofollow(&link).expect_err("reparse points must be rejected");
            assert!(format!("{error:#}").contains("reparse point"));
        }
    }
}
