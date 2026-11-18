use anyhow::{Context, Result, bail};
use cap_std::fs::Dir;
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

use super::{
    Backend, CREATED_WITH_FIELD_NAME, MIGRATED_FROM_FIELD_NAME, PROJECT_FIELD_NAME, ResolveContext,
    StoreContext,
};

pub struct GpgBackend;

struct GpgOutputLocation {
    parent: Dir,
    file_name: PathBuf,
    display_path: PathBuf,
}

impl GpgOutputLocation {
    fn from_path(path: &Path) -> Result<Self> {
        let parent_path = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let file_name = path
            .file_name()
            .map(PathBuf::from)
            .context("GPG output path must name a file")?;
        let parent = Dir::open_ambient_dir(parent_path, cap_std::ambient_authority())
            .with_context(|| {
                format!(
                    "Failed to open GPG output directory {}",
                    parent_path.display()
                )
            })?;
        Ok(Self {
            parent,
            file_name,
            display_path: path.to_path_buf(),
        })
    }

    fn replace_atomically(&self, contents: &[u8], owner_uid: u32) -> Result<()> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        for attempt in 0..100u32 {
            let staging_name = PathBuf::from(format!(
                ".pw-env-gpg-{}-{nonce}-{attempt}.tmpdir",
                std::process::id()
            ));
            let staging_dir =
                match create_private_staging_dir(&self.parent, &staging_name, owner_uid) {
                    Ok(dir) => dir,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!(
                                "Failed to create private GPG staging directory beside {}",
                                self.display_path.display()
                            )
                        });
                    }
                };

            let result = (|| {
                let mut staged_file = create_private_staging_file(&staging_dir)
                    .context("Failed to create private encrypted GPG staging file")?;
                staged_file
                    .write_all(contents)
                    .context("Failed to write encrypted GPG staging file")?;
                staged_file
                    .sync_all()
                    .context("Failed to sync encrypted GPG staging file")?;
                drop(staged_file);

                staging_dir
                    .rename("ciphertext", &self.parent, &self.file_name)
                    .with_context(|| {
                        format!(
                            "Failed to atomically replace {}",
                            self.display_path.display()
                        )
                    })?;
                if let Ok(directory) = self.parent.try_clone() {
                    let _ = directory.into_std_file().sync_all();
                }
                Ok(())
            })();

            if result.is_err() {
                let _ = staging_dir.remove_file("ciphertext");
            }
            if let Err(error) = remove_private_staging_dir(staging_dir) {
                tracing::warn!(
                    "Failed to remove private GPG staging directory beside {}: {error}",
                    self.display_path.display()
                );
            }
            return result;
        }

        anyhow::bail!(
            "Failed to choose a unique private GPG staging directory beside {}",
            self.display_path.display()
        )
    }
}

#[cfg(unix)]
fn create_private_staging_dir(parent: &Dir, name: &Path, owner_uid: u32) -> std::io::Result<Dir> {
    use cap_std::fs::{DirBuilder, DirBuilderExt};
    use cap_std::fs::{MetadataExt, PermissionsExt};

    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    parent.create_dir_with(name, &builder)?;
    let directory = parent.open_dir(name)?;
    let metadata = directory.metadata(".")?;
    let mode = metadata.permissions().mode() & 0o777;
    if metadata.uid() != owner_uid || mode & 0o077 != 0 || mode & 0o700 != 0o700 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "GPG staging directory is not owned by the current user with owner-only access",
        ));
    }
    Ok(directory)
}

#[cfg(windows)]
fn create_private_staging_dir(parent: &Dir, name: &Path, _owner_uid: u32) -> std::io::Result<Dir> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::{CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE};

    let directory_file = create_windows_private_object(
        parent,
        name.as_os_str(),
        windows_sys::core::w!("D:P(A;OICI;FA;;;OW)"),
        windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY,
        windows_sys::Wdk::Storage::FileSystem::FILE_DIRECTORY_FILE
            | windows_sys::Wdk::Storage::FileSystem::FILE_SYNCHRONOUS_IO_NONALERT,
    )?;
    verify_private_windows_dacl(
        directory_file.as_raw_handle(),
        (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
    )?;
    Ok(Dir::from_std_file(directory_file))
}

#[cfg(windows)]
fn create_private_staging_file(staging_dir: &Dir) -> std::io::Result<cap_std::fs::File> {
    use std::ffi::OsStr;
    use std::os::windows::io::AsRawHandle;

    let file = create_windows_private_object(
        staging_dir,
        OsStr::new("ciphertext"),
        windows_sys::core::w!("D:P(A;;FA;;;OW)"),
        windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL,
        windows_sys::Wdk::Storage::FileSystem::FILE_NON_DIRECTORY_FILE
            | windows_sys::Wdk::Storage::FileSystem::FILE_SYNCHRONOUS_IO_NONALERT,
    )?;
    verify_private_windows_dacl(file.as_raw_handle(), 0)?;
    Ok(cap_std::fs::File::from_std(file))
}

#[cfg(windows)]
fn create_windows_private_object(
    parent: &Dir,
    name: &std::ffi::OsStr,
    sddl: windows_sys::core::PCWSTR,
    file_attributes: u32,
    create_options: u32,
) -> std::io::Result<std::fs::File> {
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::ptr::{null, null_mut};
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{FILE_CREATE, NtCreateFile};
    use windows_sys::Win32::Foundation::{
        HANDLE, LocalFree, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError,
    };
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ALL_ACCESS, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    let mut name_wide: Vec<u16> = name.encode_wide().collect();
    if name_wide.is_empty() || name_wide.len() > (u16::MAX as usize / 2) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "GPG staging entry name is too long",
        ));
    }
    let mut object_name = windows_sys::Win32::Foundation::UNICODE_STRING {
        Length: (name_wide.len() * 2) as u16,
        MaximumLength: (name_wide.len() * 2) as u16,
        Buffer: name_wide.as_mut_ptr(),
    };

    let mut security_descriptor: PSECURITY_DESCRIPTOR = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            1,
            &mut security_descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }

    let mut io_status = IO_STATUS_BLOCK::default();
    let mut raw_handle: HANDLE = null_mut();
    let object_attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle() as HANDLE,
        ObjectName: &mut object_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: security_descriptor as *const SECURITY_DESCRIPTOR,
        SecurityQualityOfService: null(),
    };
    let status = unsafe {
        NtCreateFile(
            &mut raw_handle,
            FILE_ALL_ACCESS,
            &object_attributes,
            &mut io_status,
            null(),
            file_attributes,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_CREATE,
            create_options,
            null(),
            0,
        )
    };
    unsafe { LocalFree(security_descriptor as _) };
    if status < 0 {
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(std::io::Error::from_raw_os_error(code as i32));
    }

    // Omitting FILE_SHARE_DELETE pins the just-created entry while it is used.
    Ok(unsafe { std::fs::File::from_raw_handle(raw_handle) })
}

#[cfg(windows)]
fn verify_private_windows_dacl(
    handle: std::os::windows::io::RawHandle,
    expected_ace_flags: u8,
) -> std::io::Result<()> {
    use std::mem::{offset_of, size_of};
    use std::ptr::{null_mut, read_unaligned};
    use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL_SIZE_INFORMATION, AclSizeInformation,
        CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
        GetSecurityDescriptorControl, SE_DACL_PROTECTED, WinCreatorOwnerRightsSid,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

    let mut dacl = null_mut();
    let mut security_descriptor = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle as HANDLE,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut security_descriptor,
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }

    let result = (|| {
        if dacl.is_null() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "GPG staging object has no DACL",
            ));
        }
        let mut control = 0u16;
        let mut revision = 0u32;
        if unsafe { GetSecurityDescriptorControl(security_descriptor, &mut control, &mut revision) }
            == 0
            || control & SE_DACL_PROTECTED == 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "GPG staging object DACL is not protected from inheritance",
            ));
        }

        let mut acl_info = ACL_SIZE_INFORMATION::default();
        if unsafe {
            GetAclInformation(
                dacl,
                &mut acl_info as *mut _ as *mut _,
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
            || acl_info.AceCount != 1
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "GPG staging object DACL is not owner-only",
            ));
        }

        let mut ace_pointer = null_mut();
        if unsafe { GetAce(dacl, 0, &mut ace_pointer) } == 0 || ace_pointer.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let header = unsafe { read_unaligned(ace_pointer as *const ACE_HEADER) };
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8 || header.AceFlags != expected_ace_flags
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "GPG staging object DACL grants unexpected access",
            ));
        }
        let ace = unsafe { read_unaligned(ace_pointer as *const ACCESS_ALLOWED_ACE) };
        if ace.Mask != FILE_ALL_ACCESS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "GPG staging object DACL grants unexpected rights",
            ));
        }

        let mut owner_rights = [0u64; 16];
        let mut owner_rights_len = size_of::<[u64; 16]>() as u32;
        if unsafe {
            CreateWellKnownSid(
                WinCreatorOwnerRightsSid,
                null_mut(),
                owner_rights.as_mut_ptr() as _,
                &mut owner_rights_len,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let sid_pointer = unsafe {
            (ace_pointer as *mut u8).add(offset_of!(ACCESS_ALLOWED_ACE, SidStart)) as *mut _
        };
        if unsafe { EqualSid(sid_pointer, owner_rights.as_mut_ptr() as _) } == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "GPG staging object DACL does not limit access to its owner",
            ));
        }
        Ok(())
    })();
    unsafe { LocalFree(security_descriptor as _) };
    result
}

#[cfg(unix)]
fn create_private_staging_file(staging_dir: &Dir) -> std::io::Result<cap_std::fs::File> {
    use cap_std::fs::{OpenOptions, OpenOptionsExt};

    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    staging_dir.open_with("ciphertext", &options)
}

#[cfg(not(any(unix, windows)))]
fn create_private_staging_file(_staging_dir: &Dir) -> std::io::Result<cap_std::fs::File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "secure GPG staging files are unsupported on this platform",
    ))
}

#[cfg(not(any(unix, windows)))]
fn create_private_staging_dir(
    _parent: &Dir,
    _name: &Path,
    _owner_uid: u32,
) -> std::io::Result<Dir> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "secure GPG staging directories are unsupported on this platform",
    ))
}

fn remove_private_staging_dir(staging_dir: Dir) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::mem::size_of;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
        };

        let staging_file = staging_dir.into_std_file();
        let delete_info = FILE_DISPOSITION_INFO { DeleteFile: true };
        if unsafe {
            SetFileInformationByHandle(
                staging_file.as_raw_handle() as HANDLE,
                FileDispositionInfo,
                &delete_info as *const _ as *const _,
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        return Ok(());
    }
    #[cfg(not(windows))]
    staging_dir.remove_open_dir()
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct StoredSecret {
    value: String,
    project: Option<String>,
    migrated_from: Option<String>,
    created_with: Option<String>,
}

impl GpgBackend {
    fn metadata_comment(name: &str, value: &str) -> String {
        format!("# pw-env: {name}={value}")
    }

    /// Decrypt a GPG file and return its contents entirely in memory.
    fn decrypt_file(path: &Path) -> Result<String> {
        debug!("Decrypting GPG file: {}", path.display());
        let mut command = Command::new("gpg");
        command
            .args(["--decrypt", "--batch", "--quiet"])
            .arg(path)
            .stdin(std::process::Stdio::null());
        let output = super::run_command_with_timeout(
            command,
            "Failed to execute `gpg`. Is GnuPG installed?",
        )?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("gpg decrypt failed: {stderr}");
        }
        String::from_utf8(output.stdout).context("GPG decrypted content was not valid UTF-8")
    }

    /// Parse KEY=VALUE lines from decrypted content (like a .env file).
    fn parse_env_content(content: &str) -> HashMap<String, String> {
        Self::parse_stored_secrets(content)
            .into_iter()
            .map(|(key, secret)| (key, secret.value))
            .collect()
    }

    fn parse_stored_secrets(content: &str) -> BTreeMap<String, StoredSecret> {
        let mut map = BTreeMap::new();
        let mut pending_project: Option<String> = None;
        let mut pending_migrated_from: Option<String> = None;
        let mut pending_created_with: Option<String> = None;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                if let Some(metadata) = line.strip_prefix("# pw-env: ")
                    && let Some((name, value)) = metadata.split_once('=')
                {
                    match name.trim() {
                        PROJECT_FIELD_NAME => pending_project = Some(value.trim().to_string()),
                        MIGRATED_FROM_FIELD_NAME => {
                            pending_migrated_from = Some(value.trim().to_string())
                        }
                        CREATED_WITH_FIELD_NAME => {
                            pending_created_with = Some(value.trim().to_string())
                        }
                        _ => {}
                    }
                }
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                // Strip surrounding quotes
                let value = if value.starts_with('"') && value.ends_with('"') {
                    serde_json::from_str::<String>(value)
                        .unwrap_or_else(|_| value[1..value.len() - 1].to_string())
                } else if value.starts_with('\'') && value.ends_with('\'') {
                    value[1..value.len() - 1].to_string()
                } else {
                    value.to_string()
                };
                if !key.is_empty() {
                    map.insert(
                        key.to_string(),
                        StoredSecret {
                            value: value.to_string(),
                            project: pending_project.take(),
                            migrated_from: pending_migrated_from.take(),
                            created_with: pending_created_with.take(),
                        },
                    );
                }
            } else {
                pending_project = None;
                pending_migrated_from = None;
                pending_created_with = None;
            }
        }
        map
    }

    /// Find the GPG file path for the given directory and config.
    /// Validates that file_pattern does not escape the project directory.
    fn gpg_file_path(ctx_dir: &std::path::Path, config: &crate::config::Config) -> PathBuf {
        let gpg_config = config.effective_gpg(ctx_dir);
        let joined = ctx_dir.join(&gpg_config.file_pattern);
        // Normalize the path and verify it stays within the project directory.
        // If canonicalize fails (file doesn't exist yet), fall through to the
        // component-based check.
        if let Ok(canonical) = joined.canonicalize() {
            if let Ok(canonical_dir) = ctx_dir.canonicalize()
                && !canonical.starts_with(&canonical_dir)
            {
                tracing::warn!(
                    "GPG file_pattern '{}' escapes the project directory; falling back to default",
                    gpg_config.file_pattern
                );
                return ctx_dir.join(".env.gpg");
            }
        } else {
            // File doesn't exist yet — check for path traversal components
            if gpg_config.file_pattern.contains("..") {
                tracing::warn!(
                    "GPG file_pattern '{}' contains path traversal; falling back to default",
                    gpg_config.file_pattern
                );
                return ctx_dir.join(".env.gpg");
            }
        }
        joined
    }

    /// Decrypt and parse the GPG env file, returning all key-value pairs.
    fn load_all(ctx: &ResolveContext) -> Result<HashMap<String, String>> {
        let path = Self::gpg_file_path(ctx.dir, ctx.config);
        if !path.exists() {
            bail!("GPG encrypted file not found: {}", path.display());
        }
        let content = Self::decrypt_file(&path)?;
        Ok(Self::parse_env_content(&content))
    }

    fn load_all_stored_secrets(ctx: &ResolveContext) -> Result<BTreeMap<String, StoredSecret>> {
        let path = Self::gpg_file_path(ctx.dir, ctx.config);
        if !path.exists() {
            bail!("GPG encrypted file not found: {}", path.display());
        }
        let content = Self::decrypt_file(&path)?;
        Ok(Self::parse_stored_secrets(&content))
    }

    fn serialize_stored_secrets(secrets: &BTreeMap<String, StoredSecret>) -> String {
        let mut content = String::new();
        for (key, secret) in secrets {
            if let Some(project) = secret.project.as_deref() {
                content.push_str(&Self::metadata_comment(PROJECT_FIELD_NAME, project));
                content.push('\n');
            }
            if let Some(migrated_from) = secret.migrated_from.as_deref() {
                content.push_str(&Self::metadata_comment(
                    MIGRATED_FROM_FIELD_NAME,
                    migrated_from,
                ));
                content.push('\n');
            }
            if let Some(created_with) = secret.created_with.as_deref() {
                content.push_str(&Self::metadata_comment(
                    CREATED_WITH_FIELD_NAME,
                    created_with,
                ));
                content.push('\n');
            }
            let encoded_value = serde_json::to_string(&secret.value)
                .expect("serializing a string to JSON cannot fail");
            content.push_str(&format!("{key}={encoded_value}\n"));
        }
        content
    }

    /// Encrypt to an anonymous descriptor, then publish from a private sibling directory.
    fn encrypt_to_file(content: &str, location: &GpgOutputLocation, recipient: &str) -> Result<()> {
        debug!(
            "Encrypting content to GPG file: {}",
            location.display_path.display()
        );
        let mut ciphertext =
            tempfile::tempfile().context("Failed to create private GPG output file")?;

        let mut command = Command::new("gpg");
        command
            .args(["--encrypt", "--batch", "--yes", "--recipient", recipient])
            .stdin(Stdio::piped())
            .stdout(Stdio::from(
                ciphertext
                    .try_clone()
                    .context("Failed to duplicate private GPG output handle")?,
            ))
            .stderr(Stdio::piped());

        let mut child = command
            .spawn()
            .context("Failed to execute `gpg` for encryption")?;
        let output = (|| {
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(content.as_bytes())?;
            }
            super::wait_with_output_timeout(child, "Failed to wait for `gpg` encryption")
        })()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("gpg encrypt failed: {stderr}");
        }

        ciphertext
            .sync_all()
            .context("Failed to sync private GPG output")?;
        #[cfg(unix)]
        let owner_uid = {
            use std::os::unix::fs::MetadataExt;
            ciphertext.metadata()?.uid()
        };
        #[cfg(not(unix))]
        let owner_uid = 0;

        ciphertext
            .seek(SeekFrom::Start(0))
            .context("Failed to rewind private GPG output")?;
        let mut encrypted_content = Vec::new();
        ciphertext
            .read_to_end(&mut encrypted_content)
            .context("Failed to read private GPG output")?;
        location.replace_atomically(&encrypted_content, owner_uid)
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
        let output_location = GpgOutputLocation::from_path(&path)?;

        // Load existing content (or start empty)
        let resolve_ctx = ResolveContext {
            dir: ctx.dir,
            config: ctx.config,
            project: None,
            repository: None,
            interaction: None,
        };
        let mut existing = if path
            .try_exists()
            .context("Failed to check the existing GPG secret store")?
        {
            Self::load_all_stored_secrets(&resolve_ctx)
                .context("Refusing to overwrite an unreadable GPG secret store")?
        } else {
            BTreeMap::new()
        };

        existing.insert(
            key.to_string(),
            StoredSecret {
                value: value.to_string(),
                project: ctx.project.clone(),
                migrated_from: Some(ctx.migrated_from()),
                created_with: Some(ctx.created_with()),
            },
        );

        let content = Self::serialize_stored_secrets(&existing);

        Self::encrypt_to_file(&content, &output_location, recipient)?;
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::config::{Config, Defaults, LogConfig, UpdateConfig};
    use std::cell::Cell;

    #[test]
    fn test_parse_stored_secrets_with_line_without_equals() {
        // A line with no '=' should clear pending metadata
        let content = "# pw-env: project=service-a\nNOT_A_KV_PAIR\nVALID=value\n";
        let stored = GpgBackend::parse_stored_secrets(content);
        // Metadata should have been cleared by the non-KV line
        assert_eq!(stored.get("VALID").unwrap().project, None);
    }

    #[test]
    fn test_parse_stored_secrets_with_unknown_metadata_key() {
        let content = "# pw-env: unknown_key=some_value\nFOO=bar\n";
        let stored = GpgBackend::parse_stored_secrets(content);
        let foo = stored.get("FOO").unwrap();
        assert_eq!(foo.project, None);
        assert_eq!(foo.migrated_from, None);
        assert_eq!(foo.created_with, None);
    }

    #[test]
    fn test_parse_stored_secrets_with_double_quoted_value() {
        let content = "KEY=\"quoted value\"\n";
        let stored = GpgBackend::parse_stored_secrets(content);
        assert_eq!(stored.get("KEY").unwrap().value, "quoted value");
    }

    #[test]
    fn test_parse_stored_secrets_falls_back_for_invalid_json_quotes() {
        let content = "KEY=\"bad\\q\"\n";
        let stored = GpgBackend::parse_stored_secrets(content);
        assert_eq!(stored.get("KEY").unwrap().value, "bad\\q");
    }

    #[test]
    fn test_parse_stored_secrets_with_single_quoted_value() {
        let content = "KEY='single quoted'\n";
        let stored = GpgBackend::parse_stored_secrets(content);
        assert_eq!(stored.get("KEY").unwrap().value, "single quoted");
    }

    #[test]
    fn test_parse_stored_secrets_with_empty_key_ignored() {
        let content = "=value\n";
        let stored = GpgBackend::parse_stored_secrets(content);
        assert!(!stored.contains_key(""));
    }

    #[test]
    fn test_serialize_stored_secrets_with_no_metadata() {
        let mut stored = BTreeMap::new();
        stored.insert(
            "PLAIN_KEY".to_string(),
            StoredSecret {
                value: "plain_value".to_string(),
                project: None,
                migrated_from: None,
                created_with: None,
            },
        );
        let serialized = GpgBackend::serialize_stored_secrets(&stored);
        assert!(serialized.contains("PLAIN_KEY=\"plain_value\""));
        assert!(!serialized.contains("# pw-env:"));
    }

    #[test]
    fn test_serialize_stored_secrets_empty() {
        let stored = BTreeMap::new();
        let serialized = GpgBackend::serialize_stored_secrets(&stored);
        assert_eq!(serialized, "");
    }

    #[test]
    fn test_serialize_stored_secrets_round_trips_special_values() {
        let values = [
            " leading and trailing spaces ",
            "line one\nline two",
            "quotes: \"double\" and \\'single\\'",
            r"backslashes\\stay\",
        ];
        let mut stored = BTreeMap::new();
        for (index, value) in values.iter().enumerate() {
            stored.insert(
                format!("KEY_{index}"),
                StoredSecret {
                    value: (*value).to_string(),
                    ..StoredSecret::default()
                },
            );
        }

        let serialized = GpgBackend::serialize_stored_secrets(&stored);
        let parsed = GpgBackend::parse_stored_secrets(&serialized);

        for (index, value) in values.iter().enumerate() {
            assert_eq!(parsed[&format!("KEY_{index}")].value, *value);
        }
    }

    #[test]
    fn test_metadata_comment_format() {
        let comment = GpgBackend::metadata_comment("project", "my-project");
        assert_eq!(comment, "# pw-env: project=my-project");
    }

    #[test]
    fn test_parse_env_content_empty() {
        let map = GpgBackend::parse_env_content("");
        assert!(map.is_empty());
    }

    #[test]
    fn test_gpg_file_path() {
        let config = Config {
            defaults: Defaults::default(),
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };
        let dir = std::path::Path::new("/some/dir");
        let path = GpgBackend::gpg_file_path(dir, &config);
        assert_eq!(path, PathBuf::from("/some/dir/.env.gpg"));
    }

    #[test]
    fn test_gpg_file_path_keeps_existing_path_within_project_dir() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let nested = temp_dir.path().join("secrets").join("custom.gpg");
        std::fs::create_dir_all(nested.parent().unwrap()).unwrap();
        std::fs::write(&nested, "ciphertext").unwrap();

        let config = Config {
            defaults: Defaults {
                gpg: crate::config::GpgConfig {
                    file_pattern: "secrets/custom.gpg".to_string(),
                    recipient: None,
                },
                ..Defaults::default()
            },
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };

        let path = GpgBackend::gpg_file_path(temp_dir.path(), &config);
        assert_eq!(path, nested);
    }

    #[test]
    fn test_gpg_file_path_falls_back_when_existing_path_escapes_project_dir() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let outside_dir = tempfile::TempDir::new().unwrap();
        let outside_file = outside_dir.path().join("outside.gpg");
        let linked_path = temp_dir.path().join("linked.gpg");
        std::fs::write(&outside_file, "ciphertext").unwrap();
        std::os::unix::fs::symlink(&outside_file, &linked_path).unwrap();

        let config = Config {
            defaults: Defaults {
                gpg: crate::config::GpgConfig {
                    file_pattern: "linked.gpg".to_string(),
                    recipient: None,
                },
                ..Defaults::default()
            },
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };

        let path = GpgBackend::gpg_file_path(temp_dir.path(), &config);
        assert_eq!(path, temp_dir.path().join(".env.gpg"));
    }

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

    #[test]
    fn test_parse_stored_secrets_reads_metadata_comments() {
        let content = r#"
# pw-env: project=service-a
# pw-env: migrated_from=/tmp/work/service-a
# pw-env: created-with=pw-env (0.0.0)
API_KEY=secret
PLAIN=value
"#;

        let stored = GpgBackend::parse_stored_secrets(content);

        assert_eq!(
            stored.get("API_KEY").unwrap().project.as_deref(),
            Some("service-a")
        );
        assert_eq!(
            stored.get("API_KEY").unwrap().migrated_from.as_deref(),
            Some("/tmp/work/service-a")
        );
        assert_eq!(
            stored.get("API_KEY").unwrap().created_with.as_deref(),
            Some("pw-env (0.0.0)")
        );
        assert_eq!(stored.get("PLAIN").unwrap().project, None);
    }

    #[test]
    fn test_serialize_stored_secrets_emits_metadata_comments() {
        let mut stored = BTreeMap::new();
        stored.insert(
            "API_KEY".to_string(),
            StoredSecret {
                value: "secret".to_string(),
                project: Some("service-a".to_string()),
                migrated_from: Some("/tmp/work/service-a".to_string()),
                created_with: Some(format!("pw-env ({})", env!("CARGO_PKG_VERSION"))),
            },
        );

        let serialized = GpgBackend::serialize_stored_secrets(&stored);

        assert!(serialized.contains("# pw-env: project=service-a"));
        assert!(serialized.contains("# pw-env: migrated_from=/tmp/work/service-a"));
        assert!(serialized.contains(&format!(
            "# pw-env: created-with=pw-env ({})",
            env!("CARGO_PKG_VERSION")
        )));
        assert!(serialized.contains("API_KEY=\"secret\""));
    }

    // ------- Error-path tests (no mock needed) -------

    fn make_gpg_resolve_context<'a>(
        config: &'a Config,
        dir: &'a std::path::Path,
    ) -> super::super::ResolveContext<'a> {
        super::super::ResolveContext {
            dir,
            config,
            project: None,
            repository: None,
            interaction: None,
        }
    }

    #[test]
    fn load_all_returns_err_when_gpg_file_missing() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let config = Config {
            defaults: Defaults::default(),
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };
        let ctx = make_gpg_resolve_context(&config, temp_dir.path());
        let result = GpgBackend::resolve_all(&ctx);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("not found") || msg.contains(".env.gpg"));
    }

    #[test]
    fn backend_resolve_returns_err_when_gpg_file_missing() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let config = Config {
            defaults: Defaults::default(),
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };
        let ctx = make_gpg_resolve_context(&config, temp_dir.path());
        let backend = GpgBackend;
        let result = backend.resolve("ANY_KEY", None, &ctx);
        assert!(result.is_err());
    }

    #[test]
    fn backend_has_returns_err_when_gpg_file_missing() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let config = Config {
            defaults: Defaults::default(),
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };
        let ctx = make_gpg_resolve_context(&config, temp_dir.path());
        let backend = GpgBackend;
        let result = backend.has("ANY_KEY", &ctx);
        assert!(result.is_err());
    }

    #[test]
    fn load_all_stored_secrets_returns_err_when_gpg_file_missing() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let config = Config {
            defaults: Defaults::default(),
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };
        let ctx = make_gpg_resolve_context(&config, temp_dir.path());

        let result = GpgBackend::load_all_stored_secrets(&ctx);

        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains(".env.gpg"));
    }

    // ------- Mock-gpg infrastructure -------

    fn with_mock_gpg<F: FnOnce()>(decrypt_output: &str, f: F) {
        let _guard = super::super::MOCK_PATH_MUTEX
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::TempDir::new().unwrap();
        let script_path = dir.path().join("gpg");
        // Script echoes the preset decrypt output when --decrypt is given; exits 0 for anything else
        let script = format!(
            "#!/bin/sh\nif [ \"$1\" = \"--decrypt\" ]; then\nprintf '%s' '{}'\nelse\nfor arg do\n  [ \"$arg\" != \"--output\" ] || exit 91\ndone\ncat\nfi\nexit 0\n",
            decrypt_output.replace('\'', "'\\''")
        );
        std::fs::write(&script_path, &script).unwrap();
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

    fn with_failing_mock_gpg<F: FnOnce()>(script: &str, f: F) {
        let _guard = super::super::MOCK_PATH_MUTEX
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::TempDir::new().unwrap();
        let script_path = dir.path().join("gpg");
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
        unsafe { std::env::set_var("PATH", &new_path) };
        f();
        unsafe { std::env::set_var("PATH", &old_path) };
    }

    #[test]
    fn with_failing_mock_gpg_executes_callback() {
        let called = Cell::new(false);
        with_failing_mock_gpg("#!/bin/sh\nexit 1\n", || {
            called.set(true);
        });
        assert!(called.get());
    }

    #[test]
    fn with_mock_gpg_executes_callback() {
        let called = Cell::new(false);
        with_mock_gpg("", || {
            called.set(true);
        });
        assert!(called.get(), "expected callback to be executed");
    }

    #[test]
    fn load_all_returns_values_with_mock_gpg() {
        let gpg_content = "SECRET_KEY=top_secret\nDB_HOST=localhost\n";
        with_mock_gpg(gpg_content, || {
            let temp_dir = tempfile::TempDir::new().unwrap();
            // Create a placeholder .env.gpg file (mock ignores its content)
            let gpg_file = temp_dir.path().join(".env.gpg");
            std::fs::write(&gpg_file, "placeholder").unwrap();

            let config = Config {
                defaults: Defaults::default(),
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = make_gpg_resolve_context(&config, temp_dir.path());
            let result = GpgBackend::resolve_all(&ctx).unwrap();
            assert_eq!(
                result.get("SECRET_KEY").map(|s| s.as_str()),
                Some("top_secret")
            );
            assert_eq!(result.get("DB_HOST").map(|s| s.as_str()), Some("localhost"));
        });
    }

    #[test]
    fn backend_resolve_returns_value_with_mock_gpg() {
        let gpg_content = "API_KEY=my_api_key\n";
        with_mock_gpg(gpg_content, || {
            let temp_dir = tempfile::TempDir::new().unwrap();
            let gpg_file = temp_dir.path().join(".env.gpg");
            std::fs::write(&gpg_file, "placeholder").unwrap();

            let config = Config {
                defaults: Defaults::default(),
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = make_gpg_resolve_context(&config, temp_dir.path());
            let backend = GpgBackend;
            let result = backend.resolve("API_KEY", None, &ctx);
            assert_eq!(result.unwrap(), "my_api_key");
        });
    }

    #[test]
    fn backend_resolve_returns_err_for_missing_key_with_mock_gpg() {
        let gpg_content = "OTHER_KEY=some_value\n";
        with_mock_gpg(gpg_content, || {
            let temp_dir = tempfile::TempDir::new().unwrap();
            let gpg_file = temp_dir.path().join(".env.gpg");
            std::fs::write(&gpg_file, "placeholder").unwrap();

            let config = Config {
                defaults: Defaults::default(),
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = make_gpg_resolve_context(&config, temp_dir.path());
            let backend = GpgBackend;
            let result = backend.resolve("MISSING_KEY", None, &ctx);
            assert!(result.is_err());
        });
    }

    #[test]
    fn backend_has_returns_true_with_mock_gpg() {
        let gpg_content = "PRESENT_KEY=value\n";
        with_mock_gpg(gpg_content, || {
            let temp_dir = tempfile::TempDir::new().unwrap();
            let gpg_file = temp_dir.path().join(".env.gpg");
            std::fs::write(&gpg_file, "placeholder").unwrap();

            let config = Config {
                defaults: Defaults::default(),
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = make_gpg_resolve_context(&config, temp_dir.path());
            let backend = GpgBackend;
            assert!(backend.has("PRESENT_KEY", &ctx).unwrap());
        });
    }

    #[test]
    fn backend_has_returns_false_with_mock_gpg_when_key_absent() {
        let gpg_content = "OTHER_KEY=value\n";
        with_mock_gpg(gpg_content, || {
            let temp_dir = tempfile::TempDir::new().unwrap();
            let gpg_file = temp_dir.path().join(".env.gpg");
            std::fs::write(&gpg_file, "placeholder").unwrap();

            let config = Config {
                defaults: Defaults::default(),
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = make_gpg_resolve_context(&config, temp_dir.path());
            let backend = GpgBackend;
            assert!(!backend.has("MISSING_KEY", &ctx).unwrap());
        });
    }

    #[test]
    fn backend_name_is_gpg() {
        assert_eq!(GpgBackend.name(), "GPG");
    }

    #[cfg(unix)]
    #[test]
    fn private_gpg_staging_directory_is_owner_only() {
        use cap_std::fs::{Dir, MetadataExt as CapMetadataExt, PermissionsExt};
        use std::os::unix::fs::MetadataExt as StdMetadataExt;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let parent = Dir::open_ambient_dir(temp_dir.path(), cap_std::ambient_authority()).unwrap();
        let encrypted_output = tempfile::tempfile().unwrap();
        let owner_uid = encrypted_output.metadata().unwrap().uid();
        let stage = create_private_staging_dir(&parent, Path::new("stage"), owner_uid).unwrap();
        let metadata = stage.metadata(".").unwrap();
        assert_eq!(metadata.uid(), owner_uid);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        stage.remove_open_dir().unwrap();
    }

    #[test]
    fn encrypt_to_file_writes_content_with_mock_gpg() {
        with_mock_gpg("", || {
            let temp_dir = tempfile::TempDir::new().unwrap();
            let path = temp_dir.path().join(".env.gpg");

            let location = GpgOutputLocation::from_path(&path).unwrap();
            GpgBackend::encrypt_to_file("KEY=value\n", &location, "test@example.com").unwrap();

            assert_eq!(std::fs::read_to_string(path).unwrap(), "KEY=value\n");
        });
    }

    #[test]
    fn store_returns_err_when_recipient_not_configured() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let config = Config {
            defaults: Defaults::default(), // no GPG recipient
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };
        let ctx = super::super::StoreContext {
            dir: temp_dir.path(),
            config: &config,
            project: None,
            repository: None,
        };
        let result = GpgBackend.store("MY_KEY", "my-value", &ctx);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("GPG recipient must be configured"));
    }

    #[test]
    fn store_creates_new_file_with_mock_gpg() {
        with_mock_gpg("", || {
            let temp_dir = tempfile::TempDir::new().unwrap();
            let config = Config {
                defaults: Defaults {
                    gpg: crate::config::GpgConfig {
                        recipient: Some("test@example.com".to_string()),
                        file_pattern: ".env.gpg".to_string(),
                    },
                    ..Defaults::default()
                },
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = super::super::StoreContext {
                dir: temp_dir.path(),
                config: &config,
                project: None,
                repository: None,
            };
            // No .env.gpg file exists yet — store should create it via mock gpg encrypt
            let result = GpgBackend.store("NEW_KEY", "new-value", &ctx);
            assert!(result.is_ok(), "store failed: {:?}", result);
        });
    }

    #[test]
    fn store_appends_to_existing_file_with_mock_gpg() {
        // The mock gpg script returns an existing secret when decrypting
        with_mock_gpg("EXISTING_KEY=existing-value\n", || {
            let temp_dir = tempfile::TempDir::new().unwrap();
            let gpg_file = temp_dir.path().join(".env.gpg");
            std::fs::write(&gpg_file, "placeholder").unwrap();
            let config = Config {
                defaults: Defaults {
                    gpg: crate::config::GpgConfig {
                        recipient: Some("test@example.com".to_string()),
                        file_pattern: ".env.gpg".to_string(),
                    },
                    ..Defaults::default()
                },
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = super::super::StoreContext {
                dir: temp_dir.path(),
                config: &config,
                project: Some("my-project".to_string()),
                repository: None,
            };
            // File exists → load_all_stored_secrets is called (decrypt), then encrypt
            let result = GpgBackend.store("NEW_KEY", "new-value", &ctx);
            assert!(result.is_ok(), "store failed: {:?}", result);
            let encrypted = std::fs::read_to_string(&gpg_file).unwrap();
            assert!(encrypted.contains("EXISTING_KEY=\"existing-value\""));
            assert!(encrypted.contains("NEW_KEY=\"new-value\""));
        });
    }

    #[test]
    fn failed_encryption_leaves_existing_ciphertext_unchanged() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let gpg_file = temp_dir.path().join(".env.gpg");
        let original = b"existing ciphertext";
        std::fs::write(&gpg_file, original).unwrap();
        let script = "#!/bin/sh\nif [ \"$1\" = \"--decrypt\" ]; then\nprintf 'EXISTING_KEY=existing-value\\n'\nexit 0\nfi\nfor arg do\n  [ \"$arg\" != \"--output\" ] || exit 91\ndone\ncat >/dev/null\nprintf 'partial ciphertext'\nexit 1\n";

        with_failing_mock_gpg(script, || {
            let config = Config {
                defaults: Defaults {
                    gpg: crate::config::GpgConfig {
                        file_pattern: ".env.gpg".to_string(),
                        recipient: Some("test@example.com".to_string()),
                    },
                    ..Defaults::default()
                },
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = super::super::StoreContext {
                dir: temp_dir.path(),
                config: &config,
                project: None,
                repository: None,
            };
            let error = GpgBackend
                .store("NEW_KEY", "new-value", &ctx)
                .expect_err("failed encryption must not publish partial output");
            assert!(error.to_string().contains("gpg encrypt failed"));
        });

        assert_eq!(std::fs::read(&gpg_file).unwrap(), original);
    }

    #[test]
    fn store_refuses_to_replace_existing_file_when_decryption_fails() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let gpg_file = temp_dir.path().join(".env.gpg");
        let original = b"existing ciphertext";
        std::fs::write(&gpg_file, original).unwrap();
        let encryption_marker = temp_dir.path().join("encryption-invoked");
        let script = format!(
            "#!/bin/sh\nif [ \"$1\" = \"--decrypt\" ]; then\n  echo 'decrypt failed' >&2\n  exit 1\nfi\ntouch '{}'\nexit 0\n",
            encryption_marker.display()
        );

        with_failing_mock_gpg(&script, || {
            let config = Config {
                defaults: Defaults {
                    gpg: crate::config::GpgConfig {
                        recipient: Some("test@example.com".to_string()),
                        file_pattern: ".env.gpg".to_string(),
                    },
                    ..Defaults::default()
                },
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = super::super::StoreContext {
                dir: temp_dir.path(),
                config: &config,
                project: None,
                repository: None,
            };
            let error = GpgBackend
                .store("NEW_KEY", "new-value", &ctx)
                .expect_err("decryption failure must abort the update");
            assert!(error.to_string().contains("Refusing to overwrite"));
        });

        assert_eq!(std::fs::read(&gpg_file).unwrap(), original);
        assert!(!encryption_marker.exists());
    }

    #[test]
    fn load_all_stored_secrets_reads_mocked_gpg_content() {
        let gpg_content = "\
# pw-env: project=service-a\n\
# pw-env: migrated_from=/tmp/work/service-a\n\
# pw-env: created-with=pw-env (0.0.0)\n\
API_KEY=secret\n";

        with_mock_gpg(gpg_content, || {
            let temp_dir = tempfile::TempDir::new().unwrap();
            let gpg_file = temp_dir.path().join(".env.gpg");
            std::fs::write(&gpg_file, "placeholder").unwrap();

            let config = Config {
                defaults: Defaults::default(),
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let ctx = make_gpg_resolve_context(&config, temp_dir.path());

            let stored = GpgBackend::load_all_stored_secrets(&ctx).unwrap();
            let secret = stored.get("API_KEY").unwrap();

            assert_eq!(stored.len(), 1);
            assert_eq!(secret.value, "secret");
            assert_eq!(secret.project.as_deref(), Some("service-a"));
            assert_eq!(secret.migrated_from.as_deref(), Some("/tmp/work/service-a"));
            assert_eq!(secret.created_with.as_deref(), Some("pw-env (0.0.0)"));
        });
    }

    #[test]
    fn test_parse_stored_secrets_unmatched_leading_double_quote_not_stripped() {
        // Value starts with '"' but does not end with '"' — no stripping should occur.
        // This kills the && → || mutation at the double-quote condition.
        let content = "KEY=\"abc\n";
        let stored = GpgBackend::parse_stored_secrets(content);
        assert_eq!(stored.get("KEY").unwrap().value, "\"abc");
    }

    #[test]
    fn test_parse_stored_secrets_unmatched_leading_single_quote_not_stripped() {
        // Value starts with "'" but does not end with "'" — no stripping should occur.
        // This kills the && → || mutation at the single-quote condition.
        let content = "KEY='abc\n";
        let stored = GpgBackend::parse_stored_secrets(content);
        assert_eq!(stored.get("KEY").unwrap().value, "'abc");
    }

    #[test]
    fn test_gpg_file_path_rejects_traversal() {
        let config = Config {
            defaults: Defaults {
                gpg: crate::config::GpgConfig {
                    file_pattern: "../../etc/shadow.gpg".to_string(),
                    recipient: None,
                },
                ..Defaults::default()
            },
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };
        let dir = std::path::Path::new("/some/dir");
        let path = GpgBackend::gpg_file_path(dir, &config);
        // Should fall back to default rather than allowing traversal
        assert_eq!(path, PathBuf::from("/some/dir/.env.gpg"));
    }

    #[test]
    fn test_gpg_file_path_allows_safe_pattern() {
        let config = Config {
            defaults: Defaults {
                gpg: crate::config::GpgConfig {
                    file_pattern: "secrets.gpg".to_string(),
                    recipient: None,
                },
                ..Defaults::default()
            },
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };
        let dir = std::path::Path::new("/some/dir");
        let path = GpgBackend::gpg_file_path(dir, &config);
        assert_eq!(path, PathBuf::from("/some/dir/secrets.gpg"));
    }

    #[test]
    fn gpg_backend_reference_url_returns_none() {
        let config = Config {
            defaults: Defaults::default(),
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };
        let ctx = super::super::StoreContext {
            dir: std::path::Path::new("/tmp/project"),
            config: &config,
            project: None,
            repository: None,
        };

        // GpgBackend uses the default trait impl which returns None.
        assert_eq!(GpgBackend.reference_url("ANY_KEY", &ctx), None);
    }
}
