use anyhow::{Context, Result, bail};
use cap_std::fs::Dir;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

use super::{
    Backend, CREATED_WITH_FIELD_NAME, GpgStoreBindingAction, MIGRATED_FROM_FIELD_NAME,
    PROJECT_FIELD_NAME, ResolutionInteraction, ResolveContext, StoreContext,
};

pub struct GpgBackend;

struct GpgFileLocation {
    parent: Dir,
    file_name: PathBuf,
    display_path: PathBuf,
}

impl GpgFileLocation {
    fn open(&self) -> Result<cap_std::fs::File> {
        self.parent.open(&self.file_name).with_context(|| {
            format!(
                "Failed to open GPG encrypted file {}",
                self.display_path.display()
            )
        })
    }

    fn open_optional(&self) -> Result<Option<cap_std::fs::File>> {
        match self.parent.open(&self.file_name) {
            Ok(file) => Ok(Some(file)),
            Err(error) => match error.kind() {
                std::io::ErrorKind::NotFound => {
                    match self.parent.symlink_metadata(&self.file_name) {
                        Err(metadata_error) => match metadata_error.kind() {
                            std::io::ErrorKind::NotFound => Ok(None),
                            _ => Err(metadata_error).with_context(|| {
                                format!(
                                    "Failed to inspect configured GPG file {}",
                                    self.display_path.display()
                                )
                            }),
                        },
                        Ok(_) => Err(error).with_context(|| {
                            format!(
                                "Configured GPG file exists but cannot be opened safely: {}",
                                self.display_path.display()
                            )
                        }),
                    }
                }
                _ => Err(error).with_context(|| {
                    format!(
                        "Failed to open GPG encrypted file {}",
                        self.display_path.display()
                    )
                }),
            },
        }
    }

    fn replace_atomically(&self, contents: &[u8], owner_uid: u32) -> Result<()> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        self.replace_atomically_with_nonce(contents, owner_uid, nonce)
    }

    fn replace_atomically_with_nonce(
        &self,
        contents: &[u8],
        owner_uid: u32,
        nonce: u128,
    ) -> Result<()> {
        for attempt in 0..100u32 {
            let staging_name = PathBuf::from(format!(
                ".pw-env-gpg-{}-{nonce}-{attempt}.tmpdir",
                std::process::id()
            ));
            let staging_dir =
                match create_private_staging_dir(&self.parent, &staging_name, owner_uid) {
                    Ok(dir) => dir,
                    Err(error) => match error.kind() {
                        std::io::ErrorKind::AlreadyExists => continue,
                        _ => {
                            return Err(error).with_context(|| {
                                format!(
                                    "Failed to create private GPG staging directory beside {}",
                                    self.display_path.display()
                                )
                            });
                        }
                    },
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

#[cfg(windows)]
fn windows_directory_create_options() -> u32 {
    windows_sys::Wdk::Storage::FileSystem::FILE_DIRECTORY_FILE
        | windows_sys::Wdk::Storage::FileSystem::FILE_SYNCHRONOUS_IO_NONALERT
}

#[cfg(windows)]
fn windows_file_create_options() -> u32 {
    windows_sys::Wdk::Storage::FileSystem::FILE_NON_DIRECTORY_FILE
        | windows_sys::Wdk::Storage::FileSystem::FILE_SYNCHRONOUS_IO_NONALERT
}

#[cfg(windows)]
fn windows_file_share_mode() -> u32 {
    windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
        | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE
}

#[cfg(windows)]
fn ntstatus_failed(status: i32) -> bool {
    status < 0
}

fn create_private_staging_dir(parent: &Dir, name: &Path, owner_uid: u32) -> std::io::Result<Dir> {
    #[cfg(unix)]
    {
        use cap_std::fs::{DirBuilder, DirBuilderExt};
        use cap_std::fs::{MetadataExt, PermissionsExt};

        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        parent.create_dir_with(name, &builder)?;
        let directory = parent.open_dir(name)?;
        let metadata = directory.metadata(".")?;
        let mode = metadata.permissions().mode() & 0o777;
        validate_unix_staging_directory(metadata.uid(), owner_uid, mode)?;
        return Ok(directory);
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Security::{CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE};

        let _ = owner_uid;
        let directory_file = create_windows_private_object(
            parent,
            name.as_os_str(),
            windows_sys::core::w!("D:P(A;OICI;FA;;;OW)"),
            windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY,
            windows_directory_create_options(),
        )?;
        verify_private_windows_dacl(
            directory_file.as_raw_handle(),
            (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
        )?;
        return Ok(Dir::from_std_file(directory_file));
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, name, owner_uid);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "secure GPG staging directories are unsupported on this platform",
        ))
    }
}

#[cfg(unix)]
fn validate_unix_staging_directory(uid: u32, owner_uid: u32, mode: u32) -> std::io::Result<()> {
    if uid != owner_uid || mode & 0o077 != 0 || mode & 0o700 != 0o700 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "GPG staging directory is not owned by the current user with owner-only access",
        ));
    }
    Ok(())
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
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    let mut name_wide: Vec<u16> = name.encode_wide().collect();
    let name_length_bytes = windows_name_length_bytes(name_wide.len())?;
    let mut object_name = windows_sys::Win32::Foundation::UNICODE_STRING {
        Length: name_length_bytes,
        MaximumLength: name_length_bytes,
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
            windows_file_share_mode(),
            FILE_CREATE,
            create_options,
            null(),
            0,
        )
    };
    unsafe { LocalFree(security_descriptor as _) };
    if ntstatus_failed(status) {
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(std::io::Error::from_raw_os_error(code as i32));
    }

    // Omitting FILE_SHARE_DELETE pins the just-created entry while it is used.
    Ok(unsafe { std::fs::File::from_raw_handle(raw_handle) })
}

#[cfg(windows)]
fn windows_name_length_bytes(name_units: usize) -> std::io::Result<u16> {
    if name_units == 0 || name_units > (u16::MAX as usize / 2) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "GPG staging entry name is empty or too long",
        ));
    }
    Ok((name_units * 2) as u16)
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
        {
            return Err(std::io::Error::last_os_error());
        }
        if control & SE_DACL_PROTECTED == 0 {
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
        {
            return Err(std::io::Error::last_os_error());
        }
        if acl_info.AceCount != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "GPG staging object DACL is not owner-only",
            ));
        }

        let mut ace_pointer = null_mut();
        if unsafe { GetAce(dacl, 0, &mut ace_pointer) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if ace_pointer.is_null() {
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

fn create_private_staging_file(staging_dir: &Dir) -> std::io::Result<cap_std::fs::File> {
    #[cfg(unix)]
    {
        use cap_std::fs::{OpenOptions, OpenOptionsExt};

        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        return staging_dir.open_with("ciphertext", &options);
    }

    #[cfg(windows)]
    {
        use std::ffi::OsStr;
        use std::os::windows::io::AsRawHandle;

        let file = create_windows_private_object(
            staging_dir,
            OsStr::new("ciphertext"),
            windows_sys::core::w!("D:P(A;;FA;;;OW)"),
            windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL,
            windows_file_create_options(),
        )?;
        verify_private_windows_dacl(file.as_raw_handle(), 0)?;
        return Ok(cap_std::fs::File::from_std(file));
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = staging_dir;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "secure GPG staging files are unsupported on this platform",
        ))
    }
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

const GPG_STORE_BINDING_FIELD: &str = "gpg-store-binding";
const GPG_STORE_BINDING_VERSION: u32 = 1;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct GpgStoreBinding {
    version: u32,
    project_id: String,
    project_path: String,
    recipients: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct StoredSecret {
    value: String,
    project: Option<String>,
    migrated_from: Option<String>,
    created_with: Option<String>,
}

impl GpgBackend {
    fn relative_gpg_path(pattern: &str) -> Result<PathBuf> {
        Self::normalize_relative_gpg_path(Path::new(pattern))
    }

    fn normalize_relative_gpg_path(input: &Path) -> Result<PathBuf> {
        use std::path::Component;

        let mut path = PathBuf::new();
        for component in input.components() {
            match component {
                Component::Normal(name) => path.push(name),
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    bail!(
                        "GPG file_pattern must be a project-relative path without parent components"
                    )
                }
            }
        }
        if path.as_os_str().is_empty() {
            bail!("GPG file_pattern must name a file inside the project directory");
        }
        Ok(path)
    }

    fn gpg_file_location(
        ctx_dir: &Path,
        config: &crate::config::Config,
    ) -> Result<GpgFileLocation> {
        let gpg_config = config.effective_gpg(ctx_dir);
        let relative_path = Self::relative_gpg_path(&gpg_config.file_pattern)?;
        let project_root = std::fs::canonicalize(ctx_dir).with_context(|| {
            format!("Failed to resolve project directory {}", ctx_dir.display())
        })?;
        let project_dir = Dir::open_ambient_dir(&project_root, cap_std::ambient_authority())
            .with_context(|| {
                format!(
                    "Failed to open project directory {}",
                    project_root.display()
                )
            })?;

        // cap-std canonicalizes relative to the directory capability, so this
        // path is project-relative and cannot escape the opened project root.
        match project_dir.canonicalize(&relative_path) {
            Ok(resolved_relative) => {
                let resolved_relative = Self::normalize_relative_gpg_path(&resolved_relative)?;
                let resolved_name = resolved_relative
                    .file_name()
                    .map(PathBuf::from)
                    .context("Resolved GPG path does not name a file")?;
                let resolved_parent_relative = resolved_relative
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty());
                let resolved_parent = match resolved_parent_relative {
                    Some(parent) => project_dir.open_dir(parent).with_context(|| {
                        format!(
                            "GPG file_pattern '{}' resolves outside the project directory",
                            gpg_config.file_pattern
                        )
                    })?,
                    None => project_dir
                        .try_clone()
                        .context("Failed to clone project directory")?,
                };
                Ok(GpgFileLocation {
                    parent: resolved_parent,
                    file_name: resolved_name,
                    display_path: project_root.join(resolved_relative),
                })
            }
            Err(error) => match error.kind() {
                std::io::ErrorKind::NotFound => {
                    let configured_name = relative_path.file_name().map(PathBuf::from).context(
                        "GPG file_pattern must name a file inside the project directory",
                    )?;
                    match project_dir.symlink_metadata(&relative_path) {
                        Err(metadata_error) => match metadata_error.kind() {
                            std::io::ErrorKind::NotFound => {
                                let relative_parent = relative_path
                                    .parent()
                                    .filter(|parent| !parent.as_os_str().is_empty());
                                let (parent, display_parent) = match relative_parent {
                                    Some(parent) => {
                                        let canonical_parent = project_dir
                                    .canonicalize(parent)
                                    .with_context(|| {
                                        format!(
                                            "GPG file_pattern '{}' has a parent outside the project directory",
                                            gpg_config.file_pattern
                                        )
                                    })?;
                                        let canonical_parent =
                                            if canonical_parent.as_os_str().is_empty() {
                                                PathBuf::from(".")
                                            } else {
                                                canonical_parent
                                            };
                                        let parent = project_dir
                                    .open_dir(&canonical_parent)
                                    .with_context(|| {
                                        format!(
                                            "GPG file_pattern '{}' has a parent outside the project directory",
                                            gpg_config.file_pattern
                                        )
                                    })?;
                                        let display_parent = project_root.join(canonical_parent);
                                        (parent, display_parent)
                                    }
                                    None => (
                                        project_dir
                                            .try_clone()
                                            .context("Failed to clone project directory")?,
                                        project_root.clone(),
                                    ),
                                };
                                Ok(GpgFileLocation {
                                    parent,
                                    file_name: configured_name.clone(),
                                    display_path: display_parent.join(configured_name),
                                })
                            }
                            _ => Err(metadata_error).with_context(|| {
                                format!(
                                    "Failed to inspect configured GPG file {}",
                                    relative_path.display()
                                )
                            }),
                        },
                        Ok(_) => Err(error).with_context(|| {
                            format!(
                                "Configured GPG file exists but cannot be resolved safely: {}",
                                relative_path.display()
                            )
                        }),
                    }
                }
                _ => Err(error).with_context(|| {
                    format!(
                        "Failed to resolve configured GPG file {}",
                        gpg_config.file_pattern
                    )
                }),
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn validated_store_path(
        ctx_dir: &Path,
        config: &crate::config::Config,
    ) -> Result<PathBuf> {
        Ok(Self::gpg_file_location(ctx_dir, config)?.display_path)
    }

    fn metadata_comment(name: &str, value: &str) -> String {
        format!("# pw-env: {name}={value}")
    }

    fn project_identity(ctx_dir: &Path) -> Result<(PathBuf, String)> {
        let project_path = std::fs::canonicalize(ctx_dir).with_context(|| {
            format!(
                "Failed to resolve GPG project directory {}",
                ctx_dir.display()
            )
        })?;
        let mut hasher = Sha256::new();
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            hasher.update(b"unix\0");
            hasher.update(project_path.as_os_str().as_bytes());
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            hasher.update(b"windows\0");
            for unit in project_path.as_os_str().encode_wide() {
                hasher.update(unit.to_le_bytes());
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            hasher.update(b"other\0");
            hasher.update(project_path.to_string_lossy().as_bytes());
        }
        let project_id = Sha256::finalize(hasher)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok((project_path, project_id))
    }

    fn resolve_recipient_fingerprint(selector: &str) -> Result<String> {
        if selector.trim().is_empty() {
            bail!("GPG recipient selector cannot be empty");
        }
        let mut command = Command::new("gpg");
        command.args([
            "--batch",
            "--with-colons",
            "--fingerprint",
            "--list-keys",
            "--",
        ]);
        command.arg(selector);
        let output = super::run_command_with_timeout(
            command,
            "Failed to execute `gpg` while resolving the configured recipient",
        )?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to resolve GPG recipient {selector:?}: {stderr}");
        }
        let stdout = String::from_utf8(output.stdout)
            .context("GPG recipient listing was not valid UTF-8")?;
        Self::parse_primary_recipient_fingerprint(selector, &stdout)
    }

    fn parse_primary_recipient_fingerprint(selector: &str, stdout: &str) -> Result<String> {
        let mut primary_fingerprints: Vec<Option<String>> = Vec::new();
        let mut reading_primary_fingerprint = false;
        for line in stdout.lines() {
            let mut fields = line.split(':');
            match fields.next() {
                Some("pub") => {
                    primary_fingerprints.push(None);
                    reading_primary_fingerprint = true;
                }
                Some("sub") | Some("sec") | Some("ssb") => {
                    reading_primary_fingerprint = false;
                }
                Some("fpr") if reading_primary_fingerprint => {
                    let fingerprint = line
                        .split(':')
                        .nth(9)
                        .filter(|value| {
                            !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                        })
                        .context("GPG returned an invalid public-key fingerprint")?
                        .to_ascii_uppercase();
                    if let Some(primary) = primary_fingerprints.last_mut() {
                        *primary = Some(fingerprint);
                    }
                    reading_primary_fingerprint = false;
                }
                _ => {}
            }
        }
        let primary_fingerprints = primary_fingerprints
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        match primary_fingerprints.as_slice() {
            [fingerprint] => Ok(fingerprint.clone()),
            [] => bail!("GPG recipient selector {selector:?} did not resolve to a public key"),
            _ => bail!(
                "GPG recipient selector {selector:?} resolves to multiple public keys; use a fingerprint"
            ),
        }
    }

    fn parse_store_binding(content: &str) -> Result<Option<GpgStoreBinding>> {
        let mut binding = None;
        for line in content.lines().map(str::trim) {
            let Some(value) = line
                .strip_prefix("# pw-env: ")
                .and_then(|metadata| metadata.strip_prefix(&format!("{GPG_STORE_BINDING_FIELD}=")))
            else {
                continue;
            };
            if binding.is_some() {
                bail!("GPG store contains duplicate binding metadata");
            }
            let mut parsed: GpgStoreBinding = serde_json::from_str(value)
                .context("GPG store contains invalid binding metadata")?;
            if parsed.version != GPG_STORE_BINDING_VERSION
                || parsed.project_id.len() != 64
                || !parsed
                    .project_id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                || parsed.project_path.is_empty()
                || parsed.recipients.is_empty()
                || parsed.recipients.iter().any(|fingerprint| {
                    !matches!(fingerprint.len(), 40 | 64)
                        || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            {
                bail!("GPG store contains unsupported or invalid binding metadata");
            }
            for fingerprint in &mut parsed.recipients {
                *fingerprint = fingerprint.to_ascii_uppercase();
            }
            binding = Some(parsed);
        }
        Ok(binding)
    }

    fn serialize_bound_store(
        secrets: &BTreeMap<String, StoredSecret>,
        binding: &GpgStoreBinding,
    ) -> String {
        let binding_json = serde_json::to_string(binding)
            .expect("serializing GPG store binding metadata cannot fail");
        format!(
            "{}\n{}",
            Self::metadata_comment(GPG_STORE_BINDING_FIELD, &binding_json),
            Self::serialize_stored_secrets(secrets)
        )
    }

    fn confirm_store_binding(
        interaction: Option<&dyn ResolutionInteraction>,
        action: GpgStoreBindingAction,
        project_path: &Path,
        previous_recipients: &[String],
        new_recipients: &[String],
    ) -> Result<()> {
        let approved = match interaction {
            Some(interaction) => interaction.confirm_gpg_store_binding(
                action,
                project_path,
                previous_recipients,
                new_recipients,
            )?,
            None => false,
        };
        if approved {
            return Ok(());
        }
        let operation = match action {
            GpgStoreBindingAction::EnrollNewStore => "new GPG store enrollment",
            GpgStoreBindingAction::EnrollLegacyStore => "legacy GPG store enrollment",
            GpgStoreBindingAction::RotateRecipients => "GPG recipient rotation",
        };
        bail!(
            "{operation} requires explicit interactive confirmation; rerun `pw-env add` or `pw-env migrate` in an interactive terminal and approve the binding prompt"
        )
    }

    fn bind_store_for_write(
        existing_content: Option<&str>,
        ctx_dir: &Path,
        recipient_selector: &str,
        interaction: Option<&dyn ResolutionInteraction>,
    ) -> Result<GpgStoreBinding> {
        let (project_path, project_id) = Self::project_identity(ctx_dir)?;
        let project_path_display = project_path.to_string_lossy().into_owned();
        let mut resolved_recipients =
            vec![Self::resolve_recipient_fingerprint(recipient_selector)?];
        resolved_recipients.sort();

        let action = match existing_content {
            None => Some(GpgStoreBindingAction::EnrollNewStore),
            Some(content) => match Self::parse_store_binding(content)? {
                None => Some(GpgStoreBindingAction::EnrollLegacyStore),
                Some(binding) => {
                    if binding.project_id != project_id
                        || binding.project_path != project_path_display
                    {
                        bail!(
                            "GPG store is bound to a different project; cross-project stores cannot be rewritten"
                        );
                    }
                    if binding.recipients != resolved_recipients {
                        Self::confirm_store_binding(
                            interaction,
                            GpgStoreBindingAction::RotateRecipients,
                            &project_path,
                            &binding.recipients,
                            &resolved_recipients,
                        )?;
                    }
                    None
                }
            },
        };

        if let Some(action) = action {
            Self::confirm_store_binding(
                interaction,
                action,
                &project_path,
                &[],
                &resolved_recipients,
            )?;
        }

        Ok(GpgStoreBinding {
            version: GPG_STORE_BINDING_VERSION,
            project_id,
            project_path: project_path_display,
            recipients: resolved_recipients,
        })
    }

    /// Decrypt an already-opened GPG file so path changes cannot redirect GPG's input.
    fn decrypt_file(file: cap_std::fs::File, display_path: &Path) -> Result<String> {
        debug!("Decrypting GPG file: {}", display_path.display());
        let mut command = Command::new("gpg");
        command
            .args(["--decrypt", "--batch", "--quiet"])
            .stdin(Stdio::from(file.into_std()));
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

    /// Decrypt and parse the GPG env file, returning all key-value pairs.
    fn load_all(ctx: &ResolveContext) -> Result<HashMap<String, String>> {
        let location = Self::gpg_file_location(ctx.dir, ctx.config)?;
        let file = location.open()?;
        let content = Self::decrypt_file(file, &location.display_path)?;
        Ok(Self::parse_env_content(&content))
    }

    #[cfg(all(test, unix))]
    fn load_all_stored_secrets(ctx: &ResolveContext) -> Result<BTreeMap<String, StoredSecret>> {
        let location = Self::gpg_file_location(ctx.dir, ctx.config)?;
        let file = location.open()?;
        let content = Self::decrypt_file(file, &location.display_path)?;
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
    fn encrypt_to_file(content: &str, location: &GpgFileLocation, recipient: &str) -> Result<()> {
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
            super::wait_with_stderr_timeout(child, "Failed to wait for `gpg` encryption")
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
        self.store_with_interaction(key, value, ctx, None)
    }

    fn store_with_interaction(
        &self,
        key: &str,
        value: &str,
        ctx: &StoreContext,
        interaction: Option<&dyn ResolutionInteraction>,
    ) -> Result<()> {
        let gpg_config = ctx.config.effective_gpg(ctx.dir);
        let recipient = gpg_config
            .recipient
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("GPG recipient must be configured to store secrets"))?;

        let location = Self::gpg_file_location(ctx.dir, ctx.config)?;

        // Load and bind the existing store from one already-open, project-confined handle.
        let existing_content = if let Some(file) = location
            .open_optional()
            .context("Failed to check the existing GPG secret store")?
        {
            Some(
                Self::decrypt_file(file, &location.display_path)
                    .context("Refusing to overwrite an unreadable GPG secret store")?,
            )
        } else {
            None
        };
        let binding = Self::bind_store_for_write(
            existing_content.as_deref(),
            ctx.dir,
            recipient,
            interaction,
        )?;
        let mut existing = existing_content
            .as_deref()
            .map(Self::parse_stored_secrets)
            .unwrap_or_default();

        existing.insert(
            key.to_string(),
            StoredSecret {
                value: value.to_string(),
                project: ctx.project.clone(),
                migrated_from: Some(ctx.migrated_from()),
                created_with: Some(ctx.created_with()),
            },
        );

        let content = Self::serialize_bound_store(&existing, &binding);
        let recipient_fingerprint = binding
            .recipients
            .first()
            .context("GPG store binding has no recipient fingerprint")?;
        Self::encrypt_to_file(&content, &location, recipient_fingerprint)?;
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
fn store_config(recipient: &str) -> crate::config::Config {
    crate::config::Config {
        defaults: crate::config::Defaults {
            gpg: crate::config::GpgConfig {
                recipient: Some(recipient.to_string()),
                file_pattern: ".env.gpg".to_string(),
            },
            ..crate::config::Defaults::default()
        },
        log: crate::config::LogConfig::default(),
        updates: crate::config::UpdateConfig::default(),
        projects: vec![],
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::config::{Config, Defaults, LogConfig, UpdateConfig};
    use std::cell::{Cell, RefCell};

    struct TestGpgInteraction {
        approved: bool,
        actions: RefCell<Vec<GpgStoreBindingAction>>,
        progress_finished: std::rc::Rc<Cell<bool>>,
    }

    impl TestGpgInteraction {
        fn new(approved: bool) -> Self {
            Self {
                approved,
                actions: RefCell::new(Vec::new()),
                progress_finished: std::rc::Rc::new(Cell::new(false)),
            }
        }
    }

    #[derive(Default)]
    struct TestGpgProgress {
        finished: Option<std::rc::Rc<Cell<bool>>>,
    }

    impl super::super::ProgressReporter for TestGpgProgress {
        fn set_message(&mut self, _message: &str) {}
        fn finish(&mut self, _message: &str) {
            if let Some(finished) = &self.finished {
                finished.set(true);
            }
        }
    }

    impl super::super::ResolutionInteraction for TestGpgInteraction {
        fn confirm_gpg_store_binding(
            &self,
            action: GpgStoreBindingAction,
            _project_path: &Path,
            _previous_recipients: &[String],
            _new_recipients: &[String],
        ) -> Result<bool> {
            self.actions.borrow_mut().push(action);
            Ok(self.approved)
        }

        fn prompt_bitwarden_password(&self) -> Result<String> {
            bail!("not used by GPG tests")
        }

        fn start_progress(
            &self,
            _initial_message: &str,
        ) -> Box<dyn super::super::ProgressReporter> {
            Box::new(TestGpgProgress {
                finished: Some(self.progress_finished.clone()),
            })
        }
    }

    #[test]
    fn gpg_test_interaction_keeps_unused_bitwarden_prompt_rejected() {
        let interaction = TestGpgInteraction::new(false);
        assert!(interaction.prompt_bitwarden_password().is_err());
    }

    #[test]
    fn gpg_test_interaction_reports_progress_completion() {
        let interaction = TestGpgInteraction::new(false);
        let mut progress = interaction.start_progress("starting");
        progress.finish("finished");
        assert!(interaction.progress_finished.get());
    }

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
    fn gpg_recipient_parser_returns_primary_fingerprint_only() {
        let primary = "0123456789ABCDEF0123456789ABCDEF01234567";
        let subkey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let output = format!(
            "pub:u:2048:1:KEYID::::::scESC::::::\nfpr:::::::::{primary}:\nsub:u:2048:1:SUBKEY::::::e::::::\nfpr:::::::::{subkey}:\n"
        );

        assert_eq!(
            GpgBackend::parse_primary_recipient_fingerprint("selector", &output).unwrap(),
            primary
        );
    }

    #[test]
    fn gpg_recipient_parser_ignores_subkey_fingerprints_without_a_primary_fingerprint() {
        let subkey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let output = format!(
            "pub:u:2048:1:KEYID::::::scESC::::::\nsub:u:2048:1:SUBKEY::::::e::::::\nfpr:::::::::{subkey}:\n"
        );

        assert!(GpgBackend::parse_primary_recipient_fingerprint("selector", &output).is_err());
    }

    #[test]
    fn gpg_recipient_parser_rejects_missing_and_invalid_fingerprints() {
        let no_keys = "uid:u:::::::User Name::::::\n";
        let error = GpgBackend::parse_primary_recipient_fingerprint("selector", no_keys)
            .expect_err("a listing with no public key must fail");
        assert!(
            error
                .to_string()
                .contains("did not resolve to a public key")
        );

        for fingerprint in [String::new(), "Z".repeat(40)] {
            let output =
                format!("pub:u:2048:1:KEYID::::::scESC::::::\nfpr:::::::::{fingerprint}:\n");
            assert!(
                GpgBackend::parse_primary_recipient_fingerprint("selector", &output).is_err(),
                "invalid fingerprint should be rejected: {fingerprint:?}"
            );
        }
    }

    #[test]
    fn gpg_file_location_uses_default_pattern() {
        let config = Config {
            defaults: Defaults::default(),
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };
        let dir = tempfile::TempDir::new().unwrap();
        let location = GpgBackend::gpg_file_location(dir.path(), &config).unwrap();
        assert_eq!(
            location.display_path,
            dir.path().canonicalize().unwrap().join(".env.gpg")
        );
        assert_eq!(
            GpgBackend::validated_store_path(dir.path(), &config).unwrap(),
            location.display_path
        );
    }

    #[test]
    fn gpg_file_location_opens_contained_nested_file() {
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

        let location = GpgBackend::gpg_file_location(temp_dir.path(), &config).unwrap();
        assert_eq!(
            location.display_path,
            std::fs::canonicalize(&nested).unwrap()
        );
        assert!(location.open().is_ok());
    }

    #[test]
    fn gpg_file_location_preserves_contained_file_symlink_target() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let nested = temp_dir.path().join("secrets").join("custom.gpg");
        std::fs::create_dir_all(nested.parent().unwrap()).unwrap();
        std::fs::write(&nested, "ciphertext").unwrap();
        std::os::unix::fs::symlink("secrets/custom.gpg", temp_dir.path().join("alias.gpg"))
            .unwrap();
        let config = Config {
            defaults: Defaults {
                gpg: crate::config::GpgConfig {
                    file_pattern: "alias.gpg".to_string(),
                    recipient: None,
                },
                ..Defaults::default()
            },
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };

        let location = GpgBackend::gpg_file_location(temp_dir.path(), &config).unwrap();
        assert_eq!(
            location.display_path,
            std::fs::canonicalize(&nested).unwrap()
        );
        assert!(location.open().is_ok());
    }

    #[test]
    fn gpg_file_location_rejects_external_file_symlink_even_with_default_present() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let outside_dir = tempfile::TempDir::new().unwrap();
        let outside_file = outside_dir.path().join("outside.gpg");
        std::fs::write(&outside_file, "ciphertext").unwrap();
        std::fs::write(temp_dir.path().join(".env.gpg"), "default ciphertext").unwrap();
        std::os::unix::fs::symlink(&outside_file, temp_dir.path().join("linked.gpg")).unwrap();
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

        assert!(GpgBackend::gpg_file_location(temp_dir.path(), &config).is_err());
    }

    #[test]
    fn gpg_file_location_rejects_escaping_parent_symlink_for_missing_leaf() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let outside_dir = tempfile::TempDir::new().unwrap();
        std::fs::write(temp_dir.path().join(".env.gpg"), "default ciphertext").unwrap();
        std::os::unix::fs::symlink(outside_dir.path(), temp_dir.path().join("linked-dir")).unwrap();
        let config = Config {
            defaults: Defaults {
                gpg: crate::config::GpgConfig {
                    file_pattern: "linked-dir/new.gpg".to_string(),
                    recipient: Some("test@example.com".to_string()),
                },
                ..Defaults::default()
            },
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };

        assert!(GpgBackend::gpg_file_location(temp_dir.path(), &config).is_err());
        assert!(!outside_dir.path().join("new.gpg").exists());
    }

    #[test]
    fn relative_gpg_path_rejects_absolute_and_parent_components() {
        assert!(GpgBackend::relative_gpg_path("../../etc/shadow.gpg").is_err());
        assert!(GpgBackend::relative_gpg_path("/tmp/secrets.gpg").is_err());
        assert_eq!(
            GpgBackend::relative_gpg_path("./secrets/custom.gpg").unwrap(),
            PathBuf::from("secrets/custom.gpg")
        );
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
        with_mock_gpg_recipient(
            decrypt_output,
            "0123456789ABCDEF0123456789ABCDEF01234567",
            f,
        );
    }

    fn with_mock_gpg_recipient<F: FnOnce()>(decrypt_output: &str, fingerprint: &str, f: F) {
        let _guard = super::super::MOCK_PATH_MUTEX
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::TempDir::new().unwrap();
        let script_path = dir.path().join("gpg");
        // Return one primary fingerprint, echo decryption content, and capture
        // the encryption input for the private publication tests.
        let script = format!(
            "#!/bin/sh\nfor arg do\n  if [ \"$arg\" = \"--list-keys\" ]; then\n    printf 'pub:u:2048:1:KEYID::::::scESC::::::\\nfpr:::::::::%s:\\n' '{}'\n    exit 0\n  fi\ndone\nif [ \"$1\" = \"--decrypt\" ]; then\n[ \"$#\" -eq 3 ] || exit 92\nprintf '%s' '{}'\nelse\nfor arg do\n  [ \"$arg\" != \"--output\" ] || exit 91\ndone\ncat\nfi\nexit 0\n",
            fingerprint,
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

    fn binding_for(path: &Path, recipients: &[&str]) -> GpgStoreBinding {
        let (project_path, project_id) = GpgBackend::project_identity(path).unwrap();
        GpgStoreBinding {
            version: GPG_STORE_BINDING_VERSION,
            project_id,
            project_path: project_path.to_string_lossy().into_owned(),
            recipients: recipients
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
        }
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

    #[cfg(unix)]
    #[test]
    fn unix_staging_directory_validation_rejects_each_unsafe_attribute() {
        assert!(validate_unix_staging_directory(17, 17, 0o700).is_ok());
        assert!(validate_unix_staging_directory(18, 17, 0o700).is_err());
        assert!(validate_unix_staging_directory(17, 17, 0o600).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn remove_private_staging_directory_removes_the_open_directory() {
        use std::os::unix::fs::MetadataExt as StdMetadataExt;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let parent = Dir::open_ambient_dir(temp_dir.path(), cap_std::ambient_authority()).unwrap();
        let owner_uid = std::fs::metadata(temp_dir.path()).unwrap().uid();
        let stage = create_private_staging_dir(&parent, Path::new("stage"), owner_uid).unwrap();

        remove_private_staging_dir(stage).unwrap();

        assert!(!temp_dir.path().join("stage").exists());
    }

    #[cfg(unix)]
    #[test]
    fn optional_open_preserves_non_not_found_errors() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let path = temp_dir.path().join("loop.gpg");
        std::os::unix::fs::symlink("loop.gpg", &path).unwrap();
        let parent = Dir::open_ambient_dir(temp_dir.path(), cap_std::ambient_authority()).unwrap();
        let location = GpgFileLocation {
            parent,
            file_name: PathBuf::from("loop.gpg"),
            display_path: path,
        };

        let error = location.open_optional().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Failed to open GPG encrypted file")
        );
    }

    #[cfg(unix)]
    #[test]
    fn atomic_replacement_retries_only_a_staging_name_collision() {
        use std::os::unix::fs::MetadataExt as StdMetadataExt;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let parent = Dir::open_ambient_dir(temp_dir.path(), cap_std::ambient_authority()).unwrap();
        let owner_uid = std::fs::metadata(temp_dir.path()).unwrap().uid();
        let nonce = 41;
        let collision_name = format!(".pw-env-gpg-{}-{nonce}-0.tmpdir", std::process::id());
        std::fs::create_dir(temp_dir.path().join(&collision_name)).unwrap();
        let location = GpgFileLocation {
            parent,
            file_name: PathBuf::from("secrets.gpg"),
            display_path: temp_dir.path().join("secrets.gpg"),
        };

        location
            .replace_atomically_with_nonce(b"new ciphertext", owner_uid, nonce)
            .unwrap();

        assert_eq!(
            std::fs::read(temp_dir.path().join("secrets.gpg")).unwrap(),
            b"new ciphertext"
        );
        assert!(temp_dir.path().join(collision_name).is_dir());
        let remaining_staging_dirs = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".pw-env-gpg-")
            })
            .count();
        assert_eq!(remaining_staging_dirs, 1);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_replacement_fails_immediately_for_non_collision_staging_errors() {
        use std::os::unix::fs::{MetadataExt as StdMetadataExt, PermissionsExt};

        let temp_dir = tempfile::TempDir::new().unwrap();
        let parent = Dir::open_ambient_dir(temp_dir.path(), cap_std::ambient_authority()).unwrap();
        let owner_uid = std::fs::metadata(temp_dir.path()).unwrap().uid();
        let location = GpgFileLocation {
            parent,
            file_name: PathBuf::from("secrets.gpg"),
            display_path: temp_dir.path().join("secrets.gpg"),
        };
        let original_permissions = std::fs::metadata(temp_dir.path()).unwrap().permissions();
        let mut restricted_permissions = original_permissions.clone();
        restricted_permissions.set_mode(0o500);
        std::fs::set_permissions(temp_dir.path(), restricted_permissions).unwrap();

        let result = location.replace_atomically_with_nonce(b"new ciphertext", owner_uid, 42);

        std::fs::set_permissions(temp_dir.path(), original_permissions).unwrap();
        let error = result.expect_err("permission errors must not be treated as collisions");
        assert!(
            error
                .to_string()
                .contains("Failed to create private GPG staging directory")
        );
    }

    #[test]
    fn encrypt_to_file_writes_content_with_mock_gpg() {
        with_mock_gpg("", || {
            let temp_dir = tempfile::TempDir::new().unwrap();
            let config = Config {
                defaults: Defaults::default(),
                log: LogConfig::default(),
                updates: UpdateConfig::default(),
                projects: vec![],
            };
            let location = GpgBackend::gpg_file_location(temp_dir.path(), &config).unwrap();
            GpgBackend::encrypt_to_file("KEY=value\n", &location, "test@example.com").unwrap();

            assert_eq!(
                std::fs::read_to_string(location.display_path).unwrap(),
                "KEY=value\n"
            );
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
            let gpg_dir = temp_dir.path().join("secrets");
            std::fs::create_dir(&gpg_dir).unwrap();
            let gpg_file = gpg_dir.join("custom.gpg");
            let config = Config {
                defaults: Defaults {
                    gpg: crate::config::GpgConfig {
                        recipient: Some("test@example.com".to_string()),
                        file_pattern: "secrets/custom.gpg".to_string(),
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
            // A new file under a verified nested directory can be initialized.
            let interaction = TestGpgInteraction::new(true);
            GpgBackend
                .store_with_interaction("NEW_KEY", "new-value", &ctx, Some(&interaction))
                .unwrap();
            assert!(gpg_file.exists());
            assert_eq!(
                interaction.actions.borrow().as_slice(),
                &[GpgStoreBindingAction::EnrollNewStore]
            );
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
            let interaction = TestGpgInteraction::new(true);
            let result =
                GpgBackend.store_with_interaction("NEW_KEY", "new-value", &ctx, Some(&interaction));
            assert!(result.is_ok(), "store failed: {:?}", result);
            let encrypted = std::fs::read_to_string(&gpg_file).unwrap();
            assert!(encrypted.contains("# pw-env: gpg-store-binding="));
            assert!(encrypted.contains("EXISTING_KEY=\"existing-value\""));
            assert!(encrypted.contains("NEW_KEY=\"new-value\""));
            assert_eq!(
                interaction.actions.borrow().as_slice(),
                &[GpgStoreBindingAction::EnrollLegacyStore]
            );
        });
    }

    #[test]
    fn store_requires_explicit_approval_for_new_and_legacy_stores() {
        with_mock_gpg_recipient(
            "LEGACY_KEY=legacy-value\n",
            "0123456789ABCDEF0123456789ABCDEF01234567",
            || {
                let temp_dir = tempfile::TempDir::new().unwrap();
                let config = store_config("test@example.com");
                let ctx = super::super::StoreContext {
                    dir: temp_dir.path(),
                    config: &config,
                    project: None,
                    repository: None,
                };

                let new_error = GpgBackend
                    .store("NEW_KEY", "new-value", &ctx)
                    .expect_err("a new store must require an explicit enrollment prompt");
                assert!(
                    new_error
                        .to_string()
                        .contains("explicit interactive confirmation")
                );
                assert!(!temp_dir.path().join(".env.gpg").exists());

                let gpg_file = temp_dir.path().join(".env.gpg");
                let original = b"legacy ciphertext";
                std::fs::write(&gpg_file, original).unwrap();
                let legacy_error = GpgBackend
                    .store("NEW_KEY", "new-value", &ctx)
                    .expect_err("an unbound legacy store must require re-enrollment");
                assert!(
                    legacy_error
                        .to_string()
                        .contains("explicit interactive confirmation")
                );
                assert_eq!(std::fs::read(&gpg_file).unwrap(), original);
            },
        );
    }

    #[test]
    fn legacy_enrollment_prompts_once_then_matching_binding_is_silent() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let legacy_content = "EXISTING_KEY=existing-value\n";
        let interaction = TestGpgInteraction::new(true);

        with_mock_gpg_recipient(
            legacy_content,
            "0123456789ABCDEF0123456789ABCDEF01234567",
            || {
                let binding = GpgBackend::bind_store_for_write(
                    Some(legacy_content),
                    temp_dir.path(),
                    "test@example.com",
                    Some(&interaction),
                )
                .unwrap();
                assert_eq!(
                    interaction.actions.borrow().as_slice(),
                    &[GpgStoreBindingAction::EnrollLegacyStore]
                );

                let enrolled_content =
                    GpgBackend::serialize_bound_store(&BTreeMap::new(), &binding);
                let second_write_binding = GpgBackend::bind_store_for_write(
                    Some(&enrolled_content),
                    temp_dir.path(),
                    "test@example.com",
                    None,
                )
                .expect("matching enrolled store should not need another prompt");
                assert_eq!(second_write_binding, binding);
                assert_eq!(interaction.actions.borrow().len(), 1);
            },
        );
    }

    #[test]
    fn matching_store_binding_updates_without_another_prompt() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let binding = binding_for(
            temp_dir.path(),
            &["0123456789ABCDEF0123456789ABCDEF01234567"],
        );
        let mut secrets = BTreeMap::new();
        secrets.insert(
            "EXISTING_KEY".to_string(),
            StoredSecret {
                value: "existing-value".to_string(),
                ..StoredSecret::default()
            },
        );
        let content = GpgBackend::serialize_bound_store(&secrets, &binding);
        let gpg_file = temp_dir.path().join(".env.gpg");
        std::fs::write(&gpg_file, "ciphertext").unwrap();
        let config = store_config("test@example.com");
        let ctx = super::super::StoreContext {
            dir: temp_dir.path(),
            config: &config,
            project: None,
            repository: None,
        };

        with_mock_gpg_recipient(&content, "0123456789ABCDEF0123456789ABCDEF01234567", || {
            GpgBackend
                .store("NEW_KEY", "new-value", &ctx)
                .expect("matching binding should permit normal updates");
        });

        let updated = std::fs::read_to_string(gpg_file).unwrap();
        let updated_binding = GpgBackend::parse_store_binding(&updated).unwrap().unwrap();
        assert_eq!(updated_binding, binding);
        assert!(updated.contains("EXISTING_KEY=\"existing-value\""));
        assert!(updated.contains("NEW_KEY=\"new-value\""));
    }

    #[test]
    fn store_rejects_a_binding_from_another_project_before_replacement() {
        let foreign_dir = tempfile::TempDir::new().unwrap();
        let foreign_binding = binding_for(
            foreign_dir.path(),
            &["0123456789ABCDEF0123456789ABCDEF01234567"],
        );
        let content = GpgBackend::serialize_bound_store(&BTreeMap::new(), &foreign_binding);
        let project_dir = tempfile::TempDir::new().unwrap();
        let gpg_file = project_dir.path().join(".env.gpg");
        let original = b"foreign store ciphertext";
        std::fs::write(&gpg_file, original).unwrap();
        let config = store_config("test@example.com");
        let ctx = super::super::StoreContext {
            dir: project_dir.path(),
            config: &config,
            project: None,
            repository: None,
        };
        let interaction = TestGpgInteraction::new(true);

        with_mock_gpg_recipient(&content, "0123456789ABCDEF0123456789ABCDEF01234567", || {
            let error = GpgBackend
                .store_with_interaction("NEW_KEY", "new-value", &ctx, Some(&interaction))
                .expect_err("cross-project store must be rejected");
            assert!(error.to_string().contains("bound to a different project"));
        });

        assert!(interaction.actions.borrow().is_empty());
        assert_eq!(std::fs::read(gpg_file).unwrap(), original);
    }

    #[test]
    fn binding_rejects_each_project_identity_mismatch_independently() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let valid = binding_for(
            temp_dir.path(),
            &["0123456789ABCDEF0123456789ABCDEF01234567"],
        );
        let mut path_mismatch = valid.clone();
        path_mismatch.project_path.push_str("/different");
        let mut id_mismatch = valid.clone();
        let replacement = if id_mismatch.project_id.starts_with('0') {
            '1'
        } else {
            '0'
        };
        id_mismatch
            .project_id
            .replace_range(0..1, &replacement.to_string());

        with_mock_gpg_recipient("", "0123456789ABCDEF0123456789ABCDEF01234567", || {
            for (label, binding) in [("project path", path_mismatch), ("project ID", id_mismatch)] {
                let content = GpgBackend::serialize_bound_store(&BTreeMap::new(), &binding);
                let error = GpgBackend::bind_store_for_write(
                    Some(&content),
                    temp_dir.path(),
                    "test@example.com",
                    None,
                )
                .expect_err("a partial identity mismatch must be rejected");
                assert!(
                    error.to_string().contains("bound to a different project"),
                    "unexpected {label} mismatch error: {error}"
                );
            }
        });
    }

    #[test]
    fn changed_recipient_requires_approved_rotation_and_records_new_fingerprint() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let old_fingerprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let new_fingerprint = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let old_binding = binding_for(temp_dir.path(), &[old_fingerprint]);
        let mut secrets = BTreeMap::new();
        secrets.insert(
            "EXISTING_KEY".to_string(),
            StoredSecret {
                value: "existing-value".to_string(),
                ..StoredSecret::default()
            },
        );
        let content = GpgBackend::serialize_bound_store(&secrets, &old_binding);
        let gpg_file = temp_dir.path().join(".env.gpg");
        std::fs::write(&gpg_file, "original ciphertext").unwrap();
        let original = std::fs::read(&gpg_file).unwrap();
        let config = store_config("new@example.com");
        let ctx = super::super::StoreContext {
            dir: temp_dir.path(),
            config: &config,
            project: None,
            repository: None,
        };

        with_mock_gpg_recipient(&content, new_fingerprint, || {
            let error = GpgBackend
                .store("NEW_KEY", "new-value", &ctx)
                .expect_err("recipient changes require an explicit rotation prompt");
            assert!(
                error
                    .to_string()
                    .contains("explicit interactive confirmation")
            );
        });
        assert_eq!(std::fs::read(&gpg_file).unwrap(), original);

        let interaction = TestGpgInteraction::new(true);
        with_mock_gpg_recipient(&content, new_fingerprint, || {
            GpgBackend
                .store_with_interaction("NEW_KEY", "new-value", &ctx, Some(&interaction))
                .expect("approved rotation should re-encrypt the entire store");
        });
        assert_eq!(
            interaction.actions.borrow().as_slice(),
            &[GpgStoreBindingAction::RotateRecipients]
        );
        let updated = std::fs::read_to_string(gpg_file).unwrap();
        let updated_binding = GpgBackend::parse_store_binding(&updated).unwrap().unwrap();
        assert_eq!(updated_binding.recipients, vec![new_fingerprint]);
        assert!(updated.contains("EXISTING_KEY=\"existing-value\""));
        assert!(updated.contains("NEW_KEY=\"new-value\""));
    }

    #[test]
    fn malformed_binding_is_rejected_before_replacement() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let content = "# pw-env: gpg-store-binding={bad json}\nKEY=secret\n";
        let gpg_file = temp_dir.path().join(".env.gpg");
        let original = b"original ciphertext";
        std::fs::write(&gpg_file, original).unwrap();
        let config = store_config("test@example.com");
        let ctx = super::super::StoreContext {
            dir: temp_dir.path(),
            config: &config,
            project: None,
            repository: None,
        };

        with_mock_gpg_recipient(content, "0123456789ABCDEF0123456789ABCDEF01234567", || {
            let error = GpgBackend
                .store("NEW_KEY", "new-value", &ctx)
                .expect_err("malformed binding metadata must fail closed");
            assert!(error.to_string().contains("invalid binding metadata"));
        });
        assert_eq!(std::fs::read(gpg_file).unwrap(), original);
    }

    #[test]
    fn binding_parser_rejects_each_invalid_field_independently() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let valid = binding_for(
            temp_dir.path(),
            &["0123456789ABCDEF0123456789ABCDEF01234567"],
        );

        let mut bad_version = valid.clone();
        bad_version.version += 1;
        let mut short_project_id = valid.clone();
        short_project_id.project_id.pop();
        let mut non_hex_project_id = valid.clone();
        non_hex_project_id.project_id.replace_range(0..1, "G");
        let mut empty_project_path = valid.clone();
        empty_project_path.project_path.clear();
        let mut empty_recipients = valid.clone();
        empty_recipients.recipients.clear();
        let mut short_recipient = valid.clone();
        short_recipient.recipients[0] = "A".to_string();
        let mut non_hex_recipient = valid;
        non_hex_recipient.recipients[0] = "Z".repeat(40);

        for (label, binding) in [
            ("version", bad_version),
            ("project ID length", short_project_id),
            ("project ID encoding", non_hex_project_id),
            ("project path", empty_project_path),
            ("recipient list", empty_recipients),
            ("recipient length", short_recipient),
            ("recipient encoding", non_hex_recipient),
        ] {
            let content = GpgBackend::serialize_bound_store(&BTreeMap::new(), &binding);
            assert!(
                GpgBackend::parse_store_binding(&content).is_err(),
                "invalid {label} should be rejected"
            );
        }
    }

    #[test]
    fn failed_encryption_leaves_existing_ciphertext_unchanged() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let gpg_file = temp_dir.path().join(".env.gpg");
        let original = b"existing ciphertext";
        std::fs::write(&gpg_file, original).unwrap();
        let script = "#!/bin/sh\nfor arg do\n  if [ \"$arg\" = \"--list-keys\" ]; then\n    printf 'pub:u:2048:1:KEYID::::::scESC::::::\\nfpr:::::::::0123456789ABCDEF0123456789ABCDEF01234567:\\n'\n    exit 0\n  fi\ndone\nif [ \"$1\" = \"--decrypt\" ]; then\nprintf 'EXISTING_KEY=existing-value\\n'\nexit 0\nfi\nfor arg do\n  [ \"$arg\" != \"--output\" ] || exit 91\ndone\ncat >/dev/null\nprintf 'partial ciphertext'\nexit 1\n";

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
            let interaction = TestGpgInteraction::new(true);
            let error = GpgBackend
                .store_with_interaction("NEW_KEY", "new-value", &ctx, Some(&interaction))
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
            "#!/bin/sh\nfor arg do\n  if [ \"$arg\" = \"--list-keys\" ]; then\n    printf 'pub:u:2048:1:KEYID::::::scESC::::::\\nfpr:::::::::0123456789ABCDEF0123456789ABCDEF01234567:\\n'\n    exit 0\n  fi\ndone\nif [ \"$1\" = \"--decrypt\" ]; then\n  echo 'decrypt failed' >&2\n  exit 1\nfi\ntouch '{}'\nexit 0\n",
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
    fn gpg_file_location_rejects_traversal_without_fallback() {
        let temp_dir = tempfile::TempDir::new().unwrap();
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
        assert!(GpgBackend::gpg_file_location(temp_dir.path(), &config).is_err());
    }

    #[test]
    fn gpg_file_location_rejects_absolute_pattern() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let config = Config {
            defaults: Defaults {
                gpg: crate::config::GpgConfig {
                    file_pattern: temp_dir.path().join("secrets.gpg").display().to_string(),
                    recipient: None,
                },
                ..Defaults::default()
            },
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        };
        assert!(GpgBackend::gpg_file_location(temp_dir.path(), &config).is_err());
    }

    #[test]
    fn gpg_file_location_allows_safe_pattern() {
        let temp_dir = tempfile::TempDir::new().unwrap();
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
        let location = GpgBackend::gpg_file_location(temp_dir.path(), &config).unwrap();
        assert_eq!(
            location.display_path,
            temp_dir.path().canonicalize().unwrap().join("secrets.gpg")
        );
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

#[cfg(all(test, windows))]
mod windows_mutation_tests {
    use super::*;
    use std::ffi::OsStr;
    use std::io::Write;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetSecurityInfo};
    use windows_sys::Win32::Security::{GetSecurityDescriptorDacl, PSECURITY_DESCRIPTOR};
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;

    // FILE_NON_DIRECTORY_FILE (0x40) | FILE_SYNCHRONOUS_IO_NONALERT (0x20).
    const TEST_FILE_CREATE_OPTIONS: u32 = 0x60;
    // DACL_SECURITY_INFORMATION (0x4) | PROTECTED_DACL_SECURITY_INFORMATION (0x80000000).
    const PROTECTED_DACL_INFO: u32 = 0x8000_0004;
    // DACL_SECURITY_INFORMATION (0x4) | UNPROTECTED_DACL_SECURITY_INFORMATION (0x20000000).
    const UNPROTECTED_DACL_INFO: u32 = 0x2000_0004;

    fn create_dacl_test_file(
        parent: &Dir,
        name: &str,
        sddl: windows_sys::core::PCWSTR,
    ) -> std::io::Result<std::fs::File> {
        create_windows_private_object(
            parent,
            OsStr::new(name),
            sddl,
            FILE_ATTRIBUTE_NORMAL,
            TEST_FILE_CREATE_OPTIONS,
        )
    }

    fn set_dacl_from_sddl(
        file: &impl AsRawHandle,
        sddl: windows_sys::core::PCWSTR,
        security_information: u32,
    ) -> std::io::Result<()> {
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl,
                1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }

        let mut dacl = std::ptr::null_mut();
        let mut dacl_present = 0;
        let mut dacl_defaulted = 0;
        if unsafe {
            GetSecurityDescriptorDacl(
                descriptor,
                &mut dacl_present,
                &mut dacl,
                &mut dacl_defaulted,
            )
        } == 0
        {
            unsafe { LocalFree(descriptor as _) };
            return Err(std::io::Error::last_os_error());
        }

        let status = unsafe {
            SetSecurityInfo(
                file.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                security_information,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null_mut(),
            )
        };
        unsafe { LocalFree(descriptor as _) };
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    #[test]
    fn windows_mutation_staging_objects_are_private_shareable_and_removed() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let parent = Dir::open_ambient_dir(temp_dir.path(), cap_std::ambient_authority()).unwrap();
        assert_eq!(windows_directory_create_options(), 0x21);
        assert_eq!(windows_file_create_options(), TEST_FILE_CREATE_OPTIONS);
        assert_eq!(windows_file_share_mode(), 0x03);
        let stage = create_private_staging_dir(&parent, Path::new("stage"), 0).unwrap();
        // OBJECT_INHERIT_ACE (1) | CONTAINER_INHERIT_ACE (2).
        let directory_flags = 3u8;
        assert_eq!(directory_flags, 0x03);
        verify_private_windows_dacl(stage.as_raw_handle(), directory_flags).unwrap();

        let mut file = create_private_staging_file(&stage).unwrap();
        verify_private_windows_dacl(file.as_raw_handle(), 0).unwrap();
        file.write_all(b"staged ciphertext").unwrap();
        file.sync_all().unwrap();
        let second_reader = stage.open("ciphertext").unwrap();
        assert_eq!(second_reader.metadata().unwrap().len(), 17);
        drop(second_reader);
        drop(file);

        remove_private_staging_dir(stage).unwrap();
        assert!(parent.open_dir("stage").is_err());
    }

    #[test]
    fn windows_mutation_dacl_verifier_rejects_unprotected_and_non_owner_acls() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let parent = Dir::open_ambient_dir(temp_dir.path(), cap_std::ambient_authority()).unwrap();
        let cases = [
            (
                "unprotected",
                windows_sys::core::w!("D:(A;;FA;;;OW)"),
                UNPROTECTED_DACL_INFO,
            ),
            (
                "multiple-aces",
                windows_sys::core::w!("D:P(A;;FA;;;OW)(A;;FR;;;SY)"),
                PROTECTED_DACL_INFO,
            ),
            (
                "deny-ace",
                windows_sys::core::w!("D:P(D;;FA;;;OW)"),
                PROTECTED_DACL_INFO,
            ),
            (
                "unexpected-flags",
                windows_sys::core::w!("D:P(A;OI;FA;;;OW)"),
                PROTECTED_DACL_INFO,
            ),
            (
                "unexpected-rights",
                windows_sys::core::w!("D:P(A;;FR;;;OW)"),
                PROTECTED_DACL_INFO,
            ),
            (
                "unexpected-owner",
                windows_sys::core::w!("D:P(A;;FA;;;SY)"),
                PROTECTED_DACL_INFO,
            ),
            (
                "null-dacl",
                windows_sys::core::w!("D:NO_ACCESS_CONTROL"),
                PROTECTED_DACL_INFO,
            ),
        ];

        for (name, sddl, security_information) in cases {
            let stage_name = format!("stage-{name}");
            let stage = create_private_staging_dir(&parent, Path::new(&stage_name), 0).unwrap();
            let file = create_private_staging_file(&stage).unwrap();
            set_dacl_from_sddl(&file, sddl, security_information).unwrap();
            assert!(
                verify_private_windows_dacl(file.as_raw_handle(), 0).is_err(),
                "DACL case {name} should be rejected"
            );
            drop(file);
            remove_private_staging_dir(stage).unwrap();
        }
    }

    #[test]
    fn windows_mutation_dacl_verifier_propagates_native_handle_errors() {
        let error = verify_private_windows_dacl(std::ptr::null_mut(), 0).unwrap_err();
        assert!(error.raw_os_error().is_some());
    }

    #[test]
    fn windows_mutation_ntstatus_check_distinguishes_success_from_failure() {
        assert!(ntstatus_failed(-1));
        assert!(!ntstatus_failed(0));
        assert!(!ntstatus_failed(0x4000_0000));
    }

    #[test]
    fn windows_mutation_native_creation_rejects_a_name_collision() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let parent = Dir::open_ambient_dir(temp_dir.path(), cap_std::ambient_authority()).unwrap();
        let sddl = windows_sys::core::w!("D:P(A;;FA;;;OW)");
        let file = create_dacl_test_file(&parent, "duplicate", sddl).unwrap();
        drop(file);

        let error = create_dacl_test_file(&parent, "duplicate", sddl)
            .expect_err("FILE_CREATE must reject an existing entry");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn windows_mutation_name_length_validation_covers_utf16_boundaries() {
        let max_units = u16::MAX as usize / 2;
        assert_eq!(windows_name_length_bytes(1).unwrap(), 2);
        assert_eq!(windows_name_length_bytes(max_units).unwrap(), u16::MAX - 1);
        assert_eq!(
            windows_name_length_bytes(0).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(
            windows_name_length_bytes(max_units + 1).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );

        let temp_dir = tempfile::TempDir::new().unwrap();
        let parent = Dir::open_ambient_dir(temp_dir.path(), cap_std::ambient_authority()).unwrap();
        let valid_sddl = windows_sys::core::w!("D:P(A;;FA;;;OW)");
        let empty_name = create_dacl_test_file(&parent, "", valid_sddl).unwrap_err();
        assert_eq!(empty_name.kind(), std::io::ErrorKind::InvalidInput);
        let too_long = "x".repeat(max_units + 1);
        let too_long_name = create_dacl_test_file(&parent, &too_long, valid_sddl).unwrap_err();
        assert_eq!(too_long_name.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn windows_mutation_store_config_sets_gpg_recipient_and_file_pattern() {
        let config = store_config("test@example.com");

        assert_eq!(
            config.defaults.gpg.recipient.as_deref(),
            Some("test@example.com")
        );
        assert_eq!(config.defaults.gpg.file_pattern, ".env.gpg");
    }
}
