//! Parse `.env` files and resolve managed entries through password-manager backends.
//!
//! The `pw-env` binary owns command-line parsing, shell output, shell hooks, and
//! interactive workflows. This crate owns the reusable environment model,
//! configuration, backend resolution, caching, and file replacement operations.

pub mod backend;
pub mod cache;
pub mod config;
pub mod env_file;
pub mod resolve;

pub use config::{
    BwConfig, CacheConfig, Config, Defaults, GpgConfig, LogConfig, OpConfig, ProjectOverride,
    SecretFetchApprovalMode,
};
pub use env_file::{EntryKind, EnvEntry, EnvFile, EnvLine};
pub use resolve::{detect_project_name, resolve_env_file, resolve_env_file_with_interaction};

#[cfg(feature = "test-support")]
pub mod test_support {
    pub use crate::backend::MOCK_PATH_MUTEX;
    pub use crate::cache::{
        keyring_test_lock, reset_test_keyring, set_test_keyring_available,
        set_test_secret_cache_index_path,
    };
    pub use crate::config::set_test_reviewed_migrations_path;

    use std::path::PathBuf;

    pub fn set_test_folder_cache_path(path: Option<PathBuf>) {
        crate::backend::bw::BwBackend::set_test_folder_cache_path(path);
    }

    pub fn set_test_sync_state_path(path: Option<PathBuf>) {
        crate::backend::bw::BwBackend::set_test_sync_state_path(path);
    }
}

#[cfg(all(test, feature = "test-support"))]
mod test_support_tests {
    use super::*;

    #[test]
    fn test_support_path_setters_update_bitwarden_paths() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let folder_path = temp_dir.path().join("folder-cache.json");
        let sync_path = temp_dir.path().join("sync-state.json");

        test_support::set_test_folder_cache_path(Some(folder_path.clone()));
        test_support::set_test_sync_state_path(Some(sync_path.clone()));

        assert_eq!(
            backend::bw::BwBackend::folder_cache_path(),
            Some(folder_path)
        );
        assert_eq!(backend::bw::BwBackend::sync_state_path(), Some(sync_path));

        test_support::set_test_folder_cache_path(None);
        test_support::set_test_sync_state_path(None);
    }
}
