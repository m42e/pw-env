pub mod bw;
pub mod gpg;
pub mod op;

use anyhow::{Context, Result};
use std::io::{self, Read};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::config::Config;

pub const CREATED_WITH_FIELD_NAME: &str = "created-with";
pub const PROJECT_FIELD_NAME: &str = "project";
pub const MIGRATED_FROM_FIELD_NAME: &str = "migrated_from";
pub const REPOSITORY_FIELD_NAME: &str = "repository";

/// Single shared mutex for all mock PATH manipulations in tests.
/// All backend mock helpers (bw, gpg, op) must hold this lock while modifying PATH
/// to prevent cross-module races when running tests in parallel.
#[cfg(any(test, feature = "test-support"))]
pub static MOCK_PATH_MUTEX: std::sync::LazyLock<std::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

/// Context passed to backend operations for resolving secrets.
pub struct ResolveContext<'a> {
    pub dir: &'a Path,
    pub config: &'a Config,
    /// Auto-detected or configured project name (for disambiguating multiple matches).
    pub project: Option<String>,
    /// Selected git remote URL for repository-aware disambiguation.
    pub repository: Option<String>,
    /// Optional CLI-provided interaction implementation.
    pub interaction: Option<&'a dyn ResolutionInteraction>,
}

/// Context passed to backend operations for storing secrets.
pub struct StoreContext<'a> {
    pub dir: &'a Path,
    pub config: &'a Config,
    pub project: Option<String>,
    pub repository: Option<String>,
}

/// Non-secret metadata shown when choosing between ambiguous 1Password items.
pub enum OpMigrationChoice {
    CreateNew,
    Reuse(usize),
    Skip,
}

pub struct OpMigrationItem {
    pub item: OpItemChoice,
    pub matches_plaintext: bool,
}

pub struct OpItemChoice {
    pub id: String,
    pub title: String,
    pub vault: Option<String>,
    pub created_at: Option<String>,
    pub directory: Option<String>,
    pub repository: Option<String>,
    pub project: Option<String>,
}

/// Why a GPG store needs the user's approval to establish its binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpgStoreBindingAction {
    EnrollNewStore,
    EnrollLegacyStore,
    RotateRecipients,
}

/// UI operations that may be needed while resolving or storing secrets.
///
/// The library never reads from a terminal or writes progress output itself.
/// Applications such as the `pw-env` CLI can provide these operations when
/// they want interactive Bitwarden unlocks and progress reporting.
pub trait ResolutionInteraction {
    /// Choose whether to reuse an existing value or create a separate item.
    fn select_op_migration_item(
        &self,
        _key: &str,
        _choices: &[OpMigrationItem],
    ) -> Result<OpMigrationChoice> {
        Ok(OpMigrationChoice::Skip)
    }

    /// Select an item and approve updating its directory/repository/project metadata.
    /// Returning None leaves items untouched and reports the ambiguity.
    fn select_op_item(
        &self,
        _key: &str,
        _choices: &[OpItemChoice],
        _dir: &Path,
        _repository: Option<&str>,
        _project: Option<&str>,
    ) -> Result<Option<usize>> {
        Ok(None)
    }

    /// Confirm binding a GPG store to a project and recipient fingerprint policy.
    /// The default refuses; applications must explicitly provide an interactive approval.
    fn confirm_gpg_store_binding(
        &self,
        _action: GpgStoreBindingAction,
        _project_path: &Path,
        _previous_recipients: &[String],
        _new_recipients: &[String],
    ) -> Result<bool> {
        Ok(false)
    }

    /// Ask the caller for a Bitwarden master password.
    fn prompt_bitwarden_password(&self) -> Result<String>;

    /// Start a progress reporter for a long-running operation.
    fn start_progress(&self, initial_message: &str) -> Box<dyn ProgressReporter>;
}

/// Progress output supplied by an embedding application.
pub trait ProgressReporter {
    /// Update the current operation message.
    fn set_message(&mut self, message: &str);

    /// Finish the current operation with a final message.
    fn finish(&mut self, message: &str);
}

impl StoreContext<'_> {
    pub fn created_with(&self) -> String {
        format!("pw-env ({})", env!("CARGO_PKG_VERSION"))
    }

    pub fn migrated_from(&self) -> String {
        self.dir.display().to_string()
    }
}

/// Trait for password manager backends.
pub trait Backend {
    /// Resolve a key to its secret value.
    /// For reference-style values (e.g. `op://vault/item/field`), the reference is passed as-is.
    /// For key-only lookups, the key name is passed and the backend uses its config to find it.
    fn resolve(&self, key: &str, reference: Option<&str>, ctx: &ResolveContext) -> Result<String>;

    /// Store a key-value pair in the password manager.
    fn store(&self, key: &str, value: &str, ctx: &StoreContext) -> Result<()>;

    /// Store a key-value pair with optional UI operations for explicit backend approval.
    fn store_with_interaction(
        &self,
        key: &str,
        value: &str,
        ctx: &StoreContext,
        _interaction: Option<&dyn ResolutionInteraction>,
    ) -> Result<()> {
        self.store(key, value, ctx)
    }

    /// Store or explicitly reuse a secret during migration, returning the value to verify.
    fn store_for_migration(
        &self,
        key: &str,
        value: &str,
        ctx: &StoreContext,
        _interaction: Option<&dyn ResolutionInteraction>,
    ) -> Result<String> {
        self.store_with_interaction(key, value, ctx, _interaction)?;
        Ok(value.to_owned())
    }

    /// Return the backend reference URL to write into the .env file after storing.
    /// Returns `None` for backends that do not use URL references (e.g. GPG).
    fn reference_url(&self, _key: &str, _ctx: &StoreContext) -> Option<String> {
        None
    }

    /// Check if a key exists in the password manager.
    fn has(&self, key: &str, ctx: &ResolveContext) -> Result<bool>;

    /// Return the name of this backend (for logging).
    fn name(&self) -> &str;
}

const EXTERNAL_COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
const EXTERNAL_COMMAND_STDOUT_LIMIT: usize = 16 * 1024 * 1024;
const EXTERNAL_COMMAND_STDERR_LIMIT: usize = 1024 * 1024;

/// Run a password-manager subprocess with a hard upper bound on how long it
/// may keep the resolver blocked. A hung CLI must not hang shell startup.
pub(crate) fn run_command_with_timeout(mut command: Command, context: &str) -> Result<Output> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = command
        .spawn()
        .map_err(anyhow::Error::from)
        .with_context(|| context.to_string())?;
    wait_with_output_timeout(child, context)
}

pub(crate) fn wait_with_output_timeout(child: Child, context: &str) -> Result<Output> {
    wait_with_output_timeout_limited(
        child,
        context,
        EXTERNAL_COMMAND_TIMEOUT,
        EXTERNAL_COMMAND_STDOUT_LIMIT,
        EXTERNAL_COMMAND_STDERR_LIMIT,
    )
}

/// Wait for a child whose stdout is redirected to a file or another sink, while
/// draining bounded stderr and enforcing the same command timeout.
pub(crate) fn wait_with_stderr_timeout(child: Child, context: &str) -> Result<Output> {
    wait_with_output_timeout_inner(
        child,
        context,
        EXTERNAL_COMMAND_TIMEOUT,
        0,
        EXTERNAL_COMMAND_STDERR_LIMIT,
        false,
    )
}

enum PipeReadError {
    LimitExceeded,
    Io(io::Error),
}

enum PipeOutput {
    Stdout(std::result::Result<Vec<u8>, PipeReadError>),
    Stderr(std::result::Result<Vec<u8>, PipeReadError>),
}

fn read_pipe_limited(
    mut pipe: impl Read,
    max_bytes: usize,
) -> std::result::Result<Vec<u8>, PipeReadError> {
    let mut output = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        let read = pipe.read(&mut chunk).map_err(PipeReadError::Io)?;
        if read == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(read) > max_bytes {
            return Err(PipeReadError::LimitExceeded);
        }
        output.extend_from_slice(&chunk[..read]);
    }
}

fn wait_with_output_timeout_limited(
    child: Child,
    context: &str,
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<Output> {
    wait_with_output_timeout_inner(child, context, timeout, stdout_limit, stderr_limit, true)
}

fn wait_with_output_timeout_inner(
    mut child: Child,
    context: &str,
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
    capture_stdout: bool,
) -> Result<Output> {
    let (sender, receiver) = mpsc::channel();
    let stdout_pipe = if capture_stdout {
        Some(child.stdout.take().context("Child stdout was not piped")?)
    } else {
        if child.stdout.is_some() {
            anyhow::bail!("Child stdout must be redirected when it is not captured");
        }
        None
    };
    let stderr_pipe = child.stderr.take().context("Child stderr was not piped")?;
    let mut stdout_reader = stdout_pipe.map(|stdout_pipe| {
        let stdout_sender = sender.clone();
        thread::spawn(move || {
            let _ = stdout_sender.send(PipeOutput::Stdout(read_pipe_limited(
                stdout_pipe,
                stdout_limit,
            )));
        })
    });
    let stderr_reader = thread::spawn(move || {
        let _ = sender.send(PipeOutput::Stderr(read_pipe_limited(
            stderr_pipe,
            stderr_limit,
        )));
    });

    let started_at = Instant::now();
    let mut status = None;
    let mut stdout = (!capture_stdout).then(Vec::new);
    let mut stderr = None;
    loop {
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(child_status)) => status = Some(child_status),
                Ok(None) => {}
                Err(error) => {
                    terminate_child(&mut child);
                    join_pipe_reader(&mut stdout_reader);
                    let _ = stderr_reader.join();
                    return Err(error).with_context(|| context.to_string());
                }
            }
        }

        while let Ok(output) = receiver.try_recv() {
            match output {
                PipeOutput::Stdout(Ok(bytes)) => stdout = Some(bytes),
                PipeOutput::Stderr(Ok(bytes)) => stderr = Some(bytes),
                PipeOutput::Stdout(Err(PipeReadError::LimitExceeded)) => {
                    terminate_child(&mut child);
                    join_pipe_reader(&mut stdout_reader);
                    let _ = stderr_reader.join();
                    anyhow::bail!("{context} exceeded stdout output limit of {stdout_limit} bytes");
                }
                PipeOutput::Stderr(Err(PipeReadError::LimitExceeded)) => {
                    terminate_child(&mut child);
                    join_pipe_reader(&mut stdout_reader);
                    let _ = stderr_reader.join();
                    anyhow::bail!("{context} exceeded stderr output limit of {stderr_limit} bytes");
                }
                PipeOutput::Stdout(Err(PipeReadError::Io(error)))
                | PipeOutput::Stderr(Err(PipeReadError::Io(error))) => {
                    terminate_child(&mut child);
                    join_pipe_reader(&mut stdout_reader);
                    let _ = stderr_reader.join();
                    return Err(error).with_context(|| context.to_string());
                }
            }
        }

        if status.is_some() && stdout.is_some() && stderr.is_some() {
            let status = status.take().expect("status was checked");
            let stdout = stdout.take().expect("stdout was checked");
            let stderr = stderr.take().expect("stderr was checked");
            join_pipe_reader(&mut stdout_reader);
            let _ = stderr_reader.join();
            return Ok(Output {
                status,
                stdout,
                stderr,
            });
        }

        if started_at.elapsed() >= timeout {
            terminate_child(&mut child);
            join_pipe_reader(&mut stdout_reader);
            let _ = stderr_reader.join();
            anyhow::bail!("{context} timed out after {} seconds", timeout.as_secs());
        }

        std::thread::sleep(Duration::from_millis(25));
    }
}

fn join_pipe_reader(reader: &mut Option<thread::JoinHandle<()>>) {
    if let Some(reader) = reader.take() {
        let _ = reader.join();
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Create a backend instance by name.
pub fn create_backend(name: &str) -> Result<Box<dyn Backend>> {
    match name {
        "op" => Ok(Box::new(op::OpBackend)),
        "bw" => Ok(Box::new(bw::BwBackend)),
        "gpg" => Ok(Box::new(gpg::GpgBackend)),
        other => anyhow::bail!("Unknown backend: {other}. Supported: op, bw, gpg"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Defaults, LogConfig, UpdateConfig};
    use std::io::Write;

    const PIPE_TEST_MODE_ENV: &str = "PW_ENV_PIPE_TEST_MODE";

    fn spawn_pipe_test_child(mode: &str) -> Child {
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backend::tests::command_output_pipe_child",
                "--nocapture",
            ])
            .env(PIPE_TEST_MODE_ENV, mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    fn make_config() -> Config {
        Config {
            defaults: Defaults::default(),
            log: LogConfig::default(),
            updates: UpdateConfig::default(),
            projects: vec![],
        }
    }

    #[test]
    fn command_output_pipe_child() {
        let Ok(mode) = std::env::var(PIPE_TEST_MODE_ENV) else {
            return;
        };

        match mode.as_str() {
            "large" => {
                let stderr = thread::spawn(|| {
                    let mut stream = io::stderr().lock();
                    stream.write_all(&vec![b'e'; 256 * 1024]).unwrap();
                });
                io::stdout()
                    .lock()
                    .write_all(&vec![b'o'; 256 * 1024])
                    .unwrap();
                stderr.join().unwrap();
            }
            "over-limit" => {
                let _ = io::stdout()
                    .lock()
                    .write_all(&vec![b'o'; EXTERNAL_COMMAND_STDOUT_LIMIT + 1]);
            }
            "nonzero" => {
                io::stdout().lock().write_all(b"partial output").unwrap();
                io::stderr().lock().write_all(b"expected failure").unwrap();
                panic!("child command failed");
            }
            "hang" => {
                io::stdout().lock().write_all(b"partial-secret").unwrap();
                loop {
                    thread::sleep(Duration::from_secs(1));
                }
            }
            "slow-exit" => {
                io::stdout().lock().write_all(b"partial-secret").unwrap();
                thread::sleep(Duration::from_secs(2));
            }
            other => panic!("unknown pipe test mode: {other}"),
        }
    }

    #[test]
    fn wait_with_output_timeout_drains_large_stdout_and_stderr() {
        let child = spawn_pipe_test_child("large");

        let output = wait_with_output_timeout_limited(
            child,
            "large output test",
            Duration::from_secs(10),
            EXTERNAL_COMMAND_STDOUT_LIMIT,
            EXTERNAL_COMMAND_STDERR_LIMIT,
        )
        .unwrap();

        assert!(output.status.success());
        assert!(output.stdout.len() >= 256 * 1024);
        assert!(output.stderr.len() >= 256 * 1024);
    }

    #[test]
    fn read_pipe_limited_accepts_exactly_the_configured_limit() {
        assert!(matches!(
            read_pipe_limited(&b"four"[..], 4),
            Ok(output) if output == b"four"
        ));
        assert!(matches!(
            read_pipe_limited(&b"four"[..], 5),
            Ok(output) if output == b"four"
        ));
        assert_eq!(EXTERNAL_COMMAND_STDERR_LIMIT, 1024 * 1024);
    }

    #[test]
    fn read_pipe_limited_stops_on_the_first_eof() {
        struct EofThenError(usize);

        impl io::Read for EofThenError {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                self.0 += 1;
                if self.0 == 1 {
                    Ok(0)
                } else {
                    Err(io::Error::other("read after end of stream"))
                }
            }
        }

        let mut pipe = EofThenError(0);
        assert!(matches!(
            read_pipe_limited(&mut pipe, 0),
            Ok(output) if output.is_empty()
        ));
        assert_eq!(pipe.0, 1, "reader must not be polled after EOF");
    }

    #[test]
    fn join_pipe_reader_consumes_and_joins_the_reader_handle() {
        let mut reader = Some(thread::spawn(|| {}));

        join_pipe_reader(&mut reader);
        assert!(reader.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn wait_with_output_timeout_keeps_completed_streams_until_child_exits() {
        let child = Command::new("sh")
            .args([
                "-c",
                "printf 'completed stdout'; exec 1>&-; sleep 0.2; printf 'late stderr' >&2",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let output = wait_with_output_timeout_limited(
            child,
            "staggered stream output test",
            Duration::from_secs(5),
            EXTERNAL_COMMAND_STDOUT_LIMIT,
            EXTERNAL_COMMAND_STDERR_LIMIT,
        )
        .unwrap();

        assert!(output.status.success());
        assert_eq!(output.stdout, b"completed stdout");
        assert_eq!(output.stderr, b"late stderr");
    }

    #[cfg(unix)]
    #[test]
    fn wait_with_output_timeout_waits_for_streams_inherited_by_a_descendant() {
        let child = Command::new("sh")
            .args(["-c", "sleep 0.2 &"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let output = wait_with_output_timeout_inner(
            child,
            "inherited stream output test",
            Duration::from_secs(2),
            EXTERNAL_COMMAND_STDOUT_LIMIT,
            EXTERNAL_COMMAND_STDERR_LIMIT,
            true,
        )
        .unwrap();

        assert!(output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn wait_with_output_timeout_waits_for_child_after_stderr_closes() {
        let child = Command::new("sh")
            .args(["-c", "printf 'early stderr' >&2; exec 2>&-; sleep 0.2"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let output = wait_with_output_timeout_inner(
            child,
            "staggered stderr output test",
            Duration::from_secs(2),
            EXTERNAL_COMMAND_STDOUT_LIMIT,
            EXTERNAL_COMMAND_STDERR_LIMIT,
            true,
        )
        .unwrap();

        assert!(output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"early stderr");
    }

    #[test]
    fn wait_with_output_timeout_reports_deadline_when_child_exits_later() {
        let child = spawn_pipe_test_child("slow-exit");
        let started_at = Instant::now();

        let error = wait_with_output_timeout_limited(
            child,
            "slow output test",
            Duration::from_millis(50),
            EXTERNAL_COMMAND_STDOUT_LIMIT,
            EXTERNAL_COMMAND_STDERR_LIMIT,
        )
        .unwrap_err();

        assert!(error.to_string().contains("timed out"));
        assert!(!error.to_string().contains("partial-secret"));
        assert!(
            started_at.elapsed() < Duration::from_secs(1),
            "timed-out child must be terminated instead of being left to exit on its own"
        );
    }

    #[cfg(unix)]
    #[test]
    fn wait_with_stderr_timeout_supports_stdout_redirected_to_file() {
        let stdout_file = tempfile::NamedTempFile::new().unwrap();
        let child = Command::new("sh")
            .args([
                "-c",
                "printf 'redirected output'; printf 'captured diagnostics' >&2",
            ])
            .stdout(stdout_file.reopen().unwrap())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let output = wait_with_output_timeout_inner(
            child,
            "redirected output test",
            Duration::from_secs(2),
            0,
            EXTERNAL_COMMAND_STDERR_LIMIT,
            false,
        )
        .unwrap();

        assert!(output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"captured diagnostics");
        assert_eq!(
            std::fs::read(stdout_file.path()).unwrap(),
            b"redirected output"
        );
    }

    #[test]
    fn wait_with_output_timeout_rejects_over_limit_output_without_contents() {
        let child = spawn_pipe_test_child("over-limit");

        let error = wait_with_output_timeout_limited(
            child,
            "oversized output test",
            Duration::from_secs(10),
            1024,
            EXTERNAL_COMMAND_STDERR_LIMIT,
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("stdout output limit of 1024 bytes")
        );
        assert!(!error.to_string().contains("partial-secret"));
    }

    #[test]
    fn wait_with_output_timeout_preserves_nonzero_child_status_and_output() {
        let child = spawn_pipe_test_child("nonzero");

        let output = wait_with_output_timeout_limited(
            child,
            "nonzero output test",
            Duration::from_secs(10),
            EXTERNAL_COMMAND_STDOUT_LIMIT,
            EXTERNAL_COMMAND_STDERR_LIMIT,
        )
        .unwrap();

        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("partial output"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("expected failure"));
    }

    #[test]
    fn wait_with_output_timeout_kills_hung_child_without_exposing_partial_output() {
        let child = spawn_pipe_test_child("hang");

        let error = wait_with_output_timeout_limited(
            child,
            "hung output test",
            Duration::from_millis(100),
            EXTERNAL_COMMAND_STDOUT_LIMIT,
            EXTERNAL_COMMAND_STDERR_LIMIT,
        )
        .unwrap_err();

        assert!(error.to_string().contains("timed out"));
        assert!(!error.to_string().contains("partial-secret"));
    }

    #[test]
    fn test_create_backend_op() {
        let backend = create_backend("op").unwrap();
        assert_eq!(backend.name(), "1Password");
    }

    #[test]
    fn test_create_backend_bw() {
        let backend = create_backend("bw").unwrap();
        assert_eq!(backend.name(), "Bitwarden");
    }

    #[test]
    fn test_create_backend_gpg() {
        let backend = create_backend("gpg").unwrap();
        assert_eq!(backend.name(), "GPG");
    }

    #[test]
    fn test_create_backend_unknown_returns_error() {
        let result = create_backend("unknown");
        assert!(result.is_err());
        let err_str = format!("{}", result.err().unwrap());
        assert!(err_str.contains("Unknown backend"));
    }

    #[test]
    fn test_store_context_migrated_from() {
        let config = make_config();
        let ctx = StoreContext {
            dir: std::path::Path::new("/some/project/dir"),
            config: &config,
            project: None,
            repository: None,
        };
        assert_eq!(ctx.migrated_from(), "/some/project/dir");
    }

    #[test]
    fn test_store_context_created_with() {
        let config = make_config();
        let ctx = StoreContext {
            dir: std::path::Path::new("/some/project/dir"),
            config: &config,
            project: None,
            repository: None,
        };
        assert_eq!(
            ctx.created_with(),
            format!("pw-env ({})", env!("CARGO_PKG_VERSION"))
        );
    }

    struct DefaultInteraction;

    impl ResolutionInteraction for DefaultInteraction {
        fn prompt_bitwarden_password(&self) -> Result<String> {
            Ok(String::new())
        }

        fn start_progress(&self, _initial_message: &str) -> Box<dyn ProgressReporter> {
            Box::new(NoopProgressReporter)
        }
    }

    struct NoopProgressReporter;

    impl ProgressReporter for NoopProgressReporter {
        fn set_message(&mut self, _message: &str) {}

        fn finish(&mut self, _message: &str) {}
    }

    #[test]
    fn default_gpg_binding_interaction_refuses_enrollment() {
        assert!(
            !DefaultInteraction
                .confirm_gpg_store_binding(
                    GpgStoreBindingAction::EnrollNewStore,
                    Path::new("/project"),
                    &[],
                    &["0123456789ABCDEF0123456789ABCDEF01234567".to_string()],
                )
                .unwrap()
        );
    }

    #[derive(Default)]
    struct RecordingBackend {
        stores: std::cell::RefCell<Vec<(String, String)>>,
    }

    impl Backend for RecordingBackend {
        fn resolve(
            &self,
            _key: &str,
            _reference: Option<&str>,
            _ctx: &ResolveContext,
        ) -> Result<String> {
            anyhow::bail!("not implemented for recording backend")
        }

        fn store(&self, key: &str, value: &str, _ctx: &StoreContext) -> Result<()> {
            self.stores
                .borrow_mut()
                .push((key.to_string(), value.to_string()));
            Ok(())
        }

        fn has(&self, _key: &str, _ctx: &ResolveContext) -> Result<bool> {
            Ok(false)
        }

        fn name(&self) -> &str {
            "recording"
        }
    }

    #[test]
    fn backend_store_defaults_write_and_return_the_migration_value() {
        let config = make_config();
        let ctx = StoreContext {
            dir: Path::new("/project"),
            config: &config,
            project: None,
            repository: None,
        };
        let backend = RecordingBackend::default();

        backend
            .store_with_interaction("FIRST", "first-value", &ctx, None)
            .unwrap();
        assert_eq!(
            backend.stores.borrow().as_slice(),
            &[("FIRST".to_string(), "first-value".to_string())]
        );

        assert_eq!(
            backend
                .store_for_migration("SECOND", "verify-me", &ctx, None)
                .unwrap(),
            "verify-me"
        );
        assert_eq!(
            backend.stores.borrow().as_slice(),
            &[
                ("FIRST".to_string(), "first-value".to_string()),
                ("SECOND".to_string(), "verify-me".to_string())
            ]
        );
    }
}
