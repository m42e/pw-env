use std::fs;
use std::path::Path;
use std::process::{Command, Output};

#[cfg(unix)]
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::sync::mpsc;
#[cfg(unix)]
use std::sync::{Arc, Mutex};
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::{Duration, Instant};

use tempfile::TempDir;

fn run_migrate(dir: &Path) -> Output {
    let home_dir = TempDir::new().unwrap();
    let config_dir = TempDir::new().unwrap();
    let state_dir = TempDir::new().unwrap();

    Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("migrate")
        .current_dir(dir)
        .env("HOME", home_dir.path())
        .env("XDG_CONFIG_HOME", config_dir.path())
        .env("XDG_STATE_HOME", state_dir.path())
        .output()
        .unwrap()
}

#[cfg(unix)]
fn create_mock_op() -> TempDir {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("op");
    fs::write(&path, "#!/bin/sh\necho mock-value\nexit 0\n").unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions).unwrap();
    dir
}

#[cfg(unix)]
fn run_migrate_in_pty(
    dir: &Path,
    op_dir: &Path,
    input: &str,
) -> (String, portable_pty::ExitStatus) {
    let home_dir = TempDir::new().unwrap();
    let config_dir = TempDir::new().unwrap();
    let state_dir = TempDir::new().unwrap();
    let old_path = std::env::var_os("PATH").unwrap_or_default();
    let path = std::env::join_paths(
        std::iter::once(op_dir.to_path_buf()).chain(std::env::split_paths(&old_path)),
    )
    .unwrap();

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();

    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_pw-env"));
    command.arg("migrate");
    command.cwd(dir);
    command.env("HOME", home_dir.path());
    command.env("XDG_CONFIG_HOME", config_dir.path());
    command.env("XDG_STATE_HOME", state_dir.path());
    command.env("PATH", path);

    let mut child = pair.slave.spawn_command(command).unwrap();
    drop(pair.slave);

    let mut reader = pair.master.try_clone_reader().unwrap();
    let writer = Arc::new(Mutex::new(pair.master.take_writer().unwrap()));
    let output = Arc::new(Mutex::new(Vec::new()));
    let output_reader = Arc::clone(&output);
    let writer_for_reader = Arc::clone(&writer);
    let (reader_done_tx, reader_done_rx) = mpsc::channel();
    let reader_thread = thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        let mut pending = Vec::new();
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    let chunk = &buffer[..read];
                    output_reader.lock().unwrap().extend_from_slice(chunk);

                    pending.extend_from_slice(chunk);
                    while let Some(pos) = pending.windows(4).position(|window| window == b"\x1b[6n")
                    {
                        pending.drain(..pos + 4);
                        writer_for_reader
                            .lock()
                            .unwrap()
                            .write_all(b"\x1b[1;1R")
                            .unwrap();
                        writer_for_reader.lock().unwrap().flush().unwrap();
                    }

                    let keep_from = pending.len().saturating_sub(3);
                    pending.drain(..keep_from);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let _ = reader_done_tx.send(());
    });

    thread::sleep(Duration::from_millis(100));
    writer.lock().unwrap().write_all(input.as_bytes()).unwrap();
    writer.lock().unwrap().flush().unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            drop(writer);
            child.kill().unwrap();
            drop(pair.master);
            let _ = reader_done_rx.recv_timeout(Duration::from_secs(1));
            let output = String::from_utf8_lossy(&output.lock().unwrap()).into_owned();
            panic!("migrate did not exit after PTY input; output: {output:?}");
        }
        thread::sleep(Duration::from_millis(10));
    };

    drop(writer);
    drop(pair.master);
    if reader_done_rx.recv_timeout(Duration::from_secs(1)).is_ok() {
        reader_thread.join().unwrap();
    }
    let output = String::from_utf8_lossy(&output.lock().unwrap()).into_owned();
    (output, status)
}

#[test]
fn migrate_reports_likely_secret_count_when_present() {
    let temp_dir = TempDir::new().unwrap();
    let env_path = temp_dir.path().join(".env");
    fs::write(
        &env_path,
        "API_KEY=super_secret_value_that_is_long_enough\nHOST=localhost\n",
    )
    .unwrap();

    let output = run_migrate(temp_dir.path());
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "migrate should fail without a tty"
    );
    assert!(
        stderr.contains("1 of them look like secrets based on key names or secret-like values."),
        "stderr did not include the likely-secret summary: {stderr}"
    );
}

#[test]
fn migrate_omits_likely_secret_count_when_none_are_detected() {
    let temp_dir = TempDir::new().unwrap();
    let env_path = temp_dir.path().join(".env");
    fs::write(&env_path, "HOST=localhost\nCOLOR=blue\n").unwrap();

    let output = run_migrate(temp_dir.path());
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "migrate should fail without a tty"
    );
    assert!(
        stderr.contains("Found 2 plaintext value(s) in"),
        "stderr should still list the plaintext entries: {stderr}"
    );
    assert!(
        !stderr.contains("look like secrets based on key names or secret-like values."),
        "stderr unexpectedly included the likely-secret summary: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn migrate_without_command_scope_does_not_prompt_for_commands() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(
        temp_dir.path().join(".env"),
        "API_KEY=super_secret_value_that_is_long_enough\n",
    )
    .unwrap();
    let op_dir = create_mock_op();

    let (output, status) = run_migrate_in_pty(temp_dir.path(), op_dir.path(), "\rn\r");

    assert!(status.success(), "interactive migration failed: {output}");
    assert!(output.contains("Done. Migrated values have been removed from .env."));
    assert!(!output.contains("Command names (space or comma separated"));
    assert!(!temp_dir.path().join(".pw-env.toml").exists());
}

#[cfg(unix)]
#[test]
fn migrate_restricted_scope_prints_approval_and_wrapper_instructions() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(
        temp_dir.path().join(".env"),
        "API_KEY=super_secret_value_that_is_long_enough\n",
    )
    .unwrap();
    let op_dir = create_mock_op();

    let (output, status) = run_migrate_in_pty(temp_dir.path(), op_dir.path(), "\ry\rcargo npm\r");

    assert!(status.success(), "interactive migration failed: {output}");
    assert!(output.contains("Configured migrated secrets for these commands only: cargo, npm"));
    assert!(output.contains("Approve it with: pw-env approvals approve"));
    assert!(output.contains("Then enable the shell wrappers once with one of these:"));
}
