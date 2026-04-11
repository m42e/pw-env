use std::fs;
use std::path::Path;
use std::process::{Command, Output};

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
