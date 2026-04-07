use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

#[test]
fn hook_outputs_exact_command_wrapper_without_path_match() {
    let workspace = TempDir::new().unwrap();
    let project_dir = workspace.path().join("project");
    let xdg_config_home = workspace.path().join("xdg");

    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(xdg_config_home.join("pw-env")).unwrap();
    std::fs::write(project_dir.join(".env"), "API_KEY=\n").unwrap();
    write_config(
        &xdg_config_home,
        &format!(
            "[[projects]]\npath = {:?}\ncommands = [\"cargo\"]\n",
            project_dir.to_string_lossy()
        ),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("hook")
        .arg(&project_dir)
        .arg("--shell")
        .arg("bash")
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("__pw_env_define_command_wrapper cargo\n"));
}

#[test]
fn hook_outputs_powershell_wrappers_and_tracking() {
    let workspace = TempDir::new().unwrap();
    let project_dir = workspace.path().join("project");
    let xdg_config_home = workspace.path().join("xdg");

    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(xdg_config_home.join("pw-env")).unwrap();
    std::fs::write(project_dir.join(".env"), "API_KEY=\n").unwrap();
    write_config(
        &xdg_config_home,
        &format!(
            "[[projects]]\npath = {:?}\ncommands = [\"cargo\", \"npm\"]\n",
            project_dir.to_string_lossy()
        ),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("hook")
        .arg(&project_dir)
        .arg("--shell")
        .arg("powershell")
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("__pw_env_define_command_wrapper 'cargo'\n"));
    assert!(stdout.contains("__pw_env_define_command_wrapper 'npm'\n"));
    assert!(stdout.contains("$global:__pw_env_previous_keys = @()\n"));
    assert!(stdout.contains("$global:__pw_env_previous_commands = @('cargo', 'npm')\n"));
}

#[test]
#[cfg_attr(windows, ignore)]
fn hook_expands_globbed_command_wrappers_from_path() {
    let workspace = TempDir::new().unwrap();
    let project_dir = workspace.path().join("project");
    let xdg_config_home = workspace.path().join("xdg");
    let bin_dir = workspace.path().join("bin");

    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(xdg_config_home.join("pw-env")).unwrap();
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::write(project_dir.join(".env"), "API_KEY=\n").unwrap();
    create_executable(&bin_dir.join("cargo"));
    create_executable(&bin_dir.join("cargo-watch"));
    create_executable(&bin_dir.join("npm"));

    write_config(
        &xdg_config_home,
        &format!(
            "[[projects]]\npath = {:?}\ncommands = [\"cargo*\"]\n",
            project_dir.to_string_lossy()
        ),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("hook")
        .arg(&project_dir)
        .arg("--shell")
        .arg("bash")
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("PATH", &bin_dir)
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("__pw_env_define_command_wrapper cargo\n"));
    assert!(stdout.contains("__pw_env_define_command_wrapper cargo-watch\n"));
    assert!(!stdout.contains("__pw_env_define_command_wrapper npm\n"));
}

#[test]
#[cfg_attr(windows, ignore)]
fn exec_removes_managed_keys_from_child_environment() {
    let workspace = TempDir::new().unwrap();
    let project_dir = workspace.path().join("project");
    let xdg_state_home = workspace.path().join("state");
    let bin_dir = workspace.path().join("bin");

    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(&xdg_state_home).unwrap();
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::write(project_dir.join(".env"), "HELLO=\n").unwrap();
    create_failing_executable(&bin_dir.join("op"));

    let approval = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("approvals")
        .arg("approve-fetch")
        .arg(&project_dir)
        .env("XDG_STATE_HOME", &xdg_state_home)
        .output()
        .unwrap();

    assert!(approval.status.success());

    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("exec")
        .arg("--dir")
        .arg(&project_dir)
        .arg("--")
        .arg("/usr/bin/env")
        .env("HELLO", "parent-value")
        .env("PATH", format!("{}:/usr/bin:/bin", bin_dir.display()))
        .env("XDG_STATE_HOME", &xdg_state_home)
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("HELLO=parent-value"));
}

// ── setup_logging (kills line 960: replace setup_logging with ()) ──

#[test]
fn setup_logging_creates_debug_log_when_file_configured() {
    let workspace = TempDir::new().unwrap();
    let project_dir = workspace.path().join("project");
    let xdg_config_home = workspace.path().join("xdg");
    let log_file = workspace.path().join("pw-env-debug.log");

    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(xdg_config_home.join("pw-env")).unwrap();
    // A non-secret plaintext entry causes resolve_env_file to emit a debug
    // "No resolvable entries" message, which should appear in the log file.
    std::fs::write(project_dir.join(".env"), "GREETING=hello\n").unwrap();
    // Use forward slashes so the path is valid in a TOML quoted string on all
    // platforms — Windows backslashes would be treated as TOML escape sequences.
    let log_file_toml = log_file.to_string_lossy().replace('\\', "/");
    let config_content = format!("[log]\nlevel = \"debug\"\nfile = \"{log_file_toml}\"\n");
    std::fs::write(
        xdg_config_home.join("pw-env").join("config.toml"),
        &config_content,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("export")
        .arg(&project_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("HOME", workspace.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    // If setup_logging is replaced with (), no file-based subscriber is
    // installed and the log file is never created or written to.
    assert!(
        log_file.exists(),
        "expected log file to be created when log.file is configured"
    );
    let log_content = std::fs::read_to_string(&log_file).unwrap();
    assert!(
        log_content.contains("No resolvable entries"),
        "expected debug messages in log file, got: {log_content}"
    );
}

fn write_config(xdg_config_home: &Path, contents: &str) {
    std::fs::write(xdg_config_home.join("pw-env/config.toml"), contents).unwrap();
}

fn create_executable(path: &Path) {
    std::fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
    set_executable(path);
}

fn create_failing_executable(path: &Path) {
    std::fs::write(path, "#!/bin/sh\nexit 1\n").unwrap();
    set_executable(path);
}

fn set_executable(_path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = std::fs::metadata(_path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(_path, permissions).unwrap();
    }
}

#[test]
fn init_outputs_bash_hook() {
    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("init")
        .arg("bash")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("__pw_env_hook"));
}

#[test]
fn init_outputs_zsh_hook() {
    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("init")
        .arg("zsh")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("chpwd"));
}

#[test]
fn init_outputs_fish_hook() {
    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("init")
        .arg("fish")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--on-variable PWD"));
}

#[test]
fn config_template_prints_defaults() {
    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("config-template")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[defaults]"));
    assert!(stdout.contains("backend"));
}

#[test]
fn check_succeeds_even_without_backends() {
    let workspace = TempDir::new().unwrap();
    let xdg_config_home = workspace.path().join("xdg");
    std::fs::create_dir_all(xdg_config_home.join("pw-env")).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("check")
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .output()
        .unwrap();
    assert!(output.status.success());
}

#[test]
fn approvals_list_shows_empty_when_no_approvals() {
    let workspace = TempDir::new().unwrap();
    let xdg_state_home = workspace.path().join("state");
    std::fs::create_dir_all(&xdg_state_home).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("approvals")
        .arg("list")
        .env("XDG_STATE_HOME", &xdg_state_home)
        .env("HOME", workspace.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("No approved"));
}

#[test]
fn approvals_list_fetch_shows_empty_when_no_approvals() {
    let workspace = TempDir::new().unwrap();
    let xdg_state_home = workspace.path().join("state");
    std::fs::create_dir_all(&xdg_state_home).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("approvals")
        .arg("list-fetch")
        .env("XDG_STATE_HOME", &xdg_state_home)
        .env("HOME", workspace.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("No approved"));
}

#[test]
fn approvals_approve_and_show_project_override() {
    let workspace = TempDir::new().unwrap();
    let project_dir = workspace.path().join("project");
    let xdg_state_home = workspace.path().join("state");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(&xdg_state_home).unwrap();
    std::fs::write(project_dir.join(".pw-env.toml"), "backend = \"op\"\n").unwrap();

    let approve = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("approvals")
        .arg("approve")
        .arg(&project_dir)
        .env("XDG_STATE_HOME", &xdg_state_home)
        .env("HOME", workspace.path())
        .output()
        .unwrap();
    assert!(approve.status.success(), "approve should succeed");

    let show = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("approvals")
        .arg("show")
        .arg(&project_dir)
        .env("XDG_STATE_HOME", &xdg_state_home)
        .env("HOME", workspace.path())
        .output()
        .unwrap();
    assert!(show.status.success(), "show should succeed");
    let stderr = String::from_utf8_lossy(&show.stderr);
    assert!(stderr.contains("approved") || stderr.contains("Status"));
}

#[test]
fn approvals_revoke_project_override() {
    let workspace = TempDir::new().unwrap();
    let project_dir = workspace.path().join("project");
    let xdg_state_home = workspace.path().join("state");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(&xdg_state_home).unwrap();
    std::fs::write(project_dir.join(".pw-env.toml"), "backend = \"op\"\n").unwrap();

    // Approve first
    Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("approvals")
        .arg("approve")
        .arg(&project_dir)
        .env("XDG_STATE_HOME", &xdg_state_home)
        .env("HOME", workspace.path())
        .output()
        .unwrap();

    // Then revoke
    let revoke = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("approvals")
        .arg("revoke")
        .arg(&project_dir)
        .env("XDG_STATE_HOME", &xdg_state_home)
        .env("HOME", workspace.path())
        .output()
        .unwrap();
    assert!(revoke.status.success(), "revoke should succeed");
    let stderr = String::from_utf8_lossy(&revoke.stderr);
    assert!(
        stderr.contains("Revoked") || stderr.contains("approval"),
        "unexpected output: {stderr}"
    );
}

#[test]
fn approvals_approve_fetch_and_show() {
    let workspace = TempDir::new().unwrap();
    let project_dir = workspace.path().join("project");
    let xdg_state_home = workspace.path().join("state");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(&xdg_state_home).unwrap();
    std::fs::write(project_dir.join(".env"), "API_KEY=\n").unwrap();

    let approve = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("approvals")
        .arg("approve-fetch")
        .arg(&project_dir)
        .env("XDG_STATE_HOME", &xdg_state_home)
        .env("HOME", workspace.path())
        .output()
        .unwrap();
    assert!(approve.status.success(), "approve-fetch should succeed");

    let show = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("approvals")
        .arg("show-fetch")
        .arg(&project_dir)
        .env("XDG_STATE_HOME", &xdg_state_home)
        .env("HOME", workspace.path())
        .output()
        .unwrap();
    assert!(show.status.success(), "show-fetch should succeed");
    let stderr = String::from_utf8_lossy(&show.stderr);
    assert!(
        stderr.contains("approved") || stderr.contains("Status"),
        "unexpected output: {stderr}"
    );
}

#[test]
fn approvals_revoke_fetch() {
    let workspace = TempDir::new().unwrap();
    let project_dir = workspace.path().join("project");
    let xdg_state_home = workspace.path().join("state");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(&xdg_state_home).unwrap();
    std::fs::write(project_dir.join(".env"), "API_KEY=\n").unwrap();

    // Approve first
    Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("approvals")
        .arg("approve-fetch")
        .arg(&project_dir)
        .env("XDG_STATE_HOME", &xdg_state_home)
        .env("HOME", workspace.path())
        .output()
        .unwrap();

    // Then revoke
    let revoke = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("approvals")
        .arg("revoke-fetch")
        .arg(&project_dir)
        .env("XDG_STATE_HOME", &xdg_state_home)
        .env("HOME", workspace.path())
        .output()
        .unwrap();
    assert!(revoke.status.success(), "revoke-fetch should succeed");
}

// ── Hook: fish shell syntax (kills line 301: delete match arm "fish" in Hook) ──

#[test]
fn hook_outputs_fish_wrappers_and_tracking() {
    let workspace = TempDir::new().unwrap();
    let project_dir = workspace.path().join("project");
    let xdg_config_home = workspace.path().join("xdg");

    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(xdg_config_home.join("pw-env")).unwrap();
    std::fs::write(project_dir.join(".env"), "API_KEY=\n").unwrap();
    write_config(
        &xdg_config_home,
        &format!(
            "[[projects]]\npath = {:?}\ncommands = [\"cargo\", \"npm\"]\n",
            project_dir.to_string_lossy()
        ),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("hook")
        .arg(&project_dir)
        .arg("--shell")
        .arg("fish")
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("__pw_env_define_command_wrapper cargo\n"),
        "expected fish cargo wrapper, got: {stdout}"
    );
    assert!(
        stdout.contains("__pw_env_define_command_wrapper npm\n"),
        "expected fish npm wrapper, got: {stdout}"
    );
    assert!(
        stdout.contains("set -g __pw_env_previous_keys \"\"\n"),
        "expected fish key tracking, got: {stdout}"
    );
    assert!(
        stdout.contains("set -g __pw_env_previous_commands cargo npm\n"),
        "expected fish command tracking, got: {stdout}"
    );
}

// ── Export: fish and powershell shell syntax (kills lines 239, 240) ──

#[test]
#[cfg_attr(windows, ignore)]
fn export_uses_fish_shell_syntax() {
    let workspace = TempDir::new().unwrap();
    let project_dir = workspace.path().join("project");
    let xdg_config_home = workspace.path().join("xdg");
    let xdg_state_home = workspace.path().join("state");
    let bin_dir = workspace.path().join("bin");

    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(xdg_config_home.join("pw-env")).unwrap();
    std::fs::create_dir_all(&xdg_state_home).unwrap();
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::write(project_dir.join(".env"), "API_KEY=op://vault/item/field\n").unwrap();

    // Fake op that outputs a resolved value
    std::fs::write(bin_dir.join("op"), "#!/bin/sh\necho 'fakevalue'\n").unwrap();
    set_executable(&bin_dir.join("op"));

    let approve = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("approvals")
        .arg("approve-fetch")
        .arg(&project_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("XDG_STATE_HOME", &xdg_state_home)
        .env("HOME", workspace.path())
        .output()
        .unwrap();
    assert!(approve.status.success(), "approve-fetch should succeed");

    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("export")
        .arg(&project_dir)
        .arg("--shell")
        .arg("fish")
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("XDG_STATE_HOME", &xdg_state_home)
        .env("HOME", workspace.path())
        .env("PATH", format!("{}:/usr/bin:/bin", bin_dir.display()))
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("set -gx API_KEY 'fakevalue'\n"),
        "expected fish export syntax, got: {stdout}"
    );
    assert!(
        stdout.contains("set -g __pw_env_previous_keys \"API_KEY\""),
        "expected fish key tracking, got: {stdout}"
    );
}

#[test]
#[cfg_attr(windows, ignore)]
fn export_uses_powershell_shell_syntax() {
    let workspace = TempDir::new().unwrap();
    let project_dir = workspace.path().join("project");
    let xdg_config_home = workspace.path().join("xdg");
    let xdg_state_home = workspace.path().join("state");
    let bin_dir = workspace.path().join("bin");

    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(xdg_config_home.join("pw-env")).unwrap();
    std::fs::create_dir_all(&xdg_state_home).unwrap();
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::write(project_dir.join(".env"), "API_KEY=op://vault/item/field\n").unwrap();

    std::fs::write(bin_dir.join("op"), "#!/bin/sh\necho 'fakevalue'\n").unwrap();
    set_executable(&bin_dir.join("op"));

    let approve = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("approvals")
        .arg("approve-fetch")
        .arg(&project_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("XDG_STATE_HOME", &xdg_state_home)
        .env("HOME", workspace.path())
        .output()
        .unwrap();
    assert!(approve.status.success(), "approve-fetch should succeed");

    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("export")
        .arg(&project_dir)
        .arg("--shell")
        .arg("powershell")
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("XDG_STATE_HOME", &xdg_state_home)
        .env("HOME", workspace.path())
        .env("PATH", format!("{}:/usr/bin:/bin", bin_dir.display()))
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("$env:API_KEY = 'fakevalue'\n"),
        "expected powershell export syntax, got: {stdout}"
    );
    assert!(
        stdout.contains("$global:__pw_env_previous_keys = @('API_KEY')\n"),
        "expected powershell key tracking, got: {stdout}"
    );
}

// ── Load: entry classification (kills lines 338, 341, 324) ──

#[test]
fn load_shows_no_migrate_label_for_annotated_entries() {
    let workspace = TempDir::new().unwrap();
    let project_dir = workspace.path().join("project");
    let xdg_config_home = workspace.path().join("xdg");

    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(xdg_config_home.join("pw-env")).unwrap();
    // Entry annotated with no-migrate should show the "no-migrate" label even
    // though the key name looks like a secret.
    std::fs::write(
        project_dir.join(".env"),
        "# no-migrate\nSECRET_KEY=supersecretvalue\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("load")
        .arg(&project_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("HOME", workspace.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("(plaintext value, no-migrate)"),
        "expected no-migrate label, got: {stderr}"
    );
    assert!(
        !stderr.contains("PLAINTEXT SECRET"),
        "expected no PLAINTEXT SECRET for no-migrate entry, got: {stderr}"
    );
}

#[test]
fn load_shows_plaintext_secret_label_and_warning_for_likely_secrets() {
    let workspace = TempDir::new().unwrap();
    let project_dir = workspace.path().join("project");
    let xdg_config_home = workspace.path().join("xdg");

    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(xdg_config_home.join("pw-env")).unwrap();
    std::fs::write(project_dir.join(".env"), "SECRET_KEY=supersecretvalue\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("load")
        .arg(&project_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("HOME", workspace.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("PLAINTEXT SECRET"),
        "expected PLAINTEXT SECRET label, got: {stderr}"
    );
    assert!(
        stderr.contains("Warning: likely plaintext secrets found"),
        "expected warning about likely plaintext secrets, got: {stderr}"
    );
}

#[test]
fn load_shows_no_warning_and_plaintext_label_for_non_secret_entries() {
    let workspace = TempDir::new().unwrap();
    let project_dir = workspace.path().join("project");
    let xdg_config_home = workspace.path().join("xdg");

    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(xdg_config_home.join("pw-env")).unwrap();
    std::fs::write(project_dir.join(".env"), "GREETING=hello\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("load")
        .arg(&project_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("HOME", workspace.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("(plaintext value)"),
        "expected (plaintext value) label, got: {stderr}"
    );
    assert!(
        !stderr.contains("Warning: likely plaintext secrets"),
        "expected no warning for non-secret plaintext, got: {stderr}"
    );
    assert!(
        !stderr.contains("PLAINTEXT SECRET"),
        "expected no PLAINTEXT SECRET label for non-secret entry, got: {stderr}"
    );
}

// ── emit_plaintext_secret_warning (kills lines 455, 456) ──

#[test]
fn export_emits_warning_for_likely_plaintext_secrets() {
    let workspace = TempDir::new().unwrap();
    let project_dir = workspace.path().join("project");
    let xdg_config_home = workspace.path().join("xdg");

    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(xdg_config_home.join("pw-env")).unwrap();
    std::fs::write(project_dir.join(".env"), "SECRET_KEY=supersecretvalue\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("export")
        .arg(&project_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("HOME", workspace.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("plaintext secrets"),
        "expected warning about plaintext secrets, got: {stderr}"
    );
}

#[test]
fn export_does_not_emit_warning_for_non_secret_plaintext() {
    let workspace = TempDir::new().unwrap();
    let project_dir = workspace.path().join("project");
    let xdg_config_home = workspace.path().join("xdg");

    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(xdg_config_home.join("pw-env")).unwrap();
    std::fs::write(project_dir.join(".env"), "GREETING=hello\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("export")
        .arg(&project_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("HOME", workspace.path())
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("plaintext secrets"),
        "expected no warning for non-secret plaintext, got: {stderr}"
    );
}

// ── check_backends (kills lines 642, 651, 666, 681) ──

#[test]
fn check_outputs_backend_not_found_markers() {
    let workspace = TempDir::new().unwrap();
    let xdg_config_home = workspace.path().join("xdg");
    let empty_bin = workspace.path().join("bin");
    std::fs::create_dir_all(xdg_config_home.join("pw-env")).unwrap();
    std::fs::create_dir_all(&empty_bin).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("check")
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("PATH", &empty_bin)
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // All three backends should report failure since PATH is empty
    assert!(
        stderr.contains("1Password CLI (op): ✗"),
        "expected op not found, got: {stderr}"
    );
    assert!(
        stderr.contains("Bitwarden CLI (bw): ✗"),
        "expected bw not found, got: {stderr}"
    );
    assert!(
        stderr.contains("GnuPG (gpg): ✗"),
        "expected gpg not found, got: {stderr}"
    );
}

#[test]
#[cfg_attr(windows, ignore)]
fn check_outputs_backend_found_marker_when_op_succeeds() {
    let workspace = TempDir::new().unwrap();
    let xdg_config_home = workspace.path().join("xdg");
    let bin_dir = workspace.path().join("bin");
    std::fs::create_dir_all(xdg_config_home.join("pw-env")).unwrap();
    std::fs::create_dir_all(&bin_dir).unwrap();

    // op succeeds and outputs a version string
    std::fs::write(bin_dir.join("op"), "#!/bin/sh\necho '2.28.0'\n").unwrap();
    set_executable(&bin_dir.join("op"));
    // bw and gpg fail so we can distinguish op's ✓ from theirs
    create_failing_executable(&bin_dir.join("bw"));
    create_failing_executable(&bin_dir.join("gpg"));

    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("check")
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("PATH", &bin_dir)
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("1Password CLI (op): ✓"),
        "expected op found marker, got: {stderr}"
    );
    assert!(
        stderr.contains("Bitwarden CLI (bw): ✗"),
        "expected bw not found, got: {stderr}"
    );
}

#[test]
#[cfg_attr(windows, ignore)]
fn check_shows_backend_failure_when_exits_nonzero() {
    let workspace = TempDir::new().unwrap();
    let xdg_config_home = workspace.path().join("xdg");
    let bin_dir = workspace.path().join("bin");
    std::fs::create_dir_all(xdg_config_home.join("pw-env")).unwrap();
    std::fs::create_dir_all(&bin_dir).unwrap();

    // op is present but exits non-zero (simulating auth failure or broken install)
    create_failing_executable(&bin_dir.join("op"));
    create_failing_executable(&bin_dir.join("bw"));
    create_failing_executable(&bin_dir.join("gpg"));

    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("check")
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("PATH", &bin_dir)
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("1Password CLI (op): ✗"),
        "expected op failure marker, got: {stderr}"
    );
    assert!(
        stderr.contains("Bitwarden CLI (bw): ✗"),
        "expected bw failure marker, got: {stderr}"
    );
    assert!(
        stderr.contains("GnuPG (gpg): ✗"),
        "expected gpg failure marker, got: {stderr}"
    );
}

// ── check_config (kills line 693) ──

#[test]
fn check_outputs_configuration_section() {
    let workspace = TempDir::new().unwrap();
    let xdg_config_home = workspace.path().join("xdg");
    let empty_bin = workspace.path().join("bin");
    std::fs::create_dir_all(xdg_config_home.join("pw-env")).unwrap();
    std::fs::create_dir_all(&empty_bin).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("check")
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("PATH", &empty_bin)
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Configuration:"),
        "expected 'Configuration:' section in check output, got: {stderr}"
    );
}

// ── handle_approvals: current == approved guard (kills line 760) ──

#[test]
fn approvals_show_reports_approved_status_when_hash_matches() {
    let workspace = TempDir::new().unwrap();
    let project_dir = workspace.path().join("project");
    let xdg_state_home = workspace.path().join("state");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(&xdg_state_home).unwrap();
    std::fs::write(project_dir.join(".pw-env.toml"), "backend = \"op\"\n").unwrap();

    Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("approvals")
        .arg("approve")
        .arg(&project_dir)
        .env("XDG_STATE_HOME", &xdg_state_home)
        .env("HOME", workspace.path())
        .output()
        .unwrap();

    let show = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("approvals")
        .arg("show")
        .arg(&project_dir)
        .env("XDG_STATE_HOME", &xdg_state_home)
        .env("HOME", workspace.path())
        .output()
        .unwrap();

    assert!(show.status.success());
    let stderr = String::from_utf8_lossy(&show.stderr);
    assert!(
        stderr.contains("Status: approved"),
        "expected 'Status: approved', got: {stderr}"
    );
}

#[test]
fn approvals_show_reports_changed_status_when_file_modified() {
    let workspace = TempDir::new().unwrap();
    let project_dir = workspace.path().join("project");
    let xdg_state_home = workspace.path().join("state");
    let override_file = project_dir.join(".pw-env.toml");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(&xdg_state_home).unwrap();
    std::fs::write(&override_file, "backend = \"op\"\n").unwrap();

    Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("approvals")
        .arg("approve")
        .arg(&project_dir)
        .env("XDG_STATE_HOME", &xdg_state_home)
        .env("HOME", workspace.path())
        .output()
        .unwrap();

    // Modify the file so the hash no longer matches
    std::fs::write(&override_file, "backend = \"bw\"\n").unwrap();

    let show = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("approvals")
        .arg("show")
        .arg(&project_dir)
        .env("XDG_STATE_HOME", &xdg_state_home)
        .env("HOME", workspace.path())
        .output()
        .unwrap();

    assert!(show.status.success());
    let stderr = String::from_utf8_lossy(&show.stderr);
    assert!(
        stderr.contains("Status: changed since approval"),
        "expected 'Status: changed since approval', got: {stderr}"
    );
}

#[test]
fn hook_outputs_empty_for_dir_without_env_file() {
    let workspace = TempDir::new().unwrap();
    let project_dir = workspace.path().join("project");
    let xdg_config_home = workspace.path().join("xdg");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::create_dir_all(xdg_config_home.join("pw-env")).unwrap();
    // No .env file in project_dir

    let output = Command::new(env!("CARGO_BIN_EXE_pw-env"))
        .arg("hook")
        .arg(&project_dir)
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.is_empty(), "expected empty output, got: {stdout}");
}
