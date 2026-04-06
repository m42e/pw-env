#!/usr/bin/env bash
# test.sh — demo and smoke-test for command-scoped secret loading.
#
# What this script does:
#   1. Locates the pw-env binary (cargo build if needed).
#   2. Creates a temporary XDG_CONFIG_HOME with a [[projects]] entry that
#      sets commands = ["printenv"] for this example directory.
#   3. Creates a temporary XDG_STATE_HOME for approval state.
#   4. Prepends examples/command-scoped/bin/ to PATH so the stub `op` CLI is used
#      instead of a real 1Password CLI.
#   5. Approves this directory for secret fetching.
#   6. Verifies that `pw-env hook` emits a command wrapper for printenv (not
#      a plain export block).
#   7. Verifies that `pw-env exec` injects secrets only into the child process.
#   8. Verifies that no secrets leaked into the parent shell environment.

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ---------------------------------------------------------------------------
# Locate pw-env binary
# ---------------------------------------------------------------------------
PW_ENV_BIN="$REPO_ROOT/target/debug/pw-env"
if [[ ! -x "$PW_ENV_BIN" ]]; then
    echo "Building pw-env (debug)..."
    cargo build --manifest-path "$REPO_ROOT/Cargo.toml" --quiet
fi

# ---------------------------------------------------------------------------
# Temporary directories (cleaned up on exit)
# ---------------------------------------------------------------------------
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

XDG_CONFIG_HOME="$TMP_DIR/config"
XDG_STATE_HOME="$TMP_DIR/state"
mkdir -p "$XDG_CONFIG_HOME/pw-env" "$XDG_STATE_HOME"

# ---------------------------------------------------------------------------
# Write global config: declare this directory as a project with commands
# ---------------------------------------------------------------------------
cat > "$XDG_CONFIG_HOME/pw-env/config.toml" <<TOML
[[projects]]
path = "$SCRIPT_DIR"
commands = ["printenv"]
TOML

# ---------------------------------------------------------------------------
# Put the stub op CLI first on PATH
# ---------------------------------------------------------------------------
export PATH="$SCRIPT_DIR/bin:$PATH"
export XDG_CONFIG_HOME
export XDG_STATE_HOME

# ---------------------------------------------------------------------------
# Approve this directory for secret fetching
# ---------------------------------------------------------------------------
echo "--- Approving secret fetch for $SCRIPT_DIR ---"
"$PW_ENV_BIN" approvals approve-fetch "$SCRIPT_DIR"

# ---------------------------------------------------------------------------
# Test 1: hook output must contain a command wrapper, not an export block
# ---------------------------------------------------------------------------
echo
echo "--- Test 1: pw-env hook should emit a command wrapper for 'printenv' ---"
HOOK_OUTPUT="$("$PW_ENV_BIN" hook "$SCRIPT_DIR" --shell bash)"
echo "$HOOK_OUTPUT"

if echo "$HOOK_OUTPUT" | grep -q '__pw_env_define_command_wrapper printenv'; then
    echo "PASS: hook contains command wrapper for printenv"
else
    echo "FAIL: expected '__pw_env_define_command_wrapper printenv' in hook output" >&2
    exit 1
fi

if echo "$HOOK_OUTPUT" | grep -q 'export API_KEY'; then
    echo "FAIL: hook must not export API_KEY directly in command-scoped mode" >&2
    exit 1
else
    echo "PASS: hook does not export API_KEY into parent shell"
fi

# ---------------------------------------------------------------------------
# Test 2: exec injects secrets only into the child process
# ---------------------------------------------------------------------------
echo
echo "--- Test 2: pw-env exec should inject API_KEY into child process ---"
API_KEY_VALUE="$("$PW_ENV_BIN" exec --dir "$SCRIPT_DIR" -- printenv API_KEY)"
if [[ "$API_KEY_VALUE" == "s3cr3t-api-key" ]]; then
    echo "PASS: API_KEY resolved to '$API_KEY_VALUE' inside child process"
else
    echo "FAIL: expected 's3cr3t-api-key', got '$API_KEY_VALUE'" >&2
    exit 1
fi

DB_VALUE="$("$PW_ENV_BIN" exec --dir "$SCRIPT_DIR" -- printenv DB_PASSWORD)"
if [[ "$DB_VALUE" == "s3cr3t-db-pass" ]]; then
    echo "PASS: DB_PASSWORD resolved to '$DB_VALUE' inside child process"
else
    echo "FAIL: expected 's3cr3t-db-pass', got '$DB_VALUE'" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Test 3: secrets must not have leaked into the current (parent) shell
# ---------------------------------------------------------------------------
echo
echo "--- Test 3: secrets must not be present in the parent shell ---"
if [[ -n "${API_KEY:-}" ]]; then
    echo "FAIL: API_KEY is set in the parent shell ('${API_KEY}')" >&2
    exit 1
else
    echo "PASS: API_KEY is not set in the parent shell"
fi

if [[ -n "${DB_PASSWORD:-}" ]]; then
    echo "FAIL: DB_PASSWORD is set in the parent shell ('${DB_PASSWORD}')" >&2
    exit 1
else
    echo "PASS: DB_PASSWORD is not set in the parent shell"
fi

echo
echo "All tests passed."
