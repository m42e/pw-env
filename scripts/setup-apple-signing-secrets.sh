#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: setup-apple-signing-secrets.sh --cert <certificate.p12> \
    --identity <signing identity> [--cert-password-fd <fd>] [options]

Prepare the GitHub Actions secrets used for optional macOS signing and notarization.

Required:
  --cert <path>               Path to the exported Developer ID Application .p12 file.
  --identity <identity>       Full codesigning identity, for example:
                              Developer ID Application: Example Corp (TEAMID1234)

Optional:
  --cert-password-fd <fd>     Read the certificate password from an inherited file descriptor.
                              Without this option, prompt securely on the terminal.
  --apple-id <email>          Apple ID used for notarization.
  --app-password-fd <fd>      Read the app-specific password from an inherited file descriptor.
                              Without this option, prompt securely on the terminal.
  --team-id <team-id>         Apple Developer Team ID for notarization.
  --repo <owner/repo>         GitHub repository for `gh secret set`.
  --set-gh-secrets            Upload secrets directly with GitHub CLI.
  --env-file <path>           Write KEY=VALUE lines to a file instead of stdout.
  -h, --help                  Show this help text.

Behavior:
  - Always prepares the signing secrets.
  - Only prepares notarization secrets when --apple-id and --team-id are provided.
  - The app password is prompted unless --app-password-fd is supplied.
  - With --set-gh-secrets, uploads the prepared values as repository secrets.
  - Without --set-gh-secrets, prints KEY=VALUE lines or writes them to --env-file.
  - Password values are never accepted as command-line arguments.
EOF
}

fail() {
  echo "Error: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

base64_no_wrap() {
  if base64 < /dev/null | tr -d '\n' >/dev/null 2>&1; then
    base64 | tr -d '\n'
    return
  fi

  fail "unable to encode base64 on this system"
}

write_secret_lines() {
  printf 'APPLE_CERT_BASE64=%s\n' "$CERT_BASE64"
  printf 'APPLE_CERT_PASSWORD=%s\n' "$CERT_PASSWORD"
  printf 'APPLE_SIGNING_IDENTITY=%s\n' "$SIGNING_IDENTITY"

  if [ "$HAS_NOTARIZATION" -eq 1 ]; then
    printf 'APPLE_ID=%s\n' "$APPLE_ID"
    printf 'APPLE_APP_PASSWORD=%s\n' "$APP_PASSWORD"
    printf 'APPLE_TEAM_ID=%s\n' "$TEAM_ID"
  fi
}

verify_safe_directory() {
  local directory directory_mode directory_owner mode_value permissions sticky_bits current_uid os_name direct_directory

  directory="$1"
  current_uid=$(id -u) || fail "unable to determine current user"
  os_name=$(uname -s) || fail "unable to determine operating system"
  direct_directory=1

  while :; do
    if directory_mode=$(stat -f '%Lp' "$directory" 2>/dev/null); then
      directory_owner=$(stat -f '%u' "$directory" 2>/dev/null) || fail "unable to inspect export directory"
    else
      directory_mode=$(stat -c '%a' "$directory" 2>/dev/null) || fail "unable to inspect export directory"
      directory_owner=$(stat -c '%u' "$directory" 2>/dev/null) || fail "unable to inspect export directory"
    fi
    case "$directory_mode" in
      *[!0-7]*|'') fail "unable to inspect export directory permissions" ;;
    esac
    mode_value=$((8#$directory_mode))
    permissions=$((mode_value & 0777))
    sticky_bits=$((mode_value & 01000))
    if [ "$direct_directory" -eq 1 ]; then
      if [ "$directory_owner" != "$current_uid" ] || [ $((permissions & 0022)) -ne 0 ]; then
        fail "export directory must be owned by the current user and not writable by others"
      fi
    else
      if [ "$directory_owner" != "$current_uid" ] && [ "$directory_owner" != 0 ]; then
        fail "export directory ancestors must be owned by the current user or root"
      fi
      if [ $((permissions & 0022)) -ne 0 ] && [ "$sticky_bits" -eq 0 ]; then
        fail "export directory ancestors must not be writable by others"
      fi
    fi
    if [ "$os_name" = Darwin ] && ls -lde "$directory" | awk '/^[[:space:]]*[0-9]+:.*[[:space:]]allow[[:space:]].*(add_file|add_subdirectory|delete_child|delete|write|append|writeattr|writeextattr|writesecurity|chown)(,|[[:space:]])/ { unsafe = 1 } END { exit !unsafe }'; then
      fail "export directories with access-control write grants are not supported"
    fi
    [ "$directory" = / ] && break
    direct_directory=0
    directory="${directory%/*}"
    [ -n "$directory" ] || directory="/"
  done
}

write_private_env_file() {
  local output_path output_dir output_name resolved_dir temporary_dir temporary_file

  case "$ENV_FILE" in
    /*) output_path="$ENV_FILE" ;;
    *) output_path="./$ENV_FILE" ;;
  esac

  if [ -L "$output_path" ]; then
    fail "refusing symbolic-link export destination"
  fi
  if [ -e "$output_path" ] && [ ! -f "$output_path" ]; then
    fail "export destination must be a regular file"
  fi

  output_dir="${output_path%/*}"
  output_name="${output_path##*/}"
  [ -n "$output_dir" ] || output_dir="/"
  [ -n "$output_name" ] || fail "export destination must name a file"
  [ -d "$output_dir" ] || fail "export directory does not exist"

  resolved_dir=$(cd "$output_dir" && pwd -P) || fail "unable to resolve export directory"
  verify_safe_directory "$resolved_dir"

  output_path="$resolved_dir/$output_name"
  if [ -L "$output_path" ]; then
    fail "refusing symbolic-link export destination"
  fi
  if [ -e "$output_path" ] && [ ! -f "$output_path" ]; then
    fail "export destination must be a regular file"
  fi

  temporary_dir=$(mktemp -d "$resolved_dir/.pw-env-secrets.XXXXXX") || fail "unable to create private export directory"
  OUTPUT_TEMP_DIR="$temporary_dir"
  if [ "$(uname -s)" = Darwin ]; then
    chmod -N "$temporary_dir" || fail "unable to remove inherited export-directory access controls"
  fi
  chmod 700 "$temporary_dir" || fail "unable to secure temporary export directory"
  temporary_file="$temporary_dir/secrets"
  (umask 077; write_secret_lines > "$temporary_file") || fail "unable to write export file"
  if [ "$(uname -s)" = Darwin ]; then
    chmod -N "$temporary_file" || fail "unable to remove inherited export-file access controls"
  fi
  chmod 600 "$temporary_file" || fail "unable to secure export file"

  if [ -L "$output_path" ]; then
    fail "refusing symbolic-link export destination"
  fi
  if [ -e "$output_path" ] && [ ! -f "$output_path" ]; then
    fail "export destination must be a regular file"
  fi
  mv -f "$temporary_file" "$output_path" || fail "unable to replace export file"
  rmdir "$temporary_dir" || fail "unable to remove private export directory"
  OUTPUT_TEMP_DIR=""
}

cleanup_temporary_output() {
  if [ -n "${OUTPUT_TEMP_DIR:-}" ] && [ -d "$OUTPUT_TEMP_DIR" ]; then
    rm -rf "$OUTPUT_TEMP_DIR"
  fi
}

upload_secret() {
  local name="$1"
  local value="$2"

  if [ -n "$REPO" ]; then
    printf '%s' "$value" | gh secret set "$name" --repo "$REPO" >/dev/null
  else
    printf '%s' "$value" | gh secret set "$name" >/dev/null
  fi
}

read_secret() {
  local prompt="$1"
  local input_fd="$2"
  local secret_value=""

  if [ -n "$input_fd" ]; then
    case "$input_fd" in
      *[!0-9]*) fail "password file descriptor must be a nonnegative integer" ;;
    esac
    if ! IFS= read -r -s -u "$input_fd" secret_value && [ -z "$secret_value" ]; then
      fail "unable to read password from file descriptor"
    fi
  else
    [ -r /dev/tty ] || fail "password input requires a terminal or a password file descriptor"
    printf '%s' "$prompt" > /dev/tty
    if ! IFS= read -r -s secret_value < /dev/tty; then
      printf '\n' > /dev/tty
      fail "unable to read password from terminal"
    fi
    printf '\n' > /dev/tty
  fi

  [ -n "$secret_value" ] || fail "password must not be empty"
  SECRET_VALUE="$secret_value"
}

CERT_PATH=""
CERT_PASSWORD=""
CERT_PASSWORD_FD=""
SIGNING_IDENTITY=""
APPLE_ID=""
APP_PASSWORD=""
APP_PASSWORD_FD=""
TEAM_ID=""
REPO=""
SET_GH_SECRETS=0
ENV_FILE=""
OUTPUT_TEMP_DIR=""
SECRET_VALUE=""
trap cleanup_temporary_output EXIT

while [ $# -gt 0 ]; do
  case "$1" in
    --cert)
      [ $# -ge 2 ] || fail "--cert requires a value"
      CERT_PATH="$2"
      shift 2
      ;;
    --cert-password-fd)
      [ $# -ge 2 ] || fail "--cert-password-fd requires a value"
      CERT_PASSWORD_FD="$2"
      shift 2
      ;;
    --identity)
      [ $# -ge 2 ] || fail "--identity requires a value"
      SIGNING_IDENTITY="$2"
      shift 2
      ;;
    --apple-id)
      [ $# -ge 2 ] || fail "--apple-id requires a value"
      APPLE_ID="$2"
      shift 2
      ;;
    --app-password-fd)
      [ $# -ge 2 ] || fail "--app-password-fd requires a value"
      APP_PASSWORD_FD="$2"
      shift 2
      ;;
    --team-id)
      [ $# -ge 2 ] || fail "--team-id requires a value"
      TEAM_ID="$2"
      shift 2
      ;;
    --repo)
      [ $# -ge 2 ] || fail "--repo requires a value"
      REPO="$2"
      shift 2
      ;;
    --set-gh-secrets)
      SET_GH_SECRETS=1
      shift
      ;;
    --env-file)
      [ $# -ge 2 ] || fail "--env-file requires a value"
      ENV_FILE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[ -n "$CERT_PATH" ] || fail "--cert is required"
[ -f "$CERT_PATH" ] || fail "certificate file not found: $CERT_PATH"
[ -n "$SIGNING_IDENTITY" ] || fail "--identity is required"

need_cmd base64

if [ "$SET_GH_SECRETS" -eq 1 ]; then
  need_cmd gh
fi

HAS_NOTARIZATION=0
if [ -n "$APPLE_ID" ] || [ -n "$APP_PASSWORD_FD" ] || [ -n "$TEAM_ID" ]; then
  [ -n "$APPLE_ID" ] || fail "--apple-id is required when notarization values are provided"
  [ -n "$TEAM_ID" ] || fail "--team-id is required when notarization values are provided"
  HAS_NOTARIZATION=1
fi

read_secret "Certificate password: " "$CERT_PASSWORD_FD"
CERT_PASSWORD="$SECRET_VALUE"
if [ "$HAS_NOTARIZATION" -eq 1 ]; then
  read_secret "Apple app-specific password: " "$APP_PASSWORD_FD"
  APP_PASSWORD="$SECRET_VALUE"
fi

CERT_BASE64=$(base64_no_wrap < "$CERT_PATH")

if [ "$SET_GH_SECRETS" -eq 1 ]; then
  upload_secret APPLE_CERT_BASE64 "$CERT_BASE64"
  upload_secret APPLE_CERT_PASSWORD "$CERT_PASSWORD"
  upload_secret APPLE_SIGNING_IDENTITY "$SIGNING_IDENTITY"

  if [ "$HAS_NOTARIZATION" -eq 1 ]; then
    upload_secret APPLE_ID "$APPLE_ID"
    upload_secret APPLE_APP_PASSWORD "$APP_PASSWORD"
    upload_secret APPLE_TEAM_ID "$TEAM_ID"
  fi

  echo "Uploaded signing secrets to GitHub."
  if [ "$HAS_NOTARIZATION" -eq 1 ]; then
    echo "Uploaded notarization secrets to GitHub."
  else
    echo "Skipped notarization secrets because they were not provided."
  fi
  exit 0
fi

if [ -n "$ENV_FILE" ]; then
  write_private_env_file
  echo "Wrote secrets to $ENV_FILE"
else
  write_secret_lines
fi
