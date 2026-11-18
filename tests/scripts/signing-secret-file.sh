#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd -P)
script="$repo_root/scripts/setup-apple-signing-secrets.sh"
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
mkdir -p "$test_dir/bin"

cat > "$test_dir/bin/gh" <<'MOCK_GH'
#!/bin/bash
set -euo pipefail
cat > /dev/null
MOCK_GH
chmod 700 "$test_dir/bin/gh"

cert_file="$test_dir/certificate.p12"
password_input="$test_dir/password"
printf 'fixture-certificate-bytes' > "$cert_file"
printf 'dummy-cert-password\n' > "$password_input"

run_export() {
  local destination="$1"
  shift
  (umask 000; "$script" --cert "$cert_file" --cert-password-fd 3 --identity 'Developer ID Application: Example Corp (TEAMID1234)' --env-file "$destination" "$@" 3< "$password_input")
}

file_mode() {
  if stat -c '%a' "$1" >/dev/null 2>&1; then
    stat -c '%a' "$1"
  else
    stat -f '%Lp' "$1"
  fi
}

output_file="$test_dir/secrets.env"
run_export "$output_file"
[ "$(file_mode "$output_file")" = 600 ]
grep -Fx 'APPLE_CERT_PASSWORD=dummy-cert-password' "$output_file" >/dev/null

echo 'previous contents' > "$output_file"
chmod 0644 "$output_file"
run_export "$output_file"
[ "$(file_mode "$output_file")" = 600 ]
grep -Fx 'APPLE_CERT_PASSWORD=dummy-cert-password' "$output_file" >/dev/null

symlink_target="$test_dir/target"
symlink_output="$test_dir/link.env"
printf 'target must remain unchanged\n' > "$symlink_target"
ln -s "$symlink_target" "$symlink_output"
if run_export "$symlink_output" >/dev/null 2>&1; then
  printf '%s\n' 'symbolic-link destination was unexpectedly accepted' >&2
  exit 1
fi
[ -L "$symlink_output" ]
[ "$(cat "$symlink_target")" = 'target must remain unchanged' ]

shared_dir="$test_dir/shared"
mkdir -p "$shared_dir"
chmod 0777 "$shared_dir"
if run_export "$shared_dir/secrets.env" >/dev/null 2>&1; then
  printf '%s\n' 'shared export directory was unexpectedly accepted' >&2
  exit 1
fi
[ ! -e "$shared_dir/secrets.env" ]

if compgen -G "$test_dir/.pw-env-secrets.*" >/dev/null; then
  printf '%s\n' 'temporary credential directory remained after failure' >&2
  exit 1
fi

sentinel_file="$test_dir/upload-only.env"
printf 'keep this file unchanged\n' > "$sentinel_file"
PATH="$test_dir/bin:$PATH" "$script" \
  --cert "$cert_file" \
  --cert-password-fd 3 \
  --identity 'Developer ID Application: Example Corp (TEAMID1234)' \
  --repo example/pw-env \
  --set-gh-secrets \
  --env-file "$sentinel_file" \
  3< "$password_input" >/dev/null
[ "$(cat "$sentinel_file")" = 'keep this file unchanged' ]

printf '%s\n' 'signing secret file test passed'
