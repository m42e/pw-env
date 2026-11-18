#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd -P)
script="$repo_root/scripts/setup-apple-signing-secrets.sh"
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
mkdir -p "$test_dir/bin" "$test_dir/captured"

cat > "$test_dir/bin/gh" <<'MOCK_GH'
#!/bin/bash
set -euo pipefail
[ "$1" = secret ] && [ "$2" = set ]
name="$3"
printf '%s\n' "$*" >> "$GH_ARGS_LOG"
cat > "$GH_CAPTURE_DIR/$name"
MOCK_GH
chmod 700 "$test_dir/bin/gh"

cert_file="$test_dir/certificate.p12"
password_input="$test_dir/passwords"
printf 'fixture-certificate-bytes' > "$cert_file"
printf 'dummy-cert-password\ndummy-app-password\n' > "$password_input"

GH_ARGS_LOG="$test_dir/args" GH_CAPTURE_DIR="$test_dir/captured" PATH="$test_dir/bin:$PATH" \
  "$script" \
    --cert "$cert_file" \
    --cert-password-fd 3 \
    --identity 'Developer ID Application: Example Corp (TEAMID1234)' \
    --apple-id developer@example.com \
    --app-password-fd 3 \
    --team-id TEAMID1234 \
    --repo example/pw-env \
    --set-gh-secrets \
    3< "$password_input"

expected_cert_base64=$(printf 'fixture-certificate-bytes' | base64 | tr -d '\n')
[ "$(cat "$test_dir/captured/APPLE_CERT_BASE64")" = "$expected_cert_base64" ]
[ "$(cat "$test_dir/captured/APPLE_CERT_PASSWORD")" = dummy-cert-password ]
[ "$(cat "$test_dir/captured/APPLE_SIGNING_IDENTITY")" = 'Developer ID Application: Example Corp (TEAMID1234)' ]
[ "$(cat "$test_dir/captured/APPLE_ID")" = developer@example.com ]
[ "$(cat "$test_dir/captured/APPLE_APP_PASSWORD")" = dummy-app-password ]
[ "$(cat "$test_dir/captured/APPLE_TEAM_ID")" = TEAMID1234 ]
! grep -F 'dummy-cert-password' "$test_dir/args"
! grep -F 'dummy-app-password' "$test_dir/args"
! grep -F "$expected_cert_base64" "$test_dir/args"
! grep -F -- '--body' "$test_dir/args"

printf '%s\n' 'signing secret upload test passed'
