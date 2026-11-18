#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd -P)
script="$repo_root/scripts/install.sh"
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
mkdir -p "$test_dir/curl-bin" "$test_dir/wget-bin"

cat > "$test_dir/curl-bin/curl" <<'MOCK_CURL'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$@" > "$CURL_ARGS_LOG"
cat > "$CURL_INPUT_LOG"
printf '{"tag_name":"v9.8.7"}\n'
MOCK_CURL
chmod 700 "$test_dir/curl-bin/curl"

GITHUB_TOKEN='ghp_dummy_token_123' \
CURL_ARGS_LOG="$test_dir/curl-args" \
CURL_INPUT_LOG="$test_dir/curl-input" \
PATH="$test_dir/curl-bin:$PATH" \
  "$script" --dry-run > "$test_dir/curl-output"
! grep -F 'ghp_dummy_token_123' "$test_dir/curl-args"
grep -Fx 'Authorization: Bearer ghp_dummy_token_123' "$test_dir/curl-input" >/dev/null
grep -F 'tag=v9.8.7' "$test_dir/curl-output" >/dev/null

GITHUB_TOKEN='ghp_dummy_token_123' \
CURL_ARGS_LOG="$test_dir/fixed-version-args" \
CURL_INPUT_LOG="$test_dir/fixed-version-input" \
PATH="$test_dir/curl-bin:$PATH" \
  "$script" --version 1.2.3 --dry-run > "$test_dir/fixed-version-output"
[ ! -e "$test_dir/fixed-version-args" ]
[ ! -e "$test_dir/fixed-version-input" ]
grep -F 'tag=v1.2.3' "$test_dir/fixed-version-output" >/dev/null

for tool in bash uname mktemp awk; do
  tool_path=$(command -v "$tool")
  ln -s "$tool_path" "$test_dir/wget-bin/$tool"
done
cat > "$test_dir/wget-bin/wget" <<'MOCK_WGET'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$@" > "$WGET_ARGS_LOG"
printf '{"tag_name":"v4.5.6"}\n'
MOCK_WGET
chmod 700 "$test_dir/wget-bin/wget"

WGET_ARGS_LOG="$test_dir/wget-args" PATH="$test_dir/wget-bin" "$script" --dry-run > "$test_dir/wget-output"
grep -F 'tag=v4.5.6' "$test_dir/wget-output" >/dev/null
! grep -F 'Authorization:' "$test_dir/wget-args"

if GITHUB_TOKEN='ghp_dummy_token_123' WGET_ARGS_LOG="$test_dir/wget-auth-args" PATH="$test_dir/wget-bin" "$script" --dry-run > "$test_dir/wget-auth-output" 2> "$test_dir/wget-auth-error"; then
  printf '%s\n' 'authenticated wget fallback was unexpectedly allowed' >&2
  exit 1
fi
grep -F 'requires curl for safe token handling' "$test_dir/wget-auth-error" >/dev/null
! grep -F 'ghp_dummy_token_123' "$test_dir/wget-auth-error"
[ ! -e "$test_dir/wget-auth-args" ]

printf '%s\n' 'installer token argument test passed'
