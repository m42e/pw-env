# Configuration file

The main config file lives at `~/.config/pw-env/config.toml` unless an absolute `XDG_CONFIG_HOME` overrides that
location. Empty or relative XDG directory values are ignored. State files use `XDG_STATE_HOME` under the same rule.

If you prefer to build the file interactively, run `pw-env config-wizard`. The command opens a terminal UI with the
questions on the left and the generated TOML on the right, then saves the result to the standard config path.

## Default template

```toml [~/.config/pw-env/config.toml]
# pw-env configuration
# Place this file at ~/.config/pw-env/config.toml

[defaults]
# Default backend: "op" (1Password), "bw" (Bitwarden), or "gpg" (GPG encrypted file)
backend = "op"
# Search parent directories for .env until the git workspace root
# search_parent_env = true
# Also export plaintext (non-secret) values from .env alongside resolved secrets
# source_all = false
# Use .env.example as fallback when no .env file exists
# fallback_example_env = false

[defaults.cache]
# Cache resolved secret values in the OS keyring when available
enabled = true
# Re-fetch from the backend after this many hours
ttl_hours = 4

[defaults.op]
# Default 1Password vault to search in
# vault = "Development"
# Optional aliases for vault names used by `vault` and `op://...` references.
# [defaults.op.vault_aliases]
# work = "Work Vault"
# 1Password account shorthand (for multiple accounts)
# account = "my-team"
# Default item name - if set, keys are resolved as fields on this item
# item = "project-env"

[defaults.bw]
# Default Bitwarden folder to search in
# folder = "env-secrets"
# Stable account/server identifier used to isolate Bitwarden cache entries
# cache_identity = "vault.example.com:work-account"
# Default Bitwarden organization
# organization = "<organization-id>"
# Default Bitwarden organization collection ID (requires organization)
# collection = "<collection-id>"
# Default item name - if set, keys are resolved as custom fields on this item
# item = "project-env"

[defaults.gpg]
# Project-relative GPG file path; paths that escape the project directory are rejected.
file_pattern = ".env.gpg"
# GPG recipient for encrypting (required for `pw-env migrate` with GPG backend)
# recipient = "your-email@example.com"

[log]
# Log level: trace, debug, info, warn, error
level = "info"
# Log file path (optional, defaults to ~/.local/state/pw-env/pw-env.log)
# Successful credential fetches are also written here as AUDIT lines without secret values.
# file = "~/.local/state/pw-env/pw-env.log"

[updates]
# Automatically check GitHub releases for a newer pw-env version.
enabled = true
# Minimum time between automatic checks.
check_interval_hours = 24

# Per-project overrides
# Matched by directory path prefix - most specific match wins
#
# [[projects]]
# path = "/home/user/work/api-server"
# backend = "op"
# item = "api-server-env"
# commands = ["cargo", "npm"]
#
# [projects.cache]
# enabled = true
# ttl_hours = 1
#
# [projects.op]
# vault = "Work"
#
# [[projects]]
# path = "/home/user/personal/blog"
# backend = "gpg"
#
# [projects.gpg]
# file_pattern = ".secrets.gpg"
# recipient = "personal@example.com"
```

## Section reference

| Section | Keys | Notes |
| --- | --- | --- |
| `[defaults]` | `backend`, `search_parent_env`, `source_all`, `fallback_example_env` | Selects the default backend for empty `.env` values, controls parent `.env` discovery, controls whether plaintext values are exported, and enables `.env.example` fallback |
| `[defaults.cache]` | `enabled`, `ttl_hours` | Enables OS-keyring caching of resolved secrets and sets the expiry window |
| `[defaults.op]` | `vault`, `account`, `item` | Default 1Password lookup settings; `vault` may use a configured alias |
| `[defaults.op.vault_aliases]` | `<alias> = <vault>` | Maps user-friendly 1Password vault aliases to real vault names; also applies to `op://<alias>/...` references |
| `[defaults.bw]` | `folder`, `cache_identity`, `organization`, `collection`, `item` | Default Bitwarden lookup settings; organization items use an organization ID and optional collection ID |
| `[defaults.gpg]` | `file_pattern`, `recipient` | Project-relative GPG file path and encryption settings; paths that escape the project are rejected |
| `[log]` | `level`, `file` | Logging configuration and audit-log destination |
| `[updates]` | `enabled`, `check_interval_hours` | Automatic GitHub release checks |
| `[[projects]]` | `path`, `backend`, `search_parent_env`, `source_all`, `fallback_example_env`, `item`, `commands` | Per-path overrides; most specific path prefix wins |
| `[projects.cache]`, `[projects.op]`, `[projects.bw]`, `[projects.gpg]` | backend-specific keys | Extra settings for the most recent `[[projects]]` block |

Bitwarden `organization` and `collection` values are IDs from `bw list organizations` and
`bw list org-collections --organizationid <organization-id>`. A collection requires an
organization. Organization-scoped configuration cannot be combined with the personal
vault `folder` setting. Reads are restricted to the configured organization and, when
set, collection. New organization items require a collection; without one, reads and
updates can still use existing items owned by the configured organization.

Set `cache_identity` to a stable identifier that distinguishes both the Bitwarden server
and account, such as `vault.example.com:work-account`, to enable shared-secret caching for
Bitwarden. If it is unset or blank, Bitwarden secrets are not read from or written to the
shared cache. This value identifies the account for cache separation; do not put a
`BW_SESSION` token or other credential in it. Configure it in project overrides too when
they define their own Bitwarden settings, because project backend settings replace defaults.

## Valid backend values

`backend` accepts `op`, `bw`, or `gpg`.

## Project-local override file

For a repository-specific override, create `.pw-env.toml` in the project root or a parent directory inside the
repository.

```toml [.pw-env.toml]
backend = "op"
search_parent_env = true
source_all = false
fallback_example_env = false
item = "api-server-env"
commands = ["cargo", "npm"]

[cache]
enabled = true
ttl_hours = 4

[op]
vault = "Work"
```

`.pw-env.toml` uses the same backend-specific keys as the global config, but it does not use `[[projects]]` because the
file itself already scopes the override to the current project.

pw-env loads the local override only after the current file contents are approved.

When `search_parent_env` is `true`, pw-env walks upward from the working directory until it finds the first `.env`
file or reaches the enclosing git workspace root. Nested git markers such as submodules do not stop the walk early;
pw-env stops at the highest ancestor git root.

When `source_all` is `true`, pw-env exports all entries from the `.env` file — not just the ones resolved from a
backend. Entries with plaintext values (e.g. `LOG_LEVEL=debug`) are included in the shell exports or injected into
the child process alongside the secret values. Plaintext-only files also require approval before export, because their
values can affect shell startup and child-process behavior. The default is `false`, which means only backend-resolved
entries are exported.

When the same key has both a managed backend entry and a plaintext entry, the plaintext value does not substitute for
the managed lookup if that lookup fails.

When `[defaults.cache]` or `[cache]` is enabled, pw-env stores resolved secret values in the OS keyring when that
secure store is available. If the keyring is unavailable, pw-env keeps resolving from the backend normally and simply
skips secret-value caching for that run.

When `fallback_example_env` is `true` and no `.env` file is found in the project directory (or its
parents when `search_parent_env` is enabled), pw-env falls back to `.env.example` instead.
This is useful for repositories that check in a `.env.example` as a template with empty or
placeholder values. Entries resolved from the fallback file still require secret-fetch approval. The default is
`false`.

## Command-scoped shell integration

Set `commands` on a project entry or in `.pw-env.toml` to opt that project into transient command wrappers.

```toml
[[projects]]
path = "/home/user/work/api-server"
backend = "op"
item = "api-server-env"
commands = ["cargo", "npm", "terraform"]
```

When `commands` is set, the generated shell hook stops exporting resolved secrets into the parent shell for that
project. Instead it installs wrappers for the listed command names, and those wrappers run the command through
`pw-env exec`.

`commands` accepts exact command names and shell-style glob patterns that are matched against executable names on
`PATH`. Values must still resolve to safe shell command tokens such as `cargo`, `npm`, `docker-compose`, or patterns
such as `cargo*`.
