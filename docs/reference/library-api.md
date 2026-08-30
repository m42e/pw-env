# Library API

`pw-env-lib` is the reusable Rust package behind the `pw-env` executable. Use it when an application needs to parse
`.env` files, classify entries, resolve managed values, or replace values in an existing file without importing the
CLI's shell integration or terminal UI.

The package name on crates.io is `pw-env-lib`; the Rust crate name is `pw_env_lib`.

## Add the dependency

```toml
[dependencies]
anyhow = "1"
pw-env-lib = "0.3"
```

The library supports the same password-manager backends as the CLI: 1Password, Bitwarden, and GPG. Backend commands
and the OS keyring are used during resolution, so the corresponding tools and platform credentials must be available
to the host application.

## Parse and classify `.env`

`EnvFile::parse` reads an ordinary, non-symlink `.env` file and preserves every line. Entry values are classified as
`Empty`, `OpReference`, `BwReference`, or `Plaintext`.

```rust
use std::path::Path;
use pw_env_lib::{EntryKind, EnvFile};

let env_file = EnvFile::parse(Path::new(".env"))?;

for entry in env_file.entries() {
    match &entry.kind {
        EntryKind::Empty => println!("{} needs a default-backend lookup", entry.key),
        EntryKind::OpReference(reference) => println!("{} uses {}", entry.key, reference),
        EntryKind::BwReference(reference) => println!("{} uses {}", entry.key, reference),
        EntryKind::Plaintext(value) => println!("{} is plaintext: {}", entry.key, value),
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Useful entry selections are available through `entries`, `resolvable_entries`, `plaintext_entries`, and
`likely_secret_entries`. `EnvFile::find`, `EnvFile::find_with_parents`, and `EnvFile::find_example` provide the same
file discovery behavior used by the CLI.

## Resolve values

`resolve_env_file` returns a `BTreeMap<String, String>` containing the entries that resolved successfully. It does not
rewrite the source file. Plaintext values are omitted unless `source_all` is enabled in the effective configuration.

```rust
use std::path::Path;
use pw_env_lib::{Config, EnvFile, resolve_env_file};

let dir = Path::new(".");
let config = Config::load_for_dir(dir)?;
let env_path = EnvFile::find_with_parents(dir, config.effective_search_parent_env(dir))
    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no .env file found"))?;
let env_file = EnvFile::parse(&env_path)?;
let resolved = resolve_env_file(&env_file, &config, dir)?;

for (key, value) in resolved {
    println!("{key}={value}");
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

Before fetching credentials, the library checks the stored project and `.env` approval state. The no-argument API is
headless: it succeeds for an already approved project and returns an error when approval is missing. It never reads
from a terminal.

## Provide application interaction

Applications that own a user interface can use `resolve_env_file_with_interaction` to provide Bitwarden password input
and progress reporting:

```rust
use pw_env_lib::backend::ResolutionInteraction;
use pw_env_lib::resolve_env_file_with_interaction;

let resolved = resolve_env_file_with_interaction(
    &env_file,
    &config,
    dir,
    Some(&application_ui),
)?;
```

`application_ui` implements `ResolutionInteraction`:

- `prompt_bitwarden_password` supplies a password when Bitwarden is locked.
- `start_progress` returns a `ProgressReporter` for Bitwarden batch resolution.

The `pw-env` binary implements this trait with its hidden password prompt and stderr spinner. An embedding application
can instead provide a GUI, logging adapter, or another interaction model. Passing `None` keeps resolution completely
headless.

## Approvals and local configuration

`Config::load_for_dir` loads global settings and skips an unapproved `.pw-env.toml` without prompting. To let the host
application decide whether to apply the local override, use `load_for_dir_with_approval`:

```rust
let config = Config::load_for_dir_with_approval(dir, |path, changed| {
    let reason = if changed { "changed" } else { "is new" };
    println!("Approve {path:?}: {reason}");
    Ok(true)
})?;
```

Secret-fetch approval can be handled the same way with `ensure_secret_fetch_approved_with`. Its callback receives a
`SecretFetchApprovalRequest` and returns `Some(SecretFetchApprovalMode::CurrentEnvHash)`,
`Some(SecretFetchApprovalMode::ProjectWide)`, or `None` to deny the request. An approval decision is persisted by the
library; only the prompt and presentation belong to the host application.

## Replace values in a file

The parser preserves comments, blank lines, quoting, and trailing comments so callers can update a file without
rebuilding it from a map. These methods write the source file in place:

```rust
env_file.rewrite_with_key_value("API_KEY", "")?;
env_file.rewrite_with_cleared_keys(&["DATABASE_URL", "TOKEN"])?;
```

`rewrite_with_key_value` updates one matching key. `rewrite_with_cleared_keys` clears only the listed keys and leaves
the other entries unchanged. The CLI uses these operations during `add` and `migrate`.

## Library versus CLI

The library owns parsing, backend resolution, configuration state, cache state, and `.env` replacement. The `pw-env`
CLI owns Clap argument parsing, shell export formatting, shell hooks, child-process execution, interactive migration,
the configuration wizard, approval prompts, password prompts, and progress display.