# First project

The fastest way to adopt pw-env is to keep the shape of your `.env` file, then let the CLI fill in secrets at runtime.

## 1. Create the project env file

Use empty values for variables that should be loaded from the default backend:

```dotenv title=".env"
DATABASE_URL=
API_KEY=
```

Mix in explicit references when a key should always come from a specific backend:

```dotenv title=".env"
DATABASE_URL=op://Development/my-app/database_url
API_KEY=bw://env-secrets/my-app/api_key
LOG_LEVEL=debug
```

Plaintext values are left alone until you migrate them. Add `# no-migrate` when a local value should never be treated as a migration candidate.

## 2. Create the global config

Start from the built-in template:

```console
$ pw-env config-template > ~/.config/pw-manager-env/config.toml
```

Pick a default backend for empty values.

=== "1Password"

    ```toml title="~/.config/pw-manager-env/config.toml"
    [defaults]
    backend = "op"

    [defaults.op]
    vault = "Development"
    ```

=== "Bitwarden"

    ```toml title="~/.config/pw-manager-env/config.toml"
    [defaults]
    backend = "bw"

    [defaults.bw]
    folder = "env-secrets"
    ```

=== "GPG"

    ```toml title="~/.config/pw-manager-env/config.toml"
    [defaults]
    backend = "gpg"

    [defaults.gpg]
    file_pattern = ".env.gpg"
    recipient = "your-email@example.com"
    ```

## 3. Export the values into your shell

=== "bash or zsh"

    ```console
    $ eval "$(pw-env export . --shell bash)"
    ```

=== "fish"

    ```console
    $ pw-env export . --shell fish | source
    ```

The first time a project `.env` would trigger secret fetching, pw-env asks you to approve it. The default approval is tied to the current `.env` hash, so changing the file causes a new approval prompt.

## 4. Inspect what pw-env sees

```console
$ pw-env load .
$ pw-env check
```

`pw-env load` shows how each entry was classified before printing masked export output, which makes it a good first debugging command.

## 5. Install automatic loading when you are ready

```console
$ eval "$(pw-env init bash)"
```

Swap `bash` for `zsh` or `fish` as needed. See [Shell integration](shell-integration.md) for the full behavior.

## Next steps

Move to [Shell integration](shell-integration.md) when you want automatic loading on `cd`, or to [Migrating plaintext secrets](../guides/migrate-secrets.md) if your current `.env` file still contains credentials.