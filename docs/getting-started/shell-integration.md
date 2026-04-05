# Shell integration

pw-env supports one-off exports and persistent shell hooks.

## One-off loading

=== "bash"

    ```console
    $ eval "$(pw-env export . --shell bash)"
    ```

=== "zsh"

    ```console
    $ eval "$(pw-env export . --shell zsh)"
    ```

=== "fish"

    ```console
    $ pw-env export . --shell fish | source
    ```

If the current directory does not contain a `.env` file, `pw-env export` returns nothing.

## Automatic loading on directory change

Install the generated hook into your shell startup file.

=== "bash"

    ```console
    $ eval "$(pw-env init bash)"
    ```

    Add the same line to `~/.bashrc`.

=== "zsh"

    ```console
    $ eval "$(pw-env init zsh)"
    ```

    Add the same line to `~/.zshrc`.

=== "fish"

    ```console
    $ pw-env init fish | source
    ```

    Add the same line to `~/.config/fish/config.fish`.

## What the generated hook does

1. Unsets the keys exported by the previous directory.
2. Checks whether the new working directory contains a `.env` file.
3. Runs `pw-env export` for that directory.
4. Evaluates the output only when pw-env returned export statements.

Warnings from `pw-env export` are written to stderr, so they remain visible when the hook is running automatically.

## Per-shell behavior

| Shell | Hook strategy |
| --- | --- |
| `bash` | Wraps `cd`, `pushd`, and `popd` |
| `zsh` | Registers a `chpwd` hook |
| `fish` | Uses a `PWD` variable event |

## Debugging shell behavior

When automatic loading does not look right, verify the project directly before changing your shell config:

```console
$ pw-env load .
$ pw-env export . --shell bash
```

If you expect a backend lookup but `pw-env export` prints nothing, check the `.env` file classification rules in [Resolution model](../concepts/resolution-model.md).