# Updating pw-env

pw-env can check GitHub releases for newer versions and replace the current binary with a matching release build.

## Automatic release checks

On interactive commands other than `export` and `update`, pw-env can check GitHub for a newer release. The interval is controlled by the `[updates]` section in the config file.

```toml title="~/.config/pw-env/config.toml"
[updates]
enabled = true
check_interval_hours = 24
```

Disable the check when you prefer to manage upgrades externally.

## Self-update the current binary

```console
$ pw-env update
```

Install a specific release instead of the latest available version:

```console
$ pw-env update --version v0.2.8
```

The updater downloads the release artifact that matches the current platform and replaces the running executable in place.

## Platforms supported by self-update

| Platform | Target |
| --- | --- |
| macOS Apple Silicon | `aarch64-apple-darwin` |
| macOS Intel | `x86_64-apple-darwin` |
| Linux x86_64 | `x86_64-unknown-linux-gnu` |
| Linux arm64 | `aarch64-unknown-linux-gnu` |
| Windows x86_64 | `x86_64-pc-windows-msvc` |

If your current executable came from a different packaging channel, keep using that channel instead of mixing install methods.