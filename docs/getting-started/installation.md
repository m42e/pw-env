# Installation

pw-env ships prebuilt binaries for macOS, Linux, and Windows, and it can also be built from source with Cargo.

## Install a release build

::: code-group

```console [Latest release]
curl -fsSL https://m42e.github.io/pw-env/install.sh | bash
```

```powershell [Latest release (PowerShell)]
PS> & ([scriptblock]::Create((irm https://m42e.github.io/pw-env/install.ps1)))
```

```console [Specific version]
curl -fsSL https://m42e.github.io/pw-env/install.sh | bash -s -- --version v0.2.8
```

```powershell [Specific version (PowerShell)]
PS> & ([scriptblock]::Create((irm https://m42e.github.io/pw-env/install.ps1))) -Version v0.2.8
```

```console [Custom install directory]
curl -fsSL https://m42e.github.io/pw-env/install.sh | bash -s -- --dir "$HOME/.local/bin"
```

```powershell [Custom install directory (PowerShell)]
PS> & ([scriptblock]::Create((irm https://m42e.github.io/pw-env/install.ps1))) -Dir "$HOME/.local/bin"
```

:::

If you already have `pw-env` installed, you can also update the current binary in place with `pw-env update`. See
[Updating pw-env](../guides/update.md).

## Build from source

```console
cargo build --release
./target/release/pw-env --version
```

The compiled binary is written to `target/release/pw-env`.

## Supported prebuilt targets

| Platform | Target |
| --- | --- |
| macOS Apple Silicon | `aarch64-apple-darwin` |
| macOS Intel | `x86_64-apple-darwin` |
| Linux x86_64 | `x86_64-unknown-linux-gnu` |
| Linux arm64 | `aarch64-unknown-linux-gnu` |
| Windows x86_64 | `x86_64-pc-windows-msvc` |

## Smoke test the install

```console
pw-env --version
pw-env check
pw-env config-template
```

`pw-env check` is the fastest way to verify that the backend CLIs you expect to use are on your `PATH` and that your
config file is being discovered.

## Preview this manual locally

```console
npm install
npm run docs:dev
```

For a production-style build instead of the live preview server:

```console
npm run docs:build
```

The static site is written to `site/`, which is what the GitHub Pages workflow publishes.
