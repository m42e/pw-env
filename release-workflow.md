# Release Workflow

This document describes the release workflow used in this repository and the design choices behind it so the same pattern can be reused in other projects.

## Goals

The workflow is built around four constraints:

- Release changes should be reviewable before a tag is created.
- Generated assets such as demos and release notes should be committed, not hidden inside a one-off workflow run.
- Release binaries should be built for multiple operating systems and CPU targets from the final tag.
- Publishing should happen from a controlled, reproducible workflow rather than from a developer workstation.

The result is a three-stage GitHub Actions flow:

1. A manually triggered workflow prepares a release branch and opens a pull request.
2. Merging that release pull request tags the exact merge commit.
3. A release workflow builds all release artifacts from the tag and publishes the GitHub release.

## Workflow Overview

The automation is split across these workflow files:

- `.github/workflows/prepare-release-pr.yml`
- `.github/workflows/tag-release-pr.yml`
- `.github/workflows/release.yml`

The CI workflow in `.github/workflows/ci.yml` is separate from the release flow. It validates normal pushes and pull requests, while the release workflows focus on producing and publishing versioned artifacts.

## Prerequisites

Repository settings must allow GitHub Actions to write to the repository and create pull requests:

- `Settings > Actions > General > Workflow permissions` must be set to `Read and write permissions`.
- `Allow GitHub Actions to create and approve pull requests` must be enabled.

If those settings are missing, the prepare step can still update files inside the workflow workspace, but it will fail when it tries to open the release pull request.

For local release preparation, these tools are required:

- `git`
- `python3`
- `cargo`
- `ffmpeg`

## Stage 1: Prepare The Release Pull Request

Workflow: `.github/workflows/prepare-release-pr.yml`

Trigger:

- `workflow_dispatch`
- Required input: `version` without the leading `v`

Purpose:

- Validate the requested version.
- Update versioned project files.
- Regenerate checked-in assets.
- Generate reviewable release notes.
- Open a dedicated release pull request.

### What the workflow does

1. Checks out the repository with full history.
2. Validates that the requested version looks like semantic versioning.
3. Fails if the target tag already exists.
4. Installs the Rust toolchain.
5. Restores and saves Cargo cache data.
6. Installs Python and `ffmpeg` for demo generation.
7. Updates `Cargo.toml` and `Cargo.lock` to the requested version.
8. Regenerates `demo/usage-demo.mp4` and `demo/usage-demo.gif`.
9. Generates `release-notes/vX.Y.Z.md` from unreleased Conventional Commits with `git-cliff`.
10. Uploads the demo files and release notes as workflow artifacts for easy inspection.
11. Opens a pull request from `release/vX.Y.Z` into `main`.

The generated `release-notes/vX.Y.Z.md` file is primarily a review artifact inside the release PR. The publish workflow later regenerates the final GitHub release body from the merged tag so the published notes match the actual released history.

### Why this stage exists

This stage keeps release preparation reviewable. Instead of creating a tag immediately, it turns all release-side effects into normal repository changes:

- version bumps are visible in the diff
- generated media is reviewable before shipping
- release notes can be edited in the pull request if needed

That makes the release flow safer and easier to reproduce in other repositories, especially if more generated files are involved.

### Reusable pattern for other projects

To reuse this stage elsewhere:

1. Decide which files define your release version.
2. Add any asset-generation steps that should be committed before release.
3. Generate release notes into a tracked file inside the repository.
4. Open a pull request with a deterministic branch name such as `release/vX.Y.Z`.
5. Add a specific label such as `release` so later workflows can safely identify the PR.

## Stage 2: Tag The Merged Release Pull Request

Workflow: `.github/workflows/tag-release-pr.yml`

Trigger:

- `pull_request`
- Type: `closed`

The job runs only when all of these conditions are true:

- the pull request was merged
- the base branch is `main`
- the source branch starts with `release/v`
- the pull request has the `release` label

### What the workflow does

1. Checks out the merge commit produced by the pull request.
2. Reads the version from `Cargo.toml`.
3. Verifies that the release branch name matches that version.
4. Verifies that the tag does not already exist.
5. Creates an annotated tag `vX.Y.Z` on the merge commit.
6. Pushes the tag.
7. Dispatches the release workflow and passes the tag as an explicit input.

### Why the workflow dispatch matters

This repository intentionally dispatches the release workflow after creating the tag, even though `.github/workflows/release.yml` also listens for tag pushes.

The reason is a GitHub Actions behavior that matters when you reuse this pattern: tags pushed by a workflow using the default `GITHUB_TOKEN` do not reliably trigger downstream workflows that listen only to `push` events. Dispatching the release workflow explicitly avoids that ambiguity and guarantees that publishing starts.

That is why the release workflow supports both:

- `push` on `v*` tags
- `workflow_dispatch` with a `tag` input

In practice, the automated path uses the dispatch input for reliability, while the tag push trigger remains useful for manual recovery or direct tag-based releases.

### Reusable pattern for other projects

If you adopt this design elsewhere:

1. Gate the tagging job tightly so only real release PRs can trigger it.
2. Resolve the version from source files on the merged commit, not from the PR title.
3. Create an annotated tag on the merge commit rather than on a branch tip that could move.
4. Dispatch the publish workflow explicitly after tagging.

## Stage 3: Build And Publish The Release

Workflow: `.github/workflows/release.yml`

Triggers:

- `push` for tags matching `v*`
- `workflow_dispatch` with required input `tag`

Shared environment:

- `RELEASE_TAG` is set to either the dispatch input or `github.ref_name`

This lets one workflow handle both normal tag pushes and explicit workflow dispatches.

### Build job responsibilities

The `build` job is a matrix build that creates one archive per target.

For each matrix entry it does the following:

1. Checks out the repository at the release tag.
2. Installs the Rust toolchain and required target.
3. Restores a target-specific Cargo cache.
4. Verifies that the tag version matches the crate version.
5. Builds the release binary for the matrix target.
6. Packages the binary into a platform-appropriate archive.
7. Uploads the packaged archive as a workflow artifact.

### Publish job responsibilities

The `publish` job runs only after all matrix builds complete. It:

1. Checks out the tagged revision.
2. Downloads all packaged artifacts into `dist/`.
3. Generates release notes with `git-cliff`.
4. Creates or updates the GitHub release with the generated notes and all built archives.

### Why build and publish are split

This separation is important:

- matrix builds can run in parallel on different runners
- packaging problems are isolated per target
- publishing happens exactly once after all required artifacts exist
- the final release job can gather every archive in one place before creating the GitHub release

That same structure is a good default in other projects, even if the build outputs are not Rust binaries.

## Matrix Build Design

The release matrix currently contains four targets:

| Runner | Rust target | Output binary | Archive format |
| --- | --- | --- | --- |
| `ubuntu-latest` | `x86_64-unknown-linux-gnu` | `transfer-rs` | `.tar.gz` |
| `windows-latest` | `x86_64-pc-windows-msvc` | `transfer-rs.exe` | `.zip` |
| `macos-14` | `x86_64-apple-darwin` | `transfer-rs` | `.tar.gz` |
| `macos-14` | `aarch64-apple-darwin` | `transfer-rs` | `.tar.gz` |

### Why this matrix is structured this way

- Linux covers the common GNU desktop and server target.
- Windows uses the MSVC toolchain because that is the standard Rust target on GitHub-hosted Windows runners.
- macOS is split into Intel and Apple Silicon targets because users may need native binaries for both.
- Each matrix entry explicitly defines the runner, Rust target, binary name, and target list so packaging logic stays simple and deterministic.

### Caching considerations

The workflow uses `Swatinem/rust-cache@v2` with a cache key derived from the target triple and stores artifacts under `target/<triple>`.

That target-specific cache key matters, especially when multiple matrix jobs run on the same operating system. In this repository, both macOS jobs run on `macos-14`, so sharing a generic cache key could cause collisions or unnecessary invalidation between `x86_64-apple-darwin` and `aarch64-apple-darwin` builds.

### Packaging considerations

- Unix-like targets use `tar -czf`.
- Windows uses `Compress-Archive` to produce a `.zip` file.
- Archive names include both the tag and the target triple so they are unambiguous when downloaded from the release page.

The naming pattern is:

`transfer-rs-vX.Y.Z-<target>.<extension>`

This is worth copying in other projects because it scales cleanly when more targets are added.

### Matrix build template for other projects

To adapt the same pattern:

1. Define the matrix with explicit `include` entries instead of deriving values indirectly.
2. Store the target triple, binary name, and any extra packaging metadata in each entry.
3. Use per-target caches when multiple jobs share the same runner family.
4. Produce one archive per target and upload it as an artifact.
5. Keep the publishing logic outside the matrix so there is only one release creation step.

## Relationship To CI

The normal CI workflow in `.github/workflows/ci.yml` runs on pushes to `main` and on pull requests. It validates the project on:

- `ubuntu-latest`
- `windows-latest`
- `macos-latest`

That workflow is intentionally lighter than the release matrix:

- it checks the version flag
- it builds the release profile
- it runs library and binary tests

The release workflow is narrower in purpose. It does not replace CI; it assumes the code has already passed normal review and CI before release preparation begins.

## Local Fallback Workflow

For local release preparation, this repository also includes `scripts/release.sh`.

It performs these steps:

1. Verifies that the repository is clean.
2. Validates the provided semantic version.
3. Updates `Cargo.toml` and `Cargo.lock`.
4. Regenerates the demo media.
5. Creates a release commit.
6. Creates an annotated tag.

Example:

```bash
./scripts/release.sh 1.0.1
```

The script does not push anything. That is deliberate. It leaves a final review point before the commit and tag are published.

This local path is useful when:

- GitHub Actions is unavailable
- you want to rehearse the release steps before automating them
- another project is not ready for a PR-driven release flow yet

## Why This Pattern Transfers Well To Other Projects

This workflow is not Rust-specific in its structure. The Rust details can be swapped out, but the overall pattern remains useful for many ecosystems:

- prepare release changes in a reviewable PR
- tag only after that PR is merged
- publish from the final tag
- use a build matrix when multiple platforms need release artifacts
- separate artifact production from final publishing

To port it to another project, replace only the project-specific pieces:

- version file updates
- build toolchain installation
- generated assets
- package and archive commands
- release note generator

The control flow and safety checks can stay largely the same.

## Files To Copy Or Adapt

If you want to reuse this exact shape in another repository, these are the main pieces to adapt:

- `.github/workflows/prepare-release-pr.yml`
- `.github/workflows/tag-release-pr.yml`
- `.github/workflows/release.yml`
- `.github/workflows/ci.yml`
- `scripts/release.sh`
- `.github/cliff.toml`

## Operational Notes

- Use a clear naming convention for release branches and tags, and validate both in automation.
- Keep release notes in the repository when human review is part of the process.
- Treat generated demo assets or screenshots like release artifacts if they are shown to users.
- Prefer annotated tags over lightweight tags for releases.
- Keep one publish job as the single place that creates the release object in GitHub.