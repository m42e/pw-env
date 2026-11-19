---
name: Release Workflow Preference
description: 'Use when the task involves creating, preparing, reviewing, tagging, or publishing a pw-env release. In this repository, default to the PR-driven release workflow: prepare-release-pr.yml, merge the release PR, let tag-release-pr.yml create the tag, then verify release.yml. Only use manual local tagging if the user explicitly asks for it.'
---

# Release Workflow Preference

- For release work in this repository, prefer the PR-driven workflow over manual local tagging.
- Start by using `.github/workflows/prepare-release-pr.yml` with a semver version without a leading `v`.
- Treat the generated `release/v<version>` pull request as the review gate for version bumps and release notes.
- After merge, expect `.github/workflows/tag-release-pr.yml` to create `v<version>` with a repository-scoped GitHub App token. The tag push starts `.github/workflows/release.yml`.
- The release workflow accepts only a `push` event for an exact `refs/tags/vN.N.N` ref and verifies that the current tag still points to the run commit before building.
- Configure repository secrets `RELEASE_APP_ID` and `RELEASE_APP_PRIVATE_KEY`. The installed App needs only repository `Contents: write`; the workflow scopes its installation token to this repository.
- Protect `refs/tags/v*` with a repository ruleset that allows creation only by authorized release maintainers and the release App, and prohibits tag updates and deletions after creation. The workflow cannot enforce those repository ruleset settings.
- Verify the publish workflow finishes successfully and that the GitHub release contains the expected artifacts.
- Only fall back to `./scripts/release.sh` and manual tag pushing if the user explicitly requests the manual path.
